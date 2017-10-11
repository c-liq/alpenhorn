#ifndef ALPENHORN_PKG_H
#define ALPENHORN_PKG_H

#include <thpool/thpool.h>
#include "config.h"
#include "utils.h"
#include "net.h"
#include "bn256_ibe.h"
#include "bn256_bls.h"

typedef struct pkg_pending_client {
  u8 user_id[user_id_BYTES];
  u8 sig_key[crypto_sign_PUBLICKEYBYTES];
  u8 confirmation_key[crypto_ghash_BYTES];
  time_t timeout;
} pkg_pending_client;

typedef struct pkg_client pkg_client;
typedef struct pkg pkg;

struct pkg_client {
  u8 user_id[user_id_BYTES];
  u8 sig_pk[crypto_sign_PUBLICKEYBYTES];
  u8 certificate_msg[pkg_sig_message_BYTES];
  u8 auth_data[pkg_auth_res_BYTES];
  twistpoint_fp2_t hashed_id;
  time_t last_auth;
  pkg *server;
};

struct pkg {
  u64 id;
  u64 num_clients;
  u64 client_capacity;
  u64 round;
  pkg_client *clients;
  u8 dh_sk[crypto_box_SECRETKEYBYTES];
  u8 dh_pk[crypto_box_PUBLICKEYBYTES];
  byte_buffer *broadcast;
  bn256_bls_keypair sig_keys;
  curvepoint_fp_t ibe_master_pk;
  scalar_t ibe_master_sk;
  int num_threads;
  list *registration_requests;
  net_server net_state;
  threadpool thread_pool;
  connection mix_conn;
};

void pkg_client_init(pkg_client *client, pkg *server, const u8 *user_id, const u8 *lt_sig_key);

void pkg_new_ibe_keypair(pkg *server);

int pkg_server_init(pkg *pkg, u64 id, u64 num_users, int num_threads, char *user_data_path);

void pkg_gen_identity_sk(pkg *server, pkg_client *client);

void pkg_gen_certificate(pkg *pkg, pkg_client *client);

void pkg_new_round(pkg *server);

int pkg_auth_client(pkg *server, pkg_client *client, connection *conn, byte_buffer *buf);

int pkg_client_lookup(pkg *server, u8 *user_id);

int pkg_parallel_operation(pkg *server, void *(*operator)(void *), u8 *data_ptr, u64 data_elem_length);

int pkg_registration_request(pkg *server, byte_buffer *buf);

int pkg_confirm_registration(pkg *server, byte_buffer *buf);

int pkg_server_startup(pkg *pkg);

void pkg_server_run(pkg *s);

void pkg_server_shutdown(pkg *server);

#endif  // ALPENHORN_PKG_H
