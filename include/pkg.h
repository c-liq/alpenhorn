#ifndef ALPENHORN_PKG_H
#define ALPENHORN_PKG_H

#include <thpool/thpool.h>
#include "config.h"
#include "utils.h"
#include "net_common.h"
#if USE_PBC
#include "pbc_ibe.h"
#include "pbc_bls.h"
#else
#include "bn256_ibe.h"
#include "bn256_bls.h"

#endif
struct pkg_server;
struct pkg_client;

typedef struct pkg_pending_client pkg_pending_client;
struct pkg_pending_client
{
	uint8_t user_id[user_id_BYTES];
	uint8_t sig_key[crypto_sign_PUBLICKEYBYTES];
	char confirmation_key[crypto_ghash_BYTES * 2 + 1];
	time_t timeout;
	pkg_pending_client *next;
	pkg_pending_client *prev;
};

typedef struct pkg_server pkg_server;

typedef struct pkg_client pkg_client;
struct pkg_server
{
	int srv_id;
	uint64_t num_clients;
	uint64_t client_buf_capacity;
	uint64_t current_round;
	pkg_client *clients;
	// Long term BLS signatures, used to sign messages aiding verifying friend
	// requests by recipients
	// Epheremal IBE keypair - public key_state is broadcast to clients, secret
	// key_state used to extract clients' secret keys
	uint8_t eph_secret_dh_key[crypto_box_SECRETKEYBYTES];
	// Broadcast message buffer - contains fresh IBE public key_state + fresh DH
	// key_state + signature
	uint8_t eph_broadcast_message[net_header_BYTES + pkg_broadcast_msg_BYTES];
	uint8_t *broadcast_dh_pkey_ptr;  // Pointer into message buffer where public
	// dh key_state will be stored
#if USE_PBC
	pairing_t pairing;
	element_t lt_sig_pk_elem;
	element_t lt_sig_sk_elem;
	element_t eph_pub_key_elem_g1;
	element_t eph_secret_key_elem_zr;
	element_s bls_gen_elem_g2;
	element_s ibe_gen_elem_g1;
#else
	bn256_bls_keypair lt_keypair;
	curvepoint_fp_t eph_pub_key_elem_g1;
	scalar_t eph_secret_key_elem_zr;
#endif
	uint64_t num_threads;
	pkg_pending_client *pending_registration_requests;
	net_server_state net_state;
	FILE *log_file;
	threadpool thread_pool;
};

struct pkg_client
{
	uint8_t user_id[user_id_BYTES];
	uint8_t lt_sig_pk[crypto_sign_PUBLICKEYBYTES];
	uint8_t eph_symmetric_key[crypto_generichash_BYTES];
	uint8_t rnd_sig_msg[pkg_sig_message_BYTES];
	uint8_t eph_client_data[net_header_BYTES + pkg_enc_auth_res_BYTES];
	uint8_t *auth_response_ibe_key_ptr;
	time_t last_auth;
	pkg_server *server;
#if USE_PBC
	element_t hashed_id_elem_g2;
	element_t eph_sig_elem_G1;
	element_t eph_sig_hash_elem_g1;
	element_t eph_sk_G2;
#else
	twistpoint_fp2_t hashed_id_elem_g2;  // Permanent
#endif
};

void pkg_client_init(pkg_client *client,
                     pkg_server *server,
                     const uint8_t *user_id,
                     const uint8_t *lt_sig_key, bool is_key_hex);
void pkg_new_ibe_keypair(pkg_server *server);
int pkg_server_init(pkg_server *server, uint64_t id, uint64_t num_clients, uint64_t num_threads, char *user_data_path);
void pkg_new_ibe_keypair(pkg_server *server);
void pkg_extract_client_sk(pkg_server *server, pkg_client *client);
void pkg_sign_for_client(pkg_server *server, pkg_client *client);
void pkg_encrypt_client_response(pkg_server *server, pkg_client *client);
void pkg_client_free(pkg_client *client);
void pkg_new_round(pkg_server *server);
int pkg_auth_client(pkg_server *server, pkg_client *client, uint8_t *auth_msg_buf);
int pkg_client_lookup(pkg_server *server, uint8_t *user_id);
int pkg_parallel_operation(pkg_server *server, void *(*operator)(void *), uint8_t *data_ptr, uint64_t data_elem_length);
int pkg_registration_request(pkg_server *server,
                             const uint8_t *user_id,
                             uint8_t *sig_key);
int pkg_confirm_registration(pkg_server *server,
                             uint8_t *user_id,
                             uint8_t *sig);
int pkg_server_startup(pkg_server *pkg);
void pkg_server_run(pkg_server *s);
void
pkg_server_shutdown(pkg_server *server);

#endif  // ALPENHORN_PKG_H
