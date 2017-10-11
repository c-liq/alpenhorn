#ifndef ALPENHORN_CLIENT_H
#define ALPENHORN_CLIENT_H

#include "bloom.h"
#include "crypto.h"
#include "config.h"
#include "keywheel_table.h"
#include "net.h"
#include "utils.h"
#include <pthread.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include "bn256_bls.h"
#include "bn256_ibe.h"

typedef struct client client;

typedef struct friend_request friend_request;

typedef struct call call;

typedef struct client_net client_net;

typedef struct sign_keypair sign_keypair;

typedef struct mix_data mix_data;

typedef struct pkg_data pkg_data;

typedef struct client_event_fns client_event_fns;

typedef struct mix_client_config {
  u64 num_boxes;
  u64 msg_length;
  u64 msg_type;
  u64 mb_request_type;
  int (*build_message)(client *);
} mix_client_config;

struct mix_data {
  u64 round;
  u64 num_boxes;
  u8 mix_pks[num_mix_servers][crypto_box_PUBLICKEYBYTES];
  u64 msg_length;
  u64 encrypted_msg_length;
  u64 msg_type;
  u64 mb_request_type;
  byte_buffer_t msg_buffer;
  int (*build_message)(client *);
  void *datap;
};

struct pkg_data {
  u64 num_servers;
  u64 num_auth_responses;
  u64 num_broadcasts;
  twistpoint_fp2_t pkg_sig_pk;
  curvepoint_fp_t pkg_master_pk;
  u8 bc_ibe_keys[num_pkg_servers][bn256_ibe_pkg_pk_BYTES];
  u8 bc_dh_pks[num_pkg_servers][crypto_box_PUBLICKEYBYTES];
  u8 auth_responses[num_pkg_servers][pkg_enc_auth_res_BYTES];
  u8 symmetric_keys[num_pkg_servers][crypto_box_SECRETKEYBYTES];
  curvepoint_fp_t pkg_multisig;
  twistpoint_fp2_t id_sk;
  u8 hashed_id[g2_serialized_bytes];
  connection *pkg_conns;
};
/*

struct mix_client {
    mix_data *protocol_data;
    u64 num_protocols;
    u64 user_id[user_id_BYTES];
    u64 num_servers;
    u8 *mix_sig_pks;
    connection mix_entry;
    connection mix_exit;

};
*/

struct client_event_fns {
  void (*call_received)(call *);
  void (*call_sent)(call *);
  void (*friend_request_sent)(friend_request *);
  void (*friend_request_received)(friend_request *);
  void (*friend_request_confirmed)(friend_request *);
};

struct client {
  u8 user_id[user_id_BYTES];
  u8 sig_pk[crypto_sign_PUBLICKEYBYTES];
  u8 sig_sk[crypto_sign_SECRETKEYBYTES];
  keywheel_table kw_table;
  mix_data af_data;
  mix_data dial_data;
  pkg_data pkg_state;
  u8 session_key_buf[crypto_ghash_BYTES];
  double bloom_p_val;
  u64 num_intents;
  list *friend_requests;
  bool running;
  client_event_fns *event_fns;
  list *outgoing_requests;
  list *outgoing_calls;
  pthread_mutex_t *mutex;
  connection_t mix_entry;
  connection_t mix_last;
  int epoll_fd;
  u8 mix_sig_pks[num_mix_servers][crypto_sign_PUBLICKEYBYTES];
};

struct friend_request {
  u8 user_id[user_id_BYTES];
  u8 dh_pk[crypto_box_PKBYTES];
  u64 dialling_round;
  u8 sig_pk[crypto_sign_PUBLICKEYBYTES];
  u8 cert[g1_serialized_bytes];
  u8 user_sig[client_sigmsg_BYTES];
  bool outgoing;
};

struct call {
  u8 user_id[user_id_BYTES];
  u8 session_key[crypto_ghash_BYTES];
  u64 round;
  u64 intent;
};

client *client_alloc(const u8 *user_id, client_event_fns *event_fns, u8 *pk, u8 *sk);

int client_init(client *c, const u8 *user_id, client_event_fns *event_fns, u8 *pk, u8 *sk);

int client_run(client *cn);

void *client_process_loop(void *client_p);

int alp_add_friend(client *c, u8 *user_id);

int alp_call_friend(client *c, u8 *user_id, u64 intent);

int alp_confirm_registration(u8 *user_id, u8 *sig_key, u8 *msgs_buf);

int alp_register(char *user_id, u8 *pk, u8 *sk);


#endif // ALPENHORN_CLIENT_H
