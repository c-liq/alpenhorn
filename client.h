#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCUnusedGlobalDeclarationInspection"
#ifndef ALPENHORN_CLIENT_H
#define ALPENHORN_CLIENT_H

#include <pbc/pbc.h>
#include "keywheel_table.h"
#include "pbc_sign.h"
#include "config.h"
#include "utils.h"

struct client;
typedef struct client client_s;

struct client {
  byte_t user_id[user_id_BYTES];
  byte_t lt_secret_sig_key[crypto_sign_SECRETKEYBYTES];
  byte_t lt_pub_sig_key[crypto_sign_PUBLICKEYBYTES];
  u32 mailbox_count;
  pairing_s pairing;
  u32 dialling_round;
  keywheel_table_s keywheel;
  byte_t friend_request_id[user_id_BYTES];
  u32 af_round;
  // Long term BLS pub keys, private counterpart signs auth messages in friend requests
  element_s pkg_lt_sig_keys_combined;
  byte_t pkg_eph_pub_fragments_g1[num_pkg_servers][g2_elem_compressed_BYTES]; // Epheremal public IBE keys from PKG's
  element_s pkg_eph_pub_combined_g1; // Combined epheremal master public IBE key_state
  element_s bls_gen_element_g2;
  element_s pkg_friend_elem; // Epheremal IBE key_state for friend request recipient
  // Buffers for client_s -> PKG authrequests, filled with DH public key_state and signature over PKG's
  // broadcast messages to prove identity
  byte_t pkg_auth_requests[num_pkg_servers][net_batch_prefix + cli_pkg_single_auth_req_BYTES];
  // Buffers that hold PKG authentication responses if authentication is successful
  // Contains BLS signature fragment (verifies friend request for recipient), and IBE secret key_state fragment
  byte_t pkg_auth_responses[num_pkg_servers][net_batch_prefix + pkg_enc_auth_res_BYTES];
  element_s pkg_multisig_combined_g1;
  // Epheremal IBE secret key_state - decrypts friend requests
  element_s pkg_ibe_secret_combined_g2;
  // Buffer for the fully encrypted add friend request
  // Contains the plaintext request, encrypted through IBE, with a mailbox identifier prepended
  // Then onion-encrypted in layers for the mix_s servers
  byte_t friend_request_buf[onionenc_friend_request_BYTES];
  byte_t dial_request_buf[onionenc_dial_token_BYTES];
  byte_t session_key_buf[crypto_ghash_BYTES];
  // Epheremal public DH keys from mix_s servers - used to onion encrypt friend requests
  byte_t mix_eph_pub_keys[num_mix_servers][crypto_box_PUBLICKEYBYTES];
  // Epheremal client_s DH keys, mix_s combines with their secret DH key_state to remove layer of encryption
  byte_t cli_mix_dh_pub_keys[num_mix_servers][crypto_box_PUBLICKEYBYTES];
  // Epheremal secret keys used with mix servers, used to add a layer of encryption to friend requests
  byte_t cli_mix_dh_secret_keys[num_mix_servers][crypto_box_SECRETKEYBYTES];
  byte_t pkg_broadcast_msgs[num_pkg_servers][pkg_broadcast_msg_BYTES];
  byte_t pkg_eph_ibe_sk_fragments_g2[num_pkg_servers][g2_elem_compressed_BYTES];
  byte_t pkg_eph_symmetric_keys[num_pkg_servers][crypto_generichash_BYTES];
  element_s ibe_gen_element_g1;
};

struct friend_request {
  byte_t user_id[user_id_BYTES];
  byte_t dh_pk[crypto_box_PUBLICKEYBYTES];
  u32 dialling_round;
  byte_t lt_sig_key[crypto_sign_PUBLICKEYBYTES];
};
typedef struct friend_request friend_request_s;

client_s *client_alloc(const byte_t *user_id, const byte_t *ltp_key, const byte_t *lts_key);
void client_init(client_s *c, const byte_t *user_id, const byte_t *lt_pk, const byte_t *lt_sk);
int af_create_pkg_auth_request(client_s *c);
void af_create_request(client_s *c);
int af_process_auth_responses(client_s *c);
int af_decrypt_request(client_s *client, byte_t *request_buf);
void print_friend_request (friend_request_s *req);
int af_onion_encrypt_request(client_s *client);
int dial_onion_encrypt_request(client_s *client);
int add_onion_layer (client_s *client, byte_t *msg, u32 base_msg_length, u32 srv_id);
void af_add_friend(client_s *client, char *user_id);
void af_process_mailbox (client_s *c, byte_t *mailbox, u32 num_messages);
#endif //ALPENHORN_CLIENT_H

#pragma clang diagnostic pop