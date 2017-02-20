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
typedef struct client client;

struct client2 {
  // Long term state
  byte_t user_id[user_id_BYTES];
  // Client LT signing key pair
  byte_t lt_secret_sig_key[crypto_sign_SECRETKEYBYTES];
  byte_t lt_pub_sig_key[crypto_sign_PUBLICKEYBYTES];
  // Combined long term BLS public signature key from PKG servers - private counterparts sign verification messages in friend requests
  element_s pkg_lt_sig_keys_combined;
  // Keywheel table to maintain shared secrets between client and friends/contacts
  keywheel_table keywheel;
  // Protocol variables that update each add friend/dialing round
  uint32_t dialling_round;
  uint32_t af_round;
  uint32_t af_mailbox_count;
  uint32_t dial_mailbox_count;
  // Epheremal public DH keys from the mix servers - one set for both AF and dial friend protocols
  byte_t mix_eph_af_pub_keys[num_mix_servers][crypto_box_PUBLICKEYBYTES];
  byte_t mix_eph_dial_pub_keys[num_mix_servers][crypto_box_PUBLICKEYBYTES];
  // PKG state
  pairing_s ibe_pairing;
  // Broadcast at the start of an add friend round, contains public IBE & DH keys
  byte_t pkg_broadcast_msgs[num_pkg_servers][pkg_broadcast_msg_BYTES];
  // PKG epheremal public IBE keys, combined key used to encrypt friend requests
  byte_t pkg_eph_pub_fragments_g1[num_pkg_servers][g2_elem_compressed_BYTES];
  element_s pkg_eph_pub_combined_g1;
  // Buffers for client -> PKG auth requests, filled with DH public keys and signature over PKG's
  // broadcast messages for authentication
  byte_t pkg_auth_request[cli_pkg_combined_auth_req_BYTES];
  // Epheremal symmetric keys shared with PKG servers - used to decrypt authentication responses
  byte_t pkg_eph_symmetric_keys[num_pkg_servers][crypto_generichash_BYTES];
  // Buffers that hold encrypted PKG responses if authentication is successful
  // Contains epheremal BLS signatures (for friend request verification) and IBE secret keys
  byte_t pkg_auth_responses[num_pkg_servers][pkg_enc_auth_res_BYTES];
  byte_t pkg_eph_ibe_sk_fragments_g2[num_pkg_servers][g2_elem_compressed_BYTES];
  // Epheremal IBE secret key_state - decrypts friend requests
  element_s pkg_eph_ibe_sk_combined_g2;
  // Signature state for BLS signatures
  // Calculates and verifies signatures
  bls_instance bls_inst;
  // Stores the id of a user to make a friend request to in a particular round
  byte_t friend_request_id[user_id_BYTES];
  element_s pkg_friend_elem;
  // Buffer for the fully encrypted add friend request
  // Contains the plaintext request, encrypted through IBE, with a mailbox identifier prepended
  // Then onion-encrypted in layers for the mix servers
  byte_t friend_request_buf[onionenc_friend_request_BYTES];
};

struct client {
  byte_t user_id[user_id_BYTES];
  byte_t lt_secret_sig_key[crypto_sign_SECRETKEYBYTES];
  byte_t lt_pub_sig_key[crypto_sign_PUBLICKEYBYTES];
  uint32_t mailbox_count;
  pairing_s pairing;
  uint32_t dialling_round;
  struct keywheel_table keywheel;
  byte_t friend_request_id[user_id_BYTES];
  uint32_t af_round;
  // Long term BLS pub keys, private counterpart signs auth messages in friend requests
  element_s pkg_lt_sig_keys_combined;
  byte_t pkg_eph_pub_fragments_g1[num_pkg_servers][g2_elem_compressed_BYTES]; // Epheremal public IBE keys from PKG's
  element_s pkg_eph_pub_combined_g1; // Combined epheremal master public IBE key_state
  element_s bls_gen_element_g2;
  element_s pkg_friend_elem; // Epheremal IBE key_state for friend request recipient
  // Buffers for client -> PKG authrequests, filled with DH public key_state and signature over PKG's
  // broadcast messages to prove identity
  byte_t pkg_auth_requests[num_pkg_servers][crypto_box_PUBLICKEYBYTES + crypto_sign_BYTES];
  // Buffers that hold PKG authentication responses if authentication is successful
  // Contains BLS signature fragment (verifies friend request for recipient), and IBE secret key_state fragment
  byte_t pkg_auth_responses[num_pkg_servers][pkg_enc_auth_res_BYTES];
  element_s pkg_multisig_combined_g1;
  // Epheremal IBE secret key_state - decrypts friend requests
  element_s pkg_ibe_secret_combined_g2;
  // Buffer for the fully encrypted add friend request
  // Contains the plaintext request, encrypted through IBE, with a mailbox identifier prepended
  // Then onion-encrypted in layers for the mix servers
  byte_t friend_request_buf[onionenc_friend_request_BYTES];
  byte_t dial_request_buf[onionenc_dial_token_BYTES];
  byte_t session_key_buf[crypto_ghash_BYTES];
  // Epheremal public DH keys from mix servers - used to onion encrypt friend requests
  byte_t mix_eph_pub_keys[num_mix_servers][crypto_box_PUBLICKEYBYTES];
  // Epheremal client DH keys, mix combines with their secret DH key_state to remove layer of encryption
  byte_t cli_mix_dh_pub_keys[num_mix_servers][crypto_box_PUBLICKEYBYTES];
  // Epheremal secret key_state, used to add a layer of encryption to friend requests, removable only by corresponding
  // mix server
  byte_t cli_mix_dh_secret_keys[num_mix_servers][crypto_box_SECRETKEYBYTES];
  byte_t pkg_broadcast_msgs[num_pkg_servers][pkg_broadcast_msg_BYTES];
  byte_t pkg_eph_ibe_sk_fragments_g2[num_pkg_servers][g2_elem_compressed_BYTES];
  byte_t pkg_eph_symmetric_keys[num_pkg_servers][crypto_generichash_BYTES];
  element_s ibe_gen_element_g1;
};

struct friend_request {
  byte_t user_id[user_id_BYTES];
  byte_t dh_public_key[crypto_box_PUBLICKEYBYTES];
  uint32_t dialling_round;
  byte_t lt_sig_key[crypto_sign_PUBLICKEYBYTES];
};
typedef struct friend_request friend_request;

client *client_init(int argc, char **argv);
void client_fill(client *client, const byte_t *user_id, const byte_t *ltp_key, const byte_t *lts_key);
int af_create_pkg_auth_request(client *client);
void af_create_request(client *client);
int af_process_auth_responses(client *client);
int af_decrypt_auth_responses(client *client);
int af_decrypt_request(client *client, byte_t *request_buf);
void print_friend_request(friend_request *req);
int af_onion_encrypt_request(client *cli_st);
int add_onion_layer(client *cli_st, uint32_t srv_id);
void af_add_friend(client *client, char *user_id);
#endif //ALPENHORN_CLIENT_H

#pragma clang diagnostic pop