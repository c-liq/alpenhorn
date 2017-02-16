#define PBC_DEBUG

#ifndef ALPENHORN_CLIENT_H
#define ALPENHORN_CLIENT_H
#include "alpenhorn.h"
#include "keywheel.h"

struct client;
typedef struct client client;

#define dialling_round_length sizeof (uint32_t)

#define request_bytes af_email_string_bytes + \
        crypto_sign_PUBLICKEYBYTES + \
        crypto_sign_BYTES + \
        bls_signature_length + \
        crypto_box_PUBLICKEYBYTES + dialling_round_length

#define ibe_encrypted_request_length request_bytes + crypto_generichash_BYTES + bls_signature_length
#define mailbox_length 4U
#define encrypted_friend_request_length mailbox_length + ibe_encrypted_request_length + (num_mix_servers * af_request_ABYTES)

struct client {
  byte_t user_id[af_email_string_bytes];
  byte_t lt_secret_sig_key[crypto_sign_SECRETKEYBYTES];
  byte_t lt_pub_sig_key[crypto_sign_PUBLICKEYBYTES];
  uint32_t mailbox_count;
  pairing_s pairing;
  uint32_t dialling_round;
  struct keywheel keywheel;
  byte_t friend_request_id[af_email_string_bytes];
  uint32_t af_round;
  // Long term BLS pub keys, private counterpart signs auth messages in friend requests
  element_s pkg_lt_sig_keys_combined;
  byte_t pkg_eph_pub_fragments_g1[num_pkg_servers][ibe_public_key_length]; // Epheremal public IBE keys from PKG's
  element_s pkg_eph_pub_combined_g1; // Combined epheremal master public IBE key
  element_s bls_gen_element_g2;
  element_s pkg_friend_elem; // Epheremal IBE key for friend request recipient
  // Buffers for client -> PKG authrequests, filled with DH public key and signature over PKG's
  // broadcast messages to prove identity
  byte_t pkg_auth_request[num_pkg_servers][crypto_box_PUBLICKEYBYTES + crypto_sign_BYTES + 100];
  // Buffers that hold PKG authentication responses if authentication is successful
  // Contains BLS signature fragment (verifies friend request for recipient), and IBE secret key fragment
  byte_t pkg_auth_responses[num_pkg_servers][pkg_encr_auth_re_length];
  element_s pkg_multisig_combined_g1;
  // Epheremal IBE secret key - decrypts friend requests
  element_s pkg_ibe_secret_combined_g2;
  // Buffer for the fully encrypted add friend request
  // Contains the plaintext request, encrypted through IBE, with a mailbox identifier prepended
  // Then onion-encrypted in layers for the mix servers
  byte_t friend_request_buf[encrypted_friend_request_length];
  // Epheremal public DH keys from mix servers - used to onion encrypt friend requests
  byte_t mix_eph_pub_keys[num_mix_servers][crypto_box_PUBLICKEYBYTES];
  // Epheremal client DH keys, mix combines with their secret DH key to remove layer of encryption
  byte_t cli_mix_dh_pub_keys[num_mix_servers][crypto_box_PUBLICKEYBYTES];
  // Epheremal secret key, used to add a layer of encryption to friend requests, removable only by corresponding
  // mix server
  byte_t cli_mix_dh_secret_keys[num_mix_servers][crypto_box_SECRETKEYBYTES];

  byte_t
      pkg_broadcast_msgs[num_pkg_servers][broadcast_message_length]; // At start of round, contains public IBE & DH keys
  byte_t pkg_eph_ibe_sk_fragments_g2[num_pkg_servers][ibe_secret_key_length]; // Client's secret DH keys used with PKG's
  byte_t pkg_eph_symmetric_keys[num_pkg_servers][crypto_generichash_BYTES
  ]; // Shared DH key, client decrypts round data from pkg
  element_s ibe_gen_element_g1;
};

struct friend_request {
  byte_t user_id[af_email_string_bytes];
  byte_t dh_public_key[crypto_box_PUBLICKEYBYTES];
  uint32_t dialling_round;
  byte_t lt_sig_key[crypto_sign_PUBLICKEYBYTES];
};
typedef struct friend_request friend_request;

client *client_init(int argc, char **argv);
int af_auth_with_pkgs(client *client);
void af_create_request(client *client);
void crypto_shared_secret(byte_t *shared_secret, byte_t *scalar_mult, byte_t *client_pub, byte_t *server_pub);
int af_process_auth_responses(client *client);
int af_decrypt_auth_responses(client *client);
void client_fill(client *client, int argc, char **argv);
int af_decrypt_request(client *client, byte_t *request_buf);
void print_friend_request(friend_request *req);
int encrypt_friend_request(client *cli_st);
void serialize_uint32(byte_t *out, uint32_t in);
uint32_t deserialize_uint32(byte_t *in);
#endif //ALPENHORN_CLIENT_H
