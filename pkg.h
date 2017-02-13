//
// Created by chris on 09/02/17.
//

#ifndef ALPENHORN_PKG_H
#define ALPENHORN_PKG_H
struct pkg_server;
struct pkg_client;
typedef struct pkg_server pkg_server;
typedef struct pkg_client pkg_client;

struct pkg_server {
  int srv_id;
  uint32_t num_clients;
  uint32_t *current_round;
  pairing_t pairing;
  pkg_client *clients;
  // Long term BLS signatures, used to sign messages aiding verifying friend requests by recipients
  element_t lt_public_sig_key_elem;
  element_t lt_secret_sig_key_elem;
  //byte_t lt_public_sig_keybytes[bls_public_key_length]; // Public signing key serialized
  // Epheremal IBE keypair - public key is broadcast to clients, secret key used to extract clients' secret keys
  element_t eph_pub_key_elem;
  element_t eph_secret_key_elem;
  byte_t eph_secret_dh_key[crypto_box_SECRETKEYBYTES];
  // Broadcast message buffer - contains fresh IBE public key + fresh DH key + signature
  byte_t eph_broadcast_message[broadcast_message_length];
  byte_t *broadcast_dh_pkey_ptr;  // Pointer into message buffer where public dh key will be stored
  // Generator element for pairings, used to derive public keys from secret keys
  element_t pbc_gen_element;
};

struct pkg_client {
  // Invariant - user email address & public sig+encryption keys
  char user_id[af_email_string_bytes];
  byte_t long_term_sig_pub_key[crypto_sign_PUBLICKEYBYTES];
  // Contains DH key and a signature over (server eph ibe public key/eph dh key) to authenticate user
  byte_t auth_msg_from_client[crypto_box_PUBLICKEYBYTES + crypto_sign_BYTES];
  // Symmetric key buffer, storing server-client key generated from ECDH exchange
  byte_t eph_symmetric_key[crypto_generichash_BYTES];
  // Buffer holding message server will sign to authenticate friend requests for recipients
  byte_t round_signature_message[round_sig_message_length];
  byte_t *round_signature_numptr;
  // Post-auth response: contains IBE signature fragment + IBE secret key for user, encrypted
  // symmetrically using key derived from fresh ECDH exchange
  byte_t eph_client_data[pkg_encr_auth_re_length];
  byte_t *auth_response_ibe_key_ptr; // Pointer into response buffer where secret key will be placed
  // IBE elements
  element_t hashed_id_elem; // Permanent
  element_t eph_signature_elem;
  element_t eph_sig_hash_elem;// Round-specific sig_lts of (userid, lts-sig-key, round number)
  element_t eph_secret_key; // Round-specific IBE secret key for client
};

void pkg_client_init(pkg_client *client, pkg_server *server);
void pkg_new_ibe_keypair(pkg_server *server);
int pkg_server_init(pkg_server *server, char *cfg_file);
void pkg_new_ibe_keypair(pkg_server *server);
void pkg_extract_client_sk(pkg_server *server, pkg_client *client);
void pkg_sign_for_client(pkg_server *server, pkg_client *client);
void pkg_encrypt_client_response(pkg_server *server, pkg_client *client);
void pkg_client_clear(pkg_client *client);
void pkg_new_round(pkg_server *server);
int pkg_auth_client(pkg_server *server, pkg_client *client);
void pkg_encrypt_client_response(pkg_server *server, pkg_client *client);
#endif //ALPENHORN_PKG_H
