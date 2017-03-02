#ifndef ALPENHORN_PKG_H
#define ALPENHORN_PKG_H

#include "config.h"
#include "utils.h"
#include <pbc/pbc.h>
struct pkg_server;
struct pkg_client;
typedef struct pkg_server pkg_server;
typedef struct pkg_client pkg_client;

struct pkg_server {
  int srv_id;
  uint32_t num_clients;
  uint32_t current_round;
  pairing_t pairing;
  pkg_client *clients;
  // Long term BLS signatures, used to sign messages aiding verifying friend requests by recipients
  element_t lt_sig_pk_elem;
  element_t lt_sig_sk_elem;
  //byte_t lt_public_sig_keybytes[bls_public_key_length]; // Public signing key_state serialized
  // Epheremal IBE keypair - public key_state is broadcast to clients, secret key_state used to extract clients' secret keys
  element_t eph_pub_key_elem_g1;
  element_t eph_secret_key_elem_zr;
  byte_t eph_secret_dh_key[crypto_box_SECRETKEYBYTES];
  // Broadcast message buffer - contains fresh IBE public key_state + fresh DH key_state + signature
  byte_t eph_broadcast_message[net_batch_prefix + pkg_broadcast_msg_BYTES];
  byte_t *broadcast_dh_pkey_ptr;  // Pointer into message buffer where public dh key_state will be stored
  // Generator element for pairings, used to derive public keys from secret keys
  element_s bls_gen_elem_g2;
  element_s ibe_gen_elem_g1;
};

struct pkg_client {
  // Invariant - user email address & public signing key_state
  byte_t user_id[user_id_BYTES];
	byte_t lt_sig_pk[crypto_sign_PUBLICKEYBYTES];
  // Contains DH key_state and a signature over (server eph ibe public key_state/eph dh key_state) to authenticate user
  byte_t auth_msg_from_client[crypto_box_PUBLICKEYBYTES + crypto_sign_BYTES];
  // Symmetric key_state buffer, storing server-client_s key_state generated from ECDH exchange
  byte_t eph_symmetric_key[crypto_generichash_BYTES];
  // Buffer holding message server will sign to authenticate friend requests for recipients
  byte_t rnd_sig_msg[pkg_sig_message_BYTES];
  // Post-auth response: contains IBE signature fragment + IBE secret key_state for user, encrypted
  // symmetrically using key_state derived from fresh ECDH exchange
  byte_t eph_client_data[pkg_enc_auth_res_BYTES];
  byte_t *auth_response_ibe_key_ptr; // Pointer into response buffer where secret key_state will be placed
  // IBE elements
  element_t hashed_id_elem_g2; // Permanent
	element_t eph_sig_elem_G1;
  element_t eph_sig_hash_elem_g1;// Round-specific sig_lts of (user_id, lts-sig-key_state, round number)
	element_t eph_sk_G2; // Round-specific IBE secret key_state for client_s
};

void pkg_client_init(pkg_client *client, pkg_server *server, const byte_t *user_id, const byte_t *lt_sig_key);
void pkg_new_ibe_keypair(pkg_server *server);
int pkg_server_init (pkg_server *server, uint32_t id);
void pkg_new_ibe_keypair(pkg_server *server);
void pkg_extract_client_sk(pkg_server *server, pkg_client *client);
void pkg_sign_for_client(pkg_server *server, pkg_client *client);
void pkg_encrypt_client_response(pkg_server *server, pkg_client *client);
void pkg_client_free(pkg_client *client);
void pkg_new_round(pkg_server *server);
int pkg_auth_client (pkg_server *server, pkg_client *client);
void pkg_encrypt_client_response(pkg_server *server, pkg_client *client);
int pkg_client_lookup (pkg_server *server, byte_t *user_id);
#endif //ALPENHORN_PKG_H
