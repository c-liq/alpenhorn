#ifndef ALPENHORN_PKG_H
#define ALPENHORN_PKG_H

#include "config.h"
#include "utils.h"
#include "bn256.h"
#include "bn256_bls.h"
#include "bn256_ibe.h"
struct pkg_server;
struct pkg_client;

typedef struct pkg_server pkg_server;

typedef struct pkg_client pkg_client;
struct pkg_server
{
	int srv_id;
	uint32_t num_clients;
	uint64_t current_round;
	pkg_client *clients;
	// Long term BLS signatures, used to sign messages aiding verifying friend requests by recipients
	bn256_bls_keypair lt_keypair;
	// Epheremal IBE keypair - public key_state is broadcast to clients, secret key_state used to extract clients' secret keys
	curvepoint_fp_t eph_pub_key_elem_g1;
	scalar_t eph_secret_key_elem_zr;
	uint8_t eph_secret_dh_key[crypto_box_SECRETKEYBYTES];
	// Broadcast message buffer - contains fresh IBE public key_state + fresh DH key_state + signature
	uint8_t eph_broadcast_message[net_header_BYTES + pkg_broadcast_msg_BYTES];
	uint8_t *broadcast_dh_pkey_ptr;  // Pointer into message buffer where public dh key_state will be stored
	// Generator element for pairings, used to derive public keys from secret keys
};

struct pkg_client
{
	// Invariant - user email address & public signing key_state
	uint8_t user_id[user_id_BYTES];
	uint8_t lt_sig_pk[crypto_sign_PUBLICKEYBYTES];
	// Contains DH key_state and a signature over (server eph ibe public key_state/eph dh key_state) to authenticate user
	uint8_t auth_msg_from_client[crypto_box_PUBLICKEYBYTES + crypto_sign_BYTES];
	// Symmetric key_state buffer, storing server-client_s key_state generated from ECDH exchange
	uint8_t eph_symmetric_key[crypto_generichash_BYTES];
	// Buffer holding message server will sign to authenticate friend requests for recipients
	uint8_t rnd_sig_msg[pkg_sig_message_BYTES];
	// Post-auth response: contains IBE signature fragment + IBE secret key_state for user, encrypted
	// symmetrically using key_state derived from fresh ECDH exchange
	uint8_t eph_client_data[net_header_BYTES + pkg_enc_auth_res_BYTES];
	uint8_t *auth_response_ibe_key_ptr; // Pointer into response buffer where secret key_state will be placed
	// IBE elements
	twistpoint_fp2_t hashed_id_elem_g2; // Permanent
	curvepoint_fp_t eph_sig_elem_G1;
	curvepoint_fp_t eph_sig_hash_elem_g1;// Round-specific sig_lts of (user_id, lts-sig-key_state, round number)
	twistpoint_fp2_t eph_sk_G2; // Round-specific IBE secret key_state for client_s
};

void pkg_client_init(pkg_client *client, pkg_server *server, uint8_t *user_id, const uint8_t *lt_sig_key);
void pkg_new_ibe_keypair(pkg_server *server);
int pkg_server_init(pkg_server *server, uint32_t id);
void pkg_new_ibe_keypair(pkg_server *server);
void pkg_extract_client_sk(pkg_server *server, pkg_client *client);
void pkg_sign_for_client(pkg_server *server, pkg_client *client);
void pkg_encrypt_client_response(pkg_server *server, pkg_client *client);
void pkg_client_free(pkg_client *client);
void pkg_new_round(pkg_server *server);
int pkg_auth_client(pkg_server *server, pkg_client *client);
void pkg_encrypt_client_response(pkg_server *server, pkg_client *client);
int pkg_client_lookup(pkg_server *server, uint8_t *user_id);
int pkg_parallel_extract(pkg_server *server);

#endif //ALPENHORN_PKG_H
