#ifndef ALPENHORN_CLIENT_H
#define ALPENHORN_CLIENT_H

#include <pbc/pbc.h>
#include "keywheel_table.h"
#include "pbc_sign.h"
#include "config.h"
#include "utils.h"

struct client;
struct friend_request;
struct incoming_call;
typedef struct client client_s;
typedef struct friend_request friend_request_s;
typedef struct incoming_call incoming_call_s;

struct client
{
	uint8_t user_id[user_id_BYTES];
	uint8_t lt_sig_sk[crypto_sign_SECRETKEYBYTES];
	uint8_t lg_sig_pk[crypto_sign_PUBLICKEYBYTES];
	pairing_s pairing;
	uint32_t dialling_round;
	keywheel_table_s keywheel;
	uint8_t friend_request_id[user_id_BYTES];
	uint32_t af_round;
	uint32_t dial_num_mailboxes;
	uint32_t af_num_mailboxes;
	// Long term BLS pub keys, private counterpart signs auth messages in friend requests
	element_s pkg_lt_sig_keys_combined;
	uint8_t pkg_eph_pub_fragments_g1[num_pkg_servers][g2_elem_compressed_BYTES]; // Epheremal public IBE keys from PKG's
	element_s pkg_eph_pub_combined_g1; // Combined epheremal master public IBE key_state
	element_s bls_gen_element_g2;
	element_s pkg_friend_elem; // Epheremal IBE key_state for friend request recipient
	// Buffers for client_s -> PKG authrequests, filled with DH public key_state and signature over PKG's
	// broadcast messages to prove identity
	uint8_t pkg_auth_requests[num_pkg_servers][net_header_BYTES + cli_pkg_single_auth_req_BYTES];
	// Buffers that hold PKG authentication responses if authentication is successful
	// Contains BLS signature fragment (verifies friend request for recipient), and IBE secret key_state fragment
	uint8_t pkg_auth_responses[num_pkg_servers][net_header_BYTES + pkg_enc_auth_res_BYTES];
	element_s pkg_multisig_combined_g1;
	// Epheremal IBE secret key_state - decrypts friend requests
	element_s pkg_ibe_secret_combined_g2;
	// Buffer for the fully encrypted add friend request
	// Contains the plaintext request, encrypted through IBE, with a mailbox identifier prepended
	// Then onion-encrypted in layers for the mix_s servers
	uint8_t friend_request_buf[onionenc_friend_request_BYTES];
	uint8_t dial_request_buf[onionenc_dial_token_BYTES];
	uint8_t session_key_buf[crypto_ghash_BYTES];
	// Epheremal public DH keys from mix_s servers - used to onion encrypt friend requests
	uint8_t mix_eph_pub_keys[num_mix_servers][crypto_box_PUBLICKEYBYTES];
	// Epheremal client_s DH keys, mix_s combines with their secret DH key_state to remove layer of encryption
	uint8_t pkg_broadcast_msgs[num_pkg_servers][pkg_broadcast_msg_BYTES];
	uint8_t pkg_eph_ibe_sk_fragments_g2[num_pkg_servers][g2_elem_compressed_BYTES];
	uint8_t pkg_eph_symmetric_keys[num_pkg_servers][crypto_generichash_BYTES];
	element_s ibe_gen_element_g1;
	double bloom_p_val;
	uint32_t num_intents;
	friend_request_s *friend_requests;
};

struct friend_request
{
	uint8_t user_id[user_id_BYTES];
	uint8_t dh_pk[crypto_box_PUBLICKEYBYTES];
	uint32_t dialling_round;
	uint8_t lt_sig_key[crypto_sign_PUBLICKEYBYTES];
	friend_request_s *next;
};

struct incoming_call
{
	uint8_t user_id[user_id_BYTES];
	uint8_t session_key[crypto_ghash_BYTES];
	uint32_t round;
	uint32_t intent;
};

client_s *client_alloc(const uint8_t *user_id, const uint8_t *ltp_key, const uint8_t *lts_key);
void client_init(client_s *c, const uint8_t *user_id, const uint8_t *lt_pk_hex, const uint8_t *lt_sk_hex);
int af_create_pkg_auth_request(client_s *client);
void af_create_request(client_s *c);
int af_process_auth_responses(client_s *c);
int af_decrypt_request(client_s *c, uint8_t *request_buf);
void print_friend_request(friend_request_s *req);
int af_onion_encrypt_request(client_s *client);
int dial_onion_encrypt_request(client_s *client);
int add_onion_encryption_layer(client_s *client, uint8_t *msg, uint32_t base_msg_len, uint32_t srv_id);
void af_add_friend(client_s *client, const char *user_id);
void af_process_mb(client_s *c, uint8_t *mailbox, uint32_t num_messages);
void af_accept_request(client_s *c, friend_request_s *req);
int dial_call_friend(client_s *c, const uint8_t *user_id, uint32_t intent);
int dial_process_mb(client_s *c, uint8_t *mb_data);
void dial_fake_request(client_s *c);
void af_fake_request(client_s *c);
#endif //ALPENHORN_CLIENT_H
