#ifndef ALPENHORN_CLIENT_H
#define ALPENHORN_CLIENT_H

#include <stdbool.h>
#include "keywheel_table.h"
#include "config.h"
#include "utils.h"

#if USE_PBC
#include "ibe.h"
#include "pbc_sign.h"
#else
#include "bn256_ibe.h"
#include "bn256_bls.h"
#endif

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
	uint64_t dialling_round;
	keywheel_table_s keywheel;
	uint8_t friend_request_id[user_id_BYTES];
	uint64_t af_round;
	uint32_t dial_num_mailboxes;
	uint32_t af_num_mailboxes;
	uint8_t hashed_id[g2_serialized_bytes];
	uint8_t pkg_auth_requests[num_pkg_servers][net_header_BYTES + cli_pkg_single_auth_req_BYTES];
	uint8_t pkg_auth_responses[num_pkg_servers][net_header_BYTES + pkg_enc_auth_res_BYTES];
	uint8_t friend_request_buf[net_header_BYTES + onionenc_friend_request_BYTES];
	uint8_t dial_request_buf[net_header_BYTES + onionenc_dial_token_BYTES];
	uint8_t session_key_buf[crypto_ghash_BYTES];
	uint8_t mix_eph_pub_keys[num_mix_servers][crypto_box_PUBLICKEYBYTES];
	uint8_t pkg_broadcast_msgs[num_pkg_servers][pkg_broadcast_msg_BYTES];
	uint8_t pkg_eph_symmetric_keys[num_pkg_servers][crypto_generichash_BYTES];
	int curr_ibe;
	double bloom_p_val;
	uint32_t num_intents;
	friend_request_s *friend_requests;
	bool authed;
	bool mb_processed;
	#if USE_PBC
	pairing_s pairing;
	element_s pkg_lt_sig_keys_combined;
	element_s pkg_eph_pub_combined_g1;
	element_s ibe_gen_element_g1;
	element_s bls_gen_element_g2;
	element_s pkg_friend_elem;
	element_s pkg_multisig_combined_g1;
	element_s pkg_ibe_secret_combined_g2[2];
	#else
	twistpoint_fp2_t pkg_lt_sig_keys_combined;
	curvepoint_fp_t pkg_eph_pub_combined_g1;
	curvepoint_fp_t pkg_multisig_combined_g1;
	twistpoint_fp2_t pkg_ibe_secret_combined_g2[2];
	#endif
};

struct friend_request
{
	uint8_t user_id[user_id_BYTES];
	uint8_t dh_pk[crypto_box_PUBLICKEYBYTES];
	uint64_t dialling_round;
	uint8_t lt_sig_key[crypto_sign_PUBLICKEYBYTES];
	friend_request_s *next;
	friend_request_s *prev;
};

struct incoming_call
{
	uint8_t user_id[user_id_BYTES];
	uint8_t session_key[crypto_ghash_BYTES];
	uint64_t round;
	uint32_t intent;
};

client_s *client_alloc(const uint8_t *user_id, const uint8_t *ltp_key, const uint8_t *lts_key);
void client_init(client_s *c, const uint8_t *user_id, const uint8_t *lt_pk_hex, const uint8_t *lt_sk_hex);
int af_create_pkg_auth_request(client_s *client);
void af_create_request(client_s *c);
int af_process_auth_responses(client_s *c);
int af_decrypt_request(client_s *c, uint8_t *request_buf, uint64_t round);
void print_friend_request(friend_request_s *req);
int af_onion_encrypt_request(client_s *client);
int dial_onion_encrypt_request(client_s *client);
int add_onion_encryption_layer(client_s *client, uint8_t *msg, uint32_t base_msg_len, uint32_t srv_id);
void af_add_friend(client_s *client, const char *user_id);
void af_process_mb(client_s *c, uint8_t *mailbox, uint32_t num_messages, uint64_t round);
int af_accept_request(client_s *c, const char *user_id);
int dial_call_friend(client_s *c, const uint8_t *user_id, uint32_t intent);
int dial_process_mb(client_s *c, uint8_t *mb_data, uint64_t round, uint32_t num_tokens);
void dial_fake_request(client_s *c);
void af_fake_request(client_s *c);
#endif //ALPENHORN_CLIENT_H
