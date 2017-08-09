#ifndef ALPENHORN_CLIENT_H
#define ALPENHORN_CLIENT_H

#include "bloom.h"
#include "config.h"
#include "keywheel_table.h"
#include "net_common.h"
#include "utils.h"
#include <pthread.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>

#if USE_PBC
#include "pbc_bls.h"
#include "pbc_ibe.h"
#else
#include "bn256_bls.h"
#include "bn256_ibe.h"
#endif

struct client;
struct friend_request;
struct incoming_call;
struct pending_friend_req;
struct pending_call;
typedef struct client client_s;
typedef struct friend_request friend_request_s;
typedef struct incoming_call incoming_call_s;
typedef struct client_net client_net;
typedef struct pending_friend_req pending_friend_req;
typedef struct pending_call pending_call;
typedef struct sign_keypair sign_keypair;
struct sign_keypair
{
	uint8_t public_key[crypto_sign_PUBLICKEYBYTES];
	uint8_t secret_key[crypto_sign_SECRETKEYBYTES];
};

enum actions
{
	ADD_FRIEND = '1',
	CONFIRM_FRIEND = '2',
	DIAL_FRIEND = '3',
	PRINT_KW_TABLE = '4',
};

typedef struct action action;

struct action
{
	enum actions type;
	char user_id[user_id_BYTES];
	uint32_t intent;
	action *next;
};

struct pending_friend_req
{
	uint8_t user_id[user_id_BYTES];
	friend_request_s *req;
	pending_friend_req *next;
};

struct pending_call
{
	uint8_t user_id[user_id_BYTES];
	uint32_t intent;
	pending_call *next;
};

struct client_net
{
	connection mix_entry;
	connection mix_last;
	connection pkg_connections[num_pkg_servers];
	struct epoll_event *events;
	int epoll_fd;
	int num_broadcast_responses;
	int num_auth_responses;
	action *action_stack;
	pthread_mutex_t aq_lock;
	int interrupt_fd;
};

struct client
{
	uint8_t user_id[user_id_BYTES];
	sign_keypair lt_sig_keypair;
	uint64_t dialling_round;
	keywheel_table_s keywheel;
	uint64_t af_round;
	uint32_t dial_num_mailboxes;
	uint32_t af_num_mailboxes;
	uint8_t hashed_id[g2_serialized_bytes];
	uint8_t pkg_auth_requests[num_pkg_servers][net_header_BYTES + cli_pkg_single_auth_req_BYTES];
	uint8_t pkg_auth_responses[num_pkg_servers][net_header_BYTES + pkg_enc_auth_res_BYTES];
	uint8_t friend_request_buf[net_header_BYTES + onionenc_friend_request_BYTES];
	uint8_t dial_request_buf[net_header_BYTES + onionenc_dial_token_BYTES];
	uint8_t session_key_buf[crypto_ghash_BYTES];
	uint8_t mix_af_pks[num_mix_servers][crypto_pk_BYTES];
	uint8_t mix_dial_pks[num_mix_servers][crypto_pk_BYTES];
	uint8_t pkg_broadcast_msgs[num_pkg_servers][pkg_broadcast_msg_BYTES];
	uint8_t pkg_eph_symmetric_keys[num_pkg_servers][crypto_generichash_BYTES];
	double bloom_p_val;
	uint32_t num_intents;
	friend_request_s *friend_requests;
	client_net net_state;
	bool running;
	void (*on_recv_call)(incoming_call_s *);
	void (*on_friend_request)(friend_request_s *);
	void (*on_friend_confirm)(friend_request_s *);
	uint64_t af_mb_num_messages;
	byte_buffer_s af_mb_buffer;
	pending_friend_req *friend_request_queue;
	pending_call *outgoing_call_queue;
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
	twistpoint_fp2_t pkg_ibe_secret_combined_g2;
#endif
};

struct friend_request
{
	uint8_t user_id[user_id_BYTES];
	uint8_t dh_pk[crypto_pk_BYTES];
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

client_s *client_alloc(const uint8_t *user_id,
                       const sign_keypair *signing_keys,
                       void (*on_recv_call)(incoming_call_s *),
                       void (*on_recv_friend_request)(friend_request_s *),
                       void (*on_friend_confirm)(friend_request_s *));
int client_init(client_s *c,
                const uint8_t *user_id,
                const sign_keypair *signing_keys,
                void (*on_recv_call)(incoming_call_s *),
                void (*on_recv_friend_request)(friend_request_s *),
                void (*on_friend_confirm)(friend_request_s *));
int af_create_pkg_auth_request(client_s *c);
int af_create_request(client_s *c, uint8_t *friend_user_id);
int af_process_auth_responses(client_s *c);
int af_decrypt_request(client_s *c, uint8_t *request_buf, uint64_t round);
int af_onion_encrypt_request(client_s *client);
int dial_onion_encrypt_request(client_s *client);
int add_onion_encryption_layer(client_s *client, uint8_t *msg, uint32_t base_msg_len, uint32_t srv_id, bool is_dial);
int af_add_friend(client_s *c, const char *user_id);
int af_process_mb(client_s *c, uint8_t *mailbox, uint64_t num_messages, uint64_t round);
int af_accept_request(client_s *c, friend_request_s *pRequest);
int dial_call_friend(client_s *c, const uint8_t *user_id, uint32_t intent);
int dial_process_mb(client_s *c, uint8_t *mb_data, uint64_t round, uint64_t num_tokens);
int dial_fake_request(client_s *c);
int af_fake_request(client_s *c);
int client_net_init(client_s *c);
int net_send_message(client_s *s, struct connection *conn, uint8_t *msg, uint32_t msg_size_bytes);
int mix_entry_process_msg(void *client, struct connection *conn);
int client_net_pkg_auth(client_s *cn);
int client_net_process_pkg(void *c, connection *conn);
int mix_last_process_msg(void *client, struct connection *conn);
int client_run(client_s *cn);
void *client_process_loop(void *c);
int action_stack_push(client_s *c, action *new_action);
action *action_stack_pop(client_s *c);
int client_confirm_friend(client_s *c, uint8_t *user_id);
int client_add_friend(client_s *c, uint8_t *user_id);
int client_call_friend(client_s *c, uint8_t *user_id, uint32_t intent);
uint8_t *client_get_public_key(client_s *c);
int af_confirm_friend(client_s *c, const char *user_id);
int client_confirm_registration(uint8_t *user_id, uint8_t *sig_key, uint8_t *msgs_buf);
int client_register(sign_keypair *sig_keys, char *user_id);

#endif // ALPENHORN_CLIENT_H
