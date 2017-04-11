#ifndef ALPENHORN_CLIENT_H
#define ALPENHORN_CLIENT_H

#include <stdbool.h>
#include "keywheel_table.h"
#include "config.h"
#include "utils.h"
#include <sys/epoll.h>
#include <sys/socket.h>
#include "net_common.h"
#include <pthread.h>
#include "bloom.h"


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
typedef struct client_net client_net;
typedef struct client_connection client_connection;

enum actions
{
	ADD_FRIEND = '1',
	CONFIRM_FRIEND = '2',
	DIAL_FRIEND = '3',
	PRINT_KW_TABLE = '4',
	REGISTER = '5',
};

typedef struct action action;

struct action
{
	enum actions type;
	char user_id[user_id_BYTES];
	uint32_t intent;
	action *next;
};

struct client_connection
{
	uint32_t id;
	int sock_fd;
	byte_buffer_s *read_buf;
	size_t curr_msg_len;
	size_t bytes_read;
	uint32_t msg_type;
	uint8_t write_buf[buf_size];
	size_t bytes_written;
	size_t write_remaining;
	struct epoll_event event;
	int (*process)(client_s *owner, client_connection *conn);
	unsigned char conn_type;
};

struct client_net
{
	client_connection mix_entry;
	client_connection mix_last;
	client_connection pkg_client_connections[num_pkg_servers];
	struct epoll_event *events;
	int epoll_inst;
	int num_broadcast_responses;
	int num_auth_responses;
	action *action_stack;
	pthread_mutex_t aq_lock;
};

struct client
{
	uint8_t user_id[user_id_BYTES];
	uint8_t lt_sig_sk[crypto_sign_SECRETKEYBYTES];
	uint8_t lt_sig_pk[crypto_sign_PUBLICKEYBYTES];
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
	client_net net_state;
	bool authed;
	bool mb_processed;
	uint8_t register_buf[net_header_BYTES + cli_pkg_reg_request_BYTES];
	bool running;
	void (*on_recv_call)(incoming_call_s *call);
	void (*on_new_friend_req)(friend_request_s *req);
	void (*on_friend_confirm)(friend_request_s *req);
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
	bool registered;
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
int client_init(client_s *c, const uint8_t *user_id, const uint8_t *lt_pk_hex, const uint8_t *lt_sk_hex);
int af_create_pkg_auth_request(client_s *c);
int af_create_request(client_s *c);
int af_process_auth_responses(client_s *c);
int af_decrypt_request(client_s *c, uint8_t *request_buf, uint64_t round);
int print_friend_request(friend_request_s *req);
int af_onion_encrypt_request(client_s *client);
int dial_onion_encrypt_request(client_s *client);
int add_onion_encryption_layer(client_s *client, uint8_t *msg, uint32_t base_msg_len, uint32_t srv_id);
int af_add_friend(client_s *c, const char *user_id);
int af_process_mb(client_s *c, uint8_t *mailbox, uint32_t num_messages, uint64_t round);
int af_accept_request(struct client *c, const char *user_id, struct friend_request *pRequest);
int dial_call_friend(client_s *c, const uint8_t *user_id, uint32_t intent);
int dial_process_mb(client_s *c, uint8_t *mb_data, uint64_t round, uint32_t num_tokens);
int dial_fake_request(client_s *c);
int af_fake_request(client_s *c);
int client_connection_init(client_connection *conn);
int ep_socket_send(client_s *c, client_connection *conn);
int client_net_init(client_s *c);
int net_send_message(client_s *s, struct client_connection *conn, uint8_t *msg, uint32_t msg_size_bytes);
int mix_entry_process_msg(client_s *client, struct client_connection *conn);
int client_net_pkg_auth(client_s *cn);
int pkg_process_message(client_s *c, client_connection *conn);
int mix_last_process_msg(client_s *client, struct client_connection *conn);
void net_process_read(client_s *s, client_connection *conn, ssize_t count);
int ep_socket_read(client_s *c, client_connection *conn);
int client_run(client_s *cn);
void *client_process_loop(void *c);
int action_stack_push(client_s *c, action *new_action);
action *action_stack_pop(client_s *c);
int client_confirm_friend(client_s *c, uint8_t *user_id);
int client_add_friend(client_s *c, uint8_t *user_id);
int client_call_friend(client_s *c, uint8_t *user_id, uint32_t intent);
uint8_t *client_signing_pk(client_s *c);
int client_net_pkg_register(client_s *cn);
int af_confirm_friend(client_s *c, const char *user_id);


#endif //ALPENHORN_CLIENT_H
