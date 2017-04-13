#ifndef ALPENHORN_MIX_H
#define ALPENHORN_MIX_H

#include <stdbool.h>
#include "config.h"
#include "utils.h"
#include "bloom.h"
#include "net_common.h"


struct mix_s;
typedef struct mix_s mix_s;

struct dial_mailbox
{
	uint32_t id;
	bloomfilter_s bloom;
	uint32_t num_messages;
};

typedef struct dial_mailbox dial_mailbox_s;

struct dial_mailbox_container
{
	uint64_t round;
	uint32_t num_mailboxes;
	dial_mailbox_s mailboxes[5];
};

typedef struct dial_mailbox_container dmb_container_s;

struct af_mailbox
{
	uint32_t id;
	uint8_t *data;
	uint8_t *next_msg_ptr;
	uint32_t num_messages;
	uint32_t size_bytes;
};

struct remove_conn_list
{
	connection *conn;
	connection *next;
};

typedef struct mix_net mix_net;
struct mix_net
{
	int epoll_inst;
	int listen_socket;
	struct epoll_event *events;
	int running;
	connection prev_mix;
	connection next_mix;
	time_t next_af_round;
	time_t next_dial_round;
	connection pkg_conns[num_pkg_servers];
	byte_buffer_s bc_buf;
	connection *clients;
	struct remove_conn_list *remove_list;
};

typedef struct af_mailbox af_mailbox_s;

struct af_mailbox_container
{
	uint64_t round;
	uint32_t num_mailboxes;
	af_mailbox_s mailboxes[5];
};

typedef struct af_mailbox_container afmb_container_s;

struct mix_af
{
	uint32_t num_mailboxes;
	byte_buffer_s in_buf;
	byte_buffer_s out_buf;
	uint32_t num_inc_msgs;
	uint32_t num_out_msgs;
	uint32_t inc_msg_length;
	uint32_t out_msg_length;
	laplace_s laplace;
	uint32_t last_noise_count;
	uint64_t round;
	uint32_t round_duration;
	uint32_t mb_counts[5];
};

typedef struct mix_af mix_af_s;

struct mix_dial
{
	uint32_t num_mailboxes;
	byte_buffer_s in_buf;
	uint32_t num_inc_msgs;
	uint32_t num_out_msgs;
	uint32_t inc_msg_length;
	uint32_t out_msg_length;
	byte_buffer_s out_buf;
	uint64_t round;
	uint32_t round_duration;
	laplace_s laplace;
	uint32_t last_noise_count;
	uint32_t mailbox_counts[5];
	double bloom_p_val;
};

typedef struct mix_dial mix_dial_s;

struct mix_s
{
	uint32_t server_id;
	uint32_t num_servers;
	uint32_t num_inc_onion_layers;
	uint32_t num_out_onion_layers;
	bool is_last;
	uint8_t eph_sk[crypto_box_SECRETKEYBYTES];
	uint8_t *mix_dh_pks[crypto_box_PUBLICKEYBYTES];
	afmb_container_s af_mb_container;
	dmb_container_s dial_mb_containers[mix_num_dial_mbs_stored];
	uint32_t dial_cont_stack_head;
	mix_af_s af_data;
	mix_dial_s dial_data;
	mix_net net_state;
	#if USE_PBC
	pairing_s pairing;
	element_s ibe_gen_elem;
	element_s af_noise_Zr_elem;
	element_s af_noise_G1_elem;
	#endif
};

int mix_init(mix_s *mix, uint32_t server_id);
void mix_af_decrypt_messages(mix_s *mix);
void mix_af_shuffle(mix_s *mix);
void mix_dial_shuffle(mix_s *mix);
void mix_dial_add_noise(mix_s *mix);
void mix_af_add_noise(mix_s *mix);
void mix_dial_decrypt_messages(mix_s *mix);
void mix_dial_distribute(mix_s *mix);
void mix_af_distribute(mix_s *mix);
void mix_af_add_inc_msg(mix_s *mix, uint8_t *buf);
void mix_dial_add_inc_msg(mix_s *mix, uint8_t *msg);
void mix_af_newround(mix_s *mix);
void mix_dial_newround(mix_s *mix);
dial_mailbox_s *mix_dial_get_mailbox_buffer(mix_s *mix, uint64_t round, uint8_t *user_id);

static const char mix_client_listen[] = "7000";
static const char *mix_listen_ports[] = {"5000", "5001", "5002", "5003"};

int epoll_accept(mix_s *es, void on_accept(mix_s *, connection *), int on_read(void *, connection *));
int epoll_read(mix_s *c, connection *conn);
void epoll_send(mix_s *s, connection *conn);
void mix_entry_forward_af_batch(mix_s *mix);
void mix_dial_forward(mix_s *s);
void mix_batch_forward(mix_s *s, byte_buffer_s *buf);
void mix_broadcast_new_dialmb(mix_s *s, uint64_t round);
void mix_broadcast_new_afmb(mix_s *s, uint64_t round);
int mix_net_init(mix_s *mix);
#endif //ALPENHORN_MIX_H
