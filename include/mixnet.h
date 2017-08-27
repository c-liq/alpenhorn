#ifndef ALPENHORN_MIX_H
#define ALPENHORN_MIX_H

#include <stdbool.h>
#include "config.h"
#include "utils.h"
#include "bloom.h"
#include "net_common.h"
#include "mixnet_config.h"

static const char *mix_server_ips[] = {"34.228.221.145", "52.59.193.115", "35.176.212.74"};
static const char *mix_listen_ports[] = {"5000", "5001", "5002", "5003"};
static const char mix_entry_client_listenport[] = "7000";
static const char mix_entry_pkg_listenport[] = "6666";

struct mix_s;
typedef struct mix_s mix_s;

typedef struct mix_thread_args mix_thread_args;
struct mix_thread_args
{
	mix_s *mix;
	uint8_t *data;
	uint32_t num_msgs;
	uint32_t num_fake_msgs;
	pthread_mutex_t *mutex;
};


struct dial_mailbox
{
	uint32_t id;
	bloomfilter_s bloom;
	uint64_t num_messages;
};

typedef struct dial_mailbox dial_mailbox_s;

struct dial_mailbox_container
{
	uint64_t round;
	uint64_t num_mailboxes;
	dial_mailbox_s mailboxes[5];
};

typedef struct dial_mailbox_container dmb_container_s;

struct af_mailbox
{
	uint32_t id;
	uint8_t *data;
	uint8_t *next_msg_ptr;
	uint64_t num_messages;
	uint64_t size_bytes;
};

struct remove_conn_list
{
	connection *conn;
	connection *next;
};



typedef struct af_mailbox af_mailbox_s;

struct af_mailbox_container
{
	uint64_t round;
	uint64_t num_mailboxes;
	af_mailbox_s mailboxes[10];
};

typedef struct af_mailbox_container afmb_container_s;

struct mix_af
{
	uint64_t num_mailboxes;
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
	int32_t accept_window_duration;
	uint64_t mb_counts[20];
};

typedef struct mix_af mix_af_s;

struct mix_dial
{
	uint64_t num_mailboxes;
	byte_buffer_s in_buf;
	uint32_t num_inc_msgs;
	uint32_t num_out_msgs;
	uint32_t inc_msg_length;
	uint32_t out_msg_length;
	byte_buffer_s out_buf;
	uint64_t round;
	uint32_t round_duration;
	int32_t accept_window_duration;
	laplace_s laplace;
	uint32_t last_noise_count;
	uint64_t mailbox_counts[20];
	double bloom_p_val;
};

typedef struct mix_dial mix_dial_s;

struct mix_s
{
	uint32_t server_id;
	uint32_t num_servers;
	FILE *log_file;
	uint32_t num_inc_onion_layers;
	uint32_t num_out_onion_layers;
	bool is_last;
	uint8_t af_dh_sk[crypto_box_SECRETKEYBYTES];
	uint8_t dial_dh_sk[crypto_box_SECRETKEYBYTES];
	uint8_t *mix_af_dh_pks[crypto_pk_BYTES];
	uint8_t *mix_dial_dh_pks[crypto_pk_BYTES];
	afmb_container_s af_mb_container;
	dmb_container_s dial_mb_containers[mix_num_dial_mbs_stored];
	uint32_t dial_cont_stack_head;
	mix_af_s af_data;
	mix_dial_s dial_data;
	net_server_state net_state;
	#if USE_PBC
	struct pairing_s pairing;
	struct element_s ibe_gen_elem;
	struct element_s af_noise_Zr_elem;
	struct element_s af_noise_G1_elem;
	#endif
	bool pkg_preprocess_check;
	pthread_mutex_t *af_mutex;
	pthread_mutex_t *dial_mutex;
	uint32_t num_threads;
};

int mix_init(mix_s *mix, uint32_t server_id, uint32_t num_threads, uint32_t num_servers);
void mix_af_decrypt_messages(mix_s *mix);
void mix_af_shuffle(mix_s *mix);
void mix_dial_shuffle(mix_s *mix);
void mix_dial_add_noise(mix_s *mix);
void mix_af_add_noise(mix_s *mix);
void mix_dial_decrypt_messages(mix_s *mix);
void mix_dial_distribute(mix_s *mix);
void mix_af_distribute(mix_s *mix);
void mix_entry_add_af_message(mix_s *mix, uint8_t *buf);
void mix_entry_add_dial_msg(mix_s *mix, uint8_t *msg);
void mix_af_newround(mix_s *mix);
void mix_dial_newround(mix_s *mix);
dial_mailbox_s *mix_dial_get_mailbox_buffer(mix_s *mix, uint64_t round, uint8_t *user_id);

void mix_remove_client(mix_s *s, connection *conn);
void mix_entry_new_af_round(mix_s *mix);
void mix_entry_new_dial_round(mix_s *mix);
void mix_batch_forward(mix_s *s, byte_buffer_s *buf);
void mix_broadcast_new_dialmb(mix_s *s, uint64_t round);
void mix_broadcast_new_afmb(mix_s *s, uint64_t round);
int mix_net_init(mix_s *mix);
int mix_exit_process_client_msg(void *owner, connection *conn);
void mix_run(mix_s *mix,
             void on_accept(void *, connection *),
             int on_read(void *, connection *));
int mix_entry_sync(mix_s *mix);
int mix_main(int argc, char **argv);
int sim_mix_main(int argc, char **argv);

#endif //ALPENHORN_MIX_H
