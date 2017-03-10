#ifndef ALPENHORN_MIX_H
#define ALPENHORN_MIX_H
#include <pbc/pbc.h>
#include <unistring/stdbool.h>
#include "config.h"
#include "utils.h"
#include "bloom.h"

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
	uint32_t round;
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

typedef struct af_mailbox af_mailbox_s;

struct af_mailbox_container
{
	uint32_t round;
	uint32_t num_mailboxes;
	af_mailbox_s mailboxes[5];
};

typedef struct af_mailbox_container afmb_container_s;

struct mix_af
{
	uint32_t num_mailboxes;
	byte_buffer_s in_buf;
	byte_buffer_s out_buf;
	uint32_t noisemu;
	uint32_t round;
	uint32_t round_duration;
	uint32_t mb_counts[5];
};

typedef struct mix_af mix_af_s;

struct mix_dial
{
	uint32_t num_mailboxes;
	byte_buffer_s in_buf;
	byte_buffer_s out_buf;
	uint32_t round;
	uint32_t round_duration;
	uint32_t noisemu;
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
	pairing_s pairing;
	element_s ibe_gen_elem;
	element_s af_noise_Zr_elem;
	element_s af_noise_G1_elem;
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
int byte_buffer_init(byte_buffer_s *buf, uint32_t num_elems, uint32_t msg_size, uint32_t prefix_size);
dial_mailbox_s *mix_dial_get_mailbox_buffer(mix_s *mix, uint32_t round, uint8_t *user_id);
#endif //ALPENHORN_MIX_H
