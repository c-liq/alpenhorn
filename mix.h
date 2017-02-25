#ifndef ALPENHORN_MIX_H
#define ALPENHORN_MIX_H
#include <pbc/pbc.h>
#include "config.h"
#include "utils.h"
#include "bloom.h"

struct mix_s;
typedef struct mix_s mix_s;

struct dial_mailbox {
  uint32_t id;
  bloomfilter_s bloom;
  uint32_t num_messages;
};
typedef struct dial_mailbox dial_mailbox_s;

struct dial_mailbox_container {
  uint32_t round;
  uint32_t num_mailboxes;
  dial_mailbox_s *mailboxes;
};
typedef struct dial_mailbox_container dmb_container_s;

struct af_mailbox {
  uint32_t id;
  byte_t *data;
  byte_t *next_msg_ptr;
  uint32_t num_messages;
  uint32_t size_bytes;
};
typedef struct af_mailbox af_mailbox_s;

struct af_mailbox_container {
  uint32_t round;
  uint32_t num_mailboxes;
  af_mailbox_s *mailboxes;
};
typedef struct af_mailbox_container afmb_container_s;

struct mix_buffer_s {
  byte_t *inc_buf;
  byte_t *out_buf;
  uint32_t inc_capacity;
  uint32_t out_capacity;
  uint32_t inc_num_msgs;
  uint32_t out_num_msgs;
};

struct mix_af_s {
  uint32_t num_mailboxes;
  struct mix_buffer_s buffers;
  uint32_t mailbox_counts[10];
  afmb_container_s *mb_containers;
};

struct mix_s {
  uint32_t af_num_mailboxes;
  uint32_t dial_num_mailboxes;
  uint32_t server_id;
  uint32_t num_servers;
  uint32_t af_noisemu;
  uint32_t num_inc_onion_layers;
  uint32_t num_out_onion_layers;
  uint32_t af_round;
  uint32_t dial_round;
  double bloom_p_val;

  byte_t eph_dh_public_key[crypto_box_PUBLICKEYBYTES];
  byte_t eph_dh_secret_key[crypto_box_SECRETKEYBYTES];
  byte_t mix_dh_public_keys[num_mix_servers][crypto_box_PUBLICKEYBYTES];

  byte_t *af_incoming_msgs;
  byte_t *af_out_msgs;
  uint32_t af_incoming_msg_length;
  uint32_t af_outgoing_msg_length;
  uint32_t af_num_inc_msgs;
  uint32_t af_num_out_msgs;
  uint32_t af_inc_buf_capacity;
  uint32_t af_out_buf_capacity;
  uint32_t af_mailbox_msg_counts[10];
  afmb_container_s *af_mb_containers;

  byte_t *dial_incoming_msgs;
  byte_t *dial_out_msgs;
  uint32_t dial_incoming_msg_length;
  uint32_t dial_out_msg_len;
  uint32_t dial_num_inc_msgs;
  uint32_t dial_num_out_msgs;
  uint32_t dial_inc_buf_capacity;
  uint32_t dial_out_bug_capacity;
  uint32_t dial_noisemu;
  uint32_t dial_mailbox_msg_counts[10];

  pairing_s pairing;
  element_s ibe_gen_elem;
  element_s af_noise_Zr_elem;
  element_s af_noise_G1_elem;
  int dial_round_duration;
  int af_round_duration;
};

void mix_init(mix_s *mix, uint32_t server_id, uint32_t initial_buffer_size);
void mix_af_decrypt_messages(mix_s *mix);
void mix_af_shuffle(mix_s *mix);
void mix_dial_shuffle(mix_s *mix);
void mix_dial_add_noise(mix_s *mix);
void mix_af_add_noise(mix_s *mix);
void mix_dial_decrypt_messages(mix_s *mix);
void mix_dial_distribute(mix_s *mix);
void mix_af_distribute(mix_s *mix);
void mix_af_add_inc_msg(mix_s *mix, byte_t *buf);
void mix_dial_add_inc_msg(mix_s *mix, byte_t *buf);
void mix_af_newround(mix_s *mix);
void mix_dial_newround(mix_s *mix);
#endif //ALPENHORN_MIX_H
