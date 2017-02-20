#ifndef ALPENHORN_MIX_H
#define ALPENHORN_MIX_H
#include <pbc/pbc.h>
#include "config.h"
#include "utils.h"

struct mix;
typedef struct mix mix;

struct mix {
  uint32_t num_mailboxes;
  uint32_t server_id;
  uint32_t num_servers;
  uint32_t af_noisemu;
  uint32_t num_inc_onion_layers;

  byte_t eph_dh_public_key[crypto_box_PUBLICKEYBYTES];
  byte_t eph_dh_secret_key[crypto_box_SECRETKEYBYTES];
  byte_t mix_dh_public_keys[num_mix_servers][crypto_box_PUBLICKEYBYTES];

  byte_t *af_incoming_msgs;
  byte_t *af_outgoing_msgs;
  uint32_t af_incoming_msg_length;
  uint32_t af_outgoing_msg_length;
  uint32_t af_num_outgoing_msgs;

  byte_t *dial_incoming_msgs;
  byte_t *dial_outgoing_msgs;
  uint32_t dial_incoming_msg_length;
  uint32_t dial_outgoing_msg_length;
  uint32_t dial_num_outgoing_msgs;

  pairing_s pairing;
  element_s ibe_gen_elem;
  element_s tmp_noise_elem;

  uint32_t num_out_onion_layers;
  uint32_t dial_noisemu;
  uint32_t af_num_inc_msgs;
  uint32_t dial_num_incoming_msgs;
};

void mix_init(mix *mix, uint32_t server_id, uint32_t initial_buffer_size);
void mix_af_decrypt_messages(mix *mix);
void mix_af_shuffle(mix *mix);
void mix_dial_add_noise(mix *mix);
void mix_af_add_noise(mix *mix);
#endif //ALPENHORN_MIX_H
