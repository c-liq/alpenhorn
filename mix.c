#include <string.h>
#include "mix.h"
#include <math.h>

void mix_new_af_eph_keypair(mix_s *mix) {
  randombytes_buf(mix->eph_dh_secret_key, crypto_box_SECRETKEYBYTES);
  crypto_scalarmult_base(mix->eph_dh_public_key, mix->eph_dh_secret_key);
}

void mix_af_distribute(mix_s *mix) {
  afmb_container_s *c = calloc(1, sizeof *c);
  c->num_mailboxes = mix->af_num_mailboxes;
  c->round = mix->af_round;
  c->mailboxes = calloc(c->num_mailboxes, sizeof *c->mailboxes);

  for (uint32_t i = 0; i < c->num_mailboxes; i++) {
    af_mailbox_s *mb = &c->mailboxes[i];
    mb->id = i;
    mb->num_messages = mix->af_mailbox_msg_counts[i];
    uint32_t mailbox_sz = mailbox_BYTES + (af_ibeenc_request_BYTES * mb->num_messages);
    mb->size_bytes = mailbox_sz;
    mb->data = calloc(1, mailbox_sz);
    serialize_uint32(mb->data, mb->num_messages);
    mb->next_msg_ptr = mb->data + mailbox_BYTES;
  }

  uint32_t curr_mailbox = 0;
  byte_t *curr_msg_ptr = mix->af_out_msgs;
  af_mailbox_s *mb;

  for (uint32_t i = 0; i < mix->af_num_out_msgs; i++) {
    curr_mailbox = deserialize_uint32(curr_msg_ptr);
    mb = &c->mailboxes[curr_mailbox];
    memcpy(mb->next_msg_ptr, curr_msg_ptr + mailbox_BYTES, af_ibeenc_request_BYTES);
    mb->next_msg_ptr += af_ibeenc_request_BYTES;
    curr_msg_ptr += mailbox_BYTES + af_ibeenc_request_BYTES;
  }

  mix->af_mb_containers = c;
}

void mix_dial_distribute(mix_s *mix) {
  dmb_container_s *c = calloc(1, sizeof *c);
  c->num_mailboxes = mix->dial_num_mailboxes;
  c->mailboxes = calloc(c->num_mailboxes, sizeof *c->mailboxes);
  c->round = mix->dial_round;

  for (uint32_t i = 0; i < mix->dial_num_mailboxes; i++) {
    dial_mailbox_s *mb = &c->mailboxes[i];
    mb->id = i;
    mb->num_messages = mix->dial_mailbox_msg_counts[i];
    printf("%d\n", mb->num_messages);
    bloom_init(&mb->bloom, mix->bloom_p_val, mb->num_messages, 0);
    bloom_print_stats(&mb->bloom);
  }

  uint32_t tmp_mailbox = 0;
  byte_t *tmp_msg_ptr = mix->dial_outgoing_msgs;

  for (int i = 0; i < mix->dial_num_out_msgs; i++) {
    tmp_mailbox = deserialize_uint32(tmp_msg_ptr);
    bloom_add_elem(&c->mailboxes[tmp_mailbox].bloom, tmp_msg_ptr + mailbox_BYTES, dialling_token_BYTES);
    tmp_msg_ptr += (mailbox_BYTES + dialling_token_BYTES);
  }
}

void mix_af_add_inc_msg(mix_s *mix, byte_t *buf) {
  byte_t *buf_ptr = mix->af_incoming_msgs + (mix->af_num_inc_msgs * mix->af_incoming_msg_length);
  memcpy(buf_ptr, buf, mix->af_incoming_msg_length);
  mix->af_num_inc_msgs++;

  if (mix->af_num_inc_msgs == mix->af_inc_buf_capacity) {
    byte_t *new_buf = realloc(mix->af_incoming_msgs, (mix->af_inc_buf_capacity * mix->af_incoming_msg_length * 2));
    if (!new_buf) {
      fprintf(stderr, "Mix: Malloc failure when resizing message buffer\n");
      abort();
    }
  }
}

void mix_dial_add_inc_msg(mix_s *mix, byte_t *buf) {
  byte_t *buf_ptr = mix->dial_incoming_msgs + (mix->dial_num_inc_msgs * mix->dial_incoming_msg_length);
  memcpy(buf_ptr, buf, mix->dial_incoming_msg_length);
  mix->dial_num_inc_msgs++;

  if (mix->dial_num_inc_msgs == mix->dial_inc_buf_capacity) {
    byte_t
        *new_buf = realloc(mix->dial_incoming_msgs, (mix->dial_inc_buf_capacity * mix->dial_incoming_msg_length * 2));
    if (!new_buf) {
      fprintf(stderr, "Mix: Malloc failure when resizing message buffer\n");
      abort();
    }
  }
}

void mix_init(mix_s *mix, uint32_t server_id, uint32_t initial_buffer_size) {
  mix->num_servers = num_mix_servers;
  mix->server_id = server_id;
  // Calculate message sizes based on number of onion encryption layers as the diff between (|num servers| - srvid + 1)
  uint32_t num_inc_onion_layers = num_mix_servers - server_id;
  mix->num_inc_onion_layers = num_inc_onion_layers;
  mix->num_out_onion_layers = num_inc_onion_layers - 1;
  mix->af_incoming_msg_length = af_ibeenc_request_BYTES + mailbox_BYTES + (num_inc_onion_layers * onion_layer_BYTES);
  mix->af_outgoing_msg_length = mix->af_incoming_msg_length - onion_layer_BYTES;
  mix->dial_incoming_msg_length = dialling_token_BYTES + mailbox_BYTES + (num_inc_onion_layers * onion_layer_BYTES);
  mix->dial_outgoing_msg_length = mix->dial_incoming_msg_length - onion_layer_BYTES;
  mix_new_af_eph_keypair(mix);
  memset(mix->dial_mailbox_msg_counts, 0, sizeof mix->dial_mailbox_msg_counts);
  memset(mix->af_mailbox_msg_counts, 0, sizeof mix->af_mailbox_msg_counts);
  mix->af_incoming_msgs = calloc(initial_buffer_size, mix->af_incoming_msg_length);
  mix->af_out_msgs = calloc(1, (initial_buffer_size * mix->af_outgoing_msg_length) + net_batch_prefix);
  mix->af_out_msgs[0] = 'F';
  mix->af_inc_buf_capacity = initial_buffer_size * mix->af_incoming_msg_length;
  mix->af_out_buf_capacity = initial_buffer_size * mix->af_outgoing_msg_length;
  mix->dial_incoming_msgs = calloc(initial_buffer_size, mix->dial_incoming_msg_length);
  mix->dial_outgoing_msgs = calloc(initial_buffer_size, mix->dial_outgoing_msg_length);
  mix->af_num_out_msgs = 0;
  mix->af_num_inc_msgs = 0;
  mix->dial_num_out_msgs = 0;
  mix->dial_num_inc_msgs = 0;
  mix->af_num_mailboxes = 2;
  mix->dial_num_mailboxes = 2;
  mix->af_noisemu = 10;
  mix->dial_noisemu = 10000;
  mix->bloom_p_val = pow(10.0, -10.0);
  // When generating noise for friend requests, we need to generate valid G1 values to make them look genuine
  pairing_init_set_str(&mix->pairing, pbc_params);
  element_init_Zr(&mix->af_noise_Zr_elem, &mix->pairing);
  element_init_G1(&mix->ibe_gen_elem, &mix->pairing);
  element_init_G1(&mix->af_noise_G1_elem, &mix->pairing);
  element_set_str(&mix->ibe_gen_elem, ibe_generator, 10);
}

void mix_af_newround(mix_s *mix) {
  mix->af_num_inc_msgs = 0;
  mix->af_num_out_msgs = 0;
  mix->af_round++;
  mix_new_af_eph_keypair(mix);
}

void mix_dial_newround(mix_s *mix) {
  mix->dial_num_inc_msgs = 0;
  mix->dial_num_out_msgs = 0;
}

void mix_shuffle_messages(byte_t *messages, uint32_t msg_count, uint32_t msg_length) {
  byte_t tmp_message[msg_length];
  for (uint32_t i = msg_count - 1; i >= 1; i--) {
    uint32_t j = randombytes_uniform(i);
    memcpy(tmp_message, messages + (i * msg_length), msg_length);
    memcpy(messages + (i * msg_length), messages + (j * msg_length), msg_length);
    memcpy(messages + (j * msg_length), tmp_message, msg_length);
  }
}

void mix_af_shuffle(mix_s *mix) {
  mix_shuffle_messages(mix->af_out_msgs, mix->af_num_out_msgs, mix->af_outgoing_msg_length);
}

void mix_dial_shuffle(mix_s *mix) {
  mix_shuffle_messages(mix->dial_outgoing_msgs, mix->dial_num_out_msgs, mix->dial_outgoing_msg_length);
}

int mix_add_onion_layer(byte_t *msg, uint32_t msg_len, uint32_t index, byte_t *matching_pub_dh) {
  // Add another layer of encryption to the request, append public DH key_state for server + nonce in clear (but authenticated)
  uint32_t message_length = msg_len + (onion_layer_BYTES * index);
  byte_t *message_end_ptr = msg + message_length;
  byte_t *dh_pub_ptr = message_end_ptr + crypto_MACBYTES;
  byte_t *nonce_ptr = dh_pub_ptr + crypto_box_PUBLICKEYBYTES;

  byte_t dh_secret[crypto_box_SECRETKEYBYTES];
  byte_t scalar_mult[crypto_scalarmult_BYTES];
  byte_t shared_secret[crypto_ghash_BYTES];
  randombytes_buf(dh_secret, crypto_box_SECRETKEYBYTES);
  crypto_scalarmult_base(dh_pub_ptr, dh_secret);

  int res = crypto_scalarmult(scalar_mult, dh_secret, matching_pub_dh);
  if (res) {
    fprintf(stderr, "Mix: scalar mult error while encrypting onion request\n");
    return -1;
  }
  crypto_shared_secret(shared_secret, scalar_mult, dh_pub_ptr, matching_pub_dh, crypto_generichash_BYTES);
  randombytes_buf(nonce_ptr, crypto_NBYTES);
  crypto_aead_chacha20poly1305_ietf_encrypt(msg, NULL, msg,
                                            message_length, dh_pub_ptr, crypto_box_PUBLICKEYBYTES + crypto_NBYTES,
                                            NULL, nonce_ptr, shared_secret);

  return 0;
};

int mix_onion_encrypt_msg(mix_s *mix, byte_t *msg, uint32_t msg_len) {
  byte_t *curr_dh_pub_ptr;
  for (uint32_t i = 0; i < (num_mix_servers - mix->server_id - 1); i++) {
    curr_dh_pub_ptr = mix->mix_dh_public_keys[num_mix_servers - i - 1];
    // printf("%d: %p\n", i, &mix_s->mix_dh_public_keys[i]);
    mix_add_onion_layer(msg, msg_len, i, curr_dh_pub_ptr);
  }
  return 0;
}

void mix_dial_add_noise(mix_s *mix) {
  byte_t *curr_msg_ptr = mix->dial_outgoing_msgs;
  for (uint32_t i = 0; i < mix->af_num_mailboxes; i++) {
    for (int j = 0; j < mix->dial_noisemu; j++) {
      serialize_uint32(curr_msg_ptr, i);
      randombytes_buf(curr_msg_ptr + sizeof i, dialling_token_BYTES);
      mix_onion_encrypt_msg(mix, curr_msg_ptr, dialling_token_BYTES + mailbox_BYTES);
      curr_msg_ptr += mix->dial_outgoing_msg_length;
      mix->dial_num_out_msgs++;
    }
  }
}

void mix_af_add_noise(mix_s *mix) {
  byte_t *curr_msg_ptr = mix->af_out_msgs;
  for (uint32_t i = 0; i < mix->af_num_mailboxes; i++) {
    for (int j = 0; j < mix->af_noisemu; j++) {
      serialize_uint32(curr_msg_ptr, i);
      element_random(&mix->af_noise_Zr_elem);
      element_pow_zn(&mix->af_noise_G1_elem, &mix->ibe_gen_elem, &mix->af_noise_Zr_elem);
      element_to_bytes_compressed(curr_msg_ptr + mailbox_BYTES, &mix->af_noise_G1_elem);
      randombytes_buf(curr_msg_ptr + mailbox_BYTES + g1_elem_compressed_BYTES,
                      af_ibeenc_request_BYTES - g1_elem_compressed_BYTES);
      mix_onion_encrypt_msg(mix, curr_msg_ptr, af_ibeenc_request_BYTES + mailbox_BYTES);
      curr_msg_ptr += mix->af_outgoing_msg_length;
      mix->af_num_out_msgs++;
    }
  }
}

int mix_remove_encryption_layer(mix_s *mix, byte_t *out, byte_t *c, uint32_t message_length) {
  // Onion encrypted messages have the nonce and public key of DH keypair
  // appended to the end of the message directly after the MAC
  byte_t *nonce_ptr = c + message_length - crypto_NBYTES;
  byte_t *client_pub_dh_ptr = nonce_ptr - crypto_box_PUBLICKEYBYTES;
  byte_t scalar_mult[crypto_scalarmult_BYTES];
  int res = crypto_scalarmult(scalar_mult, mix->eph_dh_secret_key, client_pub_dh_ptr);

  if (res) {
    fprintf(stderr, "Scalarmult error\n");
    return -1;
  }

  byte_t shared_secret[crypto_ghash_BYTES];
  crypto_shared_secret(shared_secret, scalar_mult, client_pub_dh_ptr, mix->eph_dh_public_key, crypto_ghash_BYTES);

  uint32_t clen = message_length - (crypto_box_PUBLICKEYBYTES + crypto_NBYTES);
  unsigned long long mlen;
  res = crypto_aead_chacha20poly1305_ietf_decrypt(out,
                                                  &mlen,
                                                  NULL,
                                                  c,
                                                  clen, client_pub_dh_ptr,
                                                  crypto_box_PUBLICKEYBYTES + crypto_NBYTES,
                                                  nonce_ptr,
                                                  shared_secret);
  if (res) {
    printf("Decrypt error\n");
    return -1;
  }
  return 0;
}

int af_update_mailbox_counts(mix_s *mix, uint32_t n) {
  if (n > mix->af_num_mailboxes)
    return -1;
  else
    mix->af_mailbox_msg_counts[n]++;

  return 0;
}

int dial_update_mailbox_counts(mix_s *mix, uint32_t n) {
  if (n > mix->dial_num_mailboxes)
    return -1;
  else
    mix->dial_mailbox_msg_counts[n]++;

  return 0;
}

void mix_af_decrypt_messages(mix_s *mix) {
  byte_t *inc_msg_ptr = mix->af_incoming_msgs;
  // Place actual messages coming from friends after our generated noise
  // Everything gets shuffled once we've decrypted client messages
  byte_t *out_msg_ptr = mix->af_out_msgs + (mix->af_num_out_msgs * mix->af_outgoing_msg_length);
  for (int i = 0; i < mix->af_num_inc_msgs; i++) {
    int res = mix_remove_encryption_layer(mix, out_msg_ptr, inc_msg_ptr, mix->af_incoming_msg_length);
    inc_msg_ptr += mix->af_incoming_msg_length;
    if (!res) {
      // Last server in the mixnet chain
      if (mix->num_out_onion_layers == 0) {
        uint32_t n = deserialize_uint32(out_msg_ptr);
        res = af_update_mailbox_counts(mix, n);
      }
      if (!res) {
        out_msg_ptr += mix->af_outgoing_msg_length;
        mix->af_num_out_msgs++;
      }
    }
  }
  serialize_uint32(mix->af_out_msgs + 1, mix->af_num_out_msgs);
}

void mix_dial_decrypt_messages(mix_s *mix) {
  byte_t *inc_msg_ptr = mix->dial_incoming_msgs;
  // Place actual messages coming from friends after our generated noise
  // Everything gets shuffled once we've decrypted client messages
  byte_t *out_msg_ptr = mix->dial_outgoing_msgs + (mix->dial_num_out_msgs * mix->dial_outgoing_msg_length);
  for (int i = 0; i < mix->dial_num_inc_msgs; i++) {
    int res = mix_remove_encryption_layer(mix, out_msg_ptr, inc_msg_ptr, mix->dial_incoming_msg_length);
    inc_msg_ptr += mix->dial_incoming_msg_length;

    if (!res) {
      // Last server in the mixnet chain, keep track of mailbox counts
      if (mix->num_out_onion_layers == 0) {
        uint32_t n = deserialize_uint32(out_msg_ptr);
        res = dial_update_mailbox_counts(mix, n);
      }
      if (!res) {
        //printhex("Dial token decrypted", out_msg_ptr, mix->dial_outgoing_msg_length);
        out_msg_ptr += mix->dial_outgoing_msg_length;
        mix->dial_num_out_msgs++;
      }
    }
  }
}
