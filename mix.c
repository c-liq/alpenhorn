#include <string.h>
#include "mix.h"

void mix_new_af_eph_keypair(mix *mix) {
  randombytes_buf(mix->eph_dh_secret_key, crypto_box_SECRETKEYBYTES);
  crypto_scalarmult_base(mix->eph_dh_public_key, mix->eph_dh_secret_key);
}

void mix_init(mix *mix, uint32_t server_id, uint32_t initial_buffer_size) {
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
  mix->af_incoming_msgs = calloc(initial_buffer_size, mix->af_incoming_msg_length);
  mix->af_outgoing_msgs = calloc(initial_buffer_size, mix->af_outgoing_msg_length);
  mix->dial_incoming_msgs = calloc(initial_buffer_size, mix->dial_incoming_msg_length);
  mix->dial_outgoing_msgs = calloc(initial_buffer_size, mix->dial_outgoing_msg_length);
  mix->af_num_outgoing_msgs = 0;
  mix->af_num_inc_msgs = 0;
  mix->dial_num_outgoing_msgs = 0;
  mix->dial_num_incoming_msgs = 0;
  mix->num_mailboxes = 1;
  mix->af_noisemu = 10;
  mix->dial_noisemu = 100;
  pairing_init_set_str(&mix->pairing, pbc_params);
  element_init_G1(&mix->tmp_noise_elem, &mix->pairing);
}

void mix_af_newround(mix *mix, uint32_t num_messages) {
  mix->af_num_outgoing_msgs = num_messages;
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

void mix_af_shuffle(mix *mix) {
  mix_shuffle_messages(mix->af_outgoing_msgs, mix->af_num_outgoing_msgs, mix->af_outgoing_msg_length);
}

void mix_dial_shuffle(mix *mix) {
  mix_shuffle_messages(mix->dial_outgoing_msgs, mix->dial_num_outgoing_msgs, mix->dial_outgoing_msg_length);
}

int mix_add_onion_layer(byte_t *msg, uint32_t msg_len, uint32_t index, byte_t *matching_pub_dh) {
  // Add another layer of encryption to the request, append public DH key_state for server + nonce in clear (but authenticated)
  uint32_t message_length = msg_len + (onion_layer_BYTES * index);
  byte_t *message_end_ptr = msg + message_length;
  byte_t *dh_pub_ptr = message_end_ptr + crypto_MACBYTES;
  byte_t *nonce_ptr = dh_pub_ptr + crypto_box_PUBLICKEYBYTES;

  byte_t dh_secret[crypto_box_SECRETKEYBYTES];
  byte_t scalar_mult[crypto_scalarmult_BYTES];
  byte_t shared_secret[crypto_generichash_BYTES];
  randombytes_buf(dh_secret, crypto_box_SECRETKEYBYTES);
  crypto_scalarmult_base(dh_pub_ptr, dh_secret);
  //printhex("pub dh key", matching_pub_dh, crypto_box_PUBLICKEYBYTES);
  int res = crypto_scalarmult(scalar_mult, dh_secret, matching_pub_dh);
  if (res) {
    fprintf(stderr, "Mix: scalar mult error while encrypting onion request\n");
    abort();
  }
  crypto_shared_secret(shared_secret, scalar_mult, dh_pub_ptr, matching_pub_dh, crypto_generichash_BYTES);
  randombytes_buf(nonce_ptr, crypto_NBYTES);
  crypto_aead_chacha20poly1305_ietf_encrypt(msg, NULL, msg,
                                            message_length, dh_pub_ptr, crypto_box_PUBLICKEYBYTES + crypto_NBYTES,
                                            NULL, nonce_ptr, shared_secret);
  return 0;
};

int mix_onion_encrypt_msg(mix *mix, byte_t *msg, uint32_t msg_len) {
  byte_t *curr_dh_pub_ptr;
  for (uint32_t i = num_mix_servers - 1; i > mix->server_id; i--) {
    curr_dh_pub_ptr = mix->mix_dh_public_keys[i];
    // printf("%d: %p\n", i, &mix->mix_dh_public_keys[i]);
    mix_add_onion_layer(msg, msg_len, i, curr_dh_pub_ptr);
  }
  return 0;
}

void mix_dial_add_noise(mix *mix) {
  byte_t *curr_msg_ptr = mix->dial_outgoing_msgs;
  for (uint32_t i = 0; i < mix->num_mailboxes; i++) {
    for (int j = 0; j < mix->dial_noisemu; j++) {
      serialize_uint32(curr_msg_ptr, i);
      randombytes_buf(curr_msg_ptr + sizeof i, dialling_token_BYTES);
      mix_onion_encrypt_msg(mix, curr_msg_ptr, mix->dial_outgoing_msg_length);
      curr_msg_ptr += mix->dial_outgoing_msg_length;
      mix->dial_num_outgoing_msgs++;
    }
  }
}

void mix_af_add_noise(mix *mix) {
  byte_t *curr_msg_ptr = mix->af_outgoing_msgs;
  for (uint32_t i = 0; i < mix->num_mailboxes; i++) {
    for (int j = 0; j < mix->af_noisemu; j++) {
      serialize_uint32(curr_msg_ptr, i);
      element_random(&mix->tmp_noise_elem);
      element_to_bytes_compressed(curr_msg_ptr + sizeof i, &mix->tmp_noise_elem);
      randombytes_buf(curr_msg_ptr + sizeof i + g1_elem_compressed_BYTES, af_request_BYTES + crypto_ghash_BYTES);
      mix_onion_encrypt_msg(mix, curr_msg_ptr, mix->af_outgoing_msg_length);
      curr_msg_ptr += mix->af_outgoing_msg_length;
      mix->af_num_outgoing_msgs++;
    }
  }
  printf("num msgs: %d", mix->af_num_outgoing_msgs);
}

int mix_remove_encryption_layer(mix *mix, byte_t *out, byte_t *c, uint32_t message_length) {
  // Onion encrypted messages have the nonce and public part of the DH key exchange
  // appended to the end of the message directly after the MAC
  byte_t *nonce_ptr = c + message_length - crypto_NBYTES;
  byte_t *client_pub_dh_ptr = nonce_ptr - crypto_box_PUBLICKEYBYTES;
  byte_t scalar_mult[crypto_scalarmult_BYTES];
  int res = crypto_scalarmult(scalar_mult, mix->eph_dh_secret_key, client_pub_dh_ptr);
  //printhex("MIX: dh pub ptr", client_pub_dh_ptr, crypto_box_PUBLICKEYBYTES);
  //printhex("MIX before decryption: ctext", c, message_length);
  if (res) {
    printf("Scalarmult error\n");
    return -1;
  }

  byte_t shared_secret[crypto_generichash_BYTES];
  crypto_shared_secret(shared_secret, scalar_mult, client_pub_dh_ptr, mix->eph_dh_public_key, crypto_ghash_BYTES);

  //printhex("MIX: shared secret at mix", shared_secret, crypto_generichash_BYTES);
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
  printf("mlen after mix decrypt: %llu\n", mlen);
  return 0;
}

void mix_af_decrypt_messages(mix *mix) {
  byte_t *curr_incoming_msg_ptr = mix->af_incoming_msgs;
  // Place actual messages coming from friends after our generated noise
  // Everything gets shuffled once we've decrypted client_s messages
  byte_t *curr_outgoing_msg_ptr = mix->af_outgoing_msgs + (mix->af_num_outgoing_msgs * mix->af_outgoing_msg_length);
  for (int i = 0; i < mix->af_num_inc_msgs; i++) {
    mix_remove_encryption_layer(mix, curr_outgoing_msg_ptr, curr_incoming_msg_ptr, mix->af_incoming_msg_length);
    curr_incoming_msg_ptr += mix->af_incoming_msg_length;
    curr_outgoing_msg_ptr += mix->af_outgoing_msg_length;
    //printhex("friend request after onion decryption", message_ptr, mix->af_outgoing_msg_length);
  }
}








