#include <string.h>
#include "mix.h"
#include "client.h"

void mix_new_af_eph_keypair(mix *mix) {
  randombytes_buf(mix->af_eph_dh_secret_key, crypto_box_SECRETKEYBYTES);
  crypto_scalarmult_base(mix->af_eph_dh_public_key, mix->af_eph_dh_secret_key);
}

void mix_init(mix *mix, uint32_t num_servers, uint32_t server_id, uint32_t initial_buffer_size) {
  mix->server_id = server_id;
  mix->num_servers = num_servers;
  mix->af_incoming_msg_length = af_ibeenc_request_BYTES + mailbox_BYTES + (mix->server_id * onion_layer_BYTES);
  mix->af_outgoing_msg_length = mix->af_incoming_msg_length - onion_layer_BYTES;
  mix->dial_incoming_msg_length = dialling_token_BYTES + mailbox_BYTES + (mix->server_id * onion_layer_BYTES);
  mix->dial_outgoing_msg_length = mix->dial_incoming_msg_length - onion_layer_BYTES;
  mix_new_af_eph_keypair(mix);
  mix->af_msgs = malloc(initial_buffer_size * mix->af_incoming_msg_length);
  mix->dial_msgs = malloc(initial_buffer_size * mix->dial_incoming_msg_length);

}

void mix_af_newround(mix *mix, uint32_t num_messages) {
  mix->af_num_messages = num_messages;
}

void mix_af_shuffle_messages(mix *mix) {
  byte_t *messages = mix->af_msgs;
  uint32_t msg_length = mix->af_incoming_msg_length;
  byte_t tmp_message[mix->af_incoming_msg_length];
  for (uint32_t i = mix->af_num_messages - 1; i >= 1; i--) {
    uint32_t j = randombytes_uniform(i);
    memcpy(tmp_message, messages + (i * msg_length), msg_length);
    memcpy(messages + (i * msg_length), messages + (j * msg_length), msg_length);
    memcpy(messages + (j * msg_length), tmp_message, msg_length);
  }
}

void mix_add_noise() {

}

void mix_af_decrypt_messages(mix *mix) {
  uint32_t message_length = mix->af_incoming_msg_length;
  uint32_t num_messages = mix->af_num_messages;
  for (int i = 0; i < num_messages; i++) {
    byte_t *message_ptr = mix->af_msgs + (i * message_length);
    mix_remove_encryption_layer(mix, message_ptr, message_length);
    printhex("friend request after onion decryption", message_ptr, mix->af_outgoing_msg_length);
  }
}

inline int mix_remove_encryption_layer(mix *mix, byte_t *c, uint32_t message_length) {

  // Onion encrypted messages have the nonce and public part of the DH key exchange
  // appended to the end of the message directly after the MAC
  byte_t *nonce_ptr = c + message_length - crypto_NBYTES;
  byte_t *client_pub_dh_ptr = nonce_ptr - crypto_box_PUBLICKEYBYTES;


  byte_t scalar_mult[crypto_scalarmult_BYTES];
  int res = crypto_scalarmult(scalar_mult, mix->af_eph_dh_secret_key, client_pub_dh_ptr);
  if (res) {
    printf("Scalarmult error\n");
    return -1;
  }

  byte_t shared_secret[crypto_generichash_BYTES];
  crypto_shared_secret(shared_secret,
                       scalar_mult,
                       client_pub_dh_ptr,
                       mix->af_eph_dh_public_key,
                       crypto_generichash_BYTES);
  //printhex("MIX: dh pub ptr", client_pub_dh_ptr, crypto_box_PUBLICKEYBYTES);
  //printhex("MIX: shared secret at mix", shared_secret, crypto_generichash_BYTES);
  uint32_t clen = message_length - (crypto_box_PUBLICKEYBYTES + crypto_NBYTES);
  res = crypto_aead_chacha20poly1305_ietf_decrypt(c,
                                                  NULL,
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
  printf("%s\n", c);
  return 0;
}


