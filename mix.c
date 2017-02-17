#include <memory.h>
#include "alpenhorn.h"
#include "mix.h"
#include "client.h"

const char skhex1[] = "bc8a02f200c6163ba70d0d9c377cebaa44274bb1e0da097e6c81466f8d5c3d45";
const char pkhex1[] = "b2f511269f818c10bc897845e6282fc3f17a1e861f8d080c727bfffc7393842a";

typedef struct mix mix;
struct mix {
  uint32_t server_id;
  uint32_t num_servers;
  byte_t eph_dh_public_key[crypto_box_PUBLICKEYBYTES];
  byte_t eph_dh_secret_key[crypto_box_SECRETKEYBYTES];
  byte_t mix_eph_dh_public_keys[num_mix_servers][crypto_box_PUBLICKEYBYTES];
  byte_t *af_msgs;
  uint32_t af_incoming_msg_length;
  uint32_t af_outgoing_msg_length;
  byte_t *dial_msgs;
  uint32_t dial_incoming_msg_length;
  uint32_t af_num_messages;
  uint32_t dial_num_messages;
};

void mix_init(mix *mix, uint32_t num_servers, uint32_t server_id, byte_t *initial_) {

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
    mix_remove_encryption_layer(message_ptr, message_length);
  }
}

inline int mix_remove_encryption_layer(byte_t *c, uint32_t num_layers) {
  byte_t sk[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
  byte_t pk[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
  sodium_hex2bin(sk, crypto_aead_chacha20poly1305_IETF_KEYBYTES, skhex1, 64, NULL, NULL, NULL);
  sodium_hex2bin(pk, crypto_aead_chacha20poly1305_IETF_KEYBYTES, pkhex1, 64, NULL, NULL, NULL);

  uint32_t message_length = ibe_encrypted_request_length + mailbox_length + (num_layers * af_request_ABYTES);
  byte_t *nonce_ptr = c + message_length - crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
  byte_t *client_pub_dh_ptr = nonce_ptr - crypto_box_PUBLICKEYBYTES;
  byte_t msg[ibe_encrypted_request_length + mailbox_length + (num_layers * af_request_ABYTES)];

  byte_t scalar_mult[crypto_scalarmult_BYTES];
  int res = crypto_scalarmult(scalar_mult, sk, client_pub_dh_ptr);
  if (res) {
    printf("Scalarmult error\n");
    return -1;
  }
  printhex(":::::::: MIX SCALAR MULT", scalar_mult, crypto_scalarmult_BYTES);
  byte_t shared_secret[crypto_generichash_BYTES];
  crypto_shared_secret(shared_secret, scalar_mult, client_pub_dh_ptr, pk);
  // printhex("dh pub ptr", client_pub_dh_ptr, crypto_box_PUBLICKEYBYTES);
  // printhex("nonce", nonce_ptr, crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
  printhex("mix shared secret", shared_secret, crypto_generichash_BYTES);
  // printhex("ciphertext", c, message_length);


  uint32_t clen = request_bytes + crypto_aead_chacha20poly1305_IETF_ABYTES;
  res = crypto_aead_chacha20poly1305_ietf_decrypt(msg,
                                                  NULL,
                                                  NULL,
                                                  c,
                                                  message_length - (crypto_box_PUBLICKEYBYTES
                                                      + crypto_aead_chacha20poly1305_IETF_NPUBBYTES),
                                                  client_pub_dh_ptr,
                                                  crypto_box_PUBLICKEYBYTES
                                                      + crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
                                                  nonce_ptr,
                                                  shared_secret);
  if (res) {
    printf("Decrypt error\n");
    return -1;
  }
  printf("%s\n", msg);
  return 0;
}


