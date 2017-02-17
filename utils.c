#include "utils.h"

void printhex(char *msg, byte_t *data, uint32_t len) {
  uint32_t hex_len = len * 2 + 1;
  char hex_str[hex_len];
  sodium_bin2hex(hex_str, hex_len, data, len);
  printf("%s: %s\n", msg, hex_str);
}

void crypto_shared_secret(byte_t *shared_secret,
                          byte_t *scalar_mult,
                          byte_t *client_pub,
                          byte_t *server_pub,
                          uint32_t output_size) {
  crypto_generichash_state hash_state;
  crypto_generichash_init(&hash_state, NULL, 0U, output_size);
  crypto_generichash_update(&hash_state, scalar_mult, crypto_scalarmult_BYTES);
  crypto_generichash_update(&hash_state, client_pub, crypto_box_PUBLICKEYBYTES);
  crypto_generichash_update(&hash_state, server_pub, crypto_box_PUBLICKEYBYTES);
  crypto_generichash_final(&hash_state, shared_secret, output_size);
};

uint32_t deserialize_uint32(byte_t *in) {
  return in[3] + (in[2] << 8) + (in[2] << 16) + (in[0] << 24);
}
void serialize_uint32(byte_t *out, uint32_t in) {
  out[0] = (byte_t) ((in >> 24) & 0xFF);
  out[1] = (byte_t) ((in >> 16) & 0xFF);
  out[2] = (byte_t) ((in >> 8) & 0xFF);
  out[3] = (byte_t) (in & 0xFF);
};