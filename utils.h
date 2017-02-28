#ifndef ALPENHORN_UTILS_H
#define ALPENHORN_UTILS_H

#include <stdint.h>
#include <stdio.h>
#include <sodium.h>
typedef unsigned char byte_t;
typedef struct element_s element_s;
typedef struct pairing_s pairing_s;
#define buf_size 2048

struct mix_buffer_s {
  byte_t *buf_base_ptr;
  byte_t *buf_pos_ptr;
  uint32_t capacity_bytes;
  uint32_t capacity_msgs;
  uint32_t num_msgs;
  uint32_t msg_len_bytes;
};
typedef struct mix_buffer_s mix_buffer_s;

void crypto_shared_secret(byte_t *shared_secret,
                          byte_t *scalar_mult,
                          byte_t *client_pub,
                          byte_t *server_pub,
                          uint32_t output_size);

void printhex(char *msg, byte_t *data, uint32_t len);

uint32_t deserialize_uint32(byte_t *in);
void serialize_uint32(byte_t *out, uint32_t in);
void print_b64(char *msg, byte_t *data,
               size_t input_length);

int crypto_chacha_decrypt(unsigned char *m,
                          unsigned long long *mlen_p,
                          unsigned char *nsec,
                          const unsigned char *c,
                          unsigned long long clen,
                          const unsigned char *ad,
                          unsigned long long adlen,
                          const unsigned char *npub,
                          const unsigned char *k);
#endif //ALPENHORN_UTILS_H
