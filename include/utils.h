#ifndef ALPENHORN_UTILS_H
#define ALPENHORN_UTILS_H
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include "config.h"



struct byte_buffer
{
	uint8_t *data;
	uint8_t *pos;
	uint64_t used;
	uint64_t capacity;
};

struct laplace;

typedef struct laplace laplace_s;

struct laplace
{
	uint64_t mu;
	uint64_t b;
};

typedef struct byte_buffer byte_buffer_s;

void crypto_shared_secret(uint8_t *shared_secret,
                          uint8_t *scalar_mult,
                          uint8_t *client_pub,
                          uint8_t *server_pub,
                          uint64_t output_size);

ssize_t crypto_secret_nonce_seal(uint8_t *out,
                                 uint8_t *c,
                                 size_t clen,
                                 uint8_t *k);
int crypto_secret_nonce_open(uint8_t *out, uint8_t *c, size_t clen, uint8_t *k);
void printhex(char *msg, uint8_t *data, size_t len);
uint64_t deserialize_uint64(uint8_t *in);
void serialize_uint64(uint8_t *out, uint64_t input);
uint64_t deserialize_uint32(uint8_t *in);
uint64_t sizeof_serialized_bytes(uint64_t size);
void serialize_uint32(uint8_t *out, uint64_t in);
void print_b64(char *msg, uint8_t *data, size_t input_length);

int crypto_chacha_decrypt(unsigned char *m,
                          unsigned long long *mlen_p,
                          unsigned char *nsec,
                          const unsigned char *c,
                          unsigned long long clen,
                          const unsigned char *ad,
                          unsigned long long adlen,
                          const unsigned char *npub,
                          const unsigned char *k);

int byte_buffer_init(byte_buffer_s *buf, uint64_t size);
byte_buffer_s *byte_buffer_alloc(uint64_t capacity);
int byte_buffer_resize(byte_buffer_s *buf, uint64_t new_capacity);
void byte_buffer_clear(byte_buffer_s *buf);
int byte_buffer_put(byte_buffer_s *buf, uint8_t *data, size_t size);
int byte_buffer_put_virtual(byte_buffer_s *buf, size_t size);
uint64_t laplace_rand(laplace_s *l);
void get_current_time(char *out_buffer);
double get_time();

#endif  // ALPENHORN_UTILS_H
