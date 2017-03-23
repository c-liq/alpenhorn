#ifndef ALPENHORN_UTILS_H
#define ALPENHORN_UTILS_H
#include <stdint.h>
#include <stdio.h>
#include <sodium.h>
#include "config.h"


typedef struct element_s element_s;

typedef struct pairing_s pairing_s;

#define buf_size 16348

struct byte_buffer
{
	uint8_t *base;
	uint8_t *data;
	uint8_t *pos;
	ssize_t used;
	ssize_t capacity;
	ssize_t prefix_size;
};

struct laplace;

typedef struct laplace laplace_s;

struct laplace
{
	uint32_t mu;
	uint32_t b;
};

typedef struct byte_buffer byte_buffer_s;

void crypto_shared_secret(uint8_t *shared_secret,
                          uint8_t *scalar_mult,
                          uint8_t *client_pub,
                          uint8_t *server_pub,
                          uint32_t output_size);

void printhex(char *msg, uint8_t *data, uint32_t len);
uint64_t deserialize_uint64(uint8_t *in);
void serialize_uint64(uint8_t *out, const uint64_t input);
uint32_t deserialize_uint32(uint8_t *in);
void serialize_uint32(uint8_t *out, uint32_t in);
void print_b64(char *msg, uint8_t *data,
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

int byte_buffer_init(byte_buffer_s *buf, uint32_t size, uint32_t prefix_size);
byte_buffer_s *byte_buffer_alloc(uint32_t capacity, uint32_t prefix_size);
int byte_buffer_resize(byte_buffer_s *buf, ssize_t new_capacity);
void byte_buffer_clear(byte_buffer_s *buf);
int byte_buffer_put(byte_buffer_s *buf, uint8_t *data, size_t size);
int byte_buffer_put_virtual(byte_buffer_s *buf, size_t size);
uint32_t laplace_rand(laplace_s *l);


#endif //ALPENHORN_UTILS_H
