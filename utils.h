#ifndef ALPENHORN_UTILS_H
#define ALPENHORN_UTILS_H

#include <stdint.h>
#include <stdio.h>
#include <sodium.h>
typedef unsigned char byte_t;
typedef struct element_s element_s;
typedef struct pairing_s pairing_s;

void crypto_shared_secret(byte_t *shared_secret,
                          byte_t *scalar_mult,
                          byte_t *client_pub,
                          byte_t *server_pub,
                          uint32_t output_size);

void printhex(char *msg, byte_t *data, uint32_t len);

uint32_t deserialize_uint32(byte_t *in);
void serialize_uint32(byte_t *out, uint32_t in);

#endif //ALPENHORN_UTILS_H
