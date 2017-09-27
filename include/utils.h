#ifndef ALPENHORN_UTILS_H
#define ALPENHORN_UTILS_H
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include "alpenhorn/config.h"


struct laplace;

typedef struct laplace laplace_s;

struct laplace
{
	uint64_t mu;
	uint64_t b;
};



void printhex(char *msg, uint8_t *data, size_t len);
uint64_t deserialize_uint64(uint8_t *in);
void serialize_uint64(uint8_t *out, uint64_t input);
uint32_t deserialize_uint32(uint8_t *in);
uint64_t sizeof_serialized_bytes(uint64_t size);
void serialize_uint32(uint8_t *out, uint32_t in);
void print_b64(char *msg, uint8_t *data, size_t input_length);

uint64_t laplace_rand(laplace_s *l);
void get_current_time(char *out_buffer);
double get_time();

#endif  // ALPENHORN_UTILS_H
