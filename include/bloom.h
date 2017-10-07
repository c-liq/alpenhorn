#ifndef BLOOM_FILTER_H
#define BLOOM_FILTER_H

#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include "xxhash.h"
#include <stdlib.h>
#include "prime_gen.h"

typedef struct bloom bloom_s;
struct bloom {
  uint8_t *base_ptr;
  uint8_t *bloom_ptr;
  uint64_t size;
  uint64_t *partition_lengths;
  uint64_t num_partitions;
  uint8_t **partition_ptrs;
  double false_pos_rate;
  uint64_t total_size;
  uint64_t prefix_len;
  uint64_t num_elems;
  uint64_t capacity;
};

bloom_s *bloom_alloc(double p, uint64_t n, uint8_t *data, uint64_t prefix_len);

int bloom_init(bloom_s *bf, double p, uint64_t n, uint8_t *data, uint64_t prefix_len);

void bloom_clear(bloom_s *bf);

void bloom_free(bloom_s *bf);

int bloom_add_elem(bloom_s *bf, uint8_t *data, uint64_t data_len);

int bloom_lookup(bloom_s *bf, uint8_t *data, uint64_t data_len);

int bloom_lookup_constant_time(bloom_s *bf, uint8_t *data, uint64_t data_len);

void bloom_print(bloom_s *bf);

uint64_t bloom_remaining_capacity(bloom_s *bf);

#endif  // BLOOM_FILTER_H
