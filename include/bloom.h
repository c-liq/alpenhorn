#ifndef ALPENHORN_BLOOM_H
#define ALPENHORN_BLOOM_H

#include "config.h"
struct bloomfilter_s;

typedef struct bloomfilter_s bloomfilter_s;

struct bloomfilter_s
{
	uint8_t *base_ptr;
	uint8_t *bloom_ptr;
	uint32_t size_bytes;
	uint32_t *partition_lengths_bits;
	uint32_t num_partitions;
	uint64_t hash_key;
	uint32_t *partition_offsets;
	double target_falsepos_rate;
	uint32_t total_size_bytes;
	uint32_t prefix_len;
};

void bloom_calc_partitions(const int m_target,
                           uint32_t *m_actual_bytes,
                           const uint32_t num_partitions,
                           uint32_t *partition_lengths_bytes,
                           uint32_t *partition_lengths_bits,
                           const uint32_t *ptable,
                           const uint32_t ptable_size);

void bloom_add_elem(struct bloomfilter_s *bf, uint8_t *data, uint32_t data_len);
int bloom_lookup(struct bloomfilter_s *bf, uint8_t *data, uint32_t data_len);
int bloom_init(bloomfilter_s *bf,
               double p,
               uint64_t n,
               uint64_t hash_key,
               uint8_t *data,
               uint32_t prefix_len);
void bloom_clear(struct bloomfilter_s *bf);
void bloom_free(struct bloomfilter_s *bf);
void bloom_print_stats(bloomfilter_s *bf);
bloomfilter_s *bloom_alloc(double p,
                           uint32_t n,
                           uint64_t hash_key,
                           uint8_t *data,
                           uint32_t prefix_len);
#endif  // ALPENHORN_BLOOM_H
