#ifndef ALPENHORN_BLOOM_H
#define ALPENHORN_BLOOM_H

#include "config.h"
struct bloomfilter_s;

typedef struct bloomfilter_s bloomfilter_s;

struct bloomfilter_s
{
	byte_t *base_ptr;
	byte_t *bloom_ptr;
	u32 size_bytes;
	u32 *partition_lengths_bits;
	u32 num_partitions;
	uint64_t hash_key;
	u32 *partition_offsets;
	double target_falsepos_rate;
};

void bloom_calc_partitions(const int m_target, u32 *m_actual_bytes,
                           const u32 num_partitions,
                           u32 *partition_lengths_bytes,
                           u32 *partition_lengths_bits,
                           const u32 *ptable,
                           const u32 ptable_size);
void bloom_add_elem(struct bloomfilter_s *bf, byte_t *data, u32 data_len);
int bloom_lookup(struct bloomfilter_s *bf, byte_t *data, u32 data_len);
int bloom_init(bloomfilter_s *bf, double p, u32 n, uint64_t hash_key, byte_t *data, u32 prefix_len);
void bloom_clear(struct bloomfilter_s *bf);
void bloom_free(struct bloomfilter_s *bf);
void bloom_print_stats(bloomfilter_s *bf);
bloomfilter_s *bloom_alloc(double p, u32 n, uint64_t hash_key, byte_t *data, u32 prefix_len);
#endif //ALPENHORN_BLOOM_H
