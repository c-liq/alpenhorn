#include <stdio.h>
#include <stdint.h>
#include "utils.h"
#include <math.h>
#include "../lib/xxhash/xxhash.h"
#include "prime_gen.h"
#include "bloom.h"


#define MAX_PREFIX_SZ 256
void bloom_calc_partitions(const int m_target,
                           uint32_t *m_actual_bytes,
                           const uint32_t num_partitions,
                           uint32_t *partition_lengths_bytes,
                           uint32_t *partition_lengths_bits,
                           const uint32_t *ptable,
                           const uint32_t ptable_size)
{

	int pdex = 0;
	int l = 0;
	int r = ptable_size - 1;
	int mid;
	uint32_t target_avg = m_target / num_partitions;
	while (l <= r) {
		mid = (l + r + 1) / 2;
		if (target_avg < ptable[mid]) {
			r = mid - 1;
		}
		else if (target_avg > ptable[mid]) {
			l = mid + 1;
		}
		else {
			break;
		}
	}

	pdex = ptable[mid] == target_avg ? mid : mid - 1;
	int sum = 0;
	int diff = 0;

	for (int i = pdex - num_partitions + 1; i <= pdex; i++) {
		sum += ptable[i];
	}

	int min = sum - m_target;
	min = min >= 0 ? min : -min;
	int j = pdex + 1;

	while (1) {
		sum += ptable[j] - ptable[j - num_partitions];
		diff = (sum - m_target) > 0 ? (sum - m_target) : -(sum - m_target);
		if (diff >= min)
			break;

		min = diff;
		j = j + 1;
	}

	uint32_t bits_size = 0;
	for (int i = 0; i < num_partitions; i++) {
		partition_lengths_bits[i] = ptable[j - num_partitions + i];
		partition_lengths_bytes[i] = (uint32_t) ceil((double) partition_lengths_bits[i] / 8);
		bits_size += partition_lengths_bits[i];
		*m_actual_bytes += partition_lengths_bytes[i];
	}
}

void bloom_add_elem(bloomfilter_s *bf, uint8_t *data, uint32_t data_len)
{
	uint8_t *bloom_ptr = bf->bloom_ptr;
	uint32_t *part_lengths = bf->partition_lengths_bits;
	uint32_t num_partitions = bf->num_partitions;
	uint32_t *partition_offsets = bf->partition_offsets;
	uint64_t hash = XXH64(data, data_len, bf->hash_key);

	for (int i = 0; i < num_partitions; i++) {
		uint64_t mod_result = hash % part_lengths[i];
		uint8_t *partition = bloom_ptr + partition_offsets[i];
		partition[mod_result / 8] |= 1 << (mod_result % 8);
	}
}

int bloom_lookup(bloomfilter_s *bf, uint8_t *data, uint32_t data_len)
{
	uint8_t *bloom_ptr = bf->bloom_ptr;
	uint32_t *partition_lengths = bf->partition_lengths_bits;
	uint32_t *partition_offsets = bf->partition_offsets;
	uint32_t num_partitions = bf->num_partitions;
	uint64_t hash = XXH64(data, data_len, bf->hash_key);

	for (int i = 0; i < num_partitions; i++) {
		uint64_t mod_result = hash % partition_lengths[i];
		uint8_t *partition = bloom_ptr + partition_offsets[i];
		if (!(partition[mod_result / 8] & 1 << mod_result % 8)) {
			return 0;
		}
	}
	return 1;
}

bloomfilter_s *bloom_alloc(double p, uint32_t n, uint64_t hash_key, uint8_t *bloom_data, uint32_t prefix_len)
{
	if (p <= 0 | n <= 0 | prefix_len > MAX_PREFIX_SZ) {
		fprintf(stderr, "invalid parameters to bloom allocator\n");
		return NULL;
	}

	bloomfilter_s *bf = calloc(1, sizeof *bf);
	if (!bf)
		return NULL;

	int res = bloom_init(bf, p, n, hash_key, bloom_data, prefix_len);
	if (res) {
		bloom_free(bf);
		return NULL;
	}
	return bf;
}

int bloom_init(bloomfilter_s *bf, double p, uint32_t n, uint64_t hash_key, uint8_t *bloom_data, uint32_t prefix_len)
{
	// calculate number of partitions and approx filter size based on target false probability rate
	// and number of elements to be placed in the filter
	if (p <= 0 | n <= 0 | prefix_len > MAX_PREFIX_SZ) {
		fprintf(stderr, "invalid parameters to bloom allocator\n");
		return -1;
	}

	double m_target = ceil((n * log(p)) / log(1.0 / (pow(2.0, log(2.0)))));
	uint32_t k = (uint32_t) round(log(2.0) * m_target / n);
	if (m_target <= 0.0 || k <= 0.0) {
		fprintf(stderr, "invalid arguments for bloom filter\n");
		return -1;
	}

	uint32_t *primes_table;
	uint32_t prime_table_size = generate_primes(&primes_table, (m_target / k));
	uint32_t actual_size = 0;

	uint32_t *part_lengh_bits = calloc(k, sizeof *part_lengh_bits);
	if (!part_lengh_bits)
		return -1;
	uint32_t *part_length_bytes = calloc(k, sizeof *part_length_bytes);
	if (!part_length_bytes)
		return -1;
	uint32_t *part_offsets = calloc(k, sizeof *part_offsets);
	if (!part_offsets)
		return -1;

	bloom_calc_partitions((uint32_t) m_target,
	                      &actual_size,
	                      k,
	                      part_length_bytes,
	                      part_lengh_bits,
	                      primes_table,
	                      prime_table_size);

	uint32_t offset_sum = 0;
	for (int i = 1; i < k; i++) {
		offset_sum += part_length_bytes[i - 1];
		part_offsets[i] = offset_sum;
	}
	free(part_length_bytes);


	if (bloom_data != NULL) {
		bf->base_ptr = bloom_data;
	}
	else {
		bf->base_ptr = calloc(actual_size + prefix_len, sizeof(uint8_t));
		if (!bf->base_ptr) {
			fprintf(stderr, "Bloom: calloc failure\n");
			return -1;
		}
	}

	bf->bloom_ptr = bf->base_ptr + prefix_len;
	bf->num_partitions = k;
	bf->partition_lengths_bits = part_lengh_bits;
	bf->hash_key = hash_key;
	bf->partition_offsets = part_offsets;
	bf->target_falsepos_rate = p;
	bf->size_bytes = actual_size;
	bf->total_size_bytes = actual_size + prefix_len;
	bf->prefix_len = prefix_len;

	return 0;
}

void bloom_print_stats(bloomfilter_s *bf)
{
	printf("Bloomfilter stats\n--------\n");
	printf("Size: %d bytes (% d bits)\n", bf->size_bytes, bf->size_bytes * 8);
	printf("Number of partitions: %d\n", bf->num_partitions);
	printf("Target false positive rate: %f\n", bf->target_falsepos_rate);
	printf("Partition sizes: ");
	for (int i = 0; i < bf->num_partitions - 1; i++) {
		printf("%d, ", bf->partition_lengths_bits[i]);
	}
	printf("%d\n", bf->partition_lengths_bits[bf->num_partitions - 1]);
}

void bloom_clear(bloomfilter_s *bf)
{
	if (bf->partition_offsets)
		free(bf->partition_offsets);
	if (bf->partition_lengths_bits)
		free(bf->partition_lengths_bits);
	if (bf->base_ptr)
		free(bf->base_ptr);
};

void bloom_free(bloomfilter_s *bf)
{
	bloom_clear(bf);
	free(bf);
}

/*
int main() {
  int res = sodium_init();
  if (res)
    exit(EXIT_FAILURE);

  double p = pow(10.0, -10.0);
  bloomfilter_s *bloom = bloom_alloc(p, 125000, 123456789);
  bloom_print_stats(bloom);

  int test_size = 125000;
  uint8_t *positive_tests = malloc((test_size + 1) * crypto_box_SECRETKEYBYTES);
  memset(positive_tests, 0, (test_size + 1) * crypto_box_SECRETKEYBYTES);
  uint8_t *false_tests = malloc((test_size + 1) * crypto_box_SECRETKEYBYTES);
  memset(false_tests, 0, (test_size + 1) * crypto_box_SECRETKEYBYTES);
  for (int i = 0; i < test_size; i++) {
    randombytes_buf(positive_tests + (i * crypto_box_SECRETKEYBYTES), crypto_box_SECRETKEYBYTES);
    randombytes_buf(false_tests + (i * crypto_box_SECRETKEYBYTES), crypto_box_SECRETKEYBYTES);
    bloom_add_elem(bloom, positive_tests + (i * crypto_box_SECRETKEYBYTES), crypto_box_SECRETKEYBYTES);
  }
  int pos_hits = 0, false_hits = 0;
  for (int i = 0; i < test_size; i++) {
    pos_hits += bloom_lookup(bloom, positive_tests + (i * crypto_box_SECRETKEYBYTES), crypto_box_SECRETKEYBYTES);
    false_hits += bloom_lookup(bloom, false_tests + (i * crypto_box_SECRETKEYBYTES), crypto_box_SECRETKEYBYTES);
  }
  printf("pos: %d\n", pos_hits);
  printf("false hits: %d\n", false_hits);
  bloom_free(bloom);
  free(positive_tests);
  free(false_tests);

};*/
