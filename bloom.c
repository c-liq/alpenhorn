#include <stdio.h>
#include <stdint.h>
#include "alpenhorn.h"
#include <math.h>
#include <string.h>
#include <sodium.h>
#include "xxHash-master/xxhash.h"
#include "prime_gen.h"

struct bloomfilter {
  byte_t *f_base_ptr;
  uint32_t *partition_lengths_bits;
  uint32_t num_partitions;
  uint64_t hash_key;
  uint32_t *partition_offsets;
};

void bloom_calc_parts(const int m_target, uint32_t *m_actual_bytes,
                      const uint32_t num_partitions,
                      uint32_t *partition_lengths_bytes,
                      uint32_t *partition_lengths_bits,
                      const uint32_t *ptable,
                      const uint32_t ptable_size) {

  int pdex = 0;
  int l = 0;
  int r = ptable_size - 1;
  int mid;
  uint32_t target_avg = m_target / num_partitions;
  while (l <= r) {
    mid = (l + r + 1) / 2;
    if (target_avg < ptable[mid]) {
      r = mid - 1;
    } else if (target_avg > ptable[mid]) {
      l = mid + 1;
    } else {
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


void bloom_add_elem(struct bloomfilter *bf, byte_t *data, uint32_t data_len) {
  byte_t *f_base_ptr = bf->f_base_ptr;
  uint32_t *partition_lengths = bf->partition_lengths_bits;
  uint32_t num_partitions = bf->num_partitions;
  uint32_t *partition_offsets = bf->partition_offsets;
  uint64_t hash = XXH64(data, data_len, bf->hash_key);
  for (int i = 0; i < num_partitions; i++) {
    uint64_t mod_result = hash % partition_lengths[i];
    byte_t *partition = f_base_ptr + partition_offsets[i];
    partition[mod_result / 8] |= 1 << (mod_result % 8);
  }
}

int bloom_lookup(struct bloomfilter *bf, byte_t *data, uint32_t data_len) {
  byte_t *f_base_ptr = bf->f_base_ptr;
  uint32_t *partition_lengths = bf->partition_lengths_bits;
  uint32_t *partition_offsets = bf->partition_offsets;
  uint32_t num_partitions = bf->num_partitions;
  uint64_t hash = XXH64(data, data_len, bf->hash_key);

  for (int i = 0; i < num_partitions; i++) {
    uint64_t mod_result = hash % partition_lengths[i];
    byte_t *partition = f_base_ptr + partition_offsets[i];
    if (!(partition[mod_result / 8] & 1 << mod_result % 8)) {
      return 0;
    }
  }
  return 1;
}

int bloom_init(struct bloomfilter *bf, uint32_t target_size_bits,
               uint32_t num_parts, uint32_t *ptable,
               uint32_t ptable_sz, uint32_t hash_key) {
  uint32_t actual_size = 0;
  uint64_t part_array_bytes = num_parts * sizeof(uint64_t);
  uint32_t *part_lengh_bits = malloc(part_array_bytes);
  uint32_t *part_length_bytes = malloc(part_array_bytes);
  uint32_t *part_offsets = malloc(part_array_bytes);
  memset(part_lengh_bits, 0, part_array_bytes);
  memset(part_length_bytes, 0, part_array_bytes);
  memset(part_offsets, 0, part_array_bytes);

  bloom_calc_parts(target_size_bits, &actual_size, num_parts, part_length_bytes, part_lengh_bits, ptable, ptable_sz);
  bf->f_base_ptr = malloc(actual_size);
  memset(bf->f_base_ptr, 0, actual_size);
  bf->num_partitions = num_parts;
  bf->partition_lengths_bits = part_lengh_bits;
  bf->hash_key = hash_key;
  bf->partition_offsets = part_offsets;

  uint32_t offsetsum = 0;
  for (int i = 1; i < num_parts; i++) {
    offsetsum += part_length_bytes[i - 1];
    part_offsets[i] = offsetsum;
  }
  free(part_length_bytes);

  return 0;
}

void bloom_clear(struct bloomfilter *bf) {
  if (bf->partition_offsets)
    free(bf->partition_offsets);
  if (bf->partition_lengths_bits)
    free(bf->partition_lengths_bits);
  if (bf->f_base_ptr)
    free(bf->f_base_ptr);
};

void bloom_free(struct bloomfilter *bf) {
  bloom_clear(bf);
  free(bf);
}

int main() {
  int res = sodium_init();
  if (res)
    exit(EXIT_FAILURE);

  uint32_t m_target = 6000000;
  uint32_t num_partitions = 33;
  uint32_t *primes_table;
  uint32_t prime_table_size = generate_primes(&primes_table, m_target / num_partitions);

  struct bloomfilter bloom;
  bloom_init(&bloom, m_target, num_partitions, primes_table, prime_table_size, 3423424242);

  int test_size = 150000;
  byte_t *positive_tests = malloc((test_size + 1) * crypto_box_SECRETKEYBYTES);
  memset(positive_tests, 0, (test_size + 1) * crypto_box_SECRETKEYBYTES);
  byte_t *false_tests = malloc((test_size + 1) * crypto_box_SECRETKEYBYTES);
  memset(false_tests, 0, (test_size + 1) * crypto_box_SECRETKEYBYTES);
  for (int i = 0; i < test_size; i++) {
    randombytes_buf(positive_tests + (i * crypto_box_SECRETKEYBYTES), crypto_box_SECRETKEYBYTES);
    randombytes_buf(false_tests + (i * crypto_box_SECRETKEYBYTES), crypto_box_SECRETKEYBYTES);
    bloom_add_elem(&bloom, positive_tests + (i * crypto_box_SECRETKEYBYTES), crypto_box_SECRETKEYBYTES);
  }
  int pos_hits = 0, false_hits = 0;
  for (int i = 0; i < test_size; i++) {
    pos_hits += bloom_lookup(&bloom, positive_tests + (i * crypto_box_SECRETKEYBYTES), crypto_box_SECRETKEYBYTES);
    false_hits += bloom_lookup(&bloom, false_tests + (i * crypto_box_SECRETKEYBYTES), crypto_box_SECRETKEYBYTES);
  }
  printf("pos: %d\n", pos_hits);
  printf("false hits: %d\n", false_hits);
  bloom_clear(&bloom);
  free(primes_table);
  free(positive_tests);
  free(false_tests);

};