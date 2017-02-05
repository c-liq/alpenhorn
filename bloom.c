//
// Created by chris on 03/02/17.
//
#include <stdio.h>
#include <stdint.h>
#include "alpenhorn.h"
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>
#include "xxHash-master/xxhash.h"
#include "prime_gen.h"

void printBits(size_t const size, void const *const ptr) {
  unsigned char *b = (unsigned char *) ptr;
  unsigned char byte;
  size_t i, j;

  for (i = size - 1; i >= 0; i--) {
    for (j = 7; j >= 0; j--) {
      byte = (b[i] >> j) & 1;
      printf("%u", byte);
    }
  }
  puts("");
}

void calculate_partition_lengths(const int m_target,
                                 uint32_t *m_actual_bytes,
                                 const uint32_t k,
                                 uint32_t *partition_lengths_bytes,
                                 uint32_t *partition_lengths_bits,
                                 const uint32_t *ptable,
                                 const uint32_t ptable_size) {
  int pdex = 0;
  int l = 0;
  int r = ptable_size - 1;
  int mid;
  uint32_t target_avg = m_target / k;
  printf("m_target: %d | k: %d | ptable_size: %d | avg partition size: %d\n", m_target, k, ptable_size, target_avg);
  while (l <= r) {
    mid = (l + r + 1) / 2;
    //printf("mid: %d\n", mid);
    if (target_avg < ptable[mid]) {
      r = mid - 1;
    } else if (target_avg > ptable[mid]) {
      l = mid + 1;
    } else {
      break;
    }
  }
  //printf("----------------\nMID: %d\n", mid);
  pdex = ptable[mid] == target_avg ? mid : mid - 1;
  //printf("%d\n", ptable[pdex]);
  int sum = 0;
  int diff = 0;

  for (int i = pdex - k + 1; i <= pdex; i++) {
    sum += ptable[i];
  }

  int min = sum - m_target;
  min = min >= 0 ? min : -min;
  int j = pdex + 1;

  while (1) {
    sum += ptable[j] - ptable[j - k];
    diff = (sum - m_target) > 0 ? (sum - m_target) : -(sum - m_target);
    if (diff >= min) break;

    min = diff;
    j = j + 1;
  }

  memset(partition_lengths_bits, 0, k * sizeof(uint32_t));
  memset(partition_lengths_bytes, 0, k * sizeof(uint32_t));
  uint32_t bits_size = 0;
  for (int i = 0; i < k; i++) {

    partition_lengths_bits[i] = ptable[j - k + i];
    partition_lengths_bytes[i] = (uint32_t) ceil((double) partition_lengths_bits[i] / 8);
    bits_size += partition_lengths_bits[i];
    *m_actual_bytes += partition_lengths_bytes[i];
    printf("Filter size after adding %d partitions: bytes:%d - bits: %d\n", i, *m_actual_bytes, bits_size);
  }

  for (int i = 0; i < k; i++) {
    printf("%d (%d bytes), ", partition_lengths_bits[i], partition_lengths_bytes[i]);
  }
  printf("\n");

}

struct bloomfilter {
  uint32_t f_size_bits;
  uint32_t f_size_bytes;
  byte_t *f_base_ptr;
  uint32_t *partition_lengths_bits;
  uint32_t *partition_lengths_bytes;
  uint32_t num_partitions;
  uint64_t *hash_key;
  uint32_t *partition_offsets;
};

void bloom_add_elem2(struct bloomfilter *bf, byte_t *data, uint32_t data_len, uint64_t key1, uint64_t key2) {
  uint64_t hash1 = XXH64(data, data_len, key1);
  uint64_t hash2 = XXH64(data, data_len, key2);
//  printf("\nadd hash 1: %lu\n", hash1);
  // printf("add hash 2: %lu\n", hash2);
  for (int i = 0; i < bf->num_partitions; i++) {
    uint64_t mod_result = (hash1 + (i * hash2)) % bf->f_size_bits;
    bf->f_base_ptr[mod_result / 8] |= 1 << mod_result % 8;
    //   printf("setting bit %ld, char: %d\n", mod_result / 8, (unsigned int)bf->f_base_ptr[mod_result / 8]);
  }

}
int bloom_lookup2(struct bloomfilter *bf, byte_t *data, uint32_t data_len, uint64_t key1, uint64_t key2) {
  uint64_t hash1 = XXH64(data, data_len, key1);
  uint64_t hash2 = XXH64(data, data_len, key2);
  //printf("lookup hash 1: %lu\n", hash1);
//  printf("lookup hash 2: %lu\n", hash2);
  int res = 1;
  for (int i = 0; i < bf->num_partitions; i++) {
    uint64_t mod_result = (hash1 + (i * hash2)) % bf->f_size_bits;

    //printf("checking bit %ld, char: %d, bitwise&: %d\n", mod_result / 8, (unsigned int)bf->f_base_ptr[mod_result / 8], bf->f_base_ptr[mod_result / 8] & 1 << mod_result % 8);
    if (!(bf->f_base_ptr[mod_result / 8] & 1 << (byte_t) (mod_result % 8))) {
      res = 0;
    }
  }
  return res;
}

void bloom_add_elem(struct bloomfilter *bf, byte_t *data, uint32_t data_len, uint64_t key) {
  byte_t *f_base_ptr = bf->f_base_ptr;
  uint32_t *partition_lengths_bytes = bf->partition_lengths_bytes;
  uint32_t *partition_lengths = bf->partition_lengths_bits;
  uint32_t num_partitions = bf->num_partitions;
  uint32_t *partition_offsets = bf->partition_offsets;
  uint64_t hash = XXH64(data, data_len, key);
  for (int i = 0; i < num_partitions; i++) {
    uint64_t mod_result = hash % partition_lengths[i];

    byte_t *partition = f_base_ptr + partition_offsets[i];
    partition[mod_result / 8] |= 1 << (mod_result % 8);
    //  printf("partition %d: setting bit %lu byte: %u %p\n", i, mod_result, (uint32_t)partition[mod_result/8], (uint32_t*)&partition[mod_result/8]);

  }
  //printBits(bf->f_size_bytes, bf->f_base_ptr);

}

int bloom_lookup(struct bloomfilter *bf, byte_t *data, uint32_t data_len, uint64_t key) {
  byte_t *f_base_ptr = bf->f_base_ptr;
  uint32_t *partition_lengths_bytes = bf->partition_lengths_bytes;
  uint32_t *partition_lengths = bf->partition_lengths_bits;
  uint32_t *partition_offsets = bf->partition_offsets;
  uint32_t num_partitions = bf->num_partitions;
  uint64_t hash = XXH64(data, data_len, key);

  for (int i = 0; i < num_partitions; i++) {
    uint64_t mod_result = hash % partition_lengths[i];

    byte_t *partition = f_base_ptr + partition_offsets[i];
    // printf("partition %d: checking bit %lu byte: %u %p\n", i, mod_result, (uint32_t)partition[mod_result/8], (uint32_t*)&partition[mod_result/8]);
    if (!(partition[mod_result / 8] & 1 << mod_result % 8)) {
      return 0;
    }
  }
  return 1;
}

int main() {
  int res = sodium_init();
  if (res) exit(EXIT_FAILURE);
  uint32_t m_target = 6000000;
  uint32_t *m_actual_bytes = malloc(sizeof(uint32_t));
  *m_actual_bytes = 0;
  uint32_t k = 33;
  uint32_t *partition_lengths_bits = malloc(sizeof(uint32_t) * k);
  uint32_t *partition_lengths_bytes = malloc(sizeof(uint32_t) * k);
  uint32_t *primes_table;
  int32_t prime_table_size = generate_primes(&primes_table, m_target / k);
  calculate_partition_lengths(m_target,
                              m_actual_bytes,
                              k,
                              partition_lengths_bytes,
                              partition_lengths_bits,
                              primes_table,
                              6591);
  printf("\n\n::::::::::::::: %d %d", *m_actual_bytes, *m_actual_bytes * 8);
  struct bloomfilter bloom = {
      .f_base_ptr = malloc(*m_actual_bytes),
      .f_size_bits = *m_actual_bytes * 8,
      .f_size_bytes = *m_actual_bytes,
      .num_partitions = k,
      .partition_lengths_bits = partition_lengths_bits,
      .partition_lengths_bytes = partition_lengths_bytes,
      .hash_key = NULL,
      .partition_offsets = malloc(k * sizeof(uint32_t))
  };
  memset(bloom.f_base_ptr, 0, *m_actual_bytes);
  uint32_t offsetsum = 0;
  memset(bloom.partition_offsets, 0, k * sizeof(uint32_t));
  bloom.partition_offsets[0] = 0;
  for (int i = 1; i < bloom.num_partitions; i++) {
    offsetsum += bloom.partition_lengths_bytes[i - 1];
    bloom.partition_offsets[i] = offsetsum;
  }
  printf("Filter details:\n--------------\n");
  printf("Filter size in bits: %d\n", bloom.f_size_bits);
  printf("Filter size in bytes: %d\n", bloom.f_size_bytes);
  printf("Filter num partitions: %d\n", bloom.num_partitions);
  for (int i = 0; i < bloom.num_partitions; i++) {
    // printf("Partition %d (offset: %d): bitsize: %d - bytesize: %d\n", i, bloom.partition_offsets[i], bloom.partition_lengths_bits[i], bloom.partition_lengths_bytes[i]);
  }

  const char *key1 = "dsfsdfgsikfnsdfnskjldfnksdfnksdfjksddsfsdf";
  size_t x = strlen(key1);
  uint64_t hkey = XXH64(key1, x, 342423423423);
  const char *key2 = "dsfs4346dfg045jvikjnsdfcxc73482348!NKSASDCN.x91@sdf";
  size_t y = strlen(key1);
  uint64_t hkey2 = XXH64(key1, y, 2345354);

  memset(bloom.f_base_ptr, 0, (*m_actual_bytes / 8));
  int test_size = 125000;
  byte_t *positive_tests = malloc((test_size + 1) * crypto_box_NONCEBYTES);
  memset(positive_tests, 0, (test_size + 1) * crypto_box_NONCEBYTES);
  byte_t *false_tests = malloc((test_size + 1) * crypto_box_NONCEBYTES);
  memset(false_tests, 0, (test_size + 1) * crypto_box_NONCEBYTES);
  for (int i = 0; i < test_size; i++) {
    randombytes_buf(positive_tests + (i * crypto_box_NONCEBYTES), crypto_box_NONCEBYTES);
    randombytes_buf(false_tests + (i * crypto_box_NONCEBYTES), crypto_box_NONCEBYTES);
    bloom_add_elem(&bloom, positive_tests + (i * crypto_box_NONCEBYTES), crypto_box_NONCEBYTES, hkey);
  }
  int pos_hits = 0, false_hits = 0;
  for (int i = 0; i < test_size; i++) {
    //   printf ("pos test: \n");
    pos_hits += bloom_lookup(&bloom, positive_tests + (i * crypto_box_NONCEBYTES), crypto_box_NONCEBYTES, hkey);
    //printf ("false test: \n");
    false_hits += bloom_lookup(&bloom, false_tests + (i * crypto_box_NONCEBYTES), crypto_box_SECRETKEYBYTES, hkey);
  }
  printf("pos: %d\n", pos_hits);
  printf("false hits: %d\n", false_hits);
  free(bloom.f_base_ptr);
  free(bloom.partition_offsets);
  free(bloom.partition_lengths_bytes);
  free(bloom.partition_lengths_bits);
  free(positive_tests);
  free(false_tests);
  free(m_actual_bytes);
};