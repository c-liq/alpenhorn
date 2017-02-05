//
// Created by chris on 05/02/17.
//
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <math.h>
#include <string.h>

int32_t generate_primes(uint32_t **primes_out, double max_prime) {
  uint64_t pi_x = (uint64_t) (max_prime / log(max_prime) * (1 + (1.2762 / log(max_prime))));
  uint32_t a[(uint32_t) max_prime];
  memset(a, 1, sizeof a);
  uint32_t max_prime_root = (uint32_t) sqrt(max_prime);
  printf("Square root of max prime: %d\n", max_prime_root);
  for (uint32_t i = 2; i < max_prime_root * 2; i++) {
    if (a[i]) {
      for (uint32_t j = (i * i); j <= (uint32_t) max_prime; j += i) {
        a[j] = 0;
      }
    }
  }
  uint32_t *prime_tbl = malloc(sizeof(uint32_t) * pi_x);
  memset(prime_tbl, 0, sizeof(uint32_t) * pi_x);
  printf("%lu\n", pi_x);
  int32_t table_index = 0;
  for (uint32_t i = 2; i < max_prime; i++) {
    if (a[i]) {
      prime_tbl[table_index++] = i;
    }
  }
  *primes_out = prime_tbl;
  printf("\nTable size: %d\n", table_index);
  return table_index;
}

/*
int main() {
  double max_prime = 190000;
  uint32_t *table_ptr;
  int32_t table_size = generate_primes(&table_ptr, max_prime);
  for (int i = 0; i<table_size; i++) {
    printf("%d, ", table_ptr[i]);
  }
}*/
