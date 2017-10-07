#ifndef PRIME_GEN_H
#define PRIME_GEN_H

#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include <stdio.h>

typedef struct primes_t primes_s;
struct primes_t {
  uint64_t count;
  uint64_t *primes;
};

int generate_primes(primes_s *primes, double max);

void print_primes(uint64_t *table, uint64_t table_size);

#endif //PRIME_GEN_H
