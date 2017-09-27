//
// Created by chris on 05/02/17.
//

#include <stdint.h>
#ifndef ALPENHORN_PRIME_GEN_H
#define ALPENHORN_PRIME_GEN_H
uint64_t generate_primes(uint64_t **primes_out, double max_prime);
void print_primes(uint64_t *table, uint64_t table_size);
#endif //ALPENHORN_PRIME_GEN_H
