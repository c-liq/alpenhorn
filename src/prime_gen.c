#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include <stdio.h>
#include "prime_gen.h"

void
print_primes(uint32_t *table, ssize_t table_size)
{
	if (table_size <= 0) {
		return;
	}
	printf("[%u", table[0]);
	for (int i = 1; i < table_size; i++) {
		printf(", %d", table[i]);
	}
	printf("]\n");
}
uint32_t generate_primes(uint32_t **primes_out, double max_prime)
{
	uint64_t approx_count = (uint64_t) (max_prime / log(max_prime) * (1 + (1.2762 / log(max_prime))));

	uint32_t x = (uint32_t) max_prime + 1;
	uint32_t a[x];
	memset(a, 1, sizeof a);
	uint32_t max_prime_root = (uint32_t) sqrt(max_prime);
	for (uint32_t i = 2; i < max_prime_root * 2; i++) {
		if (a[i]) {
			for (uint32_t j = (i * i); j <= x; j += i) {
				a[j] = 0;
			}
		}
	}
	uint32_t *prime_tbl = malloc(sizeof(uint32_t) * approx_count);
	memset(prime_tbl, 0, sizeof(uint32_t) * approx_count);
	uint32_t table_index = 0;
	for (uint32_t i = 2; i < x; i++) {
		if (a[i]) {
			prime_tbl[table_index++] = i;
		}
	}

	*primes_out = prime_tbl;
	return table_index;
}

