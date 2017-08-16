#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include <stdio.h>
#include "prime_gen.h"

void
print_primes(uint64_t *table, uint64_t table_size)
{
	if (table_size <= 0) {
		printf("DSADASD");
		return;
	}
	printf("[%lu", table[0]);
	for (int i = 1; i < table_size; i++) {
		printf(", %ld", table[i]);
	}
	printf("]\n");
}
uint64_t generate_primes(uint64_t **primes_out, double max_prime)
{
	uint64_t approx_count = (uint64_t) ceil((max_prime / log(max_prime) * (1 + (1.2762 / log(max_prime)))));

	uint64_t x = (uint64_t) max_prime + 1;
	uint64_t table_size = x * sizeof(uint64_t);
	uint64_t *a = malloc(table_size);
	memset(a, 1, table_size);
	uint64_t max_prime_root = (uint64_t) sqrt(max_prime);
	for (uint64_t i = 2; i < max_prime_root * 2; i++) {
		if (a[i]) {
			for (uint64_t j = (i * i); j < x; j += i) {
				a[j] = 0;
			}
		}
	}
	uint64_t *prime_tbl = malloc(sizeof(uint64_t) * approx_count);
	memset(prime_tbl, 0, sizeof(uint64_t) * approx_count);
	uint64_t table_index = 0;
	for (uint64_t i = 2; i < x; i++) {
		if (a[i]) {
			prime_tbl[table_index++] = i;
		}
	}
	free(a);
	*primes_out = prime_tbl;
	return table_index;
}

