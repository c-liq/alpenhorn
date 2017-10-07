#include "prime_gen.h"

void print_primes(uint64_t *table, uint64_t table_size) {
    if (!table || table_size < 1) {
        fprintf(stderr, "invalid table\n");
        return;
	}
	printf("[%lu", table[0]);
	for (int i = 1; i < table_size; i++) {
		printf(", %ld", table[i]);
	}
	printf("]\n");
}

int generate_primes(primes_s *primes, double max) {
    if (!primes || max < 2) {
        return -1;
    }

    // This calculation guarantees an upper bound approximation, the actual number of primes will never be larger
    uint64_t approx_count = (uint64_t) ceil((max / log(max) * (1 + (1.2762 / log(max)))));
    uint64_t max_prime = (uint64_t) max + 1;
    uint64_t *a = calloc(max_prime, sizeof(uint64_t));
    if (!a) {
        return -1;
    }

    uint64_t max_prime_root = (uint64_t) sqrt(max);
    for (uint64_t i = 2; i <= max_prime_root; i++) {
        if (!a[i]) {
            for (uint64_t j = (i * i); j < max_prime; j += i) {
                a[j] = 1;
            }
		}
	}

    uint64_t *prime_table = calloc(approx_count, sizeof(uint64_t));
    if (!prime_table) {
        free(a);
        return -1;
    }

    uint64_t num_primes = 0;
    for (uint64_t i = 2; i < max_prime; i++) {
        if (!a[i]) {
            prime_table[num_primes++] = i;
        }
    }
	free(a);

    primes->primes = realloc(prime_table, num_primes * sizeof(uint64_t));
    if (!primes->primes) {
        free(prime_table);
        return -1;
    }

    primes->count = num_primes;
    return 0;
}

