#include <string.h>
#include <utime.h>
#include "bloom.h"
#include "greatest.h"

#define test_num_elems 125000
#define test_num_lookups 100000

void bloom_run_test(double p, int *pos, int *neg)
{
	*pos = 0;
	*neg = 0;
	bloomfilter_s *bf = bloom_alloc(p, test_num_elems, 12345, NULL, 0);

	for (int i = 0; i < test_num_elems; i++) {
		uint8_t rand_buf[crypto_hash_BYTES];
		randombytes_buf(rand_buf, crypto_hash_BYTES);
		bloom_add_elem(bf, rand_buf, crypto_hash_BYTES);
	}

	for (int i = 0; i < test_num_lookups; i++) {
		uint8_t rand_buf[crypto_hash_BYTES];
		randombytes_buf(rand_buf, crypto_hash_BYTES);
		int res = bloom_lookup(bf, rand_buf, crypto_hash_BYTES);
		if (res)
			(*pos)++;
		else
			(*neg)++;
	}
	printf("n: %d | target false pos rate: %f | pos: %d | neg: %d | false pos rate: %f\n",
	       test_num_elems,
	       p,
	       *pos,
	       *neg,
	       (double) *pos / test_num_lookups);

	bloom_free(bf);
}

TEST test_bloom_false_pos(void)
{
	double p = 0.000001;
	int pos, neg;
	bloom_run_test(p, &pos, &neg);
	p = 0.2;
	bloom_run_test(p, &pos, &neg);
	p = 0.3;
	bloom_run_test(p, &pos, &neg);
		PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
	if (sodium_init())
		exit(EXIT_FAILURE);

	GREATEST_MAIN_BEGIN();
		RUN_TEST(test_bloom_false_pos);
	GREATEST_MAIN_END();
}


