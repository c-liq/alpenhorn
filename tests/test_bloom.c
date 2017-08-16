#include <string.h>
#include <utime.h>
#include "bloom.h"
#include "greatest.h"
#include "math.h"

#define test_num_elems 125000
#define test_num_lookups 10000000

static bloomfilter_s *bf;
static uint8_t *data;
uint8_t *false_lookup_data;

bloomfilter_s *test_bf_setup(double p)
{
	bloomfilter_s *bf = bloom_alloc(p, test_num_elems, 12345, NULL, 0);
	if (!bf) {
		fprintf(stderr, "Fatal calloc error\n");
		exit(EXIT_FAILURE);
	}
	return bf;
}

TEST test_bloom_add(bloomfilter_s *bf, uint8_t *data_array, uint32_t elem_size, uint32_t num_elems)
{
	uint8_t *data_ptr = data_array;
	for (uint32_t i = 0; i < num_elems; i++) {
		bloom_add_elem(bf, data_ptr, elem_size);
		data_ptr += elem_size;
	}
		PASS();
}

TEST test_bloom_lookup(bloomfilter_s *bf, uint8_t *data_array, uint32_t elem_size, uint32_t num_elems)
{
	uint8_t *data_ptr = data_array;
	long pos = 0;
	for (uint32_t i = 0; i < num_elems; i++) {
		pos += bloom_lookup(bf, data_ptr, elem_size);
		data_ptr += elem_size;
	}
	printf("Number of lookups: %u | Positive: %ld | False pos rate: %f\n", num_elems, pos, (double) pos / num_elems);
		PASS();
}

uint8_t *test_generate_data(uint32_t elem_size, uint32_t num_elems)
{
	uint8_t *data_array = calloc(num_elems, elem_size);
	if (!data_array) {
		fprintf(stderr, "fatal calloc error\n");
		exit(EXIT_FAILURE);
	}

	randombytes_buf(data_array, num_elems * elem_size);
	return data_array;
}

GREATEST_MAIN_DEFS();


SUITE (add_suite)
{
		RUN_TESTp(test_bloom_add, bf, data, crypto_pk_BYTES, test_num_elems);
}

SUITE (lookup_suite)
{
		RUN_TESTp(test_bloom_lookup, bf, false_lookup_data, crypto_pk_BYTES, test_num_lookups);
}



int main(int argc, char **argv)
{
	if (sodium_init()) {
		exit(EXIT_FAILURE);
	}

	bf = test_bf_setup(0.001);
	data = test_generate_data(crypto_pk_BYTES, test_num_elems);
	false_lookup_data = test_generate_data(crypto_pk_BYTES, test_num_lookups);
	bloom_print_stats(bf);

	GREATEST_MAIN_BEGIN();
	RUN_SUITE(add_suite);
	RUN_SUITE(lookup_suite);

	bloom_free(bf);
	bf = test_bf_setup(0.0001);

	RUN_SUITE(add_suite);
	RUN_SUITE(lookup_suite);

	GREATEST_MAIN_END();
}


