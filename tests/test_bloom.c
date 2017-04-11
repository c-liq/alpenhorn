#include <string.h>
#include <utime.h>
#include "bloom.h"
#include "math.h"
#include <sys/time.h>

#include "client.h"

double get_time()
{
	struct timeval t;
	struct timezone tzp;
	gettimeofday(&t, &tzp);
	return t.tv_sec + t.tv_usec * 1e-6;
}

int main()
{
	int res = sodium_init();
	if (res)
		exit(EXIT_FAILURE);


	client_s *cl = client_alloc(user_ids[0], user_publickeys[0], user_lt_secret_sig_keys[0]);
	cl->num_intents = 5;
	char user_id_buf[user_id_BYTES] = {'u', 's', 'e', 'r'};
	uint8_t our_pk[crypto_box_PUBLICKEYBYTES];
	uint8_t their_pk[crypto_box_PUBLICKEYBYTES];
	int num_contacts = 500;
	for (int i = 0; i < num_contacts; i++) {
		sprintf(user_id_buf + 4, "%d\0", i);
		randombytes_buf(their_pk, crypto_box_PUBLICKEYBYTES);
		kw_from_request(&cl->keywheel, (uint8_t *) user_id_buf, our_pk, their_pk);
	}

	kw_print_table(&cl->keywheel);

	double p = pow(10.0, -10.0);
	bloomfilter_s *bloom = bloom_alloc(p, 125000, 0, NULL, 0);
	uint8_t buf[crypto_box_PUBLICKEYBYTES];
	for (int i = 0; i < 124990; i++) {
		randombytes_buf(buf, crypto_box_PUBLICKEYBYTES);
		bloom_add_elem(bloom, buf, crypto_box_PUBLICKEYBYTES);
	}
	uint8_t dial_token_buf[dialling_token_BYTES];
	for (int i = 0; i < num_contacts; i++) {
		sprintf(user_id_buf + 4, "%d\0", i);
		kw_dialling_token(dial_token_buf,
		                  &cl->keywheel,
		                  (uint8_t *) user_id_buf,
		                  randombytes_uniform(cl->num_intents),
		                  1);
		bloom_add_elem(bloom, dial_token_buf, dialling_token_BYTES);
	}
	double start = get_time();
	int num_calls = dial_process_mb(cl, bloom->bloom_ptr, 2, 125000);
	double end = get_time();
	printf("Time taken to process MB with %lu contacts,  %d intents: %f %f\n",
	       cl->keywheel.num_keywheels,
	       cl->num_intents,
	       1000 * (end - start),
	       (end - start));
	printf("%d calls\n", num_calls);
	cl->num_intents = 10;
	start = get_time();
	num_calls = dial_process_mb(cl, bloom->bloom_ptr, 2, 125000);
	end = get_time();
	printf("Time taken to process MB with %lu contacts,  %d intents: %f %f\n",
	       cl->keywheel.num_keywheels,
	       cl->num_intents,
	       1000 * (end - start),
	       (end - start));
	printf("%d calls\n", num_calls);
};

