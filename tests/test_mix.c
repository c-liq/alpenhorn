#include "utils.h"
#include "greatest.h"
#include "mixnet.h"

#define test_num_shuffle_elems 10000;


TEST test_mix_shuffle(void)
{

	mix_s mix1, mix2;
	mix_init(&mix1, 0);
	mix_init(&mix2, 1);
	memcpy(mix1.mix_af_dh_pks[1], mix2.mix_af_dh_pks[0], crypto_box_PUBLICKEYBYTES);
	mix_af_add_noise(&mix1);
	mix_af_add_noise(&mix2);
	byte_buffer_put(&mix2.af_data.in_buf, mix1.af_data.out_buf.data + net_header_BYTES, mix1.af_data.num_out_msgs * mix1.af_data.out_msg_length);
	mix2.af_data.num_inc_msgs += mix1.af_data.num_out_msgs;

	mix_af_decrypt_messages(&mix2);
	mix_af_shuffle(&mix2);
	mix_af_distribute(&mix2);
		PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();
	GREATEST_RUN_TEST(test_mix_shuffle);
}

