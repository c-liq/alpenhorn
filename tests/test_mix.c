#include "utils.h"
#include "greatest.h"
#include "alpenhorn/mixnet.h"

#define test_num_shuffle_elems 10000;

#ifdef num_mix_servers
#undef num_mix_servers
#endif
#define num_mix_servers 1U

TEST test_mix_shuffle(void)
{

	mix_s mix1;
	mix_init(&mix1, 0, 0, 0);


		PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();
	GREATEST_RUN_TEST(test_mix_shuffle);
}

