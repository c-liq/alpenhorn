#include <pkg.h>
#include "greatest.h"

#define num_real_clients 10
#define num_total_clients 1000

TEST test_pkg_client_auth(pkg_server *server)
{

}

TEST test_bench_pkg_keygen(pkg_server *server)
{
	pkg_parallel_extract(server);
		PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
	#if USE_PBC == 0
	bn256_init();
	#endif
	pkg_server server;
	pkg_server_init(&server, 0, 1000, 4);
	GREATEST_MAIN_BEGIN();
		RUN_TESTp(test_bench_pkg_keygen, &server);
	GREATEST_MAIN_END();
}

