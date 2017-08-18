#include <pkg.h>
#include "bn256.h"

int main(int argc, char **argv)
{
	#if !USE_PBC
	bn256_init();
	#endif
	pkg_server server;

	pkg_server_init(&server, 0, 100, 4, "/home/chris/ClionProjects/Alpenhorn/users");
	printf("%ld\n", sizeof(pkg_client));
	pkg_server_shutdown(&server);
	#if !USE_PBC
	bn256_clear();
	#endif
}

