#include "pkg.h"

int main(int argc, char **argv)
{
	#if !USE_PBC
	bn256_init();
	#endif

	int sid;
	if (argc < 2) {
		fprintf(stderr, "No server id provided\n");
		return 1;
	}

	sid = atoi(argv[1]);
	if (sid > num_pkg_servers) {
		fprintf(stderr, "Invalid server id %d\n", sid);
		return 1;
	}
	pkg_server *s = calloc(1, sizeof(struct pkg_server));

	pkg_server_init(s, (uint64_t) sid, 10, 4, "users");
	int res = pkg_server_startup(s);
	if (res) {
		fprintf(stderr, "failed to connect to mix entry server\n");
		exit(EXIT_FAILURE);
	}
	printf("[PKG %d successfully initialised]\n", s->srv_id);
	pkg_server_run(s);
}