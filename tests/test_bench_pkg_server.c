#include <pkg.h>
#include <sys/time.h>
double get_time()
{
	struct timeval t;
	struct timezone tzp;
	gettimeofday(&t, &tzp);
	return t.tv_sec + t.tv_usec * 1e-6;
}

int main()
{
	bn256_init();
	pkg_server server;
	pkg_server_init(&server, 0, 0, 0);
	double start = get_time();
	//pkg_new_round(&server);
	double end = get_time();
	//printf("Benchmarking PKG key extration/client signing for %d clients: %f\n", server.num_clients, end - start);
	pkg_new_ibe_keypair(&server);



/*	randombytes_buf(server.eph_secret_dh_key, crypto_box_SECRETKEYBYTES);
	crypto_scalarmult_base(server.broadcast_dh_pkey_ptr, server.eph_secret_dh_key);
	// Increment round counter
	server.current_round++;
	serialize_uint32(server.eph_broadcast_message, PKG_BR_MSG);
	serialize_uint32(server.eph_broadcast_message + net_msg_type_BYTES, pkg_broadcast_msg_BYTES);
	serialize_uint64(server.eph_broadcast_message + 8, server.current_round);
	start = get_time();
	for (int i = 0; i < server.num_clients; i++) {
		pkg_extract_client_sk(&server, &server.clients[i]);
	}
	end = get_time();
	pkg_sign_for_client(&server, &server.clients[0]);

	printf("Benchmarking PKG key extraction for %d clients: %f\n", server.num_clients, end - start);*/

}

