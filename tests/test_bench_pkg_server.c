#include <pkg.h>
#include <client.h>


static uint32_t num_clients;
static uint32_t num_threads;
static client_s *clients;

typedef struct thread_args thread_args;

struct thread_args
{
	int begin;
	int end;
	uint8_t *data;
};

pkg_server server;
int *indexes;
void *
cl_init(void *args)
{
	thread_args *th_args = (thread_args *) args;
	uint8_t *data = th_args->data;

	for (int i = th_args->begin; i < th_args->end; i++) {
		indexes[i] = i;
		sign_keypair sig_kp;
		client_s *client = &clients[i];
		memcpy(sig_kp.public_key, data + user_id_BYTES, crypto_sign_PUBLICKEYBYTES);
		memcpy(sig_kp.secret_key, data + user_id_BYTES + crypto_sign_PUBLICKEYBYTES, crypto_sign_SECRETKEYBYTES);
		client_init(client, data, &sig_kp, NULL, NULL, NULL);
		memcpy(client->pkg_broadcast_msgs[0], server.eph_broadcast_message + net_header_BYTES, pkg_broadcast_msg_BYTES);
		af_create_pkg_auth_request(client);
		data += (user_id_BYTES + crypto_sign_PUBLICKEYBYTES + crypto_sign_SECRETKEYBYTES);
	}
	return NULL;
}

void thpool_sim_auth_client(void *arg)
{
	if (!arg) {
		fprintf(stderr, "null pointer passed to auth\n");
		return;
	}
	int *i = (int *) arg;

	int authed = pkg_auth_client(&server, &server.clients[*i], *clients[*i].pkg_auth_requests + net_header_BYTES);

	/*if (!authed) {
		printf("successfully authed %s\n", server.clients[*i].user_id);
	}*/
}

void sim_auth_client_parallel(void *arg)
{
	if (!arg) {
		fprintf(stderr, "null pointer passed to auth\n");
		return;
	}
	int *i = (int *) arg;

	int authed = pkg_auth_client(&server, &server.clients[*i], *clients[*i].pkg_auth_requests + net_header_BYTES);

	/*if (!authed) {
		printf("successfully authed %s\n", server.clients[*i].user_id);
	}*/
}

int
parallel_op(void *(*operator)(void *), uint8_t *data_ptr, uint64_t data_elem_length)
{
	double start_timer = get_time();

	pthread_t threads[num_threads];
	thread_args args[num_threads];
	int num_per_thread = num_clients / num_threads;
	int curindex = 0;
	for (int i = 0; i < num_threads - 1; i++) {
		args[i].begin = curindex;
		args[i].end = curindex + num_per_thread;
		if (data_ptr) {
			args[i].data = data_ptr + (curindex * data_elem_length);
		}
		curindex += num_per_thread;

	}

	args[num_threads - 1].begin = curindex;
	args[num_threads - 1].end = num_clients;
	if (data_ptr) {
		args[num_threads - 1].data = data_ptr + (curindex * data_elem_length);
	}

	for (int i = 0; i < num_threads; i++) {
		int res = pthread_create(&threads[i], NULL, operator, &args[i]);
		if (res) {
			fprintf(stderr, "fatal pthread creation error\n");
			exit(EXIT_FAILURE);
		}
	}

	for (int i = 0; i < num_threads; i++) {
		pthread_join(threads[i], NULL);
	}
	char time_buffer[40];
	get_current_time(time_buffer);
	LOG_OUT(stderr,
	        "[Info] Operation time taken: %f (%d)\n",
	        get_time() - start_timer, num_clients);
	return 0;
}

int main(int argc, char **argv)
{
	#if !USE_PBC
	bn256_init();
	#endif

	num_clients = (uint32_t) strtol(argv[1], NULL, 10);
	num_threads = (uint32_t) strtol(argv[2], NULL, 10);
	pkg_server_init(&server, 0, num_clients, num_threads, argv[3]);
	indexes = calloc(num_clients, sizeof(int));
	clients = calloc(num_clients, sizeof *clients);

	FILE *user_file = fopen(argv[3], "r");
	uint64_t data_size = num_clients * (user_id_BYTES + crypto_sign_PUBLICKEYBYTES + crypto_sign_SECRETKEYBYTES);
	uint8_t *client_data_buffer = calloc(1, data_size);
	if (!user_file) {
		fprintf(stderr, "failed to open user data file, terminating\n");
		exit(EXIT_FAILURE);
	}
	uint64_t x = fread(client_data_buffer,
	                   user_id_BYTES + crypto_sign_PUBLICKEYBYTES + crypto_sign_SECRETKEYBYTES,
	                   num_clients,
	                   user_file);

	parallel_op(cl_init, client_data_buffer, user_id_BYTES + crypto_sign_SECRETKEYBYTES + crypto_sign_PUBLICKEYBYTES);

	double start = get_time();
	for (int i = 0; i < server.num_clients; i++) {
		thpool_add_work(server.thread_pool, thpool_sim_auth_client, &indexes[i]);
	}
	thpool_wait(server.thread_pool);
	printf("Responded to %d requests in %f\n", num_clients, get_time() - start);




	pkg_server_shutdown(&server);
	#if !USE_PBC
	bn256_clear();
	#endif
}

