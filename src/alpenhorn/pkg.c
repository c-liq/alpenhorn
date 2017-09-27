#include "alpenhorn/pkg.h"
#include "alpenhorn/pkg_config.h"
#include <curl/curl.h>

typedef struct pkg_thread_args pkg_thread_args;

struct pkg_thread_args
{
	pkg_server *server;
	uint64_t begin;
	uint64_t end;
	uint8_t *data;
};

struct upload_status
{
	size_t remaining;
	size_t read;
	uint8_t *data;
};

void *
pkg_client_auth_data(void *args);
void *
pkg_client_parallel_init(void *args);
static size_t
payload_source(void *ptr, size_t size, size_t nmemb, void *userp)
{
	struct upload_status *upload_ctx = (struct upload_status *) userp;
	size_t max_read = nmemb * size;

	if ((size == 0) || (nmemb == 0) || ((max_read) < 1)) {
		return 0;
	}

	size_t rem = upload_ctx->remaining;
	size_t to_read = max_read > rem ? rem : max_read;

	if (to_read <= 0) {
		return 0;
	}

	memcpy(ptr, upload_ctx->data + upload_ctx->read, to_read);
	upload_ctx->remaining -= to_read;
	upload_ctx->read += to_read;

	return to_read;
}

void pkg_configure_curl(struct upload_status *up, CURL *curl, struct curl_slist *recipients)
{
	/*curl_easy_setopt(curl, CURLOPT_USERNAME, "alpenhorn.test@gmail.com");
	curl_easy_setopt(curl, CURLOPT_PASSWORD, "alpenhorn");
	curl_easy_setopt(curl, CURLOPT_URL, "smtp://smtp.gmail.com:587");
	curl_easy_setopt(curl, CURLOPT_USE_SSL, (long) CURLUSESSL_ALL);
	curl_easy_setopt(curl, CURLOPT_MAIL_FROM, "alpenhorn.test@gmail.com");

	curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
	curl_easy_setopt(curl, CURLOPT_READDATA, up);
	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);*/
}

int
pkg_registration_request(pkg_server *server,
                         const uint8_t *user_id,
                         uint8_t *sig_key)
{
	if (!server || !user_id || !sig_key) {
		fprintf(stderr, "invalid args passed to pkg_registration_request\n");
		return -1;
	}

	printf("Reg request received: %s\n", user_id);
	char *date = "Date: Mon, 29 Nov 2010 21:54:29 +1100\r\n";
	char *from = "From: alpenhorn.test@gmail.com\r\n";
	char *subject = "Subject: Alpenhorn registration request\r\n\r\n";

	byte_buffer_s *email_buffer = byte_buffer_alloc(1024);
	byte_buffer_put(email_buffer, (uint8_t *) date, strlen(date));
	char to_string[1024];
	char body_string[1024];
	sprintf(to_string, "To: %s\r\n", user_id);
	byte_buffer_put(email_buffer, (uint8_t *) to_string, strlen(to_string));
	byte_buffer_put(email_buffer, (uint8_t *) from, strlen(from));
	byte_buffer_put(email_buffer, (uint8_t *) subject, strlen(subject));

	pkg_pending_client *pc = calloc(1, sizeof(pkg_pending_client));

	uint8_t confirm_key[crypto_ghash_BYTES];
	randombytes_buf(confirm_key, crypto_ghash_BYTES);
	printhex("confirm key", confirm_key, crypto_ghash_BYTES);
	sodium_bin2hex(pc->confirmation_key,
	               crypto_ghash_BYTES * 2 + 1,
	               confirm_key,
	               crypto_ghash_BYTES);

	sprintf(body_string, "%s\r\n", pc->confirmation_key);

	byte_buffer_put(email_buffer, (uint8_t *) body_string, strlen(body_string));
	printf("%s\n", email_buffer->data);

	struct upload_status up;
	up.data = email_buffer->data;
	up.read = 0;
	up.remaining = email_buffer->used;

	CURL *curl = curl_easy_init();
	if (!curl) {
		fprintf(stderr, "curl error\n");
		return -1;
	}

	struct curl_slist *recipients = NULL;
	recipients = curl_slist_append(recipients, (char *) user_id);

	pkg_configure_curl(&up, curl, recipients);

	memcpy(pc->user_id, user_id, user_id_BYTES);
	memcpy(pc->sig_key, sig_key, crypto_sign_PUBLICKEYBYTES);
	printhex("user public key", pc->sig_key, crypto_sign_PUBLICKEYBYTES);

	CURLcode res = curl_easy_perform(curl);

	curl_slist_free_all(recipients);
	curl_easy_cleanup(curl);

	if (res != CURLE_OK) {
		fprintf(
			stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		free(pc);
		return -1;
	}

	pc->next = server->pending_registration_requests;
	server->pending_registration_requests = pc;
	pc->prev = NULL;

	if (pc->next) {
		pc->next->prev = pc;
	}

	return 0;
}

pkg_pending_client *pkg_lookup_pending_reg(pkg_server *server, uint8_t *user_id)
{
	pkg_pending_client *pc = server->pending_registration_requests;
	while (pc) {
		if (!strncmp((char *) user_id, (char *) pc->user_id, user_id_BYTES)) {
			break;
		}
		pc = pc->next;
	}
	return pc;
}

void pkg_delete_registration_request(pkg_server *server, pkg_pending_client *pc)
{
	if (server->pending_registration_requests == pc) {
		server->pending_registration_requests = pc->next;
	}

	if (pc->next) {
		pc->next->prev = pc->prev;
	}

	if (pc->prev) {
		pc->prev->next = pc->next;
	}

	free(pc);
}

int
pkg_confirm_registration(pkg_server *server, uint8_t *user_id, uint8_t *sig)
{
	pkg_pending_client *pc = pkg_lookup_pending_reg(server, user_id);
	if (!pc) {
		fprintf(stderr, "no pending request matching userid\n");
		return -1;
	}

	int res = crypto_sign_verify_detached(
		sig, (uint8_t *) pc->confirmation_key, crypto_ghash_BYTES * 2, pc->sig_key);

	if (res) {
		fprintf(stderr, "sig verification failed when confirming user registration\n");
		return -1;
	}

	pkg_client *new_client = &server->clients[server->num_clients++];
	pkg_client_init(new_client, server, pc->user_id, pc->sig_key, false);

	pkg_extract_client_sk(server, new_client);
	pkg_sign_for_client(server, new_client);

	pkg_delete_registration_request(server, pc);
	return 0;
}

int
pkg_server_init(pkg_server *server,
                uint64_t server_id,
                uint64_t num_clients,
                uint64_t num_threads,
                char *user_data_path)
{
#if USE_PBC
	pairing_init_set_str(server->pairing, pbc_params);
	pairing_ptr pairing = server->pairing;
	element_init(&server->bls_gen_elem_g2, pairing->G2);
	element_init(&server->ibe_gen_elem_g1, pairing->G1);
	element_set_str(&server->ibe_gen_elem_g1, ibe_generator, 10);
	element_set_str(&server->bls_gen_elem_g2, bls_generator, 10);
	element_init(server->lt_sig_sk_elem, pairing->Zr);
	element_set_str(server->lt_sig_sk_elem, sk[id], 10);
	element_init(server->lt_sig_pk_elem, pairing->G2);
	element_set_str(server->lt_sig_pk_elem, pk[id], 10);
	element_init(server->eph_secret_key_elem_zr, pairing->Zr);
	element_init(server->eph_pub_key_elem_g1, pairing->G1);
#else
	twistpoint_fp2_set(server->lt_keypair.public_key, pkg_lt_pks[server_id]);
	scalar_set_lluarray(server->lt_keypair.secret_key, pkg_lt_sks[server_id]);
#endif
	char log_file_str[20];
  sprintf(log_file_str, "pkg_%ld.log", server_id);
	server->log_file = fopen(log_file_str, "a+");
	if (!server->log_file) {
		fprintf(stderr, "fatal: couldn't open log file\n");
		exit(EXIT_FAILURE);
	}
	server->current_round = 1;
	server->num_clients = num_clients;
	server->client_buf_capacity = num_clients * 2 + 10;

	server->num_threads = num_threads;
	server->srv_id = server_id;
	server->clients = calloc(server->client_buf_capacity, sizeof(pkg_client));
	if (user_data_path) {
		FILE *user_file = fopen(user_data_path, "r");
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

		pkg_parallel_operation(server,
		                       pkg_client_parallel_init,
		                       client_data_buffer,
		                       user_id_BYTES + crypto_sign_PUBLICKEYBYTES + crypto_sign_SECRETKEYBYTES);

		fclose(user_file);
		pkg_parallel_operation(server, pkg_client_auth_data, NULL, 0);

	}

	server->broadcast_dh_pkey_ptr = server->eph_broadcast_message + header_BYTES + bn256_ibe_pkg_pk_bytes;

	server->pending_registration_requests = NULL;

	pkg_new_ibe_keypair(server);
	crypto_box_keypair(server->broadcast_dh_pkey_ptr, server->eph_secret_dh_key);
	serialize_uint64(server->eph_broadcast_message, PKG_BR_MSG);
	serialize_uint64(server->eph_broadcast_message + net_msg_type_BYTES,
	                 pkg_broadcast_msg_BYTES);
	serialize_uint64(server->eph_broadcast_message + (net_msg_len_BYTES + net_msg_type_BYTES), server->current_round);
	// Extract secret keys and generate signatures for each client_s


	server->thread_pool = thpool_init(server->num_threads);

	return 0;
}

void thpool_auth_client(void *arg)
{
	if (!arg) {
		fprintf(stderr, "null pointer passed to auth\n");
		return;
	}
	connection *conn = (connection *) arg;
	pkg_client *client = conn->client_state;

	if (!client) {
		pkg_server *srv = (pkg_server *) conn->srv_state;
		uint8_t *user_id = conn->read_buf.data + header_BYTES + round_BYTES;

		int index = pkg_client_lookup(srv, user_id);
		if (index == -1) {
			fprintf(stderr, "could not find username %s\n", user_id);
			return;
		}
		conn->client_state = &srv->clients[index];
		client = conn->client_state;
	}

	int authed = pkg_auth_client(client->server, client, conn->read_buf.data + header_BYTES);

	if (!authed) {
		client->last_auth = time(0);
		memcpy(conn->write_buf.data + conn->bytes_written,
		       client->eph_client_data,
		       header_BYTES + pkg_enc_auth_res_BYTES);
		conn->write_remaining += header_BYTES + pkg_enc_auth_res_BYTES;
		net_epoll_send(conn, conn->sock_fd);
	}
}

void *
pkg_client_auth_data(void *args)
{
	pkg_thread_args *th_args = (pkg_thread_args *) args;
	pkg_server *srv = th_args->server;
	// printf("Thread %d processing clients from %d to %d\n", th_args->thread_id,
	// th_args->begin, th_args->end);
	for (int i = th_args->begin; i < th_args->end; i++) {
		pkg_extract_client_sk(srv, &srv->clients[i]);
		pkg_sign_for_client(srv, &srv->clients[i]);
	}
	return NULL;
}

void *
pkg_client_parallel_init(void *args)
{
	pkg_thread_args *th_args = (pkg_thread_args *) args;
	pkg_server *srv = th_args->server;
	uint8_t *data = th_args->data;
	// printf("Thread %d processing clients from %d to %d\n", th_args->thread_id,
	// th_args->begin, th_args->end);
	for (int i = th_args->begin; i < th_args->end; i++) {
		//pkg_extract_client_sk(srv, &srv->clients[i]);
		//pkg_sign_for_client(srv, &srv->clients[i]);
		pkg_client_init(&srv->clients[i], srv, data, data + user_id_BYTES, false);
		data += (user_id_BYTES + crypto_sign_PUBLICKEYBYTES + crypto_sign_SECRETKEYBYTES);
	}
	return NULL;
}

int
pkg_parallel_operation(pkg_server *server, void *(*operator)(void *), uint8_t *data_ptr, uint64_t data_elem_length)
{
	double start_timer = get_time();
	uint64_t num_threads = server->num_threads;
	pthread_t threads[num_threads];
	pkg_thread_args args[num_threads];
	uint64_t num_per_thread = server->num_clients / num_threads;
	int curindex = 0;
	for (int i = 0; i < num_threads - 1; i++) {
		args[i].server = server;
		args[i].begin = curindex;
		args[i].end = curindex + num_per_thread;
		if (data_ptr) {
			args[i].data = data_ptr + (curindex * data_elem_length);
		}
		curindex += num_per_thread;

	}

	args[num_threads - 1].server = server;
	args[num_threads - 1].begin = curindex;
	args[num_threads - 1].end = server->num_clients;
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
	LOG_OUT(server->log_file,
	        "[Info] Client data generated at %s | Time taken: %f (%d)\n",
	        time_buffer,
	        get_time() - start_timer,
	        server->num_clients);
	return 0;
}

int
pkg_client_lookup(pkg_server *server, uint8_t *user_id)
{
	int index = -1;
	for (int i = 0; i < server->num_clients; i++) {
		if (!(strncmp((char *) user_id, (char *) server->clients[i].user_id, user_id_BYTES))) {
			index = i;
			break;
		}
	}
	return index;
}
#if USE_PBC
void
pkg_client_init(pkg_client* client,
				pkg_server* server,
				const uint8_t* user_id,
				const uint8_t* lt_sig_key,
				bool is_key_hex)
{
  client->auth_response_ibe_key_ptr =
	client->eph_client_data + header_BYTES + g1_serialized_bytes;
  serialize_uint64(client->eph_client_data, PKG_AUTH_RES_MSG);
  memcpy(client->user_id, user_id, user_id_BYTES);

  if (is_key_hex) {
	sodium_hex2bin(client->lt_sig_pk,
				   crypto_sign_PUBLICKEYBYTES,
				   (char*)lt_sig_key,
				   crypto_sign_PUBLICKEYBYTES * 2,
				   NULL,
				   NULL,
				   NULL);
  } else {
	memcpy(client->lt_sig_pk, lt_sig_key, crypto_sign_PUBLICKEYBYTES);
  }

  memcpy(client->rnd_sig_msg + round_BYTES, client->user_id, user_id_BYTES);
  memcpy(client->rnd_sig_msg + round_BYTES + user_id_BYTES,
		 client->lt_sig_pk,
		 crypto_sign_PUBLICKEYBYTES);

  element_init(client->eph_sk_G2, server->pairing->G2);
  element_init(client->eph_sig_elem_G1, server->pairing->G1);
  element_init(client->eph_sig_hash_elem_g1, server->pairing->G1);
  element_init(client->hashed_id_elem_g2, server->pairing->G2);

  uint8_t id_hash[crypto_ghash_BYTES];
  crypto_generichash(
	id_hash, crypto_ghash_BYTES, client->user_id, user_id_BYTES, NULL, 0);
  element_from_hash(client->hashed_id_elem_g2, id_hash, crypto_ghash_BYTES);
}
#else
void
pkg_client_init(pkg_client *client,
                pkg_server *server,
                const uint8_t *user_id,
                const uint8_t *lt_sig_key,
                bool is_key_hex)
{
	client->server = server;
	client->auth_response_ibe_key_ptr = client->eph_client_data + header_BYTES + bn256_bls_sig_message_bytes;
	serialize_uint64(client->eph_client_data, PKG_AUTH_RES_MSG);
	memcpy(client->user_id, user_id, user_id_BYTES);
	if (is_key_hex) {
		sodium_hex2bin(client->lt_sig_pk,
		               crypto_sign_PUBLICKEYBYTES,
		               (char *) lt_sig_key,
		               crypto_sign_PUBLICKEYBYTES * 2,
		               NULL,
		               NULL,
		               NULL);
	}
	else {
		memcpy(client->lt_sig_pk, lt_sig_key, crypto_sign_PUBLICKEYBYTES);
	}
	memcpy(client->rnd_sig_msg + round_BYTES, client->user_id, user_id_BYTES);
	memcpy(client->rnd_sig_msg + round_BYTES + user_id_BYTES,
	       client->lt_sig_pk,
	       crypto_sign_PUBLICKEYBYTES);

	bn256_hash_g2(client->hashed_id_elem_g2, user_id, user_id_BYTES);
}
#endif
void
pkg_server_shutdown(pkg_server *server)
{
	if (!server)
		return;

	free(server->clients);
}

void
pkg_client_free(pkg_client *client)
{
	sodium_memzero(client, sizeof(pkg_client));
	free(client);
}

void
pkg_net_broadcast(void *s, connection *conn) {
  pkg_server *pkg_server = s;

  memcpy(conn->write_buf.data + conn->bytes_written + conn->write_remaining,
		 pkg_server->eph_broadcast_message,
		 header_BYTES + pkg_broadcast_msg_BYTES);
  conn->write_remaining += header_BYTES + pkg_broadcast_msg_BYTES;
  net_epoll_send(conn, conn->sock_fd);
}
void
pkg_new_round(pkg_server *server)
{
	pkg_new_ibe_keypair(server);
	crypto_box_keypair(server->broadcast_dh_pkey_ptr, server->eph_secret_dh_key);
	server->current_round++;
	net_serialize_header(server->eph_broadcast_message,
	                     PKG_BR_MSG,
	                     pkg_broadcast_msg_BYTES,
	                     server->current_round,
	                     0UL);
	pkg_parallel_operation(server, pkg_client_auth_data, NULL, 0);
  connection *curr = server->net_state.clients;
  char time_buffer[40];
  get_current_time(time_buffer);
  LOG_OUT(server->log_file, "[Info] Round %ld started at %s\n", server->current_round, time_buffer);
  while (curr) {
	pkg_net_broadcast(server, curr);
	curr = curr->next;
  }
}

int
pkg_auth_client(pkg_server *server, pkg_client *client, uint8_t *auth_msg_buf)
{
	uint64_t round_val = deserialize_uint64(auth_msg_buf);
	if (round_val != server->current_round) {
		fprintf(stderr,
		        "%lu, should be %lu | Incorrect round value in client "
			        "authentication request\n",
		        round_val,
		        server->current_round);
		return -1;
	}
	int s = crypto_sign_verify_detached(
		auth_msg_buf + cli_pkg_single_auth_req_BYTES - crypto_sign_BYTES,
		auth_msg_buf,
		cli_pkg_single_auth_req_BYTES - crypto_sign_BYTES,
		client->lt_sig_pk);

	if (s) {
		fprintf(stderr, "failed to verify signature during client auth\n");
		return -1;
	}
	uint8_t *client_dh_ptr = auth_msg_buf + round_BYTES + user_id_BYTES;
	uint8_t scalar_mult[crypto_scalarmult_BYTES];
	int result = crypto_scalarmult(scalar_mult, server->eph_secret_dh_key, client_dh_ptr);
	if (result) {
		fprintf(stderr, "scalarmult error\n");
		return -1;
	}
	crypto_shared_secret(client->eph_symmetric_key,
						 scalar_mult,
						 client_dh_ptr,
						 server->broadcast_dh_pkey_ptr,
						 NULL,
						 crypto_ghash_BYTES);

	pkg_encrypt_client_response(server, client);
	return 0;
}

void
pkg_encrypt_client_response(pkg_server *server, pkg_client *client)
{
	serialize_uint64(client->eph_client_data + net_msg_type_BYTES,
	                 pkg_enc_auth_res_BYTES);
	serialize_uint64(client->eph_client_data + (net_msg_len_BYTES + net_msg_type_BYTES), server->current_round);
	uint8_t *nonce_ptr = client->eph_client_data + header_BYTES +
		bn256_bls_sig_message_bytes + bn256_ibe_client_sk_bytes +
		crypto_MACBYTES;
	randombytes_buf(nonce_ptr, crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
	crypto_aead_chacha20poly1305_ietf_encrypt(
		client->eph_client_data + header_BYTES,
		NULL,
		client->eph_client_data + header_BYTES,
		pkg_auth_res_BYTES,
		nonce_ptr,
		crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
		NULL,
		nonce_ptr,
		client->eph_symmetric_key);
}

#if USE_PBC
void
pkg_new_ibe_keypair(pkg_server* server)
{
  element_random(server->eph_secret_key_elem_zr);
  element_pow_zn(server->eph_pub_key_elem_g1,
				 &server->ibe_gen_elem_g1,
				 server->eph_secret_key_elem_zr);
  element_to_bytes_compressed(server->eph_broadcast_message + header_BYTES,
							  server->eph_pub_key_elem_g1);
}

void
pkg_extract_client_sk(pkg_server* server, pkg_client* client)
{
  element_pow_zn(client->eph_sk_G2,
				 client->hashed_id_elem_g2,
				 server->eph_secret_key_elem_zr);
  element_to_bytes_compressed(client->auth_response_ibe_key_ptr,
							  client->eph_sk_G2);
}

void
pkg_sign_for_client(pkg_server* server, pkg_client* client)
{
	serialize_uint64(client->rnd_sig_msg, server->current_round);
	memcpy(client->rnd_sig_msg + round_BYTES, client->user_id, user_id_BYTES);
	memcpy(client->rnd_sig_msg + round_BYTES + user_id_BYTES, client->lt_sig_pk, crypto_sign_PUBLICKEYBYTES);
  bls_sign_message(client->eph_client_data + header_BYTES,
				   client->eph_sig_elem_G1,
				   client->eph_sig_hash_elem_g1,
				   client->rnd_sig_msg,
				   pkg_sig_message_BYTES,
				   server->lt_sig_sk_elem);
}

#else
void pkg_new_ibe_keypair(pkg_server *server)
{
	bn256_scalar_random(server->eph_secret_key_elem_zr);
	bn256_scalarmult_base_g1(server->eph_pub_key_elem_g1, server->eph_secret_key_elem_zr);
	curvepoint_fp_makeaffine(server->eph_pub_key_elem_g1);
	bn256_serialize_g1(server->eph_broadcast_message + header_BYTES, server->eph_pub_key_elem_g1);
}

void pkg_extract_client_sk(pkg_server *server, pkg_client *client)
{
	twistpoint_fp2_t client_sk;
	twistpoint_fp2_scalarmult_vartime(client_sk,
	                                  client->hashed_id_elem_g2,
	                                  server->eph_secret_key_elem_zr);
	twistpoint_fp2_makeaffine(client_sk);
	bn256_serialize_g2(client->auth_response_ibe_key_ptr, client_sk);
}

void pkg_sign_for_client(pkg_server *server, pkg_client *client)
{
	serialize_uint64(client->rnd_sig_msg, server->current_round);
	bn256_bls_sign_message(client->eph_client_data + header_BYTES,
	                       client->rnd_sig_msg,
	                       pkg_sig_message_BYTES,
	                       server->lt_keypair.secret_key);
}
#endif

static const char *pkg_cl_listen_ports[] = {"7500", "7501", "7502"};

bool pkg_net_auth_client(pkg_server *s, connection *conn)
{
	pkg_client *client_state = conn->client_state;
	if (!client_state) {
		uint8_t *user_id = conn->read_buf.data + header_BYTES + round_BYTES;
		int index = pkg_client_lookup(s, user_id);
		if (index == -1) {
			fprintf(stderr, "could not find username %s\n", user_id);
			return false;
		}
		client_state = &s->clients[index];
	}

	int authed = pkg_auth_client(s, client_state, conn->read_buf.data + header_BYTES);
	if (!authed) {
		client_state->last_auth = time(0);
		memcpy(conn->write_buf.data + conn->bytes_written,
		       client_state->eph_client_data,
		       header_BYTES + pkg_enc_auth_res_BYTES);
		conn->write_remaining += header_BYTES + pkg_enc_auth_res_BYTES;
		net_epoll_send(conn, conn->sock_fd);
	}
	return true;
}

void remove_client(pkg_server *s, connection *conn)
{
	net_server_state *net_state = &s->net_state;
	epoll_ctl(net_state->epoll_fd, EPOLL_CTL_DEL, conn->sock_fd, &conn->event);
	if (conn == net_state->clients) {
		net_state->clients = conn->next;
	}
	if (conn->next) {
		conn->next->prev = conn->prev;
	}
	if (conn->prev) {
		conn->prev->next = conn->next;
	}
	free(conn);
}

int
pkg_mix_read(void *srv, connection *conn)
{
	pkg_server *pkg = (pkg_server *) srv;
	if (conn->msg_type == NEW_AF_ROUND) {
	  /*connection *curr = pkg->net_state.clients;
	  char time_buffer[40];
	  get_current_time(time_buffer);
	  LOG_OUT(pkg->log_file, "[Info] Round %ld started at %s\n", pkg->current_round, time_buffer);
	  while (curr) {
		  pkg_net_broadcast(pkg, curr);
		  curr = curr->next;
	  }*/
	}
	else if (conn->msg_type == PKG_REFRESH_KEYS) {
		pkg_new_round(pkg);
	}
	return 0;
}

int
pkg_net_process_client_msg(void *srv, connection *conn)
{
	pkg_server *s = (pkg_server *) srv;
	if (conn->msg_type == CLIENT_AUTH_REQ) {
		printf("Authentication request received from %s\n",
		       conn->read_buf.data + header_BYTES + round_BYTES);
		/*int res = pkg_net_auth_client(s, conn);
		if (!res) {
			fprintf(stderr,
			        "Authentication failed for %s\n",
			        conn->read_buf.data + header_BYTES + round_BYTES);
		}*/
		thpool_add_work(s->thread_pool, thpool_auth_client, conn);
	}

	else if (conn->msg_type == CLIENT_REG_REQUEST) {
		pkg_registration_request(s,
		                         conn->read_buf.data + header_BYTES,
		                         conn->read_buf.data + header_BYTES +
			                         user_id_BYTES);

		uint8_t header[header_BYTES];
		memset(header, 0, sizeof header);
		serialize_uint64(header, PKG_REG_REQUEST_RECEIVED);
		memcpy(
			conn->write_buf.data + conn->bytes_written, header, header_BYTES);
		conn->write_remaining += header_BYTES;
		net_epoll_send(conn, conn->sock_fd);
	}

	else if (conn->msg_type == CLIENT_REG_CONFIRM) {
		pkg_confirm_registration(s,
		                         conn->read_buf.data + header_BYTES,
		                         conn->read_buf.data + header_BYTES +
			                         user_id_BYTES);
	}

	else {
		fprintf(stderr, "Invalid message type %u\n", conn->msg_type);
	}

	return 0;
}

int
pkg_server_startup(pkg_server *pkg)
{
	net_server_state *s = &pkg->net_state;
	s->owner = pkg;
	s->clients = NULL;
	s->epoll_fd = epoll_create1(0);


	int mix_fd = net_connect(mix_server_ip, mix_server_port, 1);
	if (mix_fd == -1) {
		printf("failed to connect to mix entry server\n");
		return -1;
	}
	connection_init(&s->next_mix,
	                read_buf_SIZE,
	                write_buf_SIZE,
	                pkg_mix_read,
	                s->epoll_fd,
	                mix_fd);

	s->listen_socket = net_start_listen_socket(pkg_cl_listen_ports[pkg->srv_id], 1);
	if (s->listen_socket == -1) {
		fprintf(stderr, "failed to establish listening socket for pkg server\n");
		return -1;
	}

	struct epoll_event event;
	memset(&event, 0, sizeof event);
	event.data.fd = s->listen_socket;
	event.events = EPOLLIN | EPOLLET;
	epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, s->listen_socket, &event);

	return 0;
}

void
pkg_server_run(pkg_server *s)
{
	net_server_state *net_state = &s->net_state;
	struct epoll_event *events = net_state->events;

	for (;;) {
		int n = epoll_wait(net_state->epoll_fd, net_state->events, epoll_num_events, 5000);
		connection *conn = NULL;
		// Error of some sort on the socket
		for (int i = 0; i < n; i++) {
			conn = (connection *) events[i].data.ptr;
			if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
				close(conn->sock_fd);
				remove_client(s, conn);
				continue;
			}
			else if (net_state->listen_socket == events[i].data.fd) {
				int res = net_epoll_client_accept(
					net_state, NULL, pkg_net_process_client_msg);
				if (res) {
					fprintf(stderr, "fatal server error\n");
					exit(1);
				}
			}
			else if (events[i].events & EPOLLIN) {
				net_epoll_read(s, conn);
			}
			else if (events[i].events & EPOLLOUT) {
				net_epoll_send(conn, conn->sock_fd);
			}
		}
	}
}
