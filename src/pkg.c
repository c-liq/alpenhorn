#include <sodium.h>
#include <string.h>
#include <pthread.h>
#include "pkg.h"
#include "net_common.h"
#include <curl/curl.h>

typedef struct pkg_thread_args pkg_thread_args;

static char payload_text[6][128] = {
	"Date: Mon, 29 Nov 2010 21:54:29 +1100\r\n",
	"To: alpenhorn.test@gmail.com\r\n",
	"From: alpenhorn.test@gmail.comr\n",
	"Subject: Alpenhorn registration request\r\n\r\n",
	"The body of the message starts here.\r\n",
	"\0"};

struct pkg_thread_args
{
	pkg_server *server;
	int begin;
	int end;
	int thread_id;
};

struct upload_status
{
	int lines_read;
};

static size_t payload_source(void *ptr, size_t size, size_t nmemb,
                             void *userp)
{
	struct upload_status *upload_ctx = (struct upload_status *) userp;
	const char *data;

	if ((size == 0) || (nmemb == 0) || ((size * nmemb) < 1)) {
		return 0;
	}

	data = payload_text[upload_ctx->lines_read];

	if (data) {
		size_t len = strlen(data);
		memcpy(ptr, data, len);
		upload_ctx->lines_read++;

		return len;
	}

	return 0;
}

int pkg_registration_request(pkg_server *server, const char *user_id, uint8_t *sig_key)
{
	CURL *curl;
	CURLcode res;
	struct curl_slist *recipients = NULL;
	struct upload_status upload_ctx;

	upload_ctx.lines_read = 0;

	curl = curl_easy_init();
	if (!curl) {
		fprintf(stderr, "curl error\n");
		return -1;
	}
	/* Set username and password */
	curl_easy_setopt(curl, CURLOPT_USERNAME, "alpenhorn.test@gmail.com");
	curl_easy_setopt(curl, CURLOPT_PASSWORD, "alpenhorn");
	curl_easy_setopt(curl, CURLOPT_URL, "smtp://smtp.gmail.com:587");
	curl_easy_setopt(curl, CURLOPT_USE_SSL, (long) CURLUSESSL_ALL);
	curl_easy_setopt(curl, CURLOPT_MAIL_FROM, "alpenhorn.test@gmail.com");
	recipients = curl_slist_append(recipients, user_id);
	curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
	curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

	pkg_pending_client *pc = calloc(1, sizeof(pkg_pending_client));
	memcpy(pc->user_id, user_id, user_id_BYTES);
	memcpy(pc->sig_key, sig_key, crypto_sign_PUBLICKEYBYTES);
	uint8_t confirm_key[crypto_ghash_BYTES];
	randombytes_buf(confirm_key, crypto_ghash_BYTES);
	printhex("confirm key", confirm_key, crypto_ghash_BYTES);
	sodium_bin2hex(pc->confirmation_key, crypto_ghash_BYTES * 2 + 1, confirm_key, crypto_ghash_BYTES);

	sprintf(payload_text[1], "To: %s\r\n", user_id);
	sprintf(payload_text[4], "%s\r\n", pc->confirmation_key);
	res = curl_easy_perform(curl);

	curl_slist_free_all(recipients);
	curl_easy_cleanup(curl);
	if (res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
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

int pkg_confirm_registration(pkg_server *server, uint8_t *user_id, uint8_t *sig)
{
	pkg_pending_client *pc = server->pending_registration_requests;
	while (pc) {
		printf("stored id: %s\n", pc->user_id);
		printf("new id: %s\n", user_id);
		if (!strncmp((char *) user_id, (char *) pc->user_id, user_id_BYTES)) break;
		pc = pc->next;
	}
	if (!pc) {
		fprintf(stderr, "no pending request matching userid\n");
		return -1;
	}
	printf("confirm key: %s\n", pc->confirmation_key);
	printhex("pub key: %s\n", pc->sig_key, crypto_sign_PUBLICKEYBYTES);
	int res = crypto_sign_verify_detached(sig, (uint8_t *) pc->confirmation_key, crypto_ghash_BYTES * 2, pc->sig_key);

	if (res) {
		fprintf(stderr, "sig verification failed when confirming user registration\n");
		return -1;
	}

	pkg_client *new_client = &server->clients[server->num_clients];
	memcpy(new_client->user_id, pc->user_id, user_id_BYTES);
	memcpy(new_client->lt_sig_pk, pc->sig_key, crypto_box_PUBLICKEYBYTES);
	pkg_extract_client_sk(server, new_client);
	pkg_sign_for_client(server, new_client);

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
	return 0;
}

int pkg_server_init(pkg_server *server, uint32_t server_id, uint32_t num_clients, uint32_t num_threads)
{
	server->current_round = 1;
	server->num_clients = num_clients;
	server->client_buf_capacity = num_clients * 2;
	server->num_threads = num_threads;
	server->srv_id = server_id;
	server->clients = calloc(server->client_buf_capacity, sizeof(pkg_client));
	for (int i = 0; i < 5; i++) {
		pkg_client_init(&server->clients[i], user_ids[i], user_publickeys[i]);
	}
	for (int i = 5; i < server->num_clients; i++) {
		uint8_t user_id[user_id_BYTES];
		uint8_t pk_buf[crypto_ghash_BYTES];
		randombytes_buf(user_id, user_id_BYTES);
		randombytes_buf(pk_buf, crypto_ghash_BYTES);
		pkg_client_init(&server->clients[i], user_id, pk_buf);
	}
	server->broadcast_dh_pkey_ptr = server->eph_broadcast_message + net_header_BYTES + g1_serialized_bytes;

	#if USE_PBC
	pairing_init_set_str(server->pairing, pbc_params);
	pairing_ptr pairing = server->pairing;
	element_init(&server->bls_gen_elem_g2, pairing->G2);
	element_init(&server->ibe_gen_elem_g1, pairing->G1);
	element_set_str(&server->ibe_gen_elem_g1, ibe_generator, 10);
	element_set_str(&server->bls_gen_elem_g2, bls_generator, 10);
	element_init(server->lt_sig_sk_elem, pairing->Zr);
	element_set_str(server->lt_sig_sk_elem, sk[server_id], 10);
	element_init(server->lt_sig_pk_elem, pairing->G2);
	element_set_str(server->lt_sig_pk_elem, pk[server_id], 10);
	element_init(server->eph_secret_key_elem_zr, pairing->Zr);
	element_init(server->eph_pub_key_elem_g1, pairing->G1);
	#else
	twistpoint_fp2_set(server->lt_keypair.public_key, pkg_lt_pks[server_id]);
	scalar_set_lluarray(server->lt_keypair.secret_key, pkg_lt_sks[server_id]);
	#endif

	pkg_new_ibe_keypair(server);
	crypto_box_keypair(server->broadcast_dh_pkey_ptr, server->eph_secret_dh_key);
	serialize_uint32(server->eph_broadcast_message, PKG_BR_MSG);
	serialize_uint32(server->eph_broadcast_message + net_msg_type_BYTES, pkg_broadcast_msg_BYTES);
	serialize_uint64(server->eph_broadcast_message + 8, server->current_round);
	// Extract secret keys and generate signatures for each client_s
	pkg_parallel_extract(server);
	return 0;
}

void *pkg_client_auth_data(void *args)
{
	pkg_thread_args *th_args = (pkg_thread_args *) args;
	pkg_server *srv = th_args->server;
	//printf("Thread %d processing clients from %d to %d\n", th_args->thread_id, th_args->begin, th_args->end);
	for (int i = th_args->begin; i < th_args->end; i++) {
		pkg_extract_client_sk(srv, &srv->clients[i]);
		pkg_sign_for_client(srv, &srv->clients[i]);
	}
	return NULL;
}

int pkg_parallel_extract(pkg_server *server)
{
	uint32_t num_threads = server->num_threads;
	pthread_t threads[num_threads];
	pkg_thread_args args[num_threads];
	int num_per_thread = server->num_clients / num_threads;
	int curindex = 0;
	for (int i = 0; i < num_threads - 1; i++) {
		args[i].server = server;
		args[i].begin = curindex;
		args[i].end = curindex + num_per_thread;
		curindex += num_per_thread;
		args[i].thread_id = i;

	}

	args[num_threads - 1].server = server;
	args[num_threads - 1].begin = curindex;
	args[num_threads - 1].end = server->num_clients;
	args[num_threads - 1].thread_id = num_threads;

	for (int i = 0; i < num_threads; i++) {
		int res = pthread_create(&threads[i], NULL, pkg_client_auth_data, &args[i]);
		if (res) {
			fprintf(stderr, "fatal pthread creation error\n");
			exit(EXIT_FAILURE);
		}
	}

	for (int i = 0; i < num_threads; i++) {
		pthread_join(threads[i], NULL);
	}

	return 0;
}

int pkg_client_lookup(pkg_server *server, uint8_t *user_id)
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
void pkg_client_init(pkg_client *client, pkg_server *server, const uint8_t *user_id, const uint8_t *lt_sig_key)
{

	client->auth_response_ibe_key_ptr = client->eph_client_data + net_header_BYTES + g1_serialized_bytes;
	serialize_uint32(client->eph_client_data, PKG_AUTH_RES_MSG);
	memcpy(client->user_id, user_id, user_id_BYTES);
	sodium_hex2bin(client->lt_sig_pk,
				   crypto_sign_PUBLICKEYBYTES,
				   (char *) lt_sig_key,
				   crypto_sign_PUBLICKEYBYTES * 2,
				   NULL,
				   NULL,
				   NULL);
	memcpy(client->rnd_sig_msg + round_BYTES, client->user_id, user_id_BYTES);
	memcpy(client->rnd_sig_msg + round_BYTES + user_id_BYTES,
		   client->lt_sig_pk, crypto_sign_PUBLICKEYBYTES);

	element_init(client->eph_sk_G2, server->pairing->G2);
	element_init(client->eph_sig_elem_G1, server->pairing->G1);
	element_init(client->eph_sig_hash_elem_g1, server->pairing->G1);
	element_init(client->hashed_id_elem_g2, server->pairing->G2);

	uint8_t id_hash[crypto_ghash_BYTES];
	crypto_generichash(id_hash, crypto_ghash_BYTES, client->user_id, user_id_BYTES, NULL, 0);
	element_from_hash(client->hashed_id_elem_g2, id_hash, crypto_ghash_BYTES);
}
#else
void pkg_client_init(pkg_client *client, const uint8_t *user_id, const uint8_t *lt_sig_key)
{

	client->auth_response_ibe_key_ptr = client->eph_client_data + net_header_BYTES + g1_serialized_bytes;
	serialize_uint32(client->eph_client_data, PKG_AUTH_RES_MSG);
	memcpy(client->user_id, user_id, user_id_BYTES);
	sodium_hex2bin(client->lt_sig_pk,
	               crypto_sign_PUBLICKEYBYTES,
	               (char *) lt_sig_key,
	               crypto_sign_PUBLICKEYBYTES * 2,
	               NULL,
	               NULL,
	               NULL);
	memcpy(client->rnd_sig_msg + round_BYTES, client->user_id, user_id_BYTES);
	memcpy(client->rnd_sig_msg + round_BYTES + user_id_BYTES,
	       client->lt_sig_pk, crypto_sign_PUBLICKEYBYTES);


	bn256_hash_g2(client->hashed_id_elem_g2, user_id, user_id_BYTES);
}
#endif
void pkg_server_shutdown(pkg_server *server)
{

}

void pkg_client_free(pkg_client *client)
{
	free(client);
}

void pkg_new_round(pkg_server *server)
{
	// Generate epheremal IBE + DH keypairs, place public keys into broadcast message buffer
	pkg_new_ibe_keypair(server);
	randombytes_buf(server->eph_secret_dh_key, crypto_box_SECRETKEYBYTES);
	crypto_scalarmult_base(server->broadcast_dh_pkey_ptr, server->eph_secret_dh_key);
	// Increment round counter
	server->current_round++;
	serialize_uint32(server->eph_broadcast_message, PKG_BR_MSG);
	serialize_uint32(server->eph_broadcast_message + net_msg_type_BYTES, pkg_broadcast_msg_BYTES);
	serialize_uint64(server->eph_broadcast_message + 8, server->current_round);
	// Extract secret keys and generate signatures for each client_s
	pkg_parallel_extract(server);
}

int pkg_auth_client(pkg_server *server, pkg_client *client)
{
	uint64_t round_val = deserialize_uint64(client->auth_msg_from_client);
	if (round_val != server->current_round) {
		fprintf(stderr,
		        "%lu, should be %lu | Incorrect round value in client authentication requestion\n",
		        round_val,
		        server->current_round);
		return -1;
	}

	int s =
		crypto_sign_verify_detached(client->auth_msg_from_client + cli_pkg_single_auth_req_BYTES - crypto_sign_BYTES,
		                            client->auth_msg_from_client,
		                            cli_pkg_single_auth_req_BYTES - crypto_sign_BYTES,
		                            client->lt_sig_pk);

	if (s) {
		//printhex("pkg sig", client->auth_msg_from_client, crypto_sign_BYTES);
		fprintf(stderr, "failed to verify signature during client auth\n");
		return -1;
	}
	uint8_t *client_dh_ptr = client->auth_msg_from_client + round_BYTES + user_id_BYTES;
	uint8_t scalar_mult[crypto_scalarmult_BYTES];
	int suc = crypto_scalarmult(scalar_mult, server->eph_secret_dh_key, client_dh_ptr);
	if (suc) {
		fprintf(stderr, "scalarmult error\n");
		return -1;
	}
	crypto_shared_secret(client->eph_symmetric_key,
	                     scalar_mult,
	                     client_dh_ptr,
	                     server->broadcast_dh_pkey_ptr,
	                     crypto_ghash_BYTES);
	pkg_encrypt_client_response(server, client);
	return 0;
}

void pkg_encrypt_client_response(pkg_server *server, pkg_client *client)
{
	serialize_uint32(client->eph_client_data + net_msg_type_BYTES, pkg_enc_auth_res_BYTES);
	serialize_uint64(client->eph_client_data + 8, server->current_round);
	uint8_t
		*nonce_ptr = client->eph_client_data + net_header_BYTES + g1_serialized_bytes + g2_serialized_bytes
		+ crypto_MACBYTES;
	randombytes_buf(nonce_ptr, crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
	crypto_aead_chacha20poly1305_ietf_encrypt(client->eph_client_data + net_header_BYTES,
	                                          NULL,
	                                          client->eph_client_data + net_header_BYTES,
	                                          pkg_auth_res_BYTES,
	                                          nonce_ptr,
	                                          crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
	                                          NULL,
	                                          nonce_ptr,
	                                          client->eph_symmetric_key);
}

#if USE_PBC
void pkg_new_ibe_keypair(pkg_server *server)
{
	element_random(server->eph_secret_key_elem_zr);
	element_pow_zn(server->eph_pub_key_elem_g1, &server->ibe_gen_elem_g1, server->eph_secret_key_elem_zr);
	element_to_bytes_compressed(server->eph_broadcast_message + net_header_BYTES, server->eph_pub_key_elem_g1);

}

void pkg_extract_client_sk(pkg_server *server, pkg_client *client)
{
	element_pow_zn(client->eph_sk_G2, client->hashed_id_elem_g2, server->eph_secret_key_elem_zr);
	element_to_bytes_compressed(client->auth_response_ibe_key_ptr, client->eph_sk_G2);
}

void pkg_sign_for_client(pkg_server *server, pkg_client *client)
{
	serialize_uint64(client->rnd_sig_msg, server->current_round + 1);
	bls_sign_message(client->eph_client_data + net_header_BYTES, client->eph_sig_elem_G1,
					 client->eph_sig_hash_elem_g1, client->rnd_sig_msg,
					 pkg_sig_message_BYTES, server->lt_sig_sk_elem);
}

#else
void pkg_new_ibe_keypair(pkg_server *server)
{
	bn256_scalar_random(server->eph_secret_key_elem_zr);
	bn256_scalarmult_bg1(server->eph_pub_key_elem_g1, server->eph_secret_key_elem_zr);
	curvepoint_fp_makeaffine(server->eph_pub_key_elem_g1);
	bn256_serialize_g1(server->eph_broadcast_message + net_header_BYTES, server->eph_pub_key_elem_g1);
	/*fpe_out_str(stdout, server->eph_pub_key_elem_g1->m_x);
	printf("\n");
	fpe_out_str(stdout, server->eph_pub_key_elem_g1->m_y);*/
	printf("\n");
}

void pkg_extract_client_sk(pkg_server *server, pkg_client *client)
{
	twistpoint_fp2_scalarmult_vartime(client->eph_sk_G2, client->hashed_id_elem_g2, server->eph_secret_key_elem_zr);
	twistpoint_fp2_makeaffine(client->eph_sk_G2);
	bn256_serialize_g2(client->auth_response_ibe_key_ptr, client->eph_sk_G2);
	//fp2e_out_str(stdout,client->eph_sk_G2->m_x);
//	fp2e_out_str(stdout,client->eph_sk_G2->m_y);
}

void pkg_sign_for_client(pkg_server *server, pkg_client *client)
{
	serialize_uint64(client->rnd_sig_msg, server->current_round + 1);
	bn256_bls_sign_message(client->eph_client_data + net_header_BYTES,
	                       client->rnd_sig_msg,
	                       pkg_sig_message_BYTES,
	                       server->lt_keypair.secret_key);
}
#endif

