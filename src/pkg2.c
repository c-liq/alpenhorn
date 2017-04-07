#include <sodium.h>
#include <string.h>
#include <pthread.h>
#include "pkg2.h"
#include "net_common.h"

typedef struct pkg_thread_args pkg_thread_args;

struct pkg_thread_args
{
	pkg_server *server;
	int begin;
	int end;
	int thread_id;
};


int pkg_server_init(pkg_server *server, uint32_t server_id)
{
	server->current_round = 1;
	server->num_clients = 1000000;
	server->srv_id = server_id;
	// Initialise gen_elem element + long term ibe public/secret signature keypair
	// Initialise elements for epheremal IBE key_state generation and create an initial keypair
	// Allocate and initialise clients
	server->clients = calloc(server->num_clients, sizeof(pkg_client));
	for (int i = 0; i < 5; i++) {
		pkg_client_init(&server->clients[i], server, user_ids[i], user_publickeys[i]);
	}
	for (int i = 5; i < server->num_clients; i++) {
		uint8_t user_id[user_id_BYTES];
		uint8_t pk_buf[crypto_ghash_BYTES];
		randombytes_buf(user_id, user_id_BYTES);
		randombytes_buf(pk_buf, crypto_ghash_BYTES);
		pkg_client_init(&server->clients[i], server, user_id, pk_buf);
	}

	server->broadcast_dh_pkey_ptr = server->eph_broadcast_message + net_header_BYTES + g1_elem_compressed_BYTES;
	fprintf(stderr, "p\n", (void *) server->broadcast_dh_pkey_ptr);
	twistpoint_fp2_set(server->lt_keypair.public_key, pkg_lt_pks[server_id]);
	scalar_set_lluarray(server->lt_keypair.secret_key, pkg_lt_sks[server_id]);

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
	printf("Thread %d processing clients from %d to %d\n", th_args->thread_id, th_args->begin, th_args->end);

	for (int i = th_args->begin; i < th_args->end; i++) {
		pkg_extract_client_sk(srv, &srv->clients[i]);
		//pkg_sign_for_client(srv, &srv->clients[i]);
	}
	return NULL;
}

int pkg_parallel_extract(pkg_server *server)
{
	int num_threads = 32;
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

void pkg_client_init(pkg_client *client, pkg_server *server, uint8_t *user_id, const uint8_t *lt_sig_key)
{

	client->auth_response_ibe_key_ptr = client->eph_client_data + net_header_BYTES + g1_elem_compressed_BYTES;
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


	bn256_hash_g2(client->hashed_id_elem_g2, user_id, user_id_BYTES, NULL);
}

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
	if (!server->broadcast_dh_pkey_ptr) {
		server->broadcast_dh_pkey_ptr = server->eph_broadcast_message + net_header_BYTES + g1_elem_compressed_BYTES;
		printf("%p\n", (void *) server->broadcast_dh_pkey_ptr);
	}
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
	int s = crypto_sign_verify_detached(client->auth_msg_from_client,
	                                    server->eph_broadcast_message + net_header_BYTES,
	                                    pkg_broadcast_msg_BYTES,
	                                    client->lt_sig_pk);

	if (s) {
		//printhex("pkg sig", client->auth_msg_from_client, crypto_sign_BYTES);
		fprintf(stderr, "failed to verify signature during client auth\n");
		return -1;
	}
	uint8_t *client_dh_ptr = client->auth_msg_from_client + crypto_sign_BYTES;
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
		*nonce_ptr = client->eph_client_data + net_header_BYTES + g1_elem_compressed_BYTES + g2_elem_compressed_BYTES
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
	bn256_serialize_g2(client->auth_response_ibe_key_ptr, client->eph_sk_G2->m_x, client->eph_sk_G2->m_y);
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


