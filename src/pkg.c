#include <pbc/pbc.h>
#include <sodium.h>
#include <string.h>
#include <pbc/pbc_test.h>
#include "../include/pbc_sign.h"
#include "../include/pkg.h"
#include "../include/net_common.h"

int pkg_server_init(pkg_server *server, uint32_t server_id)
{
	pairing_init_set_str(server->pairing, pbc_params);
	server->current_round = 1;
	server->num_clients = 10;
	server->srv_id = server_id;
	pairing_ptr pairing = server->pairing;
	// Initialise gen_elem element + long term ibe public/secret signature keypair
	element_init(&server->bls_gen_elem_g2, pairing->G2);
	element_init(&server->ibe_gen_elem_g1, pairing->G1);
	element_set_str(&server->ibe_gen_elem_g1, ibe_generator, 10);
	element_set_str(&server->bls_gen_elem_g2, bls_generator, 10);
	element_init(server->lt_sig_sk_elem, pairing->Zr);
	element_set_str(server->lt_sig_sk_elem, sk[server_id], 10);
	element_init(server->lt_sig_pk_elem, pairing->G2);
	element_set_str(server->lt_sig_pk_elem, pk[server_id], 10);
	server->broadcast_dh_pkey_ptr = server->eph_broadcast_message + net_header_BYTES + g1_elem_compressed_BYTES;
	// Initialise elements for epheremal IBE key_state generation and create an initial keypair
	element_init(server->eph_secret_key_elem_zr, pairing->Zr);
	element_init(server->eph_pub_key_elem_g1, pairing->G1);
	// Allocate and initialise clients
	server->clients = malloc(sizeof(pkg_client) * server->num_clients);
	for (int i = 0; i < 5; i++) {
		memset(&server->clients[i], 0, sizeof(pkg_client));
		pkg_client_init(&server->clients[i], server, user_ids[i], user_publickeys[i]);
	}
	uint8_t user_buf[user_id_BYTES];
	uint8_t pk_buff[crypto_box_PUBLICKEYBYTES];
	for (int i = 5; i < server->num_clients; i++) {
		randombytes_buf(user_buf, user_id_BYTES);
		randombytes_buf(pk_buff, crypto_box_PUBLICKEYBYTES);
		pkg_client_init(&server->clients[i], server, user_buf, pk_buff);
	}

	pkg_new_ibe_keypair(server);
	crypto_box_keypair(server->broadcast_dh_pkey_ptr, server->eph_secret_dh_key);
	serialize_uint32(server->eph_broadcast_message, PKG_BR_MSG);
	serialize_uint32(server->eph_broadcast_message + net_msg_type_BYTES, pkg_broadcast_msg_BYTES);
	serialize_uint64(server->eph_broadcast_message + 8, server->current_round);
	// Extract secret keys and generate signatures for each client_s
	for (int i = 0; i < server->num_clients; i++) {
		pkg_extract_client_sk(server, &server->clients[i]);
		pkg_sign_for_client(server, &server->clients[i]);
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

void pkg_client_init(pkg_client *client, pkg_server *server, const uint8_t *user_id, const uint8_t *lt_sig_key)
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

	element_init(client->eph_sk_G2, server->pairing->G2);
	element_init(client->eph_sig_elem_G1, server->pairing->G1);
	element_init(client->eph_sig_hash_elem_g1, server->pairing->G1);
	element_init(client->hashed_id_elem_g2, server->pairing->G2);

	uint8_t id_hash[crypto_ghash_BYTES];
	crypto_generichash(id_hash, crypto_ghash_BYTES, client->user_id, user_id_BYTES, NULL, 0);
	element_from_hash(client->hashed_id_elem_g2, id_hash, crypto_ghash_BYTES);
}

void pkg_server_shutdown(pkg_server *server)
{
	element_clear(server->lt_sig_sk_elem);
	element_clear(server->lt_sig_pk_elem);
	element_clear(server->eph_pub_key_elem_g1);
	element_clear(server->eph_secret_key_elem_zr);
	element_clear(&server->bls_gen_elem_g2);
	for (int i = 0; i < server->num_clients; i++) {
		pkg_client_free(&server->clients[i]);
	}
	pairing_clear(server->pairing);
}

void pkg_client_free(pkg_client *client)
{
	element_clear(client->hashed_id_elem_g2);
	element_clear(client->eph_sig_elem_G1);
	element_clear(client->eph_sig_hash_elem_g1);
	element_clear(client->eph_sk_G2);
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
	for (int i = 0; i < server->num_clients; i++) {
		pkg_extract_client_sk(server, &server->clients[i]);
		pkg_sign_for_client(server, &server->clients[i]);
	}
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


