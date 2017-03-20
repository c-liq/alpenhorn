#include <sodium.h>
#include <string.h>
#include "client.h"
#include "ibe.h"
#include "../lib/xxhash/xxhash.h"
#include "bloom.h"
#include <math.h>


uint32_t af_calc_mailbox_num(client_s *c, const uint8_t *user_id)
{
	uint64_t hash = XXH64(user_id, user_id_BYTES, 0);
	return (uint32_t) hash % c->af_num_mailboxes;
}

uint32_t dial_calc_mailbox_num(client_s *c, const uint8_t *user_id)
{
	uint64_t hash = XXH64(user_id, user_id_BYTES, 0);
	return (uint32_t) hash % c->dial_num_mailboxes;
}

int dial_call_friend(client_s *c, const uint8_t *user_id, const uint32_t intent)
{
	//verify userid string
	int result;
	uint32_t mailbox = dial_calc_mailbox_num(c, user_id);
	serialize_uint32(c->dial_request_buf + net_header_BYTES, mailbox);
	serialize_uint32(c->dial_request_buf, CLIENT_DIAL_MSG);
	serialize_uint32(c->dial_request_buf + 4, onionenc_dial_token_BYTES);
	serialize_uint64(c->dial_request_buf + 8, c->dialling_round);
	result = kw_dialling_token(c->dial_request_buf + net_header_BYTES + mb_BYTES, &c->keywheel, user_id, intent, true);
	if (result) {
		fprintf(stderr, "could not create dialling token for %s\n", user_id);
		return -1;
	}

	result = kw_session_key(c->session_key_buf, &c->keywheel, user_id, true);
	if (result) {
		fprintf(stderr, "could not generate session key for %s\n", user_id);
		return -1;
	}

	result = dial_onion_encrypt_request(c);
	if (result) {
		fprintf(stderr, "Error while onion encrypting dialling token\n");
		return -1;
	}
	char session_key_hex[dialling_token_BYTES * 2 + 1];
	sodium_bin2hex(session_key_hex, sizeof session_key_hex, c->session_key_buf, dialling_token_BYTES);
	printf("Calling friend %s | Session Key: %s\n", user_id, session_key_hex);
	return 0;
}

void af_add_friend(client_s *client, const char *user_id)
{
	printf("Adding friend id %s\n", user_id);
	memcpy(client->friend_request_id, user_id, user_id_BYTES);
	//memcpy(client->friend_request_id, client->user_id, user_id_BYTES);
	af_create_request(client);
}

void af_process_mb(client_s *c, uint8_t *mailbox, uint32_t num_messages, uint64_t round)
{

	//printf("Processing AF mailbox for round %lu, %d messages\n", round, num_messages);
	uint8_t *msg_ptr = mailbox;
	for (int i = 0; i < num_messages; i++) {
		af_decrypt_request(c, msg_ptr, round);
		msg_ptr += af_ibeenc_request_BYTES;
	}
}

void af_fake_request(client_s *c)
{
	memset(c->friend_request_buf, 0, sizeof c->friend_request_buf);
	// To avoid distributing cover requests, set the mailbox to an invalid number so last mix server can discard them
	serialize_uint32(c->friend_request_buf, CLIENT_AF_MSG);
	serialize_uint32(c->friend_request_buf + net_msg_type_BYTES, onionenc_friend_request_BYTES);
	serialize_uint64(c->friend_request_buf + 8, c->af_round);
	serialize_uint32(c->friend_request_buf + net_header_BYTES, c->af_num_mailboxes + 1);
	af_onion_encrypt_request(c);
}

void dial_fake_request(client_s *c)
{
	memset(c->dial_request_buf, 0, sizeof c->dial_request_buf);
	serialize_uint32(c->dial_request_buf, CLIENT_DIAL_MSG);
	serialize_uint32(c->dial_request_buf + net_msg_type_BYTES, onionenc_dial_token_BYTES);
	serialize_uint64(c->dial_request_buf + 8, c->dialling_round);
	serialize_uint32(c->dial_request_buf + net_header_BYTES, c->dial_num_mailboxes + 1);
	dial_onion_encrypt_request(c);
}

void print_call(incoming_call_s *call)
{
	printf("Incoming call\n------------\n");
	printf("User ID: %s\n", call->user_id);
	printf("Round: %ld\n", call->round);
	printf("Intent: %d\n", call->intent);
	printhex("Session Key", call->session_key, crypto_ghash_BYTES);
}

int dial_process_mb(client_s *c, uint8_t *mb_data, uint64_t round, uint32_t num_tokens)
{

	while (c->keywheel.table_round < round) {
		kw_advance_table(&c->keywheel);
	}

	//printf("Processing Dial mb for round %ld, %d tokens\n", round, num_tokens);
	bloomfilter_s bloom;
	int found = 0, num_calls = 0;
	uint8_t dial_token_buf[dialling_token_BYTES];

	bloom_init(&bloom, c->bloom_p_val, num_tokens, 0, mb_data, 0);
	keywheel_s *curr_kw = c->keywheel.keywheels;
	while (curr_kw) {
		for (uint32_t j = 0; j < c->num_intents; j++) {
			kw_dialling_token(dial_token_buf, &c->keywheel, curr_kw->user_id, j, false);
			found = bloom_lookup(&bloom, dial_token_buf, dialling_token_BYTES);
			if (found) {
				incoming_call_s *new_call = calloc(1, sizeof *new_call);
				new_call->round = round;
				new_call->intent = j;
				memcpy(new_call->user_id, curr_kw->user_id, user_id_BYTES);
				kw_session_key(new_call->session_key, &c->keywheel, curr_kw->user_id, false);
				num_calls++;
				print_call(new_call);
				break;
			}
		}
		curr_kw = curr_kw->next;
	}
	return num_calls;
}

struct friend_request_buf
{
	uint8_t buf_base[onionenc_friend_request_BYTES];
	uint8_t *dial_round;
	uint8_t *user_id;
	uint8_t *dh_pk;
	uint8_t *lt_sig_sk;
	uint8_t *client_sig;
	uint8_t *multisig;
};

void init_fr_buf(struct friend_request_buf *buf)
{
	uint8_t *base = buf->buf_base;
	buf->dial_round = base + mb_BYTES + g1_elem_compressed_BYTES + crypto_ghash_BYTES + crypto_NBYTES;
	buf->user_id = buf->dial_round + round_BYTES;
	buf->dh_pk = buf->user_id + user_id_BYTES;
	buf->lt_sig_sk = buf->dh_pk + crypto_box_PUBLICKEYBYTES;
	buf->client_sig = buf->lt_sig_sk + crypto_sign_PUBLICKEYBYTES;
	buf->multisig = buf->client_sig + crypto_sign_BYTES;
}

int af_accept_request(client_s *c, const char *user_id)
{
	if (!user_id) {
		fprintf(stderr, "no user id supplied to accept request\n");
		return -1;
	}
	friend_request_s *req = NULL;
	friend_request_s *tmp = c->friend_requests;
	while (tmp) {
		if (!(strncmp((char *) user_id, (char *) tmp->user_id, user_id_BYTES))) {
			req = tmp;
			break;
		}
		tmp = tmp->next;
	}

	if (!req) {
		fprintf(stderr, "could not find pending friend request matching id\n");
		return -1;
	}

	printf("Responding to friend request from %s\n", user_id);
	serialize_uint32(c->friend_request_buf, CLIENT_AF_MSG);
	serialize_uint32(c->friend_request_buf + 4, onionenc_friend_request_BYTES);
	serialize_uint64(c->friend_request_buf + 8, c->af_round);

	uint8_t *dr_ptr =
		c->friend_request_buf + net_header_BYTES + mb_BYTES + g1_elem_compressed_BYTES + crypto_ghash_BYTES
			+ crypto_NBYTES;
	uint8_t *user_id_ptr = dr_ptr + round_BYTES;
	uint8_t *dh_pk_ptr = user_id_ptr + user_id_BYTES;
	uint8_t *lt_sig_key_ptr = dh_pk_ptr + crypto_box_PUBLICKEYBYTES;
	uint8_t *client_sig_ptr = lt_sig_key_ptr + crypto_sign_PUBLICKEYBYTES;
	uint8_t *multisig_ptr = client_sig_ptr + crypto_sign_BYTES;

	keywheel_s *new_kw = kw_from_request(&c->keywheel, req->user_id, dh_pk_ptr, req->dh_pk);
	if (!new_kw) {
		fprintf(stderr, "Client: Couldn't construct keywheel for new contact\n");
		return -1;
	}
	if (req == c->friend_requests) {
		c->friend_requests = req->next;
	}

	if (req->next) {
		req->next->prev = req->prev;
	}

	if (req->prev) {
		req->prev->next = req->next;
	}
	free(req);

	memcpy(user_id_ptr, c->user_id, user_id_BYTES);
	memcpy(lt_sig_key_ptr, c->lg_sig_pk, crypto_sign_PUBLICKEYBYTES);
	serialize_uint64(dr_ptr, new_kw->dialling_round);

	crypto_sign_detached(client_sig_ptr, NULL, dr_ptr,
	                     round_BYTES + user_id_BYTES + crypto_box_PUBLICKEYBYTES,
	                     c->lt_sig_sk);
	element_to_bytes_compressed(multisig_ptr, &c->pkg_multisig_combined_g1);
	// Encrypt the request using IBE
	ibe_encrypt(c->friend_request_buf + net_header_BYTES + mb_BYTES, dr_ptr, af_request_BYTES,
	            &c->pkg_eph_pub_combined_g1, &c->ibe_gen_element_g1,
	            new_kw->user_id, user_id_BYTES, &c->pairing);
	// Only information identifying the destination of a request, the mailbox no. of the recipient
	uint32_t mb = af_calc_mailbox_num(c, c->friend_request_id);
	serialize_uint32(c->friend_request_buf + net_header_BYTES, mb);
	// Encrypt the request in layers ready for the mixnet
	af_onion_encrypt_request(c);
	return 0;
}

void af_create_request(client_s *c)
{
	serialize_uint32(c->friend_request_buf, CLIENT_AF_MSG);
	serialize_uint32(c->friend_request_buf + net_msg_type_BYTES, onionenc_friend_request_BYTES);
	serialize_uint64(c->friend_request_buf + 8, c->af_round);

	uint8_t *dr_ptr =
		c->friend_request_buf + net_header_BYTES + mb_BYTES + g1_elem_compressed_BYTES + crypto_ghash_BYTES
			+ crypto_NBYTES;
	uint8_t *user_id_ptr = dr_ptr + round_BYTES;
	uint8_t *dh_pub_ptr = user_id_ptr + user_id_BYTES;
	uint8_t *lt_sig_key_ptr = dh_pub_ptr + crypto_box_PUBLICKEYBYTES;
	uint8_t *client_sig_ptr = lt_sig_key_ptr + crypto_sign_PUBLICKEYBYTES;
	uint8_t *multisig_ptr = client_sig_ptr + crypto_sign_BYTES;
	// Generate a DH keypair that forms the basis of the shared keywheel state with the friend being added
	uint8_t dh_secret_key[crypto_box_SECRETKEYBYTES];
	crypto_box_keypair(dh_pub_ptr, dh_secret_key);
	// Both parties need to agree on the dialling round to synchronise their keywheel
	uint64_t dialling_round = c->dialling_round + 2;

	// Serialise userid/dial round/signature key
	memcpy(user_id_ptr, c->user_id, user_id_BYTES);
	serialize_uint64(dr_ptr, dialling_round);
	memcpy(lt_sig_key_ptr, c->lg_sig_pk, crypto_sign_PUBLICKEYBYTES);
	kw_new_keywheel(&c->keywheel, c->friend_request_id, dh_pub_ptr, dh_secret_key, c->dialling_round);
	// Sign our information with our LT signing key
	crypto_sign_detached(client_sig_ptr,
	                     NULL,
	                     dr_ptr,
	                     round_BYTES + user_id_BYTES + crypto_box_PUBLICKEYBYTES,
	                     c->lt_sig_sk);
	// Also include the multisignature from PKG servers, primary source of verification
	element_to_bytes_compressed(multisig_ptr, &c->pkg_multisig_combined_g1);
	// Encrypt the request using IBE
	ibe_encrypt(c->friend_request_buf + net_header_BYTES + mb_BYTES, dr_ptr, af_request_BYTES,
	            &c->pkg_eph_pub_combined_g1, &c->ibe_gen_element_g1,
	            c->friend_request_id, user_id_BYTES, &c->pairing);
	// Only information identifying the destination of a request, the mailbox no. of the recipient
	uint32_t mb = af_calc_mailbox_num(c, c->friend_request_id);
	serialize_uint32(c->friend_request_buf + net_header_BYTES, mb);
	// Encrypt the request in layers ready for the mixnet
	af_onion_encrypt_request(c);
}

int af_decrypt_request(client_s *c, uint8_t *request_buf, uint64_t round)
{
	uint8_t request_buffer[af_request_BYTES];
	int result = ibe_decrypt(request_buffer, request_buf, af_request_BYTES + crypto_MACBYTES,
	                         &c->pkg_ibe_secret_combined_g2[!c->curr_ibe], &c->pairing);

	if (result) {
		//fprintf(stderr, "%s: ibe decryption failure\n", c->user_id);
		return -1;
	}

	uint8_t *dialling_round_ptr = request_buffer;
	uint8_t *user_id_ptr = dialling_round_ptr + round_BYTES;
	uint8_t *dh_pub_ptr = user_id_ptr + user_id_BYTES;
	uint8_t *lt_sig_key_ptr = dh_pub_ptr + crypto_box_PUBLICKEYBYTES;
	uint8_t *personal_sig_ptr = lt_sig_key_ptr + crypto_sign_PUBLICKEYBYTES;
	uint8_t *multisig_ptr = personal_sig_ptr + crypto_sign_BYTES;

	// Reconstruct the message signed by the PKG's so we can verify the signature
	uint8_t multisig_message[pkg_sig_message_BYTES];
	serialize_uint64(multisig_message, round);
	memcpy(multisig_message + round_BYTES, user_id_ptr, user_id_BYTES);
	memcpy(multisig_message + round_BYTES + user_id_BYTES, lt_sig_key_ptr, crypto_sign_PUBLICKEYBYTES);

	element_t sig_verify_elem, hash_elem;
	element_init(sig_verify_elem, c->pairing.G1);
	element_init(hash_elem, c->pairing.G1);
	result = bls_verify_signature(sig_verify_elem,
	                              hash_elem,
	                              multisig_ptr,
	                              multisig_message,
	                              pkg_sig_message_BYTES,
	                              &c->pkg_lt_sig_keys_combined,
	                              &c->bls_gen_element_g2,
	                              &c->pairing);

	if (result) {
		fprintf(stderr, "Multisig verification failed\n");
		return -1;
	}

	result = crypto_sign_verify_detached(personal_sig_ptr, dialling_round_ptr,
	                                     round_BYTES + user_id_BYTES + crypto_sign_PUBLICKEYBYTES,
	                                     lt_sig_key_ptr);

	if (result) {
		printf("Personal sig verification failed\n");
		return -1;
	}
	// Both signatures verified, copy the relevant information into a new structure
	// Ultimately to be passed on to the higher level application
	keywheel_unsynced *entry = kw_unsynced_lookup(&c->keywheel, user_id_ptr);
	if (entry) {
		int res = kw_complete_keywheel(&c->keywheel, user_id_ptr, dh_pub_ptr, deserialize_uint64(dialling_round_ptr));
		if (res) {
			fprintf(stderr, "Failure occurred when trying to complete keywheel for %s\n", user_id_ptr);
		}
		else {
			printf("[Client: friend request accepted by %s, keywheel completed]\n", user_id_ptr);
		}

	}
	friend_request_s *new_req = calloc(1, sizeof(friend_request_s));
	memcpy(new_req->user_id, user_id_ptr, user_id_BYTES);
	memcpy(new_req->dh_pk, dh_pub_ptr, crypto_box_PUBLICKEYBYTES);
	memcpy(new_req->lt_sig_key, lt_sig_key_ptr, crypto_sign_PUBLICKEYBYTES);

	new_req->dialling_round = deserialize_uint64(dialling_round_ptr);
	new_req->next = c->friend_requests;
	c->friend_requests = new_req;
	print_friend_request(c->friend_requests);
	return 0;
}

int af_create_pkg_auth_request(client_s *client)
{
	uint8_t *client_sig;
	uint8_t *client_pk;
	uint8_t *pkg_pub_key_ptr;
	uint8_t *symmetric_key_ptr;
	uint8_t *auth_request;

	for (int i = 0; i < num_pkg_servers; i++) {
		auth_request = client->pkg_auth_requests[i];
		serialize_uint32(auth_request, CLI_AUTH_REQ);
		serialize_uint32(auth_request + net_msg_type_BYTES, cli_pkg_single_auth_req_BYTES);
		serialize_uint64(auth_request + 8, client->af_round);
		client_pk = auth_request + net_header_BYTES + user_id_BYTES + crypto_sign_BYTES;
		client_sig = auth_request + net_header_BYTES + user_id_BYTES;

		pkg_pub_key_ptr = client->pkg_broadcast_msgs[i] + g1_elem_compressed_BYTES;
		symmetric_key_ptr = client->pkg_eph_symmetric_keys[i];

		crypto_sign_detached(client_sig,
		                     NULL,
		                     client->pkg_broadcast_msgs[i],
		                     pkg_broadcast_msg_BYTES,
		                     client->lt_sig_sk);

		uint8_t secret_key[crypto_box_SECRETKEYBYTES];
		uint8_t scalar_mult[crypto_scalarmult_BYTES];
		randombytes_buf(secret_key, crypto_box_SECRETKEYBYTES);
		crypto_box_keypair(client_pk, secret_key);

		if (crypto_scalarmult(scalar_mult, secret_key, pkg_pub_key_ptr)) {
			fprintf(stderr, "Scalar mult error while creating PKG auth request\n");
			return -1;
		}

		crypto_shared_secret(symmetric_key_ptr,
		                     scalar_mult,
		                     client_pk,
		                     pkg_pub_key_ptr,
		                     crypto_box_SECRETKEYBYTES);
	}

	pbc_sum_bytes_G1_compressed(&client->pkg_eph_pub_combined_g1,
	                            client->pkg_broadcast_msgs[0],
	                            pkg_broadcast_msg_BYTES,
	                            num_pkg_servers,
	                            &client->pairing);
	return 0;
}

int af_process_auth_responses(client_s *c)
{
	element_set1(&c->pkg_ibe_secret_combined_g2[!c->curr_ibe]);
	element_set1(&c->pkg_multisig_combined_g1);
	element_t g1_tmp, g2_tmp;
	element_init(g1_tmp, c->pairing.G1);
	element_init(g2_tmp, c->pairing.G2);

	uint8_t *auth_response;
	uint8_t *nonce_ptr;

	for (int i = 0; i < num_pkg_servers; i++) {
		auth_response = c->pkg_auth_responses[i];
		nonce_ptr = auth_response + pkg_auth_res_BYTES + crypto_MACBYTES;
		int res = crypto_chacha_decrypt(auth_response, NULL, NULL, auth_response,
		                                pkg_auth_res_BYTES + crypto_MACBYTES,
		                                nonce_ptr, crypto_NBYTES,
		                                nonce_ptr, c->pkg_eph_symmetric_keys[i]);
		if (res) {
			fprintf(stderr, "%s: decryption failed on auth response from pkg %d\n", c->user_id, i);
			return -1;
		}
		element_from_bytes_compressed(g1_tmp, auth_response);
		element_from_bytes_compressed(g2_tmp, auth_response + g1_elem_compressed_BYTES);
		element_add(&c->pkg_multisig_combined_g1, &c->pkg_multisig_combined_g1, g1_tmp);
		element_add(&c->pkg_ibe_secret_combined_g2[!c->curr_ibe], &c->pkg_ibe_secret_combined_g2[!c->curr_ibe], g2_tmp);
	}
	c->authed = true;
	c->curr_ibe = !c->curr_ibe;
	printf("[Client authed for round %lu]\n", c->af_round);
	return 0;
}

int onion_encrypt_message(client_s *client, uint8_t *msg, uint32_t base_msg_length)
{
	for (uint32_t i = 0; i < num_mix_servers; i++) {
		int res = add_onion_encryption_layer(client, msg, base_msg_length, i);
		if (res) {
			fprintf(stderr, "Client: Error while onion encrypting message\n");
			return -1;
		}
	}
	return 0;
}

int af_onion_encrypt_request(client_s *client)
{
	return onion_encrypt_message(client, client->friend_request_buf + net_header_BYTES, af_ibeenc_request_BYTES);
}

int dial_onion_encrypt_request(client_s *client)
{
	return onion_encrypt_message(client, client->dial_request_buf + net_header_BYTES, dialling_token_BYTES);
}

int add_onion_encryption_layer(client_s *client, uint8_t *msg, uint32_t base_msg_len, uint32_t srv_id)
{
	uint32_t msg_len = base_msg_len + mb_BYTES + (onion_layer_BYTES * srv_id);
	uint8_t *message_end = msg + msg_len;
	uint8_t *dh_pk = message_end + crypto_MACBYTES;
	uint8_t *nonce = dh_pk + crypto_box_PUBLICKEYBYTES;
	uint8_t *dh_mix_pk = client->mix_eph_pub_keys[num_mix_servers - 1 - srv_id];

	uint8_t dh_secret[crypto_box_SECRETKEYBYTES];
	uint8_t scalar_mult[crypto_scalarmult_BYTES];
	uint8_t shared_secret[crypto_ghash_BYTES];
	randombytes_buf(dh_secret, crypto_box_SECRETKEYBYTES);
	crypto_scalarmult_base(dh_pk, dh_secret);

	int res = crypto_scalarmult(scalar_mult, dh_secret, dh_mix_pk);
	if (res) {
		fprintf(stderr, "Scalarmult error while oniong encrypting friend request\n");
		return -1;
	}
	crypto_shared_secret(shared_secret, scalar_mult, dh_pk, dh_mix_pk, crypto_ghash_BYTES);
	randombytes_buf(nonce, crypto_NBYTES);
	crypto_aead_chacha20poly1305_ietf_encrypt(msg, NULL, msg,
	                                          msg_len, dh_pk, crypto_box_PUBLICKEYBYTES + crypto_NBYTES,
	                                          NULL, nonce, shared_secret);
	return 0;
};

void client_init(client_s *c, const uint8_t *user_id, const uint8_t *lt_pk_hex, const uint8_t *lt_sk_hex)
{
	c->authed = false;
	c->af_num_mailboxes = 1;
	c->dial_num_mailboxes = 1;
	c->dialling_round = 1;
	c->af_round = 1;
	c->friend_requests = NULL;

	memcpy(c->user_id, user_id, user_id_BYTES);
	for (int i = 0; i < num_pkg_servers; i++) {
		memcpy(c->pkg_auth_requests[i] + net_header_BYTES, user_id, user_id_BYTES);
	}

	pairing_init_set_str(&c->pairing, pbc_params);
	element_init(&c->pkg_multisig_combined_g1, c->pairing.G1);
	element_init(&c->pkg_ibe_secret_combined_g2[0], c->pairing.G2);
	element_init(&c->pkg_ibe_secret_combined_g2[1], c->pairing.G2);
	c->curr_ibe = 0;
	element_init(&c->pkg_eph_pub_combined_g1, c->pairing.G1);
	element_init(&c->pkg_friend_elem, c->pairing.G2);
	element_init(&c->ibe_gen_element_g1, c->pairing.G1);
	element_init(&c->bls_gen_element_g2, c->pairing.G2);
	element_init(&c->pkg_lt_sig_keys_combined, c->pairing.G2);
	element_set_str(&c->ibe_gen_element_g1, ibe_generator, 10);
	element_set_str(&c->bls_gen_element_g2, bls_generator, 10);

	element_s pkg_sig_keys[num_pkg_servers];
	uint8_t pkg_sig_key_bytes[num_pkg_servers][g2_elem_compressed_BYTES];
	for (int i = 0; i < num_pkg_servers; i++) {
		element_init(&pkg_sig_keys[i], c->pairing.G2);
		element_set_str(&pkg_sig_keys[i], pk[i], 10);
		element_to_bytes_compressed(pkg_sig_key_bytes[i], &pkg_sig_keys[i]);
	}

	pbc_sum_bytes_G2_compressed(&c->pkg_lt_sig_keys_combined,
	                            pkg_sig_key_bytes[0], g2_elem_compressed_BYTES,
	                            num_pkg_servers,
	                            &c->pairing);
	c->af_round = 1;
	sodium_hex2bin(c->lg_sig_pk,
	               crypto_sign_PUBLICKEYBYTES,
	               (char *) lt_pk_hex,
	               64,
	               NULL,
	               NULL,
	               NULL);

	sodium_hex2bin(c->lt_sig_sk, crypto_sign_SECRETKEYBYTES, (char *) lt_sk_hex, 128, NULL,
	               NULL,
	               NULL);

	kw_table_init(&c->keywheel, c->dialling_round, NULL);
	c->num_intents = 1;
	c->bloom_p_val = pow(10.0, -10.0);
}

client_s *client_alloc(const uint8_t *user_id, const uint8_t *ltp_key, const uint8_t *lts_key)
{
	client_s *client = calloc(1, sizeof(client_s));
	if (!client) {
		fprintf(stderr, "Malloc failure in client allocation\n");
		return NULL;
	}
	client_init(client, user_id, ltp_key, lts_key);
	return client;
};

void print_friend_request(friend_request_s *req)
{
	printf("Sender id: %s\n", req->user_id);
	printhex("Sender DH key_state", req->dh_pk, crypto_box_PUBLICKEYBYTES);
	printhex("Sender signing key_state: ", req->lt_sig_key, crypto_sign_PUBLICKEYBYTES);
	printf("Dialling round: %ld\n", req->dialling_round);
}
