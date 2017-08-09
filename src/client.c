#include "client.h"
#include "client_config.h"
#include "xxhash.h"
#include <math.h>

uint32_t af_calc_mailbox_num(client_s *c, const uint8_t *user_id)
{
	if (!c || !user_id) return c->af_num_mailboxes + 1;

	uint64_t hash = XXH64(user_id, user_id_BYTES, 0);
	return (uint32_t) hash % c->af_num_mailboxes;
}

uint32_t dial_calc_mailbox_num(client_s *c, const uint8_t *user_id)
{
	uint64_t hash = XXH64(user_id, user_id_BYTES, 0);
	return (uint32_t) hash % c->dial_num_mailboxes;
}

static void delete_friend_request(client_s *c, friend_request_s *req)
{
	if (!req) return;
	if (req == c->friend_requests) c->friend_requests = req->next;
	if (req->next) req->next->prev = req->prev;
	if (req->prev) req->prev->next = req->next;

	free(req);
}

int client_register(sign_keypair *sig_keys, char *user_id)
{
	if (!sig_keys || !user_id)
		return -1;

	int res = crypto_sign_keypair(sig_keys->public_key, sig_keys->secret_key);
	if (res)
		return -1;

	uint8_t register_buf[net_header_BYTES + cli_pkg_reg_request_BYTES];
	memset(register_buf, 0, sizeof register_buf);
	net_serialize_header(register_buf, CLIENT_REG_REQUEST, cli_pkg_reg_request_BYTES, 0, 0);

	memcpy(register_buf + net_header_BYTES, user_id, user_id_BYTES);
	memcpy(register_buf + net_header_BYTES + user_id_BYTES, sig_keys->public_key,
	       crypto_sign_PUBLICKEYBYTES);

	for (uint32_t i = 0; i < num_pkg_servers; i++) {
		int sock_fd = net_connect("127.0.0.1", pkg_cl_listen_ports[i], 0);
		if (sock_fd == -1) {
			fprintf(stderr, "server connection failure\n");
			return -1;
		}

		res = net_send_blocking(sock_fd, register_buf, sizeof register_buf);
		if (res) {
			fprintf(stderr, "socket send error\n");
			close(sock_fd);
			return -1;
		}

		uint8_t buf[net_header_BYTES + net_header_BYTES + pkg_broadcast_msg_BYTES];
		res = net_read_blocking(sock_fd, buf, sizeof buf);
		if (res) {
			fprintf(stderr, "Read fail: read %d\n", res);
			close(sock_fd);
			exit(EXIT_FAILURE);
		}
		close(sock_fd);
	}

	printf("Registration request made for email %s\n", user_id);

	return 0;
}

int client_confirm_registration(uint8_t *user_id, uint8_t *sig_key,
                                uint8_t *msgs_buf)
{

	uint32_t net_msg_size_bytes = net_header_BYTES + cli_pkg_reg_confirm_BYTES;
	uint8_t reg_confirm_msg[net_msg_size_bytes];
	memset(reg_confirm_msg, 0, net_msg_size_bytes);
	net_serialize_header(reg_confirm_msg, CLIENT_REG_CONFIRM, cli_pkg_reg_confirm_BYTES, 0, 0);

	uint8_t user_id_verified[user_id_BYTES];
	memset(user_id_verified, 0, user_id_BYTES);

	size_t uid_len = strlen((char *) user_id);
	if (uid_len > user_id_BYTES) {
		fprintf(stderr, "username too long\n");
		return -1;
	}

	memcpy(user_id_verified, user_id, uid_len);
	memcpy(reg_confirm_msg + net_header_BYTES, user_id_verified, user_id_BYTES);

	const uint64_t msg_length_hex = crypto_ghash_BYTES * 2;
	uint64_t sig_offset = net_header_BYTES + user_id_BYTES;

	for (uint32_t i = 0; i < num_pkg_servers; i++) {
		crypto_sign(reg_confirm_msg + sig_offset, NULL,
		            msgs_buf + (i * msg_length_hex), crypto_ghash_BYTES * 2,
		            sig_key);

		int socket_fd = net_connect("127.0.0.1", "7500", 0);
		if (socket_fd == -1) {
			fprintf(stderr, "pkg server connection failure\n");
			return -1;
		}

		int res = net_send_blocking(socket_fd, reg_confirm_msg, net_msg_size_bytes);
		if (res) {
			fprintf(stderr, "socket send failure\n");
			close(socket_fd);
			return -1;
		}

		uint8_t response_buf[net_header_BYTES + pkg_broadcast_msg_BYTES +
			net_header_BYTES];
		res = net_read_blocking(socket_fd, response_buf, sizeof response_buf);

		if (res) {
			fprintf(stderr, "socket read failure\n");
			close(socket_fd);
			return -1;
		}
		close(socket_fd);
	}

	return 0;
}

uint8_t *client_get_public_key(client_s *c)
{
	return c->lt_sig_keypair.public_key;
}

int client_call_friend(client_s *c, uint8_t *user_id, uint32_t intent)
{
	if (!c || !user_id)
		return -1;

	action *act = calloc(1, sizeof(action));
	if (!act)
		return -1;

	memcpy(act->user_id, user_id, user_id_BYTES);
	act->type = DIAL_FRIEND;
	act->intent = intent;
	action_stack_push(c, act);
	return 0;
}

int client_add_friend(client_s *c, uint8_t *user_id)
{
	if (!c || !user_id)
		return -1;

	action *act = calloc(1, sizeof(action));
	if (!act)
		return -1;

	memcpy(act->user_id, user_id, user_id_BYTES);
	act->type = ADD_FRIEND;
	action_stack_push(c, act);
	return 0;
}

int client_confirm_friend(client_s *c, uint8_t *user_id)
{
	if (!c || !user_id)
		return -1;

	action *act = calloc(1, sizeof(action));
	if (!act)
		return -1;

	memcpy(act->user_id, user_id, user_id_BYTES);
	act->type = CONFIRM_FRIEND;
	action_stack_push(c, act);
	return 0;
}

int dial_queue_call(client_s *c, const uint8_t *user_id,
                    const uint32_t intent)
{
	if (!c || !user_id || intent > c->num_intents)
		return -1;

	pending_call *new_call = calloc(1, sizeof(*new_call));
	if (!new_call) {
		fprintf(stderr, "fatal calloc error\n");
		return -1;
	}

	memcpy(new_call->user_id, user_id, user_id_BYTES);
	new_call->intent = intent;
	new_call->next = c->outgoing_call_queue;
	c->outgoing_call_queue = new_call;

	return 0;

}

int dial_build_call(client_s *c)
{
	if (!c)
		return -1;

	pending_call *call = c->outgoing_call_queue;

	if (!call) {
		dial_fake_request(c);
		dial_onion_encrypt_request(c);
		return 0;
	}

	int result = dial_call_friend(c, call->user_id, call->intent);
	if (result) {
		return -1;
	}

	result = dial_onion_encrypt_request(c);
	if (result) {
		return -1;
	}

	c->outgoing_call_queue = call->next;
	free(call);

	return 0;
}

int dial_call_friend(client_s *c, const uint8_t *user_id,
                     const uint32_t intent)
{
	if (!c || !user_id || intent > c->num_intents)
		return -1;

	uint32_t mailbox = dial_calc_mailbox_num(c, user_id);
	net_serialize_header(c->dial_request_buf,
	                     CLIENT_DIAL_MSG,
	                     onionenc_dial_token_BYTES,
	                     c->af_round,
	                     c->dialling_round);
	serialize_uint32(c->dial_request_buf + net_header_BYTES, mailbox);

	int result = kw_dialling_token(c->dial_request_buf + net_header_BYTES + mb_BYTES,
	                               &c->keywheel, user_id, intent);

	if (result) {
		fprintf(stderr, "could not create dialling token for %s\n", user_id);
		return -1;
	}

	result = kw_session_key(c->session_key_buf, &c->keywheel, user_id);
	if (result) {
		fprintf(stderr, "could not generate session key for %s\n", user_id);
		return -1;
	}

	char session_key_hex[dialling_token_BYTES * 2 + 1];
	sodium_bin2hex(session_key_hex, sizeof session_key_hex, c->session_key_buf,
	               dialling_token_BYTES);
	printf("Calling friend %s | Session Key: %s\n", user_id, session_key_hex);
	//printhex("dialling token", c->dial_request_buf + net_header_BYTES + mb_BYTES,
	//         crypto_ghash_BYTES);
	return 0;
}

int af_add_friend(client_s *c, const char *user_id)
{
	if (!c || !user_id)
		return -1;

	pending_friend_req *new_req = calloc(1, sizeof(*new_req));
	if (!new_req) {
		fprintf(stderr, "fatal calloc error\n");
		return -1;
	}

	memcpy(new_req->user_id, user_id, user_id_BYTES);
	new_req->next = c->friend_request_queue;
	new_req->req = NULL;
	c->friend_request_queue = new_req;

	return 0;
}

int af_confirm_friend(client_s *c, const char *user_id)
{
	if (!c || !user_id) {
		fprintf(stderr, "no user id supplied to accept request\n");
		return -1;
	}

	friend_request_s *req = c->friend_requests;

	while (req) {
		if (!(strncmp((char *) user_id, (char *) req->user_id, user_id_BYTES))) {
			break;
		}
		req = req->next;
	}

	if (!req) {
		fprintf(stderr, "could not find pending friend request matching id\n");
		return -1;
	}

	pending_friend_req *new_req = calloc(1, sizeof(*new_req));
	if (!new_req) {
		fprintf(stderr, "fatal calloc error\n");
		return -1;
	}

	memcpy(new_req->user_id, user_id, user_id_BYTES);
	new_req->next = c->friend_request_queue;
	new_req->req = req;
	c->friend_request_queue = new_req;

	return 0;
}

int af_process_mb(client_s *c, uint8_t *mailbox, uint64_t num_messages,
                  uint64_t round)
{
	if (!c || !mailbox)
		return -1;

	printf("Processing AF mailbox for round %lu, %ld messages\n", round,
	       num_messages);
	uint8_t *msg_ptr = mailbox;
	for (int i = 0; i < num_messages; i++) {
		af_decrypt_request(c, msg_ptr, round);
		msg_ptr += af_ibeenc_request_BYTES;
	}
	return 0;
}

int af_fake_request(client_s *c)
{
	if (!c)
		return -1;

	memset(c->friend_request_buf, 0, sizeof c->friend_request_buf);
	net_serialize_header(c->friend_request_buf,
	                     CLIENT_AF_MSG,
	                     onionenc_friend_request_BYTES,
	                     c->af_round,
	                     c->dialling_round);

	serialize_uint32(c->friend_request_buf + net_header_BYTES, c->af_num_mailboxes + 1);
	return 0;
}

int dial_fake_request(client_s *c)
{
	if (!c)
		return -1;

	memset(c->dial_request_buf, 0, sizeof c->dial_request_buf);
	net_serialize_header(c->dial_request_buf,
	                     CLIENT_DIAL_MSG,
	                     onionenc_dial_token_BYTES,
	                     c->af_round,
	                     c->dialling_round);

	// Set mailbox number to invalid valuse to mark the message as cover traffic
	serialize_uint32(c->dial_request_buf + net_header_BYTES,
	                 c->dial_num_mailboxes + 1);

	return 0;
}

int dial_process_mb(client_s *c, uint8_t *mb_data, uint64_t round,
                    uint64_t num_tokens)
{
	if (!c || !mb_data)
		return -1;

	while (c->keywheel.table_round < round) {
		kw_advance_table(&c->keywheel);
	}
	printf("Processing Dial mb for round %ld, %ld tokens\n", round, num_tokens);
	bloomfilter_s bloom;
	int found = 0;
	uint8_t dial_token_buf[dialling_token_BYTES];

	if (bloom_init(&bloom, c->bloom_p_val, num_tokens, 0, mb_data, 0)) {
		fprintf(stderr, "failed to initialise bloom filter\n");
		return -1;
	};

	keywheel_s *curr_kw = c->keywheel.keywheels;
	while (curr_kw) {
		for (uint32_t j = 0; j < c->num_intents; j++) {
			kw_dialling_token(dial_token_buf, &c->keywheel, curr_kw->user_id, j);
			found = bloom_lookup(&bloom, dial_token_buf, dialling_token_BYTES);

			if (found) {
				incoming_call_s new_call;
				new_call.round = round;
				new_call.intent = j;
				memcpy(new_call.user_id, curr_kw->user_id, user_id_BYTES);
				kw_session_key(new_call.session_key, &c->keywheel, curr_kw->user_id);
				if (c->on_recv_call) {
					c->on_recv_call(&new_call);
				}
				printf("Incoming call from: %s (%u)\n", new_call.user_id, new_call.intent);
				printhex("Session key", new_call.session_key, crypto_ghash_BYTES);

			}
		}
		curr_kw = curr_kw->next;
	}
	return 0;
}

#if USE_PBC
int af_create_pkg_auth_request(client_s *client) {
  uint8_t *client_sig;
  uint8_t *client_pk;
  uint8_t *pkg_pub_key_ptr;
  uint8_t *symmetric_key_ptr;
  uint8_t *auth_request;

  for (int i = 0; i < num_pkg_servers; i++) {
	auth_request = client->pkg_auth_requests[i];
	serialize_uint32(auth_request, CLIENT_AUTH_REQ);
	serialize_uint32(auth_request + net_msg_type_BYTES,
					 cli_pkg_single_auth_req_BYTES);
	serialize_uint64(auth_request + 8, client->af_round);
	client_pk =
		auth_request + net_header_BYTES + user_id_BYTES + crypto_sign_BYTES;
	client_sig = auth_request + net_header_BYTES + user_id_BYTES;

	pkg_pub_key_ptr = client->pkg_broadcast_msgs[i] + g1_serialized_bytes;
	symmetric_key_ptr = client->pkg_eph_symmetric_keys[i];

	crypto_sign_detached(client_sig, NULL, client->pkg_broadcast_msgs[i],
						 pkg_broadcast_msg_BYTES,
						 client->lt_sig_keypair.secret_key);

	uint8_t secret_key[crypto_box_SECRETKEYBYTES];
	uint8_t scalar_mult[crypto_scalarmult_BYTES];
	randombytes_buf(secret_key, crypto_box_SECRETKEYBYTES);
	crypto_box_keypair(client_pk, secret_key);

	if (crypto_scalarmult(scalar_mult, secret_key, pkg_pub_key_ptr)) {
	  fprintf(stderr, "Scalar mult error while creating PKG auth request\n");
	  return -1;
	}

	crypto_shared_secret(symmetric_key_ptr, scalar_mult, client_pk,
						 pkg_pub_key_ptr, crypto_box_SECRETKEYBYTES);
  }

  pbc_sum_bytes_G1_compressed(
	  &client->pkg_eph_pub_combined_g1, client->pkg_broadcast_msgs[0],
	  pkg_broadcast_msg_BYTES, num_pkg_servers, &client->pairing);
  return 0;
}
int af_process_auth_responses(client_s *c) {
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
									nonce_ptr, crypto_NBYTES, nonce_ptr,
									c->pkg_eph_symmetric_keys[i]);
	if (res) {
	  fprintf(stderr, "%s: decryption failed on auth response from pkg %d\n",
			  c->user_id, i);
	  return -1;
	}
	element_from_bytes_compressed(g1_tmp, auth_response);
	element_from_bytes_compressed(g2_tmp, auth_response + g1_serialized_bytes);
	element_add(&c->pkg_multisig_combined_g1, &c->pkg_multisig_combined_g1,
				g1_tmp);
	element_add(&c->pkg_ibe_secret_combined_g2[!c->curr_ibe],
				&c->pkg_ibe_secret_combined_g2[!c->curr_ibe], g2_tmp);
  }
  c->authed = true;
  c->curr_ibe = !c->curr_ibe;
  printf("[Client authed for round %lu]\n", c->af_round);
  return 0;
}

int af_accept_request(client_s *c, friend_request_s *req) {

  if (!c || !req) {
	fprintf(stderr, "could not find pending friend request matching id\n");
	return -1;
  }

  printf("Responding to friend request from %s\n", req->user_id);
  serialize_uint32(c->friend_request_buf, CLIENT_AF_MSG);
  serialize_uint32(c->friend_request_buf + 4, onionenc_friend_request_BYTES);
  serialize_uint64(c->friend_request_buf + 8, c->af_round);

  uint8_t *dr_ptr = c->friend_request_buf + net_header_BYTES + mb_BYTES +
					g1_serialized_bytes + crypto_ghash_BYTES + crypto_NBYTES;
  uint8_t *user_id_ptr = dr_ptr + round_BYTES;
  uint8_t *dh_pk_ptr = user_id_ptr + user_id_BYTES;
  uint8_t *lt_sig_key_ptr = dh_pk_ptr + crypto_pk_BYTES;
  uint8_t *client_sig_ptr = lt_sig_key_ptr + crypto_sign_PUBLICKEYBYTES;
  uint8_t *multisig_ptr = client_sig_ptr + crypto_sign_BYTES;

  keywheel_s *new_kw =
	  kw_from_request(&c->keywheel, req->user_id, dh_pk_ptr, req->dh_pk);
  if (!new_kw) {
	fprintf(stderr, "Client: Couldn't construct keywheel for new contact\n");
	return -1;
  }

  delete_friend_request(c, req);

  memcpy(user_id_ptr, c->user_id, user_id_BYTES);
  memcpy(lt_sig_key_ptr, c->lt_sig_keypair.public_key,
		 crypto_sign_PUBLICKEYBYTES);
  serialize_uint64(dr_ptr, new_kw->dialling_round);

  crypto_sign_detached(client_sig_ptr, NULL, dr_ptr,
					   round_BYTES + user_id_BYTES + crypto_pk_BYTES,
					   c->lt_sig_keypair.secret_key);
  element_to_bytes_compressed(multisig_ptr, &c->pkg_multisig_combined_g1);
  // Encrypt the request using IBE
  ibe_pbc_encrypt(c->friend_request_buf + net_header_BYTES + mb_BYTES, dr_ptr,
				  af_request_BYTES, &c->pkg_eph_pub_combined_g1,
				  &c->ibe_gen_element_g1, new_kw->user_id, user_id_BYTES,
				  &c->pairing);
  // Only information identifying the destination of a request, the mailbox no.
  // of the recipient
  uint32_t mb = af_calc_mailbox_num(c, c->friend_request_id);
  serialize_uint32(c->friend_request_buf + net_header_BYTES, mb);
  // Encrypt the request in layers ready for the mixnet
  af_onion_encrypt_request(c);
  return 0;
}

int af_create_request(client_s *c) {
  serialize_uint32(c->friend_request_buf, CLIENT_AF_MSG);
  serialize_uint32(c->friend_request_buf + net_msg_type_BYTES,
				   onionenc_friend_request_BYTES);
  serialize_uint64(c->friend_request_buf + 8, c->af_round);

  uint8_t *dr_ptr = c->friend_request_buf + net_header_BYTES + mb_BYTES +
					g1_serialized_bytes + crypto_NBYTES;
  uint8_t *user_id_ptr = dr_ptr + round_BYTES;
  uint8_t *dh_pub_ptr = user_id_ptr + user_id_BYTES;
  uint8_t *lt_sig_key_ptr = dh_pub_ptr + crypto_pk_BYTES;
  uint8_t *client_sig_ptr = lt_sig_key_ptr + crypto_sign_PUBLICKEYBYTES;
  uint8_t *multisig_ptr = client_sig_ptr + crypto_sign_BYTES;
  // Generate a DH keypair that forms the basis of the shared keywheel state
  // with the friend being added
  uint8_t dh_secret_key[crypto_box_SECRETKEYBYTES];
  crypto_box_keypair(dh_pub_ptr, dh_secret_key);
  // Both parties need to agree on the dialling round to synchronise their
  // keywheel
  uint64_t dialling_round = c->dialling_round + 2;

  // Serialise userid/dial round/signature key
  memcpy(user_id_ptr, c->user_id, user_id_BYTES);
  serialize_uint64(dr_ptr, dialling_round);
  memcpy(lt_sig_key_ptr, c->lt_sig_keypair.public_key,
		 crypto_sign_PUBLICKEYBYTES);
  kw_new_keywheel(&c->keywheel, c->friend_request_id, dh_pub_ptr, dh_secret_key,
				  c->dialling_round);
  // Sign our information with our LT signing key
  crypto_sign_detached(client_sig_ptr, NULL, dr_ptr,
					   round_BYTES + user_id_BYTES + crypto_pk_BYTES,
					   c->lt_sig_keypair.secret_key);
  // Also include the multisignature from PKG servers, primary source of
  // verification
  element_to_bytes_compressed(multisig_ptr, &c->pkg_multisig_combined_g1);
  // Encrypt the request using IBE
  ssize_t res = ibe_pbc_encrypt(
	  c->friend_request_buf + net_header_BYTES + mb_BYTES, dr_ptr,
	  af_request_BYTES, &c->pkg_eph_pub_combined_g1, &c->ibe_gen_element_g1,
	  c->friend_request_id, user_id_BYTES, &c->pairing);
  if (res < 0) {
	fprintf(stderr, "IBE encryption failure\n");
	return -1;
  }
  // Only information identifying the destination of a request, the mailbox no.
  // of the recipient
  uint32_t mb = af_calc_mailbox_num(c, c->friend_request_id);
  serialize_uint32(c->friend_request_buf + net_header_BYTES, mb);
  // Encrypt the request in layers ready for the mixnet
  return af_onion_encrypt_request(c);
}

int af_decrypt_request(client_s *c, uint8_t *request_buf, uint64_t round) {
  uint8_t request_buffer[af_request_BYTES];
  ssize_t result = ibe_pbc_decrypt(
	  request_buffer, request_buf, af_ibeenc_request_BYTES,
	  &c->pkg_ibe_secret_combined_g2[!c->curr_ibe], c->hashed_id, &c->pairing);

  if (result) {
	// fprintf(stderr, "%s: ibe decryption failure\n", c->user_id);
	return -1;
  }

  uint8_t *dialling_round_ptr = request_buffer;
  uint8_t *user_id_ptr = dialling_round_ptr + round_BYTES;
  uint8_t *dh_pub_ptr = user_id_ptr + user_id_BYTES;
  uint8_t *lt_sig_key_ptr = dh_pub_ptr + crypto_pk_BYTES;
  uint8_t *personal_sig_ptr = lt_sig_key_ptr + crypto_sign_PUBLICKEYBYTES;
  uint8_t *multisig_ptr = personal_sig_ptr + crypto_sign_BYTES;

  // Reconstruct the message signed by the PKG's so we can verify the signature
  uint8_t multisig_message[pkg_sig_message_BYTES];
  serialize_uint64(multisig_message, round);
  memcpy(multisig_message + round_BYTES, user_id_ptr, user_id_BYTES);
  memcpy(multisig_message + round_BYTES + user_id_BYTES, lt_sig_key_ptr,
		 crypto_sign_PUBLICKEYBYTES);

  element_t sig_verify_elem, hash_elem;
  element_init(sig_verify_elem, c->pairing.G1);
  element_init(hash_elem, c->pairing.G1);
  result = bls_verify_signature(sig_verify_elem, hash_elem, multisig_ptr,
								multisig_message, pkg_sig_message_BYTES,
								&c->pkg_lt_sig_keys_combined,
								&c->bls_gen_element_g2, &c->pairing);

  if (result) {
	fprintf(stderr, "Multisig verification failed\n");
	return -1;
  }

  result = crypto_sign_verify_detached(
	  personal_sig_ptr, dialling_round_ptr,
	  round_BYTES + user_id_BYTES + crypto_sign_PUBLICKEYBYTES, lt_sig_key_ptr);

  if (result) {
	printf("Personal sig verification failed\n");
	return -1;
  }
  // Both signatures verified, copy the relevant information into a new
  // structure
  // Ultimately to be passed on to the higher level application
  keywheel_unsynced *entry = kw_unsynced_lookup(&c->keywheel, user_id_ptr);
  if (entry) {
	int res = kw_complete_keywheel(&c->keywheel, user_id_ptr, dh_pub_ptr,
								   deserialize_uint64(dialling_round_ptr));
	if (res) {
	  fprintf(stderr,
			  "Failure occurred when trying to complete keywheel for %s\n",
			  user_id_ptr);
	  return -1;
	} else {
	  printf("[Client: friend request accepted by %s, keywheel completed]\n",
			 user_id_ptr);
	  return 0;
	}
  }
  friend_request_s *new_req = calloc(1, sizeof(friend_request_s));
  memcpy(new_req->user_id, user_id_ptr, user_id_BYTES);
  memcpy(new_req->dh_pk, dh_pub_ptr, crypto_pk_BYTES);
  memcpy(new_req->lt_sig_key, lt_sig_key_ptr, crypto_sign_PUBLICKEYBYTES);

  new_req->dialling_round = deserialize_uint64(dialling_round_ptr);
  new_req->next = c->friend_requests;
  c->friend_requests = new_req;
  printf("[Client: friend request received]\n");
  print_friend_request(c->friend_requests);
  return 0;
}
#else

int af_build_request(client_s *c)
{
	if (!c)
		return -1;

	pending_friend_req *request = c->friend_request_queue;

	if (!request) {
		af_fake_request(c);
		af_onion_encrypt_request(c);
		return 0;
	}

	if (request->req) {
		af_accept_request(c, request->req);
	}
	else {
		af_create_request(c, request->user_id);
	}

	c->friend_request_queue = request->next;
	free(request);
	af_onion_encrypt_request(c);

	return 0;
}

int af_accept_request(client_s *c, friend_request_s *req)
{
	printf("Responding to friend request from %s\n", req->user_id);
	net_serialize_header(c->friend_request_buf,
	                     CLIENT_AF_MSG,
	                     onionenc_friend_request_BYTES,
	                     c->af_round,
	                     c->dialling_round);

	uint8_t *dr_ptr = c->friend_request_buf + net_header_BYTES + mb_BYTES +
		g1_serialized_bytes + crypto_ghash_BYTES + crypto_NBYTES;
	uint8_t *user_id_ptr = dr_ptr + round_BYTES;
	uint8_t *dh_pk_ptr = user_id_ptr + user_id_BYTES;
	uint8_t *lt_sig_key_ptr = dh_pk_ptr + crypto_pk_BYTES;
	uint8_t *client_sig_ptr = lt_sig_key_ptr + crypto_sign_PUBLICKEYBYTES;
	uint8_t *multisig_ptr = client_sig_ptr + crypto_sign_BYTES;

	keywheel_s *new_kw =
		kw_from_request(&c->keywheel, req->user_id, dh_pk_ptr, req->dh_pk);
	if (!new_kw) {
		fprintf(stderr, "Client: Couldn't construct keywheel for new contact\n");
		return -1;
	}

	memcpy(user_id_ptr, c->user_id, user_id_BYTES);
	memcpy(lt_sig_key_ptr, c->lt_sig_keypair.public_key,
	       crypto_sign_PUBLICKEYBYTES);
	serialize_uint64(dr_ptr, new_kw->dialling_round);

	crypto_sign_detached(client_sig_ptr, NULL, dr_ptr,
	                     round_BYTES + user_id_BYTES + crypto_pk_BYTES,
	                     c->lt_sig_keypair.secret_key);
	bn256_serialize_g1(multisig_ptr, c->pkg_multisig_combined_g1);
	// Encrypt the request using IBE
	ssize_t rs =
		bn256_ibe_encrypt(c->friend_request_buf + net_header_BYTES + mb_BYTES,
		                  dr_ptr, af_request_BYTES, c->pkg_eph_pub_combined_g1,
		                  new_kw->user_id, user_id_BYTES);

	if (rs < 0) {
		fprintf(stderr, "ibe encryption failure\n");
		return -1;
	}
	// Only information identifying the destination of a request, the mailbox no.
	// of the recipient
	uint32_t mb = af_calc_mailbox_num(c, req->user_id);
	serialize_uint32(c->friend_request_buf + net_header_BYTES, mb);

	delete_friend_request(c, req);
	// Encrypt the request in layers ready for the mixnet
	return 0;
}

int af_create_request(client_s *c, uint8_t *friend_user_id)
{
	if (!c)
		return -1;

	printf("Adding friend: %s\n", friend_user_id);
	net_serialize_header(c->friend_request_buf,
	                     CLIENT_AF_MSG,
	                     onionenc_friend_request_BYTES,
	                     c->af_round,
	                     c->dialling_round);

	uint8_t *dr_ptr = c->friend_request_buf + net_header_BYTES + mb_BYTES +
		g1_serialized_bytes + crypto_NBYTES;
	uint8_t *user_id_ptr = dr_ptr + round_BYTES;
	uint8_t *dh_pub_ptr = user_id_ptr + user_id_BYTES;
	uint8_t *lt_sig_key_ptr = dh_pub_ptr + crypto_pk_BYTES;
	uint8_t *client_sig_ptr = lt_sig_key_ptr + crypto_sign_PUBLICKEYBYTES;
	uint8_t *multisig_ptr = client_sig_ptr + crypto_sign_BYTES;
	// Generate a DH keypair that forms the basis of the shared keywheel state
	// with the friend being added
	uint8_t dh_secret_key[crypto_box_SECRETKEYBYTES];
	crypto_box_keypair(dh_pub_ptr, dh_secret_key);
	uint64_t dialling_round = 0;

	memcpy(user_id_ptr, c->user_id, user_id_BYTES);
	serialize_uint64(dr_ptr, dialling_round);
	memcpy(lt_sig_key_ptr, c->lt_sig_keypair.public_key, crypto_sign_PUBLICKEYBYTES);
	kw_new_keywheel(&c->keywheel, friend_user_id, dh_pub_ptr, dh_secret_key,
	                c->dialling_round);
	// Sign our information with our LT signing key
	crypto_sign_detached(client_sig_ptr, NULL, dr_ptr,
	                     round_BYTES + user_id_BYTES + crypto_pk_BYTES,
	                     c->lt_sig_keypair.secret_key);
	// Also include the multisignature from PKG servers, primary source of
	// verification
	bn256_serialize_g1(multisig_ptr, c->pkg_multisig_combined_g1);
	// Encrypt the request using IBE
	ssize_t res = bn256_ibe_encrypt(c->friend_request_buf + net_header_BYTES + mb_BYTES,
	                                dr_ptr, af_request_BYTES, c->pkg_eph_pub_combined_g1,
	                                friend_user_id, user_id_BYTES);

	uint8_t serialized_g1[g1_serialized_bytes];
	bn256_serialize_g1(serialized_g1, c->pkg_eph_pub_combined_g1);
	////printhex("ibe public key", serialized_g1, g1_serialized_bytes);

	if (res < 0) {
		fprintf(stderr, "failure during ibe encryption\n");
		return -1;
	}

	// Only information identifying the destination of a request, the mailbox
	// number of the recipient
	uint32_t mb = af_calc_mailbox_num(c, friend_user_id);
	serialize_uint32(c->friend_request_buf + net_header_BYTES, mb);

	return 0;
}

int af_decrypt_request(client_s *c, uint8_t *request_buf, uint64_t round)
{
	if (!c || !request_buf)
		return -1;

	uint8_t serialized_g2[g2_serialized_bytes];
	bn256_serialize_g2(serialized_g2, c->pkg_ibe_secret_combined_g2);
	uint8_t request_buffer[af_request_BYTES];
	ssize_t result = bn256_ibe_decrypt(
		request_buffer, request_buf, af_ibeenc_request_BYTES, c->hashed_id,
		c->pkg_ibe_secret_combined_g2);

	if (result) {
		return -1;
	}

	uint8_t *dialling_round_ptr = request_buffer;
	uint8_t *user_id_ptr = dialling_round_ptr + round_BYTES;
	uint8_t *dh_pub_ptr = user_id_ptr + user_id_BYTES;
	uint8_t *lt_sig_key_ptr = dh_pub_ptr + crypto_pk_BYTES;
	uint8_t *personal_sig_ptr = lt_sig_key_ptr + crypto_sign_PUBLICKEYBYTES;
	uint8_t *multisig_ptr = personal_sig_ptr + crypto_sign_BYTES;

	// Reconstruct the message signed by the PKG's so we can verify the signature
	uint8_t multisig_message[pkg_sig_message_BYTES];
	serialize_uint64(multisig_message, round);
	memcpy(multisig_message + round_BYTES, user_id_ptr, user_id_BYTES);
	memcpy(multisig_message + round_BYTES + user_id_BYTES, lt_sig_key_ptr,
	       crypto_sign_PUBLICKEYBYTES);

	result = bn256_bls_verify_message(c->pkg_lt_sig_keys_combined, multisig_ptr,
	                                  multisig_message, pkg_sig_message_BYTES);

	if (result) {
		fprintf(stderr, "Multisig verification failed\n");
		return -1;
	}

	result = crypto_sign_verify_detached(
		personal_sig_ptr, dialling_round_ptr,
		round_BYTES + user_id_BYTES + crypto_sign_PUBLICKEYBYTES, lt_sig_key_ptr);

	if (result) {
		printf("Personal sig verification failed\n");
		return -1;
	}

	keywheel_unsynced *entry = kw_unsynced_lookup(&c->keywheel, user_id_ptr);
	if (entry) {
		uint64_t dial_round = deserialize_uint64(dialling_round_ptr);
		int res = kw_complete_keywheel(&c->keywheel, user_id_ptr, dh_pub_ptr, dial_round);
		if (res) {
			fprintf(stderr, "Failure occurred when trying to complete keywheel for %s\n", user_id_ptr);
			return -1;
		}

		printf("[Client: friend request accepted by %s, keywheel completed]\n",
		       user_id_ptr);
		if (c->on_friend_confirm) {
			friend_request_s confirmed_friend;
			memset(&confirmed_friend, 0, sizeof confirmed_friend);
			memcpy(confirmed_friend.user_id, entry->user_id, user_id_BYTES);
			memcpy(confirmed_friend.lt_sig_key, lt_sig_key_ptr, crypto_sign_PUBLICKEYBYTES);
			memcpy(confirmed_friend.dh_pk, dh_pub_ptr, crypto_box_PUBLICKEYBYTES);
			confirmed_friend.dialling_round = dial_round;
			c->on_friend_confirm(&confirmed_friend);
		}

		return 0;

	}

	friend_request_s *new_req = calloc(1, sizeof(friend_request_s));
	if (!new_req) {
		fprintf(stderr, "fatal malloc error\n");
		return -1;
	}
	memcpy(new_req->user_id, user_id_ptr, user_id_BYTES);
	memcpy(new_req->dh_pk, dh_pub_ptr, crypto_pk_BYTES);
	memcpy(new_req->lt_sig_key, lt_sig_key_ptr, crypto_sign_PUBLICKEYBYTES);
	new_req->dialling_round = deserialize_uint64(dialling_round_ptr);
	new_req->next = c->friend_requests;
	c->friend_requests = new_req;

	printf("[Client: friend request received]\n");
	if (c->on_friend_request) {
		c->on_friend_request(new_req);
	}
	return 0;
}

int af_update_pkg_public_keys(client_s *c)
{
	if (!c)
		return -1;

	curvepoint_fp_t g1_temp;
	curvepoint_fp_setneutral(c->pkg_eph_pub_combined_g1);

	for (int i = 0; i < num_pkg_servers; i++) {
		bn256_deserialize_g1(g1_temp, c->pkg_broadcast_msgs[i]);
		curvepoint_fp_add_vartime(c->pkg_eph_pub_combined_g1, c->pkg_eph_pub_combined_g1, g1_temp);
	}

	return 0;
}

int af_create_pkg_auth_request(client_s *c)
{
	if (!c)
		return -1;

	uint8_t *client_sig;
	uint8_t *client_pk;
	uint8_t *pkg_pub_key_ptr;
	uint8_t *symmetric_key_ptr;
	uint8_t *auth_request;

	for (int i = 0; i < num_pkg_servers; i++) {
		auth_request = c->pkg_auth_requests[i];


		net_serialize_header(auth_request,
		                     CLIENT_AUTH_REQ,
		                     cli_pkg_single_auth_req_BYTES,
		                     c->af_round,
		                     c->dialling_round);

		serialize_uint64(auth_request + net_header_BYTES, c->af_round);
		client_pk = auth_request + net_header_BYTES + round_BYTES + user_id_BYTES;
		client_sig = auth_request + net_header_BYTES + round_BYTES + user_id_BYTES +
			crypto_pk_BYTES;
		pkg_pub_key_ptr = c->pkg_broadcast_msgs[i] + g1_serialized_bytes;
		symmetric_key_ptr = c->pkg_eph_symmetric_keys[i];

		uint8_t secret_key[crypto_box_SECRETKEYBYTES];
		uint8_t scalar_mult[crypto_scalarmult_BYTES];
		crypto_box_keypair(client_pk, secret_key);

		crypto_sign_detached(client_sig, NULL, auth_request + net_header_BYTES,
		                     cli_pkg_single_auth_req_BYTES - crypto_sign_BYTES,
		                     c->lt_sig_keypair.secret_key);

		if (crypto_scalarmult(scalar_mult, secret_key, pkg_pub_key_ptr)) {
			fprintf(stderr, "Scalar mult error while creating PKG auth request\n");
			return -1;
		}

		crypto_shared_secret(symmetric_key_ptr, scalar_mult, client_pk,
		                     pkg_pub_key_ptr, crypto_box_SECRETKEYBYTES);
	}

	return 0;
}

int af_process_auth_responses(client_s *c)
{
	if (!c)
		return -1;

	curvepoint_fp_t g1_tmp;
	twistpoint_fp2_t g2_tmp;
	curvepoint_fp_setneutral(c->pkg_multisig_combined_g1);
	twistpoint_fp2_setneutral(c->pkg_ibe_secret_combined_g2);

	for (int i = 0; i < num_pkg_servers; i++) {
		uint8_t *auth_response = c->pkg_auth_responses[i];
		uint8_t *nonce_ptr = auth_response + pkg_auth_res_BYTES + crypto_MACBYTES;
		int res = crypto_chacha_decrypt(auth_response, NULL, NULL, auth_response,
		                                pkg_auth_res_BYTES + crypto_MACBYTES,
		                                nonce_ptr, crypto_NBYTES, nonce_ptr,
		                                c->pkg_eph_symmetric_keys[i]);
		if (res) {
			fprintf(stderr, "%s: decryption failed on auth response from pkg %d\n",
			        c->user_id, i);
			return -1;
		}
		bn256_deserialize_g1(g1_tmp, auth_response);
		bn256_deserialize_g2(g2_tmp, auth_response + g1_serialized_bytes);
		curvepoint_fp_add_vartime(c->pkg_multisig_combined_g1,
		                          c->pkg_multisig_combined_g1, g1_tmp);
		twistpoint_fp2_add_vartime(c->pkg_ibe_secret_combined_g2,
		                           c->pkg_ibe_secret_combined_g2,
		                           g2_tmp);
	}

	printf("[Client authed for round %lu]\n", c->af_round);
	return 0;
}
#endif

int onion_encrypt_message(client_s *c, uint8_t *msg, uint32_t base_msg_length,
                          bool is_dial)
{
	if (!c || !msg)
		return -1;

	for (uint32_t i = 0; i < num_mix_servers; i++) {
		int res = add_onion_encryption_layer(c, msg, base_msg_length, i, is_dial);
		if (res) {
			fprintf(stderr, "Client: Error while onion encrypting message\n");
			return -1;
		}
	}
	return 0;
}

int af_onion_encrypt_request(client_s *client)
{
	if (!client) {
		return -1;
	}
	return onion_encrypt_message(client,
	                             client->friend_request_buf + net_header_BYTES,
	                             af_ibeenc_request_BYTES,
	                             false);
}

int dial_onion_encrypt_request(client_s *client)
{
	if (!client)
		return -1;
	return onion_encrypt_message(client,
	                             client->dial_request_buf + net_header_BYTES,
	                             dialling_token_BYTES, true);
}

int add_onion_encryption_layer(client_s *client, uint8_t *msg,
                               uint32_t base_msg_len, uint32_t srv_id,
                               bool is_dial)
{
	if (!client || !msg)
		return -1;

	uint32_t msg_len = base_msg_len + mb_BYTES + (onion_layer_BYTES * srv_id);
	uint8_t *message_end = msg + msg_len;
	uint8_t *dh_pk = message_end + crypto_MACBYTES;
	uint8_t *nonce = dh_pk + crypto_pk_BYTES;
	uint8_t *dh_mix_pk;
	if (is_dial) {
		dh_mix_pk = client->mix_dial_pks[num_mix_servers - 1 - srv_id];
	}
	else {
		dh_mix_pk = client->mix_af_pks[num_mix_servers - 1 - srv_id];
	}

	uint8_t dh_secret[crypto_box_SECRETKEYBYTES];
	uint8_t scalar_mult[crypto_scalarmult_BYTES];
	uint8_t shared_secret[crypto_ghash_BYTES];
	randombytes_buf(dh_secret, crypto_box_SECRETKEYBYTES);
	crypto_scalarmult_base(dh_pk, dh_secret);

	int res = crypto_scalarmult(scalar_mult, dh_secret, dh_mix_pk);
	if (res) {
		fprintf(stderr,
		        "Scalarmult error while oniong encrypting friend request\n");
		return -1;
	}
	crypto_shared_secret(shared_secret, scalar_mult, dh_pk, dh_mix_pk,
	                     crypto_ghash_BYTES);
	randombytes_buf(nonce, crypto_NBYTES);
	res = crypto_aead_chacha20poly1305_ietf_encrypt(
		msg, NULL, msg, msg_len, dh_pk, crypto_pk_BYTES + crypto_NBYTES, NULL,
		nonce, shared_secret);
	if (res) {
		fprintf(stderr, "chacha20 encryption erro\n");
	}
	return res;
}

int client_init(client_s *c,
                const uint8_t *user_id1,
                const sign_keypair *sign_keys,
                void (*on_recv_call)(incoming_call_s *),
                void (*on_recv_friend_request)(friend_request_s *),
                void (*on_friend_confirm)(friend_request_s *))
{
	if (!c || !user_id1 || !sign_keys)
		return -1;

	int res = sodium_init();
	if (res == -1) {
		fprintf(stderr, "libsodium fatal error\n");
		exit(EXIT_FAILURE);
	}


	c->af_num_mailboxes = 1;
	c->dial_num_mailboxes = 1;
	c->dialling_round = 1;
	c->af_round = 1;
	c->friend_requests = NULL;
	c->friend_request_queue = NULL;
	c->on_recv_call = on_recv_call;
	c->on_friend_confirm = on_friend_confirm;
	c->on_friend_request = on_recv_friend_request;

	res = byte_buffer_init(&c->af_mb_buffer, 1024 * 64);
	if (res) {
		fprintf(stderr, "byte buffer init failure\n");
		return -1;
	}

	uint8_t user_id_sanitized[user_id_BYTES];
	memset(user_id_sanitized, 0, user_id_BYTES);
	strncpy((char *) user_id_sanitized, (char *) user_id1, user_id_BYTES);

	memcpy(c->user_id, user_id_sanitized, user_id_BYTES);
	for (int i = 0; i < num_pkg_servers; i++) {
		memcpy(c->pkg_auth_requests[i] + net_header_BYTES + round_BYTES, user_id_sanitized,
		       user_id_BYTES);
	}


	memcpy(c->lt_sig_keypair.public_key, sign_keys->public_key,
	       crypto_sign_PUBLICKEYBYTES);
	memcpy(c->lt_sig_keypair.secret_key, sign_keys->secret_key,
	       crypto_sign_SECRETKEYBYTES);

	kw_table_init(&c->keywheel, c->dialling_round, NULL);
	c->num_intents = num_INTENTS;
	c->bloom_p_val = pow(10.0, -10.0);
#if USE_PBC
	pairing_init_set_str(&c->pairing, pbc_params);
	element_init(&c->pkg_multisig_combined_g1, c->pairing.G1);
	element_init(&c->pkg_ibe_secret_combined_g2[0], c->pairing.G2);
	element_init(&c->pkg_ibe_secret_combined_g2[1], c->pairing.G2);
	element_init(&c->pkg_eph_pub_combined_g1, c->pairing.G1);
	element_init(&c->pkg_friend_elem, c->pairing.G2);
	element_init(&c->ibe_gen_element_g1, c->pairing.G1);
	element_init(&c->bls_gen_element_g2, c->pairing.G2);
	element_init(&c->pkg_lt_sig_keys_combined, c->pairing.G2);
	element_set_str(&c->ibe_gen_element_g1, ibe_generator, 10);
	element_set_str(&c->bls_gen_element_g2, bls_generator, 10);

	element_s pkg_sig_keys[num_pkg_servers];
	uint8_t pkg_sig_key_bytes[num_pkg_servers][g2_serialized_bytes];
	for (int i = 0; i < num_pkg_servers; i++) {
	  element_init(&pkg_sig_keys[i], c->pairing.G2);
	  element_set_str(&pkg_sig_keys[i], pk[i], 10);
	  element_to_bytes_compressed(pkg_sig_key_bytes[i], &pkg_sig_keys[i]);
	}

	pbc_sum_bytes_G2_compressed(&c->pkg_lt_sig_keys_combined,
								pkg_sig_key_bytes[0], g2_serialized_bytes,
								num_pkg_servers, &c->pairing);
	uint8_t id_hash[crypto_ghash_BYTES];
	crypto_generichash(id_hash, crypto_ghash_BYTES, c->user_id, user_id_BYTES,
					   NULL, 0);
	element_s q_id;
	element_init(&q_id, c->pairing.G2);
	element_from_hash(&q_id, id_hash, crypto_ghash_BYTES);
	element_to_bytes_compressed(c->hashed_id, &q_id);
#else
	twistpoint_fp2_t userid_hash;
	bn256_hash_g2(userid_hash, user_id_sanitized, user_id_BYTES);
	bn256_serialize_g2(c->hashed_id, userid_hash);
	bn256_sum_g2(c->pkg_lt_sig_keys_combined, pkg_lt_pks, 2);
	twistpoint_fp2_setneutral(c->pkg_ibe_secret_combined_g2);
	twistpoint_fp2_setneutral(c->pkg_ibe_secret_combined_g2);
#endif

	return 0;
}

client_s *client_alloc(const uint8_t *user_id,
                       const sign_keypair *signing_keys,
                       void (*on_recv_call)(incoming_call_s *),
                       void (*on_recv_friend_request)(friend_request_s *),
                       void (*on_friend_confirm)(friend_request_s *))
{
	client_s *client = calloc(1, sizeof(client_s));
	if (!client) {
		fprintf(stderr, "Malloc failure in client allocation\n");
		return NULL;
	}

	int result =
		client_init(client, user_id, signing_keys, on_recv_call, on_recv_friend_request, on_friend_confirm);
	if (result) {
		sodium_memzero(client, sizeof(client_s));
		free(client);
		return NULL;
	}

	return client;
}

int do_action(client_s *c, action *a)
{
	if (!c || !a)
		return -1;

	switch (a->type) {
	case ADD_FRIEND:
		af_add_friend(c, a->user_id);
		break;
	case CONFIRM_FRIEND:
		af_confirm_friend(c, a->user_id);
		break;
	case DIAL_FRIEND:
		dial_queue_call(c, (uint8_t *) a->user_id, a->intent);
		break;
	case PRINT_KW_TABLE:
		kw_print_table(&c->keywheel);
		break;
	}
	free(a);
	return 0;
}

action *action_stack_pop(client_s *c)
{
	if (!c)
		return NULL;

	client_net *net_state = &c->net_state;
	pthread_mutex_lock(&net_state->aq_lock);
	if (!net_state->action_stack) {
		pthread_mutex_unlock(&net_state->aq_lock);
		return NULL;
	}

	action *popped = net_state->action_stack;
	net_state->action_stack = net_state->action_stack->next;
	pthread_mutex_unlock(&net_state->aq_lock);

	return popped;
}

int action_stack_push(client_s *c, action *new_action)
{
	if (!c || !new_action)
		return -1;

	pthread_mutex_lock(&c->net_state.aq_lock);
	new_action->next = c->net_state.action_stack;
	c->net_state.action_stack = new_action;
	pthread_mutex_unlock(&c->net_state.aq_lock);
	eventfd_write(c->net_state.interrupt_fd, 1);
	return 0;
}

int net_send_message(client_s *s, connection *conn, uint8_t *msg,
                     uint32_t msg_size_bytes)
{
	if (!s || !conn || !msg)
		return -1;

	memcpy(conn->write_buf.data + conn->bytes_written + conn->write_remaining,
	       msg, msg_size_bytes);
	conn->write_remaining += msg_size_bytes;

	return net_epoll_send(s, conn, conn->sock_fd);
}

void client_update_dial_keys(client_s *client, uint8_t *buffer)
{
	uint8_t *ptr = buffer;
	for (int i = 0; i < num_mix_servers; i++) {
		memcpy(client->mix_dial_pks[i], ptr, crypto_pk_BYTES);
		ptr += crypto_pk_BYTES;
	}
}

void client_update_af_keys(client_s *client, uint8_t *buffer)
{
	uint8_t *ptr = buffer;
	for (int i = 0; i < num_mix_servers; i++) {
		memcpy(client->mix_af_pks[i], ptr, crypto_pk_BYTES);
		ptr += crypto_pk_BYTES;
	}
}

int client_net_init(client_s *c)
{
	if (!c)
		return -1;

	client_net *net_state = &c->net_state;
	pthread_mutex_init(&net_state->aq_lock, NULL);
	net_state->action_stack = NULL;
	net_state->epoll_fd = epoll_create1(0);
	net_state->events = calloc(100, sizeof *net_state->events);
	net_state->interrupt_fd = eventfd(0, EFD_NONBLOCK);
	struct epoll_event event;
	memset(&event, 0, sizeof event);
	event.events = EPOLLIN | EPOLLET;
	event.data.fd = net_state->interrupt_fd;
	epoll_ctl(net_state->epoll_fd, EPOLL_CTL_ADD, net_state->interrupt_fd,
	          &event);
	if (!net_state->events) {
		fprintf(stderr, "fatal malloc error\n");
		return -1;
	}
	net_state->num_auth_responses = 0;
	net_state->num_broadcast_responses = 0;
	return 0;
}

int mix_entry_process_msg(void *client_ptr, connection *conn)
{
	if (!client_ptr || !conn) {
		return -1;
	}

	client_s *client = (client_s *) client_ptr;
	client_net *net_state = &client->net_state;

	switch (conn->msg_type) {
	case NEW_AF_ROUND:
		// //printhex("new af round buffer", conn->read_buf.data, conn->curr_msg_len
		// + net_header_BYTES);
		client_update_af_keys(client, conn->read_buf.data + net_header_BYTES);
		/*af_onion_encrypt_request(client);
		net_send_message(client, conn, client->friend_request_buf,
						 net_header_BYTES + onionenc_friend_request_BYTES);*/

		net_state->num_broadcast_responses = 0;
		net_state->num_auth_responses = 0;
		client->af_round = deserialize_uint64(conn->read_buf.data + 8);

		printf("AF round %ld started\n", client->af_round);
		break;
	case NEW_DIAL_ROUND:
		client_update_dial_keys(client, conn->read_buf.data + net_header_BYTES);
		dial_build_call(client);
		net_send_message(client, conn, client->dial_request_buf,
		                 net_header_BYTES + onionenc_dial_token_BYTES);
		client->dialling_round = deserialize_uint64(conn->read_buf.data + 16);

		printf("Dial round %ld started\n", client->dialling_round);
		dial_fake_request(client);
		break;
	case MIX_SYNC:
		client->af_round = deserialize_uint64(conn->read_buf.data + 8);
		client->dialling_round = deserialize_uint64(conn->read_buf.data + 16);
		printf("AF round: %lu | Dial round: %lu\n", client->af_round, client->dialling_round);
		break;
	default:
		fprintf(stderr, "Invalid message from Mix Entry\n");
		return -1;
	}
	return 0;
}

int client_net_pkg_auth(client_s *cn)
{
	if (!cn)
		return -1;

	for (int i = 0; i < num_pkg_servers; i++) {
		connection *conn = &cn->net_state.pkg_connections[i];
		int res =
			net_send_message(cn, conn, cn->pkg_auth_requests[i],
			                 net_header_BYTES + cli_pkg_single_auth_req_BYTES);
		if (res) {
			fprintf(stderr, "error during pkg authentication\n");
			return -1;
		}
	}
	cn->net_state.num_broadcast_responses = 0;
	return 0;
}

int client_net_process_pkg(void *client_ptr, connection *conn)
{
	if (!client_ptr || !conn)
		return -1;

	client_s *c = (client_s *) client_ptr;
	client_net *net_state = &c->net_state;

	switch (conn->msg_type) {
	case PKG_BR_MSG:
		memcpy(c->pkg_broadcast_msgs[conn->id],
		       conn->read_buf.data + net_header_BYTES, pkg_broadcast_msg_BYTES);
		net_state->num_broadcast_responses++;
		if (net_state->num_broadcast_responses == num_pkg_servers) {
			af_update_pkg_public_keys(c);
			af_build_request(c);
			net_send_message(c,
			                 &c->net_state.mix_entry,
			                 c->friend_request_buf,
			                 net_header_BYTES + onionenc_friend_request_BYTES);
		}
		break;

	case PKG_AUTH_RES_MSG:
		memcpy(c->pkg_auth_responses[conn->id],
		       conn->read_buf.data + net_header_BYTES, pkg_enc_auth_res_BYTES);
		net_state->num_auth_responses++;
		if (net_state->num_auth_responses == num_pkg_servers) {
			af_process_auth_responses(c);
			af_process_mb(c, c->af_mb_buffer.data,
			              c->af_mb_num_messages,
			              c->af_round);

			net_state->num_auth_responses = 0;
		}
		break;
	default:
		fprintf(stderr, "Invalid message received from PKG server\n");
		return -1;
	}
	return 0;
}

int mix_last_process_msg(void *client_ptr, connection *conn)
{
	if (!client_ptr || !conn)
		return -1;

	client_s *client = (client_s *) client_ptr;
	client_net *net_state = &client->net_state;
	switch (conn->msg_type) {
	case DIAL_MB:
		dial_process_mb(client, conn->read_buf.data + net_header_BYTES,
		                deserialize_uint64(conn->read_buf.data + 8),
		                deserialize_uint64(conn->read_buf.data + 16));
		kw_advance_table(&client->keywheel);
		break;
	case AF_MB:
		byte_buffer_clear(&client->af_mb_buffer);
		byte_buffer_put(&client->af_mb_buffer, conn->read_buf.data + net_header_BYTES, conn->curr_msg_len);
		client->af_mb_num_messages = deserialize_uint64(conn->read_buf.data + 16);
		af_create_pkg_auth_request(client);
		client_net_pkg_auth(client);
		net_state->num_broadcast_responses = 0;
		/*	af_process_mb(client, conn->read_buf.data + net_header_BYTES,
						  deserialize_uint64(conn->read_buf.data + 16),
						  deserialize_uint64(conn->read_buf.data + 8));
			client->mb_processed = true;*/
		if (net_state->num_auth_responses == num_pkg_servers) {
			af_process_auth_responses(client);
			net_state->num_auth_responses = 0;
		}

		break;
	case NEW_AFMB_AVAIL: {
		uint64_t round = deserialize_uint64(conn->read_buf.data + 8);
		net_serialize_header(conn->write_buf.data + conn->bytes_written + conn->write_remaining,
		                     CLIENT_AF_MB_REQUEST,
		                     user_id_BYTES,
		                     round,
		                     client->af_round);
		conn->write_remaining += net_header_BYTES;
		memcpy(conn->write_buf.data + conn->bytes_written + conn->write_remaining, client->user_id, user_id_BYTES);
		conn->write_remaining += user_id_BYTES;
		net_epoll_send(client, conn, conn->sock_fd);
		break;
	}
	case NEW_DMB_AVAIL: {
		uint64_t round = deserialize_uint64(conn->read_buf.data + 8);
		net_serialize_header(conn->write_buf.data + conn->bytes_written + conn->write_remaining,
		                     CLIENT_DIAL_MB_REQUEST,
		                     user_id_BYTES,
		                     client->dialling_round,
		                     round);
		conn->write_remaining += net_header_BYTES;
		memcpy(conn->write_buf.data + conn->bytes_written + conn->write_remaining, client->user_id, user_id_BYTES);
		conn->write_remaining += user_id_BYTES;
		net_epoll_send(client, conn, conn->sock_fd);
		break;
	}
	default:
		fprintf(stderr, "Invalid message from Mix distribution server\n");
		return -1;
	}
	return 0;
}

int client_run(client_s *client)
{
	if (!client)
		return -1;

	client_net_init(client);
	client_net *net_state = &client->net_state;

	int last_sockfd =
		net_connect("127.0.0.1", mix_listen_ports[num_mix_servers - 1], 1);
	if (last_sockfd == -1) {
		fprintf(stderr, "could not connect to mix distribution server\n");
		return -1;
	}
	connection_init(&net_state->mix_last, read_buf_SIZE, write_buf_SIZE,
	                mix_last_process_msg, net_state->epoll_fd, last_sockfd);

	int entry_sockfd = net_connect("127.0.0.1", mix_client_listen, 0);
	if (entry_sockfd == -1) {
		fprintf(stderr, "could not connect to mix entry server\n");
		return -1;
	}
	connection_init(&net_state->mix_entry, read_buf_SIZE, write_buf_SIZE,
	                mix_entry_process_msg, net_state->epoll_fd, entry_sockfd);

	int res =
		net_read_blocking(net_state->mix_entry.sock_fd,
		                  net_state->mix_entry.read_buf.data, net_header_BYTES);
	if (res == -1) {
		perror("client read");
		return -1;
	}

	client->af_round = deserialize_uint64(net_state->mix_entry.read_buf.data + 8);
	client->dialling_round = deserialize_uint64(net_state->mix_entry.read_buf.data + 16);
	client->keywheel.table_round = client->dialling_round;

	printf("[Connected as %s: Dial round: %ld | Add friend round: %ld]\n",
	       client->user_id, client->dialling_round, client->af_round);

	af_fake_request(client);
	dial_fake_request(client);

	res = socket_set_nonblocking(net_state->mix_entry.sock_fd);
	if (res) {
		fprintf(stderr, "socket setoption error\n");
		return -1;
	}

	for (uint32_t i = 0; i < num_pkg_servers; i++) {
		int new_pkg_sockfd = net_connect("127.0.0.1", pkg_cl_listen_ports[i], 1);
		if (new_pkg_sockfd == -1) {
			return -1;
		}
		connection_init(&net_state->pkg_connections[i], read_buf_SIZE,
		                write_buf_SIZE, client_net_process_pkg, net_state->epoll_fd,
		                new_pkg_sockfd);
		net_state->pkg_connections[i].id = i;
	}

	pthread_t net_thread;
	pthread_create(&net_thread, NULL, client_process_loop, client);
	return 0;
}

void *client_process_loop(void *clptr)
{
	client_s *client = (client_s *) clptr;
	client_net *net_state = &client->net_state;
	struct epoll_event *events = net_state->events;
	client->running = true;

	while (client->running) {
		int n = epoll_wait(net_state->epoll_fd, net_state->events, 100, 100000);
		unsigned long long dummy;
		read(net_state->interrupt_fd, &dummy, sizeof dummy);

		action *curr_action = action_stack_pop(client);
		while (curr_action) {
			do_action(client, curr_action);
			curr_action = action_stack_pop(client);
		}

		connection *conn = NULL;
		for (int i = 0; i < n; i++) {
			conn = events[i].data.ptr;
			if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
				fprintf(stderr, "Client: Socket error on socket %d - Exiting\n",
				        conn->sock_fd);
				client->running = false;
				break;
			}

			else if (events[i].data.fd == net_state->interrupt_fd) {
				continue;
			}
			else if (events[i].events & EPOLLIN) {
				net_epoll_read(client, conn);
			}
			else if (events[i].events & EPOLLOUT) {
				net_epoll_send(client, conn, client->net_state.epoll_fd);
			}
		}
	}
	return NULL;
}
