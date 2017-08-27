#include "mixnet.h"
#include "xxhash.h"
#include <math.h>
#include <signal.h>
#include <pkg_config.h>

void *sim_mix_af_entry_add_noise(void *args);
void sim_mix_entry_dial_add_noise(void *args);
int mix_buffers_init(mix_s *mix)
{
	if (byte_buffer_init(&mix->af_data.in_buf, mix_num_buffer_elems * mix->af_data.inc_msg_length))
		return -1;
	if (byte_buffer_init(&mix->af_data.out_buf, mix_num_buffer_elems * mix->af_data.out_msg_length))
		return -1;
	if (byte_buffer_init(&mix->dial_data.in_buf, mix_num_buffer_elems * mix->dial_data.inc_msg_length))
		return -1;
	if (byte_buffer_init(&mix->dial_data.out_buf, mix_num_buffer_elems * mix->dial_data.out_msg_length))
		return -1;

	return 0;
}

void mix_af_distribute(mix_s *mix)
{
	afmb_container_s *c = &mix->af_mb_container;
	c->num_mailboxes = mix->af_data.num_mailboxes;

	c->round = mix->af_data.round;

	for (uint32_t i = 0; i < c->num_mailboxes; i++) {
		af_mailbox_s *mb = &c->mailboxes[i];
		mb->id = i;
		mb->num_messages = mix->af_data.mb_counts[i];

		uint64_t mailbox_sz = net_header_BYTES + (af_ibeenc_request_BYTES * mb->num_messages);
		mb->size_bytes = mailbox_sz;

		mb->data = realloc(mb->data, mailbox_sz);
		if (!mb->data) {
			fprintf(stderr, "fatal calloc error");
			exit(EXIT_FAILURE);
		}

		net_serialize_header(mb->data, AF_MB, (uint32_t) mailbox_sz - net_header_BYTES,
		                     c->round, mb->num_messages);
		mb->next_msg_ptr = mb->data + net_header_BYTES;
	}

	uint64_t curr_mailbox = 0;
	uint8_t *curr_msg_ptr = mix->af_data.out_buf.data + net_header_BYTES;
	af_mailbox_s *mb;

	for (uint32_t i = 0; i < mix->af_data.num_out_msgs; i++) {
		curr_mailbox = deserialize_uint64(curr_msg_ptr);
		mb = &c->mailboxes[curr_mailbox];
		memcpy(mb->next_msg_ptr, curr_msg_ptr + mb_BYTES, af_ibeenc_request_BYTES);
		mb->next_msg_ptr += af_ibeenc_request_BYTES;
		curr_msg_ptr += mb_BYTES + af_ibeenc_request_BYTES;
	}
}

void mix_dial_update_stack_index(mix_s *mix)
{
	uint32_t i = mix->dial_cont_stack_head;
	mix->dial_cont_stack_head = i == (mix_num_dial_mbs_stored - 1) ? 0 : i + 1;
}

void mix_dial_distribute(mix_s *mix)
{
	// mix_dial_update_stack_index(mix);
	dmb_container_s *c = &mix->dial_mb_containers[0];
	memset(c, 0, sizeof(dmb_container_s));
	for (int i = 0; i < c->num_mailboxes; i++) {
		bloom_clear(&c->mailboxes[i].bloom);
	}

	c->num_mailboxes = mix->dial_data.num_mailboxes;
	c->round = mix->dial_data.round;

	for (uint32_t i = 0; i < c->num_mailboxes; i++) {
		dial_mailbox_s *mb = &c->mailboxes[i];
		mb->id = i;
		mb->num_messages = mix->dial_data.mailbox_counts[i];
		printf("MAILBOX COUNT %d: %lu\n", i, mb->num_messages);
		mb->num_messages = 1000;
		bloom_init(&mb->bloom, mix->dial_data.bloom_p_val, mb->num_messages, 0,
		           NULL, net_header_BYTES);
		net_serialize_header(mb->bloom.base_ptr, DIAL_MB, (uint32_t) mb->bloom.size_bytes,
		                     c->round, mb->num_messages);
	}

	uint8_t *curr_msg_ptr = mix->dial_data.out_buf.data + net_header_BYTES;
	for (int i = 0; i < mix->dial_data.num_out_msgs; i++) {
		uint64_t mailbox = deserialize_uint64(curr_msg_ptr);
		bloom_add_elem(&c->mailboxes[mailbox].bloom, curr_msg_ptr + mb_BYTES,
		               dialling_token_BYTES);
		curr_msg_ptr += (mb_BYTES + dialling_token_BYTES);
	}
}

dial_mailbox_s *mix_dial_get_mailbox_buffer(mix_s *mix,
                                            uint64_t round,
                                            uint8_t *user_id)
{
	dmb_container_s *container = &mix->dial_mb_containers[0];

	uint64_t mb_num = XXH64(user_id, user_id_BYTES, 0) % container->num_mailboxes;
	return &mix->dial_mb_containers[0].mailboxes[mb_num];
}

void mix_entry_add_af_message(mix_s *mix, uint8_t *buf)
{
	byte_buffer_put(&mix->af_data.in_buf, buf, mix->af_data.inc_msg_length);
	mix->af_data.num_inc_msgs++;
}

void mix_entry_add_dial_msg(mix_s *mix, uint8_t *msg)
{
	byte_buffer_put(&mix->dial_data.in_buf, msg, mix->dial_data.inc_msg_length);
	mix->dial_data.num_inc_msgs++;
}

int mix_init(mix_s *mix, uint32_t server_id, uint32_t num_threads, uint32_t num_servers)
{
	int result;
	char log_file_str[20];
	sprintf(log_file_str, "mix_%d.log", server_id);
	mix->log_file = fopen(log_file_str, "a+");
	if (!mix->log_file) {
		fprintf(stderr, "fatal: couldn't open log file\n");
		exit(EXIT_FAILURE);
	}
#if USE_PBC
	pairing_init_set_str(&mix->pairing, pbc_params);
	element_init_Zr(&mix->af_noise_Zr_elem, &mix->pairing);
	element_init_G1(&mix->ibe_gen_elem, &mix->pairing);
	element_init_G1(&mix->af_noise_G1_elem, &mix->pairing);
	result = element_set_str(&mix->ibe_gen_elem, ibe_generator, 10);
	if (result == 0) {
		fprintf(stderr, "Invalid string for ibe generation element\n");
		return -1;
	}
#endif
	mix->num_servers = num_mix_servers;
	mix->server_id = server_id;
	mix->is_last = num_mix_servers - mix->server_id == 1;
	mix->af_data.num_mailboxes = 1;
	mix->dial_data.num_mailboxes = 1;
	mix->num_inc_onion_layers = num_mix_servers - server_id;
	mix->num_out_onion_layers = mix->num_inc_onion_layers - 1;

	memset(mix->af_mb_container.mailboxes, 0, sizeof mix->af_mb_container.mailboxes);

	mix->af_data.num_inc_msgs = 0;
	mix->af_data.num_out_msgs = 0;
	mix->dial_data.num_inc_msgs = 0;
	mix->dial_data.num_out_msgs = 0;
	uint32_t inc_onion_layer_bytes = (mix->num_inc_onion_layers * onion_layer_BYTES);
	mix->af_data.inc_msg_length = mb_BYTES + af_ibeenc_request_BYTES + inc_onion_layer_bytes;
	mix->dial_data.inc_msg_length = dialling_token_BYTES + mb_BYTES + inc_onion_layer_bytes;
	mix->af_data.out_msg_length = mix->af_data.inc_msg_length - onion_layer_BYTES;
	mix->dial_data.out_msg_length = mix->dial_data.inc_msg_length - onion_layer_BYTES;
	mix->dial_data.bloom_p_val = pow(10.0, -10.0);

	result = mix_buffers_init(mix);
	if (result) {
		fprintf(stderr, "Mix server: error initialising data buffers\n");
		return -1;
	}

	mix->dial_cont_stack_head = 0;
	for (int i = 0; i < mix_num_dial_mbs_stored; i++) {
		memset(&mix->dial_mb_containers[i], 0, sizeof *mix->dial_mb_containers);
	}

	mix->af_data.round = 1;
	mix->af_data.round_duration = af_duration;
	mix->af_data.accept_window_duration = af_window;
	mix->dial_data.round = 1;
	mix->dial_data.round_duration = dial_duration;
	mix->dial_data.accept_window_duration = dial_window;
	mix->af_data.laplace.mu = af_mu;
	mix->af_data.laplace.b = af_b;
	mix->dial_data.laplace.mu = dial_mu;
	mix->dial_data.laplace.b = dial_b;
	mix->af_data.num_mailboxes = 1;
	mix->dial_data.num_mailboxes = 1;
	memset(&mix->af_mb_container, 0, sizeof mix->af_mb_container);
	memset(mix->dial_data.mailbox_counts, 0,
	       sizeof mix->dial_data.mailbox_counts);
	memset(mix->af_data.mb_counts, 0, sizeof mix->af_data.mb_counts);

	for (int i = 0; i < mix->num_inc_onion_layers; i++) {
		mix->mix_af_dh_pks[i] = calloc(1, crypto_pk_BYTES);
		if (!mix->mix_af_dh_pks[i]) {
			fprintf(stderr, "fatal malloc error during setup\n");
			return -1;
		}
		mix->mix_dial_dh_pks[i] = calloc(1, crypto_pk_BYTES);
		if (!mix->mix_dial_dh_pks[i]) {
			fprintf(stderr, "fatal malloc error during setup\n");
			return -1;
		}
	}
	mix->af_mutex = calloc(1, sizeof *mix->af_mutex);
	mix->dial_mutex = calloc(1, sizeof *mix->dial_mutex);
	pthread_mutex_init(mix->af_mutex, NULL);
	pthread_mutex_init(mix->dial_mutex, NULL);
	mix->num_threads = num_threads;
	crypto_box_keypair(mix->mix_af_dh_pks[0], mix->af_dh_sk);
	crypto_box_keypair(mix->mix_dial_dh_pks[0], mix->dial_dh_sk);
	mix_net_init(mix);
	return 0;
}

void mix_af_newround(mix_s *mix)
{
	byte_buffer_clear(&mix->af_data.in_buf);
	byte_buffer_clear(&mix->af_data.out_buf);
	mix->af_data.round++;
	mix->af_data.num_inc_msgs = 0;
	mix->af_data.num_out_msgs = 0;
	if (mix->is_last) {
		for (int i = 0; i < 5; i++) {
			mix->af_data.mb_counts[i] = 0;
		}
	}
	mix_af_add_noise(mix);
}

void mix_dial_newround(mix_s *mix)
{
	byte_buffer_clear(&mix->dial_data.in_buf);
	byte_buffer_clear(&mix->dial_data.out_buf);
	mix->dial_data.num_inc_msgs = 0;
	mix->dial_data.num_out_msgs = 0;

	mix->dial_data.round++;
	if (mix->is_last) {
		for (int i = 0; i < 5; i++) {
			mix->dial_data.mailbox_counts[i] = 0;
		}
	}
	mix_dial_add_noise(mix);
}

void mix_shuffle_messages(uint8_t *messages,
                          uint32_t msg_count,
                          uint32_t msg_length)
{
	if (msg_count < 2) {
		fprintf(stderr, "Cannot shuffle a set of less than 2 messages\n");
		return;
	}
	uint8_t tmp_message[msg_length];
	for (uint32_t i = msg_count - 1; i >= 1; i--) {
		uint32_t j = randombytes_uniform(i);
		memcpy(tmp_message, messages + (i * msg_length), msg_length);
		memcpy(messages + (i * msg_length), messages + (j * msg_length), msg_length);
		memcpy(messages + (j * msg_length), tmp_message, msg_length);
	}
}

void mix_af_shuffle(mix_s *mix)
{
	mix_shuffle_messages(mix->af_data.out_buf.data + net_header_BYTES,
	                     mix->af_data.num_out_msgs,
	                     mix->af_data.out_msg_length);
}

void mix_dial_shuffle(mix_s *mix)
{
	mix_shuffle_messages(mix->dial_data.out_buf.data + net_header_BYTES,
	                     mix->dial_data.num_out_msgs,
	                     mix->dial_data.out_msg_length);
}

int mix_add_onion_layer(uint8_t *msg,
                        uint32_t msg_len,
                        uint32_t index,
                        uint8_t *matching_pub_dh)
{

	uint32_t message_length = msg_len + (onion_layer_BYTES * index);
	uint8_t *message_end_ptr = msg + message_length;
	uint8_t *dh_pub_ptr = message_end_ptr + crypto_MACBYTES;
	uint8_t *nonce_ptr = dh_pub_ptr + crypto_pk_BYTES;

	uint8_t dh_secret[crypto_box_SECRETKEYBYTES];
	uint8_t scalar_mult[crypto_scalarmult_BYTES];
	uint8_t shared_secret[crypto_ghash_BYTES];

	crypto_box_keypair(dh_pub_ptr, dh_secret);
	int res = crypto_scalarmult(scalar_mult, dh_secret, matching_pub_dh);
	if (res) {
		fprintf(stderr, "Mix: scalar mult error while encrypting onion request\n");
		return -1;
	}
	crypto_shared_secret(shared_secret, scalar_mult, dh_pub_ptr, matching_pub_dh,
	                     crypto_generichash_BYTES);
	randombytes_buf(nonce_ptr, crypto_NBYTES);
	crypto_aead_chacha20poly1305_ietf_encrypt(
		msg, NULL, msg, message_length, dh_pub_ptr,
		crypto_pk_BYTES + crypto_NBYTES, NULL, nonce_ptr, shared_secret);

	return 0;
}

int mix_onion_encrypt_msg(mix_s *mix,
                          uint8_t *msg,
                          uint32_t msg_len,
                          uint8_t **keys)
{
	uint8_t *curr_dh_pub_ptr;
	for (uint32_t i = 0; i < mix->num_out_onion_layers; i++) {
		curr_dh_pub_ptr = keys[mix->num_out_onion_layers - i];
		mix_add_onion_layer(msg, msg_len, i, curr_dh_pub_ptr);
	}
	return 0;
}

void mix_dial_add_noise(mix_s *mix)
{
	byte_buffer_put_virtual(&mix->dial_data.out_buf, net_header_BYTES);
	mix->dial_data.last_noise_count = 0;
	uint64_t num_mailboxes = mix->dial_data.num_mailboxes + 1;
	if (mix->is_last)
		num_mailboxes--;
	for (uint64_t i = 0; i < num_mailboxes; i++) {
		uint32_t noise = laplace_rand(&mix->dial_data.laplace);
		for (int j = 0; j < noise; j++) {
			uint8_t *curr_ptr = mix->dial_data.out_buf.pos;
			serialize_uint64(curr_ptr, i);
			randombytes_buf(curr_ptr + sizeof i, dialling_token_BYTES);
			mix_onion_encrypt_msg(mix, curr_ptr, dialling_token_BYTES + mb_BYTES,
			                      mix->mix_dial_dh_pks);
			byte_buffer_put_virtual(&mix->dial_data.out_buf,
			                        mix->dial_data.out_msg_length);
			mix->dial_data.num_out_msgs++;
		}
		mix->dial_data.last_noise_count += noise;
		if (mix->num_out_onion_layers == 0) {
			mix->dial_data.mailbox_counts[i] += noise;
		}
	}
}

void mix_af_add_noise(mix_s *mix)
{
#if !USE_PBC
	scalar_t random;
	curvepoint_fp_t tmp;
#endif
	byte_buffer_put_virtual(&mix->af_data.out_buf, net_header_BYTES);
	mix->af_data.last_noise_count = 0;
	uint64_t num_mailboxes = mix->af_data.num_mailboxes + 1;
	if (mix->is_last)
		num_mailboxes--;
	for (uint64_t i = 0; i < num_mailboxes; i++) {

		uint32_t noise = laplace_rand(&mix->af_data.laplace);
		for (int j = 0; j < noise; j++) {
			uint8_t *curr_ptr = mix->af_data.out_buf.pos;
			serialize_uint64(curr_ptr, i);
#if USE_PBC
			element_random(&mix->af_noise_Zr_elem);
			element_pow_zn(&mix->af_noise_G1_elem, &mix->ibe_gen_elem,
			               &mix->af_noise_Zr_elem);
			element_to_bytes_compressed(curr_ptr + mb_BYTES, &mix->af_noise_G1_elem);
#else
			bn256_scalar_random(random);
			bn256_scalarmult_base_g1(tmp, random);
			bn256_serialize_g1(curr_ptr + mb_BYTES, tmp);
#endif
			// After the group element, fill out the rest of the request with random
			// data
			randombytes_buf(curr_ptr + mb_BYTES + g1_serialized_bytes,
			                af_ibeenc_request_BYTES - g1_serialized_bytes);
			mix_onion_encrypt_msg(mix, curr_ptr, af_ibeenc_request_BYTES + mb_BYTES,
			                      mix->mix_af_dh_pks);
			mix->af_data.num_out_msgs++;
			byte_buffer_put_virtual(&mix->af_data.out_buf,
			                        mix->af_data.out_msg_length);
		}
		mix->af_data.last_noise_count += noise;
		if (mix->num_out_onion_layers == 0) {
			mix->af_data.mb_counts[i] += noise;
		}
	}
}

int mix_remove_encryption_layer(uint8_t *out,
                                uint8_t *c,
                                uint32_t onionm_len,
                                uint8_t *pk,
                                uint8_t *sk)
{
	// Onion encrypted messages have the nonce and public key of DH keypair
	// appended to the end of the message directly after the MAC
	uint8_t *nonce_ptr = c + onionm_len - crypto_NBYTES;
	uint8_t *client_pub_dh_ptr = nonce_ptr - crypto_pk_BYTES;
	uint8_t scalar_mult[crypto_scalarmult_BYTES];

	int result = crypto_scalarmult(scalar_mult, sk, client_pub_dh_ptr);
	if (result) {
		// printhex("", c, onionm_len);
		fprintf(stderr, "Scalarmult error removing encryption layer\n");
		return -1;
	}

	uint8_t shared_secret[crypto_ghash_BYTES];
	crypto_shared_secret(shared_secret, scalar_mult, client_pub_dh_ptr, pk,
	                     crypto_ghash_BYTES);

	uint32_t ctextlen = onionm_len - (crypto_pk_BYTES + crypto_NBYTES);
	result = crypto_chacha_decrypt(
		out, NULL, NULL, c, ctextlen, client_pub_dh_ptr,
		crypto_pk_BYTES + crypto_NBYTES, nonce_ptr, shared_secret);
	if (result) {
		fprintf(stderr, "Mix: Decryption error\n");
		return -1;
	}

	sodium_memzero(shared_secret, crypto_ghash_BYTES);
	return 0;
}

int mix_update_mailbox_counts(uint64_t n,
                              uint64_t num_mailboxes,
                              uint64_t *mailbox_counts)
{
	if (n >= num_mailboxes) {
		return -1;
	}
	else {
		mailbox_counts[n]++;
	}

	return 0;
}

int mix_decrypt_messages(mix_s *mix,
                         uint8_t *in_ptr,
                         uint8_t *out_ptr,
                         uint32_t in_msg_len,
                         uint32_t out_msg_len,
                         uint32_t msg_count,
                         uint64_t num_mailboxes,
                         uint64_t *mailbox_counts,
                         uint8_t *pk,
                         uint8_t *sk)
{
	uint8_t *curr_in_ptr = in_ptr;
	uint8_t *curr_out_ptr = out_ptr;
	uint32_t decrypted_msg_count = 0;

	for (int i = 0; i < msg_count; i++) {
		int result = mix_remove_encryption_layer(curr_out_ptr, curr_in_ptr,
		                                         in_msg_len, pk, sk);
		curr_in_ptr += in_msg_len;
		if (!result) {
			// Last server in the mixnet chain
			if (mix->is_last) {
				uint64_t n = deserialize_uint64(curr_out_ptr);
				result = mix_update_mailbox_counts(n, num_mailboxes, mailbox_counts);
			}
			if (!result) {
				curr_out_ptr += out_msg_len;
				decrypted_msg_count++;
			}
		}
	}
	return decrypted_msg_count;
}

void *mix_dial_parallel_decrypt(void *args)
{
	mix_thread_args *targs = (mix_thread_args *) args;
	mix_s *mix = targs->mix;
	uint8_t *in_ptr = targs->data;
	uint8_t *buf = calloc(targs->num_msgs, mix->dial_data.out_msg_length);
	uint64_t mb_counts[20];
	memset(mb_counts, 0, sizeof mb_counts);

	int n = mix_decrypt_messages(
		mix, in_ptr, buf, mix->dial_data.inc_msg_length,
		mix->dial_data.out_msg_length, targs->num_msgs,
		mix->dial_data.num_mailboxes, mb_counts, mix->mix_dial_dh_pks[0],
		mix->dial_dh_sk);

	pthread_mutex_lock(mix->dial_mutex);
	if (mix->is_last) {
		for (int i = 0; i < mix->dial_data.num_mailboxes; i++) {
			mix->dial_data.mailbox_counts[i] += mb_counts[i];
		}
	}
	mix->dial_data.num_out_msgs += n;
	byte_buffer_put(&mix->dial_data.out_buf, buf, n * mix->dial_data.out_msg_length);
	pthread_mutex_unlock(mix->dial_mutex);
	free(buf);
	return NULL;
}
int
mix_dial_parallel_dispatch(mix_s *server)
{
	double start_timer = get_time();
	uint32_t num_threads = server->num_threads;
	pthread_t threads[num_threads];
	mix_thread_args args[num_threads];
	uint32_t num_per_thread = server->dial_data.num_inc_msgs / num_threads;
	uint32_t leftover_msgs = server->dial_data.num_inc_msgs;
	int curindex = 0;
	uint8_t *in_ptr = server->dial_data.in_buf.data;
	//printf("Total num msgs: %u\n", server->dial_data.num_inc_msgs);
	for (int i = 0; i < num_threads - 1; i++) {
		args[i].mix = server;
		args[i].data = in_ptr + (curindex * server->dial_data.inc_msg_length);
		args[i].num_msgs = num_per_thread;
		//printf("Thread %d taking messages %d to", i, curindex);
		curindex += num_per_thread;
		//	printf("%d\n", curindex);
		leftover_msgs -= num_per_thread;

	}

	args[num_threads - 1].mix = server;
	args[num_threads - 1].num_msgs = leftover_msgs;
	args[num_threads - 1].data = in_ptr + (curindex * server->dial_data.inc_msg_length);
	//printf("Thread %d taking messages %d to %d (%d)\n", num_threads-1, curindex, server->dial_data.num_inc_msgs, leftover_msgs);

	for (int i = 0; i < num_threads; i++) {
		int res = pthread_create(&threads[i], NULL, mix_dial_parallel_decrypt, &args[i]);
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

	return 0;
}

void mix_dial_decrypt_messages(mix_s *mix)
{
	mix_dial_parallel_dispatch(mix);
/*	uint8_t *in_ptr = mix->dial_data.in_buf.data;
	uint8_t *out_ptr = mix->dial_data.out_buf.pos;

	int n = mix_decrypt_messages(
		mix, in_ptr, out_ptr, mix->dial_data.inc_msg_length,
		mix->dial_data.out_msg_length, mix->dial_data.num_inc_msgs,
		mix->dial_data.num_mailboxes, mix->dial_data.mailbox_counts,
		mix->mix_dial_dh_pks[0], mix->dial_dh_sk);

	mix->dial_data.num_out_msgs += n;
	byte_buffer_put_virtual(&mix->dial_data.out_buf,
	                        n * mix->dial_data.out_msg_length);

	mix_dial_shuffle(mix);*/

}

void *mix_af_parallel_decrypt(void *args)
{
	mix_thread_args *targs = (mix_thread_args *) args;
	mix_s *mix = targs->mix;
	uint8_t *in_ptr = targs->data;
	uint8_t *buf = calloc(targs->num_msgs, mix->af_data.out_msg_length);
	uint64_t mb_counts[20];
	memset(mb_counts, 0, sizeof mb_counts);

	int n = mix_decrypt_messages(
		mix, in_ptr, buf, mix->af_data.inc_msg_length,
		mix->af_data.out_msg_length, targs->num_msgs,
		mix->af_data.num_mailboxes, mb_counts, mix->mix_af_dh_pks[0],
		mix->af_dh_sk);

	pthread_mutex_lock(mix->af_mutex);
	if (mix->is_last) {
		for (int i = 0; i < mix->af_data.num_mailboxes; i++) {
			mix->af_data.mb_counts[i] += mb_counts[i];
		}
	}
	mix->af_data.num_out_msgs += n;
	byte_buffer_put(&mix->af_data.out_buf, buf, n * mix->af_data.out_msg_length);
	pthread_mutex_unlock(mix->af_mutex);
	free(buf);
	return NULL;
}

int
mix_af_parallel_dispatch(mix_s *server)
{
	double start_timer = get_time();

	uint32_t num_threads = server->num_threads;
	pthread_t threads[num_threads];
	mix_thread_args args[num_threads];
	uint32_t num_per_thread = server->af_data.num_inc_msgs / num_threads;
	uint32_t leftover_msgs = server->af_data.num_inc_msgs;
	int curindex = 0;
	uint8_t *in_ptr = server->af_data.in_buf.data;

	for (int i = 0; i < num_threads - 1; i++) {
		args[i].mix = server;
		args[i].data = in_ptr + (curindex * server->af_data.inc_msg_length);
		args[i].num_msgs = num_per_thread;
		curindex += num_per_thread;
		leftover_msgs -= num_per_thread;
	}

	args[num_threads - 1].mix = server;
	args[num_threads - 1].num_msgs = leftover_msgs;
	args[num_threads - 1].data = in_ptr + (curindex * server->af_data.inc_msg_length);

	for (int i = 0; i < num_threads; i++) {
		int res = pthread_create(&threads[i], NULL, mix_af_parallel_decrypt, &args[i]);
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

	return 0;
}


void mix_af_decrypt_messages(mix_s *mix)
{
	//mix_af_parallel_dispatch(mix);
	uint8_t *in_ptr = mix->af_data.in_buf.data;
	uint8_t *out_ptr = mix->af_data.out_buf.pos;

	int n = mix_decrypt_messages(
		mix, in_ptr, out_ptr, mix->af_data.inc_msg_length,
		mix->af_data.out_msg_length, mix->af_data.num_inc_msgs,
		mix->af_data.num_mailboxes, mix->af_data.mb_counts, mix->mix_af_dh_pks[0],
		mix->af_dh_sk);

	mix->af_data.num_out_msgs += n;
	byte_buffer_put_virtual(&mix->af_data.out_buf,
	                        n * mix->af_data.out_msg_length);
}

void mix_pkg_broadcast(mix_s *s, uint32_t msg_type)
{
	uint8_t buf[net_header_BYTES];
	memset(buf, 0, net_header_BYTES);
	serialize_uint32(buf, msg_type);
	serialize_uint64(buf + 8, s->af_data.round);
	for (int i = 0; i < num_pkg_servers; i++) {
		send(s->net_state.pkg_conns[i].sock_fd, buf, net_header_BYTES, 0);
	}
}

int mix_exit_process_client_msg(void *owner, connection *conn)
{
	mix_s *mix = (mix_s *) owner;
	if (conn->msg_type == CLIENT_DIAL_MB_REQUEST) {
		uint64_t mb_round = deserialize_uint64(conn->read_buf.data + 8);
		/*printf("Received Dial mailbox download request for round %ld from %.60s\n",
		       mb_round, conn->read_buf.data + net_header_BYTES);*/
		dial_mailbox_s *request_mb = mix_dial_get_mailbox_buffer(
			owner, mb_round, conn->read_buf.data + net_header_BYTES);
		if (request_mb) {
			net_epoll_queue_write(&mix->net_state, conn, request_mb->bloom.base_ptr,
			                      request_mb->bloom.total_size_bytes, NULL);
		}
	}
	else if (conn->msg_type == CLIENT_AF_MB_REQUEST) {
		//uint64_t round_num = deserialize_uint64(conn->read_buf.data + 8);
		/*	printf("Received AF mailbox download request for round %ld from %.60s\n",
				   round_num, conn->read_buf.data + net_header_BYTES);*/
		uint64_t index =
			XXH64(conn->read_buf.data + net_header_BYTES, user_id_BYTES, 0) % mix->af_mb_container.num_mailboxes;
		af_mailbox_s *mailbox = &mix->af_mb_container.mailboxes[index];
		net_epoll_queue_write(&mix->net_state, conn, mailbox->data, mailbox->size_bytes, NULL);
	}

	else {
		fprintf(stderr, "Invalid message\n");
		return -1;
	}
	return 0;
}

void mix_exit_new_af_key(mix_s *mix)
{
	net_server_state *net_state = &mix->net_state;
	crypto_box_keypair(mix->mix_af_dh_pks[0], mix->af_dh_sk);
	byte_buffer_clear(&net_state->af_client_broadcast);
	byte_buffer_put_virtual(&net_state->af_client_broadcast, net_header_BYTES);
	byte_buffer_put(&net_state->af_client_broadcast, mix->mix_af_dh_pks[0],
	                crypto_pk_BYTES);

	serialize_uint32(net_state->af_client_broadcast.data, NEW_AF_ROUND);
	serialize_uint32(net_state->af_client_broadcast.data + net_msg_type_BYTES,
	                 crypto_pk_BYTES);
	net_epoll_queue_write(net_state, &net_state->prev_mix,
	                      net_state->af_client_broadcast.data,
	                      crypto_pk_BYTES + net_header_BYTES, true);
}

void mix_exit_new_dial_key(mix_s *mix)
{
	net_server_state *net_state = &mix->net_state;
	crypto_box_keypair(mix->mix_dial_dh_pks[0], mix->dial_dh_sk);
	byte_buffer_clear(&net_state->dial_client_broadcast);

	serialize_uint32(net_state->dial_client_broadcast.data, NEW_DIAL_ROUND);
	serialize_uint32(net_state->dial_client_broadcast.data + net_msg_type_BYTES,
	                 crypto_pk_BYTES);
	byte_buffer_put_virtual(&net_state->dial_client_broadcast, net_header_BYTES);
	byte_buffer_put(&net_state->dial_client_broadcast, mix->mix_dial_dh_pks[0],
	                crypto_pk_BYTES);

	net_epoll_queue_write(net_state, &net_state->prev_mix,
	                      net_state->dial_client_broadcast.data,
	                      crypto_pk_BYTES + net_header_BYTES, true);
}

int mix_process_mix_msg(void *m, connection *conn)
{
	mix_s *mix = (mix_s *) m;
	net_server_state *net_state = &mix->net_state;
	if (conn->msg_type == NEW_AF_ROUND) {
		crypto_box_keypair(mix->mix_af_dh_pks[0], mix->af_dh_sk);
		byte_buffer_clear(&net_state->af_client_broadcast);

		serialize_uint32(net_state->af_client_broadcast.data, NEW_AF_ROUND);
		serialize_uint32(net_state->af_client_broadcast.data + net_msg_type_BYTES,
		                 conn->curr_msg_len + crypto_pk_BYTES);
		serialize_uint64(net_state->af_client_broadcast.data + 8,
		                 mix->af_data.round + 1);
		byte_buffer_put_virtual(&net_state->af_client_broadcast, net_header_BYTES);
		byte_buffer_put(&net_state->af_client_broadcast, mix->mix_af_dh_pks[0],
		                crypto_pk_BYTES);
		byte_buffer_put(&net_state->af_client_broadcast,
		                net_state->next_mix.read_buf.data + net_header_BYTES,
		                conn->curr_msg_len);

		uint8_t *ptr = mix->net_state.af_client_broadcast.data + net_header_BYTES + crypto_pk_BYTES;
		for (int i = 1; i <= mix->num_out_onion_layers; i++) {
			memcpy(mix->mix_af_dh_pks[i], ptr, crypto_pk_BYTES);
			ptr += crypto_pk_BYTES;
		}

		if (mix->server_id > 0) {
			net_epoll_queue_write(net_state, &net_state->prev_mix,
			                      net_state->af_client_broadcast.data,
			                      net_state->af_client_broadcast.used, true);
		}
		mix_af_newround(mix);
	}

	else if (conn->msg_type == NEW_DIAL_ROUND) {
		crypto_box_keypair(mix->mix_dial_dh_pks[0], mix->dial_dh_sk);
		// printhex("mix dial key", mix->mix_dial_dh_pks[0],
		// crypto_box_PUBLICKEYBYTES);
		byte_buffer_s *dial_broadcast_buf = &net_state->dial_client_broadcast;
		byte_buffer_clear(dial_broadcast_buf);
		serialize_uint32(dial_broadcast_buf->data, NEW_DIAL_ROUND);
		serialize_uint64(dial_broadcast_buf->data + 16, mix->dial_data.round + 1);
		serialize_uint32(dial_broadcast_buf->data + net_msg_type_BYTES,
		                 conn->curr_msg_len + crypto_pk_BYTES);
		byte_buffer_put_virtual(dial_broadcast_buf, net_header_BYTES);
		byte_buffer_put(dial_broadcast_buf, mix->mix_dial_dh_pks[0],
		                crypto_pk_BYTES);

		byte_buffer_put(dial_broadcast_buf,
		                net_state->next_mix.read_buf.data + net_header_BYTES,
		                conn->curr_msg_len);
		serialize_uint32(dial_broadcast_buf->data, NEW_DIAL_ROUND);

		uint8_t *ptr = dial_broadcast_buf->data + net_header_BYTES + crypto_pk_BYTES;
		for (int i = 1; i <= mix->num_out_onion_layers; i++) {
			memcpy(mix->mix_dial_dh_pks[i], ptr, crypto_pk_BYTES);
			ptr += crypto_pk_BYTES;
		}

		if (mix->server_id > 0) {
			net_epoll_queue_write(net_state, &net_state->prev_mix, dial_broadcast_buf->data,
			                      dial_broadcast_buf->used, true);
		}
		mix_dial_newround(mix);
	}

	else if (conn->msg_type == MIX_AF_BATCH) {
		mix->af_data.num_inc_msgs = conn->curr_msg_len / mix->af_data.inc_msg_length;
		byte_buffer_put(&mix->af_data.in_buf,
		                conn->read_buf.data + net_header_BYTES, conn->curr_msg_len);
		mix_af_decrypt_messages(mix);
		mix_af_shuffle(mix);

		if (mix->is_last) {
			mix_af_s *af = &mix->af_data;
			LOG_OUT(stdout,
			        "AF Round %lu: Received %d msgs, added %d noise, discarded %d "
					"cover msgs -> Distributing %d\n",
			        af->round, af->num_inc_msgs, af->last_noise_count,
			        af->num_inc_msgs + af->last_noise_count - af->num_out_msgs,
			        af->num_out_msgs);
			mix_af_distribute(mix);
			mix_exit_new_af_key(mix);
			mix_broadcast_new_afmb(mix, mix->af_data.round);
			char time_buffer[40];
			get_current_time(time_buffer);
			LOG_OUT(stdout, "[AF Round %lu] MB availability announced at %s\n", mix->af_data.round, time_buffer);
			mix->af_data.num_mailboxes = deserialize_uint64(conn->read_buf.data + 16);
			mix_af_newround(mix);
		}
		else {
			mix_af_s *af = &mix->af_data;
			LOG_OUT(stdout,
			        "AF Round %lu: Received %d msgs, added %d noise, forwarding %d\n",
			        af->round, af->num_inc_msgs, af->last_noise_count, af->num_out_msgs);
			mix->af_data.num_mailboxes = deserialize_uint64(conn->read_buf.data + 16);
			net_serialize_header(mix->af_data.out_buf.data,
			                     MIX_AF_BATCH,
			                     mix->af_data.num_out_msgs * mix->af_data.out_msg_length,
			                     mix->af_data.round,
			                     mix->af_data.num_mailboxes);
			mix_batch_forward(mix, &mix->af_data.out_buf);
		}

	}

	else if (conn->msg_type == MIX_DIAL_BATCH) {
		mix->dial_data.num_inc_msgs = conn->curr_msg_len / mix->dial_data.inc_msg_length;
		byte_buffer_put(&mix->dial_data.in_buf,
		                conn->read_buf.data + net_header_BYTES, conn->curr_msg_len);
		mix_dial_decrypt_messages(mix);

		if (mix->is_last) {
			mix_dial_s *dd = &mix->dial_data;
			uint32_t discarded = dd->num_inc_msgs + dd->last_noise_count - dd->num_out_msgs;
			LOG_OUT(stdout,
			        "Dial Round %lu: Received %d msgs, added %u noise, discarded %u "
					"noise -> Distributing %d\n",
			        dd->round, dd->num_inc_msgs, dd->last_noise_count, discarded,
			        dd->num_out_msgs);
			char time_buffer[40];
			get_current_time(time_buffer);
			LOG_OUT(stdout,
			        "[Dial Round %lu] MB availability announced at %s\n",
			        mix->dial_data.round,
			        time_buffer);
			mix_dial_distribute(mix);
			mix_exit_new_dial_key(mix);
			mix_broadcast_new_dialmb(mix, mix->dial_data.round);
			mix->dial_data.num_mailboxes = deserialize_uint64(conn->read_buf.data + 16);
			mix_dial_newround(mix);
		}
		else {
			mix_dial_s *dd = &mix->dial_data;
			LOG_OUT(stdout,
			        "Dial Round %lu: Received %d msgs, added %u noise -> forwarding %d\n",
			        dd->round, dd->num_inc_msgs, dd->last_noise_count,
			        dd->num_out_msgs);
			mix_dial_shuffle(mix);
			byte_buffer_s *buf = &mix->dial_data.out_buf;
			mix->dial_data.num_mailboxes = deserialize_uint64(conn->read_buf.data + 16);
			net_serialize_header(mix->dial_data.out_buf.data,
			                     MIX_DIAL_BATCH,
			                     mix->dial_data.num_out_msgs * mix->dial_data.out_msg_length,
			                     mix->dial_data.round,
			                     mix->dial_data.num_mailboxes);

			mix_batch_forward(mix, buf);
		}

	}
	return 0;
}

int mix_connect_neighbour(int srv_id)
{
	if (srv_id <= 0) {
		fprintf(stderr, "invalid server id %d\n", srv_id);
		return -1;
	}
	const char *port = mix_listen_ports[srv_id - 1];

	int sock_fd = net_connect(mix_server_ips[srv_id - 1], port, 0);
	if (sock_fd == -1) {
		return -1;
	}
	return sock_fd;
}

int mix_net_sync(mix_s *mix)
{
	uint32_t srv_id = mix->server_id;
	net_server_state *net_state = &mix->net_state;

	if (mix->is_last) {
		mix_dial_add_noise(mix);
		mix_af_add_noise(mix);

		int listen_socket = net_start_listen_socket(mix_listen_ports[srv_id], 1);
		if (listen_socket == -1) {
			fprintf(stderr, "failed to start listen socket %s\n", mix_listen_ports[srv_id]);
			return -1;
		}

		net_state->listen_socket = listen_socket;
		connection *listen_conn = calloc(1, sizeof *listen_conn);
		listen_conn->sock_fd = net_state->listen_socket;
		struct epoll_event event;
		event.data.ptr = listen_conn;
		event.events = EPOLLIN | EPOLLET;
		epoll_ctl(net_state->epoll_fd, EPOLL_CTL_ADD, net_state->listen_socket,
		          &event);

	}
		// Unless we're the last server in the mixnet chain, setup a temp listening
		// socket to allow the next server
		// to establish a connection
	else {
		int listen_socket = net_start_listen_socket(mix_listen_ports[srv_id], 0);
		net_state->listen_socket = listen_socket;
		int next_mix_sfd = net_accept(listen_socket, 0);

		if (next_mix_sfd == -1) {
			fprintf(stderr, "fatal error on listening socket %s\n", mix_listen_ports[srv_id]);
			return -1;
		}
		connection_init(&net_state->next_mix, 540000000, 540000000,
		                mix_process_mix_msg, net_state->epoll_fd, next_mix_sfd);
		int res = net_read_blocking(
			net_state->next_mix.sock_fd, net_state->next_mix.read_buf.data,
			net_state->bc_buf.capacity - (2 * crypto_pk_BYTES));
		if (res) {
			fprintf(stderr, "fatal socket error during mix startup\n");
			return -1;
		}

		byte_buffer_put(&net_state->bc_buf,
		                net_state->next_mix.read_buf.data + net_header_BYTES,
		                net_state->bc_buf.capacity - (2 * crypto_pk_BYTES) - net_header_BYTES);

		uint8_t *ptr = net_state->bc_buf.data + net_header_BYTES + (2 * crypto_pk_BYTES);
		for (int i = 1; i <= mix->num_out_onion_layers; i++) {
			memcpy(mix->mix_af_dh_pks[i], ptr, crypto_pk_BYTES);
			ptr += crypto_pk_BYTES;
			memcpy(mix->mix_dial_dh_pks[i], ptr, crypto_pk_BYTES);
			ptr += crypto_pk_BYTES;
		}

		mix_dial_add_noise(mix);
		mix_af_add_noise(mix);

		close(listen_socket);
		net_state->listen_socket = -1;
		res = socket_set_nonblocking(net_state->next_mix.sock_fd);
		if (res) {
			fprintf(stderr, "error when setting socket to non blocking\n");
			return -1;
		}
	}

	if (mix->server_id > 0) {
		int neighbour_sockfd = mix_connect_neighbour(mix->server_id);
		if (neighbour_sockfd == -1) {
			fprintf(stderr, "Failed to connect to neighbour in mixchain\n");
			return -1;
		}

		connection_init(&net_state->prev_mix, 540000000, 540000000,
		                mix_process_mix_msg, net_state->epoll_fd, neighbour_sockfd);

		int res = net_send_blocking(net_state->prev_mix.sock_fd, net_state->bc_buf.data,
		                            net_state->bc_buf.capacity);
		if (res) {
			fprintf(stderr,
			        "socker error writing to previous server in mixnet chain\n");
			return -1;
		}

		res = socket_set_nonblocking(net_state->prev_mix.sock_fd);
		if (res) {
			fprintf(stderr, "failure setting socket to non blocking mode\n");
			return -1;
		}
		mix->af_data.round++;
		mix->dial_data.round++;
	}
	printf("[Mix server %d: initialised]\n", mix->server_id);

	return 0;
}

void mix_entry_client_onconnect(void *s, connection *conn)
{
	mix_s *mix = (mix_s *) s;
	net_epoll_queue_write(&mix->net_state, conn, mix->net_state.bc_buf.data, net_header_BYTES,
	                      0);
}

void mix_remove_client(mix_s *s, connection *conn)
{
	if (conn == s->net_state.clients) {
		s->net_state.clients = conn->next;
	}
	if (conn->next) {
		conn->next->prev = conn->prev;
	}
	if (conn->prev) {
		conn->prev->next = conn->next;
	}
	free(conn);
}

void mix_broadcast_dialround(mix_s *s)
{
	serialize_uint64(s->net_state.bc_buf.data + 16, s->dial_data.round);
	connection *conn = s->net_state.clients;
	byte_buffer_s *dial_broadcast = &s->net_state.dial_client_broadcast;
	serialize_uint64(dial_broadcast->data + 8, s->dial_data.round);
	serialize_uint64(dial_broadcast->data + 16, s->dial_data.num_mailboxes);

	while (conn) {
		net_epoll_queue_write(&s->net_state, conn, dial_broadcast->data,
		                      dial_broadcast->capacity, 0);
		conn = conn->next;
	}
}

void mix_broadcast_new_dialmb(mix_s *s, uint64_t round)
{
	uint8_t bc_buff[net_header_BYTES];
	serialize_uint32(bc_buff, NEW_DMB_AVAIL);
	serialize_uint32(bc_buff + 4, 0);
	serialize_uint32(bc_buff + net_msg_type_BYTES, 0);
	serialize_uint64(bc_buff + 8, round);
	connection *conn = s->net_state.clients;
	while (conn) {
		send(conn->sock_fd, bc_buff, sizeof bc_buff, 0);
		conn = conn->next;
	}
}

void mix_broadcast_new_afmb(mix_s *s, uint64_t round)
{
	uint8_t bc_buff[net_header_BYTES];
	memset(bc_buff, 0, sizeof bc_buff);
	serialize_uint32(bc_buff, NEW_AFMB_AVAIL);
	serialize_uint32(bc_buff + 4, 0);
	serialize_uint64(bc_buff + 8, round);
	connection *conn = s->net_state.clients;
	while (conn) {
		send(conn->sock_fd, bc_buff, sizeof bc_buff, 0);
		conn = conn->next;
	}
}

void mix_broadcast_new_afr(mix_s *s)
{
	connection *conn = s->net_state.clients;
	byte_buffer_s *af_broadcast = &s->net_state.af_client_broadcast;
	serialize_uint64(af_broadcast->data + 16, s->af_data.num_mailboxes);
	while (conn) {
		net_epoll_queue_write(&s->net_state, conn, af_broadcast->data, af_broadcast->capacity,
		                      0);
		conn = conn->next;
	}
}

int mix_entry_sync(mix_s *mix)
{
	net_server_state *net_state = &mix->net_state;
	int res;
	struct epoll_event event;
	event.events = EPOLLIN | EPOLLET;
	int listen_fd = net_start_listen_socket(mix_entry_pkg_listenport, 0);

	// Wait for PKG servers to connect
	for (int i = 0; i < num_pkg_servers; i++) {
		int fd = net_accept(listen_fd, 1);
		connection_init(&net_state->pkg_conns[i], 2048, 2048, NULL,
		                net_state->epoll_fd, fd);
	}

	close(listen_fd);

	// Wait for the rest of the mixnet servers to start and connect to us
	res = mix_net_sync(mix);
	if (res) {
		fprintf(stderr, "fatal error during mixnet startup\n");
		return -1;
	}

	byte_buffer_s *bc_buf = &net_state->bc_buf;
	byte_buffer_clear(bc_buf);
	serialize_uint32(bc_buf->data, MIX_SYNC);
	serialize_uint32(bc_buf->data + net_msg_type_BYTES, 0);
	serialize_uint64(bc_buf->data + 8, mix->af_data.round);
	serialize_uint64(bc_buf->data + 16, mix->dial_data.round);

	mix->af_data.round++;
	mix->dial_data.round++;
	serialize_uint32(net_state->af_client_broadcast.data, NEW_AF_ROUND);
	serialize_uint32(net_state->dial_client_broadcast.data, NEW_DIAL_ROUND);
	serialize_uint32(net_state->af_client_broadcast.data + net_msg_type_BYTES,
	                 (uint32_t) net_state->af_client_broadcast.capacity - net_header_BYTES);
	serialize_uint32(
		net_state->dial_client_broadcast.data + net_msg_type_BYTES,
		(uint32_t) net_state->dial_client_broadcast.capacity - net_header_BYTES);
	serialize_uint64(net_state->af_client_broadcast.data + 8, mix->af_data.round);
	serialize_uint64(net_state->dial_client_broadcast.data + 16,
	                 mix->dial_data.round);
	byte_buffer_put_virtual(&net_state->af_client_broadcast, net_header_BYTES);
	byte_buffer_put_virtual(&net_state->dial_client_broadcast, net_header_BYTES);
	for (int i = 0; i < num_mix_servers; i++) {
		byte_buffer_put(&net_state->af_client_broadcast, mix->mix_af_dh_pks[i],
		                crypto_pk_BYTES);
		byte_buffer_put(&net_state->dial_client_broadcast, mix->mix_dial_dh_pks[i],
		                crypto_pk_BYTES);
	}

	// Start mix_main listening socket for client connections
	net_state->listen_socket = net_start_listen_socket(mix_entry_client_listenport, 1);
	if (net_state->listen_socket == -1) {
		fprintf(stderr, "entry mix error when starting listensocket\n");
		return -1;
	}
	connection *listen_conn = calloc(1, sizeof *listen_conn);
	listen_conn->sock_fd = net_state->listen_socket;
	event.data.ptr = listen_conn;
	event.events = EPOLLIN | EPOLLET;
	epoll_ctl(net_state->epoll_fd, EPOLL_CTL_ADD, net_state->listen_socket,
	          &event);
	printf("[Mix entry: system initialised on socket %d %d]\n",
	       mix->net_state.listen_socket, net_state->listen_socket);
	return 0;
}

int mix_process_client_msg(void *server, connection *conn)
{
	mix_s *mix = (mix_s *) server;

	if (conn->msg_type == CLIENT_DIAL_MSG) {
		mix_entry_add_dial_msg(mix, conn->read_buf.data + net_header_BYTES);
	}
	else if (conn->msg_type == CLIENT_AF_MSG) {
		mix_entry_add_af_message(mix, conn->read_buf.data + net_header_BYTES);
	}
	else {
		fprintf(stderr, "Invalid client msg\n");
	}
	return 0;
}

int mix_net_init(mix_s *mix)
{
	net_server_state *net_state = &mix->net_state;
	net_state->owner = mix;
	net_state->epoll_fd = epoll_create1(0);

	if (net_state->epoll_fd == -1) {
		fprintf(stderr, "Entry Server: failure when creating epoll instance\n");
		return -1;
	}
	signal(SIGPIPE, SIG_IGN);

	uint32_t buffer_size = crypto_pk_BYTES * 2 * (num_mix_servers - mix->server_id);
	byte_buffer_init(&net_state->bc_buf, net_header_BYTES + buffer_size);

	byte_buffer_init(&net_state->af_client_broadcast,
	                 net_header_BYTES + buffer_size / 2);
	byte_buffer_init(&net_state->dial_client_broadcast,
	                 net_header_BYTES + buffer_size / 2);
	serialize_uint32(net_state->bc_buf.data, MIX_SYNC);
	serialize_uint32(net_state->bc_buf.data + net_msg_type_BYTES, buffer_size);
	serialize_uint64(net_state->bc_buf.data + 8, mix->af_data.round);
	serialize_uint64(net_state->bc_buf.data + 16, mix->dial_data.round);
	byte_buffer_put_virtual(&net_state->bc_buf, net_header_BYTES);

	byte_buffer_put(&net_state->bc_buf, mix->mix_af_dh_pks[0], crypto_pk_BYTES);
	byte_buffer_put(&net_state->bc_buf, mix->mix_dial_dh_pks[0], crypto_pk_BYTES);
	net_state->events = calloc(2000, sizeof *net_state->events);
	net_state->clients = NULL;
	net_state->af_window_close = -1;
	net_state->dial_window_close = -1;

	return 0;
}

void mix_batch_forward(mix_s *mix, byte_buffer_s *buf)
{
	net_epoll_queue_write(&mix->net_state, &mix->net_state.next_mix, buf->data, buf->used,
	                      true);
}

void mix_af_calc_num_mbs(mix_s *mix)
{
	mix->af_data.num_mailboxes = 1;
}

void mix_dial_calc_num_mbs(mix_s *mix)
{
	mix->dial_data.num_mailboxes = 1;
}

void mix_entry_new_af_round(mix_s *mix)
{
	serialize_uint64(mix->net_state.bc_buf.data + 8, mix->af_data.round);
	mix_broadcast_new_afr(mix);
	mix_pkg_broadcast(mix, NEW_AF_ROUND);
	char time_buffer[40];
	get_current_time(time_buffer);
	LOG_OUT(stdout, "[AF Round %lu] Started at %s\n", mix->af_data.round, time_buffer);
}

void mix_entry_process_af_batch(mix_s *mix)
{
	mix_af_decrypt_messages(mix);
	byte_buffer_clear(&mix->af_data.in_buf);

	mix_af_s *af_data = &mix->af_data;
	char time_buffer[40];
	get_current_time(time_buffer);
	LOG_OUT(stdout, "[Entry] AF Round %ld: Received %d msgs, added %d noise -> Forwarding %d at %s\n",
	        af_data->round, af_data->num_inc_msgs, af_data->last_noise_count,
	        af_data->num_out_msgs, time_buffer);
	mix->af_data.num_inc_msgs = 0;
	mix_af_calc_num_mbs(mix);
	net_serialize_header(mix->af_data.out_buf.data,
	                     MIX_AF_BATCH,
	                     mix->af_data.num_out_msgs * mix->af_data.out_msg_length,
	                     mix->af_data.round,
	                     mix->af_data.num_mailboxes);

	mix_batch_forward(mix, &mix->af_data.out_buf);
	byte_buffer_clear(&mix->af_data.out_buf);
	mix->af_data.num_out_msgs = 0;
}

void mix_entry_process_dial_batch(mix_s *mix)
{
	mix_dial_decrypt_messages(mix);
	byte_buffer_clear(&mix->dial_data.in_buf);
	mix_dial_s *dd = &mix->dial_data;
	char time_buffer[40];
	get_current_time(time_buffer);
	LOG_OUT(stdout, "Dial Round %ld: Received %d msgs, added %u noise -> Forwarding %d at %s\n",
	        dd->round, dd->num_inc_msgs, dd->last_noise_count, dd->num_out_msgs, time_buffer);

	mix->dial_data.num_inc_msgs = 0;
	mix_dial_calc_num_mbs(mix);
	net_serialize_header(mix->dial_data.out_buf.data,
	                     MIX_DIAL_BATCH,
	                     mix->dial_data.num_out_msgs * mix->dial_data.out_msg_length,
	                     mix->dial_data.round,
	                     mix->dial_data.num_mailboxes);
	mix_batch_forward(mix, &mix->dial_data.out_buf);
	byte_buffer_clear(&mix->dial_data.out_buf);
	mix->dial_data.num_out_msgs = 0;
}

void mix_entry_new_dial_round(mix_s *mix)
{
	mix_broadcast_dialround(mix);
	char time_buffer[40];
	get_current_time(time_buffer);
	LOG_OUT(stdout, "[Dial Round %lu] Started at %s\n", mix->dial_data.round, time_buffer);
}

void mix_entry_check_timers(mix_s *s)
{
	time_t rem;

	if (s->net_state.dial_window_close > 0) {
		rem = s->net_state.dial_window_close - time(0);
		if (rem <= 0) {
			mix_entry_process_dial_batch(s);
			s->net_state.dial_window_close = -1;
		}
	}

	if (s->net_state.af_window_close > 0) {
		rem = s->net_state.af_window_close - time(0);
		if (rem <= 0) {
			mix_entry_process_af_batch(s);
			s->net_state.af_window_close = -1;
		}
	}

	rem = s->net_state.next_dial_round - time(0);

	if (rem <= 0) {
		mix_entry_new_dial_round(s);
		s->net_state.next_dial_round = time(0) + s->dial_data.round_duration;
		s->net_state.dial_window_close = time(0) + s->dial_data.accept_window_duration;
		printf("New dial round started: %lu\n", s->dial_data.round);
	}

	rem = s->net_state.next_af_round - time(0);
	double proportion_remaining = (double) rem / s->af_data.round_duration;
	if (proportion_remaining <= 0.3) {
		if (!s->pkg_preprocess_check) {
			printf("%lu of %u remaining (%f), informing PKGs\n", rem, s->af_data.round_duration, proportion_remaining);
			mix_pkg_broadcast(s, AF_START_GEN_KEYS);
			s->pkg_preprocess_check = true;
		}
	}

	if (rem <= 0) {
		mix_entry_new_af_round(s);
		s->pkg_preprocess_check = false;
		s->net_state.next_af_round = time(0) + s->af_data.round_duration;
		s->net_state.af_window_close = time(0) + s->af_data.accept_window_duration;
		printf("New add friend round started: %lu\n", s->af_data.round);
	}
}

void mix_run(mix_s *mix,
             void on_accept(void *, connection *),
             int on_read(void *, connection *))
{
	net_server_state *es = &mix->net_state;
	struct epoll_event *events = es->events;

	es->running = 1;
	es->next_af_round = time(0) + mix->af_data.round_duration;
	es->next_dial_round = time(0) + mix->dial_data.round_duration;

	while (es->running) {
		if (mix->server_id == 0) {
			mix_entry_check_timers(mix);
		}

		int num_events = epoll_wait(es->epoll_fd, es->events, 2000, 10000);
		for (int i = 0; i < num_events; i++) {
			connection *conn = events[i].data.ptr;
			if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
				fprintf(stderr, "Error on socket %d\n", conn->sock_fd);
				close(conn->sock_fd);
				mix_remove_client(mix, conn);
				continue;
			}
			else if (es->listen_socket == conn->sock_fd) {
				net_epoll_client_accept(&mix->net_state, on_accept, on_read);
			}
			else if (events[i].events & EPOLLIN) {
				net_epoll_read(mix, conn);
			}
			else if (events[i].events & EPOLLOUT) {
				net_epoll_send_queue(&mix->net_state, conn);
			}
		}
	}
}

void sim_mix_entry_process_af_batch(mix_s *mix)
{
	mix_af_decrypt_messages(mix);
	byte_buffer_clear(&mix->af_data.in_buf);

	mix_af_s *af_data = &mix->af_data;
	printf("AF Round %ld: Received %d msgs, added %d noise -> Forwarding %d\n",
	       af_data->round, af_data->num_inc_msgs, af_data->last_noise_count,
	       af_data->num_out_msgs);
	mix->af_data.num_inc_msgs = 0;
	mix_af_calc_num_mbs(mix);

	mix->af_data.num_out_msgs = 0;
}

int sim_mix_onion_encrypt_msg(mix_s *mix,
                              uint8_t *msg,
                              uint32_t msg_len,
                              uint8_t **keys)
{
	uint8_t *curr_dh_pub_ptr;
	for (uint32_t i = 0; i < num_mix_servers; i++) {
		curr_dh_pub_ptr = keys[mix->num_out_onion_layers - i];
		mix_add_onion_layer(msg, msg_len, i, curr_dh_pub_ptr);
	}
	return 0;
}

int
sim_mix_parallel_fake_client_traffic(mix_s *server, int p)
{
	double start_timer = get_time();
	uint32_t num_threads = server->num_threads;
	pthread_t threads[num_threads];
	mix_thread_args args[num_threads];
	uint32_t num_real_msgs = (uint32_t) ((1000000 / 100) * 5);
	uint32_t num_cover_msgs = (uint32_t) ((1000000 / 100) * 95);

	uint32_t num_real_per_thread = num_real_msgs / num_threads;
	uint32_t num_cover_per_thread = num_cover_msgs / num_threads;

	pthread_mutex_t *mut = calloc(1, sizeof *mut);
	pthread_mutex_init(mut, NULL);


	for (int i = 0; i < num_threads; i++) {
		args[i].mix = server;
		args[i].num_msgs = num_real_per_thread;
		args[i].num_fake_msgs = num_cover_per_thread;
		args[i].mutex = mut;
	}

	void *func;
	if (p == 0) {
		func = sim_mix_af_entry_add_noise;
	}
	else {
		func = sim_mix_entry_dial_add_noise;
	}

	for (int i = 0; i < num_threads; i++) {
		int res = pthread_create(&threads[i], NULL, func, &args[i]);
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

	return 0;
}

void sim_mix_entry_dial_add_noise(void *args)
{
	mix_thread_args *targs = (mix_thread_args *) args;
	uint32_t num_noise_msgs = targs->num_msgs;
	uint32_t num_cover_msgs = targs->num_fake_msgs;
	mix_s *mix = targs->mix;
	uint64_t num_mailboxes = mix->dial_data.num_mailboxes + 1;
	uint8_t *buf = calloc(mix->dial_data.inc_msg_length, num_noise_msgs + num_cover_msgs);
	uint8_t *curr_ptr = buf;
	for (uint64_t i = 0; i < num_mailboxes; i++) {
		uint32_t noise = num_noise_msgs;
		if (i == num_mailboxes - 1) {
			noise = num_cover_msgs;
		}
		for (int j = 0; j < noise; j++) {
			serialize_uint64(curr_ptr, i);
			randombytes_buf(curr_ptr + sizeof i, dialling_token_BYTES);
			sim_mix_onion_encrypt_msg(mix, curr_ptr, dialling_token_BYTES + mb_BYTES, mix->mix_dial_dh_pks);
			curr_ptr += mix->dial_data.inc_msg_length;
		}
	}

	pthread_mutex_lock(targs->mutex);
	byte_buffer_put(&mix->dial_data.in_buf, buf, mix->dial_data.inc_msg_length * (num_noise_msgs + num_cover_msgs));
	mix->dial_data.num_inc_msgs += num_noise_msgs + num_cover_msgs;
	pthread_mutex_unlock(targs->mutex);
	free(buf);
}

void *sim_mix_af_entry_add_noise(void *args)
{
#if !USE_PBC
	scalar_t random;
	curvepoint_fp_t tmp;
#endif

	mix_thread_args *targs = (mix_thread_args *) args;
	uint32_t num_noise_msgs = targs->num_msgs;
	uint32_t num_cover_msgs = targs->num_fake_msgs;
	mix_s *mix = targs->mix;

	uint8_t *buf = calloc(mix->af_data.inc_msg_length, num_noise_msgs + num_cover_msgs);
	uint8_t *curr_ptr = buf;
	uint64_t num_mailboxes = mix->af_data.num_mailboxes + 1;
	for (uint64_t i = 0; i < num_mailboxes; i++) {
		uint32_t noise = num_noise_msgs;
		if (i == num_mailboxes - 1) {
			noise = num_cover_msgs;
		}
		printf("Adding %d msgs to mailbox %ld\n", noise, i);
		for (int j = 0; j < noise; j++) {

			serialize_uint64(curr_ptr, i);
#if USE_PBC
			element_random(&mix->af_noise_Zr_elem);
			element_pow_zn(&mix->af_noise_G1_elem, &mix->ibe_gen_elem,
						   &mix->af_noise_Zr_elem);
			element_to_bytes_compressed(curr_ptr + mb_BYTES, &mix->af_noise_G1_elem);
#else
			bn256_scalar_random(random);
			bn256_scalarmult_base_g1(tmp, random);
			bn256_serialize_g1(curr_ptr + mb_BYTES, tmp);
#endif
			randombytes_buf(curr_ptr + mb_BYTES + g1_serialized_bytes, af_ibeenc_request_BYTES - g1_serialized_bytes);
			sim_mix_onion_encrypt_msg(mix, curr_ptr, af_ibeenc_request_BYTES + mb_BYTES, mix->mix_af_dh_pks);
			curr_ptr += mix->af_data.inc_msg_length;
		}
	}
	pthread_mutex_lock(targs->mutex);
	byte_buffer_put(&mix->af_data.in_buf, buf, mix->af_data.inc_msg_length * (num_noise_msgs + num_cover_msgs));
	mix->af_data.num_inc_msgs += num_noise_msgs + num_cover_msgs;
	pthread_mutex_unlock(targs->mutex);
	free(buf);
}

int sim_mix_main(int argc, char **argv)
{
	if (argc != 4) {
		fprintf(stderr, "invalid args\n");
		exit(EXIT_FAILURE);
	}
#if !USE_PBC
	bn256_init();
#endif
	long sid = strtol(argv[1], NULL, 10);
	uint32_t num_threads = (uint32_t) strtol(argv[2], NULL, 10);
	if (sid >= num_mix_servers || sid < 0) {
		fprintf(stderr, "invalid server id\n");
		exit(EXIT_FAILURE);
	}

	if (sid == 0) {
		mix_s mix;
		mix_init(&mix, 0, num_threads, 0);
		mix_net_init(&mix);
		mix_entry_sync(&mix);
		if (*argv[3] == 'A') {
			sim_mix_parallel_fake_client_traffic(&mix, 0);
			mix_entry_process_af_batch(&mix);
			while (mix.net_state.next_mix.send_queue_head) {
				printf("%ld left to send\n", mix.net_state.next_mix.send_queue_head->write_remaining);
				net_epoll_send_queue(&mix.net_state, &mix.net_state.next_mix);
			}
			//mix_run(&mix, mix_entry_client_onconnect, mix_process_client_msg);
		}
		else {
			sim_mix_parallel_fake_client_traffic(&mix, 1);
			mix_entry_process_dial_batch(&mix);
		}
		printf("Traffic forwarded, waiting for response\n");
		sleep(30);
	}
	else if (sid == num_mix_servers - 1) {
		mix_s mix;
		mix_init(&mix, (uint32_t) sid, num_threads, 0);
		mix_net_init(&mix);
		mix_net_sync(&mix);
		mix_run(&mix, NULL, mix_exit_process_client_msg);
	}

	else {
		mix_s mix;
		mix_init(&mix, (uint32_t) sid, num_threads, 0);
		mix_net_init(&mix);
		mix_net_sync(&mix);
		mix_run(&mix, NULL, mix_process_mix_msg);
	}

	return 0;
}

int mix_main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "invalid args\n");
		exit(EXIT_FAILURE);
	}
#if !USE_PBC
	bn256_init();
#endif
	long sid = strtol(argv[1], NULL, 10);
	uint32_t num_threads = (uint32_t) strtol(argv[2], NULL, 10);
	if (sid >= num_mix_servers || sid < 0) {
		fprintf(stderr, "invalid server id\n");
		exit(EXIT_FAILURE);
	}

	if (sid == 0) {
		mix_s mix;
		mix_init(&mix, 0, num_threads, 0);
		mix_net_init(&mix);
		mix_entry_sync(&mix);
		mix_run(&mix, mix_entry_client_onconnect, mix_process_client_msg);
	}
	else if (sid == num_mix_servers - 1) {
		mix_s mix;
		mix_init(&mix, (uint32_t) sid, num_threads, 0);
		mix_net_init(&mix);
		mix_net_sync(&mix);
		mix_run(&mix, NULL, mix_exit_process_client_msg);
	}

	else {
		mix_s mix;
		mix_init(&mix, (uint32_t) sid, num_threads, 0);
		mix_net_init(&mix);
		mix_net_sync(&mix);
		mix_run(&mix, NULL, mix_process_mix_msg);
	}

	return 0;
}