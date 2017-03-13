#include <string.h>
#include "mix.h"
#include "../lib/xxhash/xxhash.h"
#include <math.h>



int mix_buffers_init(mix_s *mix)
{
	uint32_t inc_onion_layer_bytes = (mix->num_inc_onion_layers * onion_layer_BYTES);
	uint32_t af_inc_msg_size = mb_BYTES + af_ibeenc_request_BYTES + inc_onion_layer_bytes;
	uint32_t dial_inc_msg_size = dialling_token_BYTES + mb_BYTES + inc_onion_layer_bytes;
	uint32_t af_out_msg_size = af_inc_msg_size - onion_layer_BYTES;
	uint32_t dial_out_msg_size = dial_inc_msg_size - onion_layer_BYTES;

	int result;
	result = byte_buffer_init(&mix->af_data.in_buf, mix_num_buffer_elems, af_inc_msg_size, 0);
	if (result)
		return -1;
	result = byte_buffer_init(&mix->af_data.out_buf, mix_num_buffer_elems, af_out_msg_size, net_header_BYTES);
	if (result)
		return -1;
	result = byte_buffer_init(&mix->dial_data.in_buf, mix_num_buffer_elems, dial_inc_msg_size, 0);
	if (result)
		return -1;
	result = byte_buffer_init(&mix->dial_data.out_buf, mix_num_buffer_elems, dial_out_msg_size, net_header_BYTES);
	if (result)
		return -1;

	return 0;
}

void mix_af_distribute(mix_s *mix)
{
	afmb_container_s *c = &mix->af_mb_container;
	memset(c, 0, sizeof(afmb_container_s));
	c->num_mailboxes = mix->af_data.num_mailboxes;
	c->round = mix->af_data.round;

	for (uint32_t i = 0; i < c->num_mailboxes; i++) {
		af_mailbox_s *mb = &c->mailboxes[i];
		mb->id = i;
		mb->num_messages = mix->af_data.mb_counts[i];
		uint32_t mailbox_sz = net_header_BYTES + (af_ibeenc_request_BYTES * mb->num_messages);
		printf("Mailbox num msgs: %d - Mailbox size bytes: %d\n", mb->num_messages, mailbox_sz);
		mb->size_bytes = mailbox_sz;
		mb->data = calloc(1, mailbox_sz);
		serialize_uint32(mb->data, AF_MB);
		serialize_uint32(mb->data + 4, mb->num_messages);
		mb->next_msg_ptr = mb->data + net_header_BYTES;
	}

	uint32_t curr_mailbox = 0;
	uint8_t *curr_msg_ptr = mix->af_data.out_buf.base + net_header_BYTES;
	af_mailbox_s *mb;

	for (uint32_t i = 0; i < mix->af_data.out_buf.num_msgs; i++) {
		curr_mailbox = deserialize_uint32(curr_msg_ptr);
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
	//mix_dial_update_stack_index(mix);
	dmb_container_s *c = &mix->dial_mb_containers[0];
	for (int i = 0; i < c->num_mailboxes; i++) {
		bloom_clear(&c->mailboxes[i].bloom);
	}
	memset(c, 0, sizeof(dmb_container_s));
	c->num_mailboxes = mix->dial_data.num_mailboxes;
	c->round = mix->dial_data.round;

	for (uint32_t i = 0; i < c->num_mailboxes; i++) {
		dial_mailbox_s *mb = &c->mailboxes[i];
		mb->id = i;
		mb->num_messages = mix->dial_data.mailbox_counts[i];
		mb->num_messages = 1000;
		bloom_init(&mb->bloom, mix->dial_data.bloom_p_val, mb->num_messages, 0, NULL, 16);
		// Fill in network prefix data
		serialize_uint32(mb->bloom.base_ptr, DIAL_MB);
		serialize_uint32(mb->bloom.base_ptr + 4, mb->bloom.total_size_bytes - net_header_BYTES);
		serialize_uint32(mb->bloom.base_ptr + 8, c->round);
		serialize_uint32(mb->bloom.base_ptr + 12, mb->num_messages);
	}

	uint8_t *curr_msg_ptr = mix->dial_data.out_buf.data;
	for (int i = 0; i < mix->dial_data.out_buf.num_msgs; i++) {
		uint32_t mailbox = deserialize_uint32(curr_msg_ptr);
		bloom_add_elem(&c->mailboxes[mailbox].bloom, curr_msg_ptr + mb_BYTES, dialling_token_BYTES);
		curr_msg_ptr += (mb_BYTES + dialling_token_BYTES);
	}
}

dial_mailbox_s *mix_dial_get_mailbox_buffer(mix_s *mix, uint32_t round, uint8_t *user_id)
{
/*
	if (round < mix->dial_data.round - mix_num_dial_mbs_stored) {
		return NULL;
	}
*/
	dmb_container_s *container = &mix->dial_mb_containers[0];

	uint32_t mb_num = (uint32_t) (XXH64(user_id, user_id_BYTES, 0) % container->num_mailboxes);
	return &mix->dial_mb_containers[0].mailboxes[mb_num];
}

void mix_af_add_inc_msg(mix_s *mix, uint8_t *buf)
{
	uint32_t msg_length = mix->af_data.in_buf.msg_len_bytes;
	memcpy(mix->af_data.in_buf.pos, buf, msg_length);
	mix->af_data.in_buf.pos += msg_length;
	mix->af_data.in_buf.num_msgs++;
}

void mix_dial_add_inc_msg(mix_s *mix, uint8_t *msg)
{
	uint32_t msg_length = mix->dial_data.in_buf.msg_len_bytes;
	memcpy(mix->dial_data.in_buf.pos, msg, msg_length);
	mix->dial_data.in_buf.pos += msg_length;
	mix->dial_data.in_buf.num_msgs++;
}

int mix_init(mix_s *mix, uint32_t server_id)
{
	int result;
	pairing_init_set_str(&mix->pairing, pbc_params);
	element_init_Zr(&mix->af_noise_Zr_elem, &mix->pairing);
	element_init_G1(&mix->ibe_gen_elem, &mix->pairing);
	element_init_G1(&mix->af_noise_G1_elem, &mix->pairing);
	result = element_set_str(&mix->ibe_gen_elem, ibe_generator, 10);
	if (result == 0) {
		fprintf(stderr, "Invalid string for ibe generation element\n");
		return -1;
	}

	mix->num_servers = num_mix_servers;
	mix->server_id = server_id;
	mix->is_last = num_mix_servers - mix->server_id == 1;

	mix->num_inc_onion_layers = num_mix_servers - server_id;
	mix->num_out_onion_layers = mix->num_inc_onion_layers - 1;
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

	mix->af_data.round = 0;
	mix->af_data.round_duration = 30;
	mix->dial_data.round = 0;
	mix->dial_data.round_duration = 20;
	mix->af_data.noisemu = 1;
	mix->dial_data.noisemu = 1;
	mix->af_data.num_mailboxes = 1;
	mix->dial_data.num_mailboxes = 1;
	memset(&mix->af_mb_container, 0, sizeof mix->af_mb_container);

	memset(mix->dial_data.mailbox_counts, 0, sizeof mix->dial_data.mailbox_counts);
	memset(mix->af_data.mb_counts, 0, sizeof mix->af_data.mb_counts);
	for (int i = 0; i < mix->num_inc_onion_layers; i++) {
		mix->mix_dh_pks[i] = calloc(1, crypto_box_PUBLICKEYBYTES);
		if (!mix->mix_dh_pks[i]) {
			fprintf(stderr, "fatal malloc error during setup\n");
			return -1;
		}
	}

	crypto_box_keypair(mix->mix_dh_pks[0], mix->eph_sk);
	//printhex("mix pk", mix->mix_dh_pks[0], crypto_box_PUBLICKEYBYTES);
	return 0;
}


void mix_af_newround(mix_s *mix)
{
	buffer_clear(&mix->af_data.in_buf);
	buffer_clear(&mix->af_data.out_buf);
	mix->af_data.round++;
	if (mix->is_last) {
		for (int i = 0; i < 5; i++) {
			mix->af_data.mb_counts[i] = 0;
		}
	}
	mix_af_add_noise(mix);
}

void mix_dial_newround(mix_s *mix)
{
	buffer_clear(&mix->dial_data.in_buf);
	buffer_clear(&mix->dial_data.out_buf);
	mix->dial_data.round++;
	if (mix->is_last) {
		for (int i = 0; i < 5; i++) {
			mix->dial_data.mailbox_counts[i] = 0;
		}
	}
	mix_dial_add_noise(mix);
}

void mix_shuffle_messages(uint8_t *messages, uint32_t msg_count, uint32_t msg_length)
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
	byte_buffer_s *buf = &mix->af_data.out_buf;
	printf("%p %p %u %u\n", (void *) buf->base, (void *) buf->pos, buf->num_msgs, buf->msg_len_bytes);
	mix_shuffle_messages(mix->af_data.out_buf.data,
	                     mix->af_data.out_buf.num_msgs,
	                     mix->af_data.out_buf.msg_len_bytes);
}

void mix_dial_shuffle(mix_s *mix)
{
	mix_shuffle_messages(mix->dial_data.out_buf.data,
	                     mix->dial_data.out_buf.num_msgs,
	                     mix->dial_data.out_buf.msg_len_bytes);
}

int mix_add_onion_layer(uint8_t *msg, uint32_t msg_len, uint32_t index, uint8_t *matching_pub_dh)
{
	// Add another layer of encryption to the request, append public DH key_state for server + nonce in clear (but authenticated)
	uint32_t message_length = msg_len + (onion_layer_BYTES * index);
	uint8_t *message_end_ptr = msg + message_length;
	uint8_t *dh_pub_ptr = message_end_ptr + crypto_MACBYTES;
	uint8_t *nonce_ptr = dh_pub_ptr + crypto_box_PUBLICKEYBYTES;

	uint8_t dh_secret[crypto_box_SECRETKEYBYTES];
	uint8_t scalar_mult[crypto_scalarmult_BYTES];
	uint8_t shared_secret[crypto_ghash_BYTES];
	randombytes_buf(dh_secret, crypto_box_SECRETKEYBYTES);
	crypto_scalarmult_base(dh_pub_ptr, dh_secret);
	//printhex("dh", matching_pub_dh, crypto_box_PUBLICKEYBYTES);
	int res = crypto_scalarmult(scalar_mult, dh_secret, matching_pub_dh);
	if (res) {
		fprintf(stderr, "Mix: scalar mult error while encrypting onion request\n");
		return -1;
	}
	crypto_shared_secret(shared_secret, scalar_mult, dh_pub_ptr, matching_pub_dh, crypto_generichash_BYTES);
	randombytes_buf(nonce_ptr, crypto_NBYTES);
	crypto_aead_chacha20poly1305_ietf_encrypt(msg, NULL, msg,
	                                          message_length, dh_pub_ptr, crypto_box_PUBLICKEYBYTES + crypto_NBYTES,
	                                          NULL, nonce_ptr, shared_secret);

	return 0;
};

int mix_onion_encrypt_msg(mix_s *mix, uint8_t *msg, uint32_t msg_len)
{
	uint8_t *curr_dh_pub_ptr;
	for (uint32_t i = 0; i < mix->num_out_onion_layers; i++) {
		curr_dh_pub_ptr = mix->mix_dh_pks[i + 1];
		mix_add_onion_layer(msg, msg_len, i, curr_dh_pub_ptr);
	}
	return 0;
}

void mix_dial_add_noise(mix_s *mix)
{
	for (uint32_t i = 0; i < mix->dial_data.num_mailboxes; i++) {
		for (int j = 0; j < mix->dial_data.noisemu; j++) {
			uint8_t *curr_ptr = mix->dial_data.out_buf.pos;
			serialize_uint32(curr_ptr, i);
			randombytes_buf(curr_ptr + sizeof i, dialling_token_BYTES);
			//printhex ("gen di", mix->dial_data.out_buf.buf_pos_ptr, dialling_token_BYTES + mailbox_BYTES);
			mix_onion_encrypt_msg(mix, curr_ptr, dialling_token_BYTES + mb_BYTES);
			mix->dial_data.out_buf.pos += mix->dial_data.out_buf.msg_len_bytes;
			mix->dial_data.out_buf.num_msgs++;
		}
		if (mix->num_out_onion_layers == 0) {
			mix->dial_data.mailbox_counts[i] += mix->dial_data.noisemu;
		}
	}
}

void mix_af_add_noise(mix_s *mix)
{
	for (uint32_t i = 0; i < mix->af_data.num_mailboxes; i++) {
		for (int j = 0; j < mix->af_data.noisemu; j++) {
			uint8_t *curr_ptr = mix->af_data.out_buf.pos;
			serialize_uint32(curr_ptr, i);
			element_random(&mix->af_noise_Zr_elem);
			element_pow_zn(&mix->af_noise_G1_elem, &mix->ibe_gen_elem, &mix->af_noise_Zr_elem);
			element_to_bytes_compressed(curr_ptr + mb_BYTES, &mix->af_noise_G1_elem);
			// After the group element, fill out the rest of the request with random data
			randombytes_buf(curr_ptr + mb_BYTES + g1_elem_compressed_BYTES,
			                af_ibeenc_request_BYTES - g1_elem_compressed_BYTES);
			//printhex("gen af", curr_ptr, mix->af_data.out_buf.msg_len_bytes);
			mix_onion_encrypt_msg(mix, curr_ptr, af_ibeenc_request_BYTES + mb_BYTES);
			mix->af_data.out_buf.pos += mix->af_data.out_buf.msg_len_bytes;
			mix->af_data.out_buf.num_msgs++;
		}
		if (mix->num_out_onion_layers == 0) {
			mix->af_data.mb_counts[i] += mix->af_data.noisemu;
		}
	}
}

int mix_remove_encryption_layer(mix_s *mix, uint8_t *out, uint8_t *c, uint32_t onionm_len)
{
	// Onion encrypted messages have the nonce and public key of DH keypair
	// appended to the end of the message directly after the MAC
	uint8_t *nonce_ptr = c + onionm_len - crypto_NBYTES;
	uint8_t *client_pub_dh_ptr = nonce_ptr - crypto_box_PUBLICKEYBYTES;
	uint8_t scalar_mult[crypto_scalarmult_BYTES];
	//printhex("entry dh", client_pub_dh_ptr, crypto_box_PUBLICKEYBYTES);
	int result = crypto_scalarmult(scalar_mult, mix->eph_sk, client_pub_dh_ptr);
	if (result) {
		fprintf(stderr, "Scalarmult error removing encryption layer\n");
		return -1;
	}

	uint8_t shared_secret[crypto_ghash_BYTES];
	crypto_shared_secret(shared_secret, scalar_mult, client_pub_dh_ptr, mix->mix_dh_pks[0], crypto_ghash_BYTES);

	uint32_t ctextlen = onionm_len - (crypto_box_PUBLICKEYBYTES + crypto_NBYTES);
	result = crypto_chacha_decrypt(out,
	                               NULL,
	                               NULL,
	                               c,
	                               ctextlen, client_pub_dh_ptr,
	                               crypto_box_PUBLICKEYBYTES + crypto_NBYTES,
	                               nonce_ptr,
	                               shared_secret);
	if (result) {
		fprintf(stderr, "Mix: Decryption error\n");
		return -1;
	}
	//printhex("decrypted token", out, mb_BYTES + crypto_ghash_BYTES);
	return 0;
}

int mix_update_mailbox_counts(uint32_t n, uint32_t num_mailboxes, uint32_t *mailbox_counts)
{
	if (n >= num_mailboxes)
		return -1;
	else
		mailbox_counts[n]++;

	return 0;
}

int mix_decrypt_messages(mix_s *mix,
                         uint8_t *in_ptr,
                         uint8_t *out_ptr,
                         uint32_t in_msg_len,
                         uint32_t out_msg_len,
                         uint32_t msg_count,
                         uint32_t num_mailboxes,
                         uint32_t *mailbox_counts)
{

	uint8_t *curr_in_ptr = in_ptr;
	uint8_t *curr_out_ptr = out_ptr;
	uint32_t decrypted_msg_count = 0;

	for (int i = 0; i < msg_count; i++) {
		int result = mix_remove_encryption_layer(mix, curr_out_ptr, curr_in_ptr, in_msg_len);
		curr_in_ptr += in_msg_len;
		if (!result) {
			// Last server in the mixnet chain
			if (mix->is_last) {
				uint32_t n = deserialize_uint32(curr_out_ptr);
				result = mix_update_mailbox_counts(n, num_mailboxes, mailbox_counts);
				if (result) {
					//printf("Invalid mailbox %d -- cover traffic\n", n);
				}
			}
			if (!result) {
				curr_out_ptr += out_msg_len;
				decrypted_msg_count++;
			}
		}
	}
	return decrypted_msg_count;
}

void mix_dial_decrypt_messages(mix_s *mix)
{
	uint8_t *in_ptr = mix->dial_data.in_buf.data;
	uint8_t *out_ptr = mix->dial_data.out_buf.pos;
	//printf("Num messages to decrypt: %d\n", mix->dial_data.in_buf.num_msgs);
	int n = mix_decrypt_messages(mix,
	                             in_ptr,
	                             out_ptr,
	                             mix->dial_data.in_buf.msg_len_bytes,
	                             mix->dial_data.out_buf.msg_len_bytes,
	                             mix->dial_data.in_buf.num_msgs,
	                             mix->dial_data.num_mailboxes,
	                             mix->dial_data.mailbox_counts);

	mix->dial_data.out_buf.num_msgs += n;
	mix->dial_data.out_buf.pos += n * (mix->dial_data.out_buf.msg_len_bytes);
	serialize_uint32(mix->dial_data.out_buf.base, DIAL_BATCH);
	serialize_uint32(mix->dial_data.out_buf.base + 4, mix->dial_data.out_buf.num_msgs);

}

void mix_af_decrypt_messages(mix_s *mix)
{
	uint8_t *in_ptr = mix->af_data.in_buf.data;
	uint8_t *out_ptr = mix->af_data.out_buf.pos;

	int n = mix_decrypt_messages(mix,
	                             in_ptr,
	                             out_ptr,
	                             mix->af_data.in_buf.msg_len_bytes,
	                             mix->af_data.out_buf.msg_len_bytes,
	                             mix->af_data.in_buf.num_msgs,
	                             mix->af_data.num_mailboxes,
	                             mix->af_data.mb_counts);

	mix->af_data.out_buf.num_msgs += n;
	//printf("%d messages decrypted, now %d total\n",n, mix->af_data.out_buf.num_msgs);
	mix->af_data.out_buf.pos += n * (mix->af_data.out_buf.msg_len_bytes);
	serialize_uint32(mix->af_data.out_buf.base, AF_BATCH);
	serialize_uint32(mix->af_data.out_buf.base + sizeof(uint32_t), mix->af_data.out_buf.num_msgs);
}

