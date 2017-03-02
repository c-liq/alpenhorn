#include <string.h>
#include "mix.h"
#include <math.h>

int mix_buffer_init(byte_buffer_s *buf, u32 num_elems, u32 msg_size)
{
	buf->num_msgs = 0;
	buf->msg_len_bytes = msg_size;
	buf->capacity_msgs = num_elems;
	buf->capacity_bytes = num_elems * msg_size;
	buf->buf_base_ptr = calloc(1, buf->capacity_bytes);
	if (!buf->buf_base_ptr) {
		fprintf(stderr, "calloc error in mix_buf_init\n");
		return -1;
	}
	buf->buf_pos_ptr = buf->buf_base_ptr;
	return 0;
}

int mix_buffers_init(mix_s *mix)
{
	u32 inc_onion_layer_bytes = (mix->num_inc_onion_layers * onion_layer_BYTES);
	u32 af_inc_msg_size = mb_BYTES + af_ibeenc_request_BYTES + inc_onion_layer_bytes;
	u32 dial_inc_msg_size = dialling_token_BYTES + mb_BYTES + inc_onion_layer_bytes;
	u32 af_out_msg_size = af_inc_msg_size - onion_layer_BYTES;
	u32 dial_out_msg_size = dial_inc_msg_size - onion_layer_BYTES;

	int result;
	result = mix_buffer_init(&mix->af_data.in_buf, mix_num_buffer_elems, af_inc_msg_size);
	if (result)
		return -1;
	result = mix_buffer_init(&mix->af_data.out_buf, mix_num_buffer_elems, af_out_msg_size);
	if (result)
		return -1;
	result = mix_buffer_init(&mix->dial_data.in_buf, mix_num_buffer_elems, dial_inc_msg_size);
	if (result)
		return -1;
	result = mix_buffer_init(&mix->dial_data.out_buf, mix_num_buffer_elems, dial_out_msg_size);
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

	for (u32 i = 0; i < c->num_mailboxes; i++) {
		af_mailbox_s *mb = &c->mailboxes[i];
		mb->id = i;
		mb->num_messages = mix->af_data.mb_counts[i];
		u32 mailbox_sz = mb_BYTES + (af_ibeenc_request_BYTES * mb->num_messages);
		printf("Mailbox num msgs: %d - Mailbox size bytes: %d\n", mb->num_messages, mailbox_sz);
		mb->size_bytes = mailbox_sz;
		mb->data = calloc(1, mailbox_sz);
		serialize_uint32(mb->data, mb->num_messages);
		mb->next_msg_ptr = mb->data + mb_BYTES;
	}

	u32 curr_mailbox = 0;
	byte_t *curr_msg_ptr = mix->af_data.out_buf.buf_base_ptr + net_batch_prefix;
	af_mailbox_s *mb;

	for (u32 i = 0; i < mix->af_data.out_buf.num_msgs; i++) {
		curr_mailbox = deserialize_uint32(curr_msg_ptr);
		mb = &c->mailboxes[curr_mailbox];
		memcpy(mb->next_msg_ptr, curr_msg_ptr + mb_BYTES, af_ibeenc_request_BYTES);
		mb->next_msg_ptr += af_ibeenc_request_BYTES;
		curr_msg_ptr += mb_BYTES + af_ibeenc_request_BYTES;
	}
}

void mix_dial_distribute(mix_s *mix)
{
	dmb_container_s *c = &mix->dial_mb_container;
	memset(c, 0, sizeof(dmb_container_s));
	c->num_mailboxes = mix->dial_data.num_mailboxes;
	c->round = mix->dial_data.round;

	for (u32 i = 0; i < c->num_mailboxes; i++) {
		dial_mailbox_s *mb = &c->mailboxes[i];
		mb->id = i;
		mb->num_messages = mix->dial_data.mailbox_counts[i];
		bloom_init(&mb->bloom, mix->dial_data.bloom_p_val, mb->num_messages, 0, NULL, 12);
		// Fill in network prefix data
		serialize_uint32(mb->bloom.base_ptr, DIAL_MB);
		serialize_uint32(mb->bloom.base_ptr + sizeof(u32), c->round);
		serialize_uint32(mb->bloom.base_ptr + sizeof(u32) * 2, mb->num_messages);
	}

	u32 tmp_mailbox = 0;
	byte_t *curr_msg_ptr = mix->dial_data.out_buf.buf_base_ptr + net_batch_prefix;

	for (int i = 0; i < mix->dial_data.out_buf.num_msgs; i++) {
		tmp_mailbox = deserialize_uint32(curr_msg_ptr);
		bloom_add_elem(&c->mailboxes[tmp_mailbox].bloom, curr_msg_ptr + mb_BYTES, dialling_token_BYTES);
		curr_msg_ptr += (mb_BYTES + dialling_token_BYTES);
	}
}

void mix_af_add_inc_msg(mix_s *mix, byte_t *buf)
{
	u32 msg_length = mix->af_data.in_buf.msg_len_bytes;
	memcpy(mix->af_data.in_buf.buf_pos_ptr, buf, msg_length);
	mix->af_data.in_buf.buf_pos_ptr += msg_length;
	mix->af_data.in_buf.num_msgs++;
}

void mix_dial_add_inc_msg(mix_s *mix, byte_t *msg)
{
	u32 msg_length = mix->dial_data.in_buf.msg_len_bytes;
	memcpy(mix->dial_data.in_buf.buf_pos_ptr, msg, msg_length);
	mix->dial_data.in_buf.buf_pos_ptr += msg_length;
	mix->dial_data.in_buf.num_msgs++;
}

int mix_init(mix_s *mix, u32 server_id)
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
	mix->is_last = num_mix_servers - mix->server_id - 1 == 0;
	u32 num_inc_onion_layers = num_mix_servers - server_id;
	mix->num_inc_onion_layers = num_inc_onion_layers;
	mix->num_out_onion_layers = num_inc_onion_layers - 1;
	mix->dial_data.bloom_p_val = pow(10.0, -10.0);

	result = mix_buffers_init(mix);
	if (result) {
		fprintf(stderr, "Mix server: error initialising data buffers\n");
		return -1;
	}

	mix->af_data.round = 0;
	mix->af_data.round_duration = 60 * 5;
	mix->dial_data.round = 0;
	mix->dial_data.round_duration = 5;
	mix->af_data.noisemu = 1;
	mix->dial_data.noisemu = 50000;
	mix->af_data.num_mailboxes = 1;
	mix->dial_data.num_mailboxes = 1;
	memset(&mix->af_mb_container, 0, sizeof mix->af_mb_container);
	memset(&mix->dial_mb_container, 0, sizeof mix->dial_mb_container);
	memset(mix->dial_data.mailbox_counts, 0, sizeof mix->dial_data.mailbox_counts);
	memset(mix->af_data.mb_counts, 0, sizeof mix->af_data.mb_counts);

	crypto_box_keypair(mix->eph_pk, mix->eph_sk);
	return 0;
}

void mix_reset_buffer(byte_buffer_s *buf)
{
	buf->buf_pos_ptr = buf->buf_base_ptr;
	buf->num_msgs = 0;
}

void mix_af_newround(mix_s *mix)
{
	mix_reset_buffer(&mix->af_data.in_buf);
	mix_reset_buffer(&mix->af_data.out_buf);
	mix->af_data.round++;
	//crypto_box_keypair(mix->eph_pk, mix->eph_sk);
}

void mix_dial_newround(mix_s *mix)
{
	mix_reset_buffer(&mix->dial_data.in_buf);
	mix_reset_buffer(&mix->dial_data.out_buf);
	mix->dial_data.round++;
}

void mix_shuffle_messages(byte_t *messages, u32 msg_count, u32 msg_length)
{
	byte_t tmp_message[msg_length];
	for (u32 i = msg_count - 1; i >= 1; i--) {
		u32 j = randombytes_uniform(i);
		memcpy(tmp_message, messages + (i * msg_length), msg_length);
		memcpy(messages + (i * msg_length), messages + (j * msg_length), msg_length);
		memcpy(messages + (j * msg_length), tmp_message, msg_length);
	}
}

void mix_af_shuffle(mix_s *mix)
{
	mix_shuffle_messages(mix->af_data.out_buf.buf_base_ptr + net_batch_prefix,
	                     mix->af_data.out_buf.num_msgs,
	                     mix->af_data.out_buf.msg_len_bytes);
}

void mix_dial_shuffle(mix_s *mix)
{
	mix_shuffle_messages(mix->dial_data.out_buf.buf_base_ptr + net_batch_prefix,
	                     mix->dial_data.out_buf.num_msgs,
	                     mix->dial_data.out_buf.msg_len_bytes);
}

int mix_add_onion_layer(byte_t *msg, u32 msg_len, u32 index, byte_t *matching_pub_dh)
{
	// Add another layer of encryption to the request, append public DH key_state for server + nonce in clear (but authenticated)
	u32 message_length = msg_len + (onion_layer_BYTES * index);
	byte_t *message_end_ptr = msg + message_length;
	byte_t *dh_pub_ptr = message_end_ptr + crypto_MACBYTES;
	byte_t *nonce_ptr = dh_pub_ptr + crypto_box_PUBLICKEYBYTES;

	byte_t dh_secret[crypto_box_SECRETKEYBYTES];
	byte_t scalar_mult[crypto_scalarmult_BYTES];
	byte_t shared_secret[crypto_ghash_BYTES];
	randombytes_buf(dh_secret, crypto_box_SECRETKEYBYTES);
	crypto_scalarmult_base(dh_pub_ptr, dh_secret);

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
	//printhex("dh ptr", dh_pub_ptr, crypto_box_PUBLICKEYBYTES);
	//printhex("nonce ptr", nonce_ptr, crypto_NBYTES)

	return 0;
};

int mix_onion_encrypt_msg(mix_s *mix, byte_t *msg, u32 msg_len)
{
	byte_t *curr_dh_pub_ptr;
	for (u32 i = 0; i < (num_mix_servers - mix->server_id - 1); i++) {
		curr_dh_pub_ptr = mix->mix_dh_public_keys[num_mix_servers - i - 1];
		// printf("%d: %p\n", i, &mix_s->mix_dh_public_keys[i]);
		mix_add_onion_layer(msg, msg_len, i, curr_dh_pub_ptr);
	}
	return 0;
}

void mix_dial_add_noise(mix_s *mix)
{
	mix->dial_data.out_buf.buf_pos_ptr = mix->dial_data.out_buf.buf_base_ptr;
	mix->dial_data.out_buf.buf_pos_ptr += net_batch_prefix;
	for (u32 i = 0; i < mix->dial_data.num_mailboxes; i++) {
		for (int j = 0; j < mix->dial_data.noisemu; j++) {
			byte_t *curr_ptr = mix->dial_data.out_buf.buf_pos_ptr;
			serialize_uint32(curr_ptr, i);
			randombytes_buf(curr_ptr + sizeof i, dialling_token_BYTES);
			//printhex ("gen di", mix->dial_data.out_buf.buf_pos_ptr, dialling_token_BYTES + mailbox_BYTES);
			mix_onion_encrypt_msg(mix, curr_ptr, dialling_token_BYTES + mb_BYTES);
			mix->dial_data.out_buf.buf_pos_ptr += mix->dial_data.out_buf.msg_len_bytes;
			mix->dial_data.out_buf.num_msgs++;
		}
		if (mix->num_out_onion_layers == 0) {
			mix->dial_data.mailbox_counts[i] += mix->dial_data.noisemu;
		}
	}
}

void mix_af_add_noise(mix_s *mix)
{
	mix->af_data.out_buf.buf_pos_ptr = mix->af_data.out_buf.buf_base_ptr;
	mix->af_data.out_buf.buf_pos_ptr += net_batch_prefix;

	for (u32 i = 0; i < mix->af_data.num_mailboxes; i++) {
		for (int j = 0; j < mix->af_data.noisemu; j++) {
			byte_t *curr_ptr = mix->af_data.out_buf.buf_pos_ptr;
			serialize_uint32(curr_ptr, i);
			element_random(&mix->af_noise_Zr_elem);
			element_pow_zn(&mix->af_noise_G1_elem, &mix->ibe_gen_elem, &mix->af_noise_Zr_elem);
			element_to_bytes_compressed(curr_ptr + mb_BYTES, &mix->af_noise_G1_elem);
			// After the group element, fill out the rest of the request with random data
			randombytes_buf(curr_ptr + mb_BYTES + g1_elem_compressed_BYTES,
			                af_ibeenc_request_BYTES - g1_elem_compressed_BYTES);
			//printhex("gen af", curr_ptr, mix->af_data.out_buf.msg_len_bytes);
			mix_onion_encrypt_msg(mix, curr_ptr, af_ibeenc_request_BYTES + mb_BYTES);
			mix->af_data.out_buf.buf_pos_ptr += mix->af_data.out_buf.msg_len_bytes;
			mix->af_data.out_buf.num_msgs++;
		}
		if (mix->num_out_onion_layers == 0) {
			mix->af_data.mb_counts[i] += mix->af_data.noisemu;
		}
	}
}

int mix_remove_encryption_layer(mix_s *mix, byte_t *out, byte_t *c, u32 onionm_len)
{
	// Onion encrypted messages have the nonce and public key of DH keypair
	// appended to the end of the message directly after the MAC
	byte_t *nonce_ptr = c + onionm_len - crypto_NBYTES;
	byte_t *client_pub_dh_ptr = nonce_ptr - crypto_box_PUBLICKEYBYTES;
	byte_t scalar_mult[crypto_scalarmult_BYTES];

	int result = crypto_scalarmult(scalar_mult, mix->eph_sk, client_pub_dh_ptr);
	if (result) {
		fprintf(stderr, "Scalarmult error\n");
		return -1;
	}

	byte_t shared_secret[crypto_ghash_BYTES];
	crypto_shared_secret(shared_secret, scalar_mult, client_pub_dh_ptr, mix->eph_pk, crypto_ghash_BYTES);

	u32 ctextlen = onionm_len - (crypto_box_PUBLICKEYBYTES + crypto_NBYTES);
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
	return 0;
}

int mix_update_mailbox_counts(u32 n, u32 num_mailboxes, u32 *mailbox_counts)
{
	if (n >= num_mailboxes)
		return -1;
	else
		mailbox_counts[n]++;

	return 0;
}

int mix_decrypt_messages(mix_s *mix,
                         byte_t *in_ptr,
                         byte_t *out_ptr,
                         u32 in_msg_len,
                         u32 out_msg_len,
                         u32 msg_count,
                         u32 num_mailboxes,
                         u32 *mailbox_counts)
{

	byte_t *curr_in_ptr = in_ptr;
	byte_t *curr_out_ptr = out_ptr;
	u32 decrypted_msg_count = 0;

	for (int i = 0; i < msg_count; i++) {
		int result = mix_remove_encryption_layer(mix, curr_out_ptr, curr_in_ptr, in_msg_len);
		curr_in_ptr += in_msg_len;
		if (!result) {
			printf("dec %d", mix->server_id);
			printhex("", curr_out_ptr, out_msg_len);
			// Last server in the mixnet chain
			if (mix->num_out_onion_layers == 0) {
				u32 n = deserialize_uint32(curr_out_ptr);

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

void mix_dial_decrypt_messages(mix_s *mix)
{
	byte_t *in_ptr = mix->dial_data.in_buf.buf_base_ptr;
	byte_t *out_ptr = mix->dial_data.out_buf.buf_pos_ptr;

	int n = mix_decrypt_messages(mix,
	                             in_ptr,
	                             out_ptr,
	                             mix->dial_data.in_buf.msg_len_bytes,
	                             mix->dial_data.out_buf.msg_len_bytes,
	                             mix->dial_data.in_buf.num_msgs,
	                             mix->dial_data.num_mailboxes,
	                             mix->dial_data.mailbox_counts);

	mix->dial_data.out_buf.num_msgs += n;
	mix->dial_data.out_buf.buf_pos_ptr += n * (mix->dial_data.out_buf.msg_len_bytes);
	serialize_uint32(mix->dial_data.out_buf.buf_base_ptr, DIAL_BATCH);
	serialize_uint32(mix->dial_data.out_buf.buf_base_ptr + 4, mix->dial_data.out_buf.num_msgs);

}

void mix_af_decrypt_messages(mix_s *mix)
{
	byte_t *in_ptr = mix->af_data.in_buf.buf_base_ptr;
	byte_t *out_ptr = mix->af_data.out_buf.buf_pos_ptr;

	int n = mix_decrypt_messages(mix,
	                             in_ptr,
	                             out_ptr,
	                             mix->af_data.in_buf.msg_len_bytes,
	                             mix->af_data.out_buf.msg_len_bytes,
	                             mix->af_data.in_buf.num_msgs,
	                             mix->af_data.num_mailboxes,
	                             mix->af_data.mb_counts);

	mix->af_data.out_buf.num_msgs += n;
	mix->af_data.out_buf.buf_pos_ptr += n * (mix->af_data.out_buf.msg_len_bytes);
	serialize_uint32(mix->af_data.out_buf.buf_base_ptr, AF_BATCH);
	serialize_uint32(mix->af_data.out_buf.buf_base_ptr + sizeof(u32), mix->af_data.out_buf.num_msgs);
}

