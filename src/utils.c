#include <netinet/in.h>
#include <memory.h>
#include "utils.h"

void printhex(char *msg, uint8_t *data, uint32_t len)
{
  uint32_t hex_len = len * 2 + 1;
  char hex_str[hex_len];
	sodium_bin2hex(hex_str, hex_len, data, len);
	printf("%s: %s\n", msg, hex_str);
}

void crypto_shared_secret(uint8_t *shared_secret,
                          uint8_t *scalar_mult,
                          uint8_t *client_pub,
                          uint8_t *server_pub,
                          uint32_t output_size)
{
  crypto_generichash_state hash_state;
	crypto_generichash_init(&hash_state, NULL, 0U, output_size);
	crypto_generichash_update(&hash_state, scalar_mult, crypto_scalarmult_BYTES);
	crypto_generichash_update(&hash_state, client_pub, crypto_box_PUBLICKEYBYTES);
	crypto_generichash_update(&hash_state, server_pub, crypto_box_PUBLICKEYBYTES);
	crypto_generichash_final(&hash_state, shared_secret, output_size);
};

void serialize_uint32(uint8_t *out, uint32_t in)
{
  uint32_t network_in = htonl(in);
  memcpy (out, &network_in, sizeof network_in);
};

uint32_t deserialize_uint32(uint8_t *in)
{
  uint32_t *ptr = (uint32_t *) in;
  return ntohl(*ptr);
}

void serialize_uint64(uint8_t *out, const uint64_t input)
{

	out[0] = (uint8_t) (input >> 56);
	out[1] = (uint8_t) (input >> 48);
	out[2] = (uint8_t) (input >> 40);
	out[3] = (uint8_t) (input >> 32);
	out[4] = (uint8_t) (input >> 24);
	out[5] = (uint8_t) (input >> 16);
	out[6] = (uint8_t) (input >> 8);
	out[7] = (uint8_t) (input >> 0);
}

uint64_t deserialize_uint64(uint8_t *in)
{
	uint64_t *ptr = (uint64_t *) in;
	return be64toh(*ptr);
}

int crypto_chacha_decrypt(uint8_t *m,
                          unsigned long long *mlen_p,
                          uint8_t *nsec,
                          const uint8_t *c,
                          unsigned long long clen,
                          const uint8_t *ad,
                          unsigned long long adlen,
                          const uint8_t *npub,
                          const uint8_t *k)
{
	return crypto_aead_chacha20poly1305_ietf_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k);
};

int byte_buffer_resize(byte_buffer_s *buf, ssize_t new_capacity)
{
	if (new_capacity <= buf->capacity) {
		fprintf(stderr, "cannot shrink buffer\n");
		return -1;
	}

	uint8_t *new_buf = realloc(buf->base, (size_t) new_capacity);
	if (!new_buf) {
		fprintf(stderr, "failed to resize byte buffer, realloc failure\n");
		return -1;
	}

	buf->base = new_buf;
	buf->data = new_buf + buf->prefix_size;
	buf->pos = buf->data + buf->used;
	buf->capacity = new_capacity;
	return 0;
}

int byte_buffer_put(byte_buffer_s *buf, uint8_t *data, size_t size)
{
	if (size > buf->capacity - buf->used) {
		int res = byte_buffer_resize(buf, buf->capacity * 2);
		if (res)
			return -1;
	}

	memcpy(buf->pos, data, size);
	buf->pos += size;
	buf->used += size;
	return 0;
}

int byte_buffer_put_virtual(byte_buffer_s *buf, size_t size)
{
	if (size > buf->capacity - buf->used) {
		int res = byte_buffer_resize(buf, buf->capacity * 2);
		if (res)
			return -1;
	}
	buf->pos += size;
	buf->used += size;
	return 0;
}

byte_buffer_s *byte_buffer_alloc(uint32_t capacity, uint32_t prefix_size)
{
	byte_buffer_s *buffer = calloc(1, sizeof *buffer);
	if (!buffer) {
		return NULL;
	}

	int res = byte_buffer_init(buffer, capacity, prefix_size);
	if (res) {
		free(buffer);
		return NULL;
	}
	return buffer;
}

int byte_buffer_init(byte_buffer_s *buf, uint32_t capacity, uint32_t prefix_size)
{
	buf->prefix_size = prefix_size;
	buf->capacity = capacity;
	buf->base = calloc(1, prefix_size + buf->capacity);

	if (!buf->base) {
		fprintf(stderr, "calloc error in mix_buf_init\n");
		return -1;
	}

	buf->data = buf->base + prefix_size;
	buf->pos = buf->data;
	buf->used = 0;
	return 0;
}

void byte_buffer_clear(byte_buffer_s *buf)
{
	buf->pos = buf->data;
	buf->used = 0;
}
