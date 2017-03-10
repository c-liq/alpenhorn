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

int byte_buffer_init(byte_buffer_s *buf, uint32_t num_elems, uint32_t msg_size, uint32_t prefix_size)
{
	buf->num_msgs = 0;
	buf->prefix_size = prefix_size;
	buf->msg_len_bytes = msg_size;
	buf->capacity_msgs = num_elems;
	buf->capacity_bytes = num_elems * msg_size;
	buf->base = calloc(1, prefix_size + buf->capacity_bytes);
	if (!buf->base) {
		fprintf(stderr, "calloc error in mix_buf_init\n");
		return -1;
	}
	buf->pos = buf->base + prefix_size;
	buf->data = buf->base + prefix_size;
	return 0;
}

void buffer_clear(byte_buffer_s *buf)
{
	memset(buf->base, 0, buf->prefix_size);
	buf->pos = buf->data;
	buf->num_msgs = 0;
}
