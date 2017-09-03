#include <netinet/in.h>
#include <memory.h>
#include "utils.h"
#include <math.h>
#include <time.h>

void printhex(char *msg, uint8_t *data, size_t len)
{
	size_t hex_len = len * 2 + 1;
	char hex_str[hex_len];
	sodium_bin2hex(hex_str, hex_len, data, len);
	printf("%s: %s\n", msg, hex_str);
}

void crypto_shared_secret(uint8_t *shared_secret,
                          uint8_t *scalar_mult,
                          uint8_t *client_pub,
                          uint8_t *server_pub,
                          uint64_t output_size)
{
	crypto_generichash_state hash_state;
	crypto_generichash_init(&hash_state, NULL, 0U, output_size);
	crypto_generichash_update(&hash_state, scalar_mult, crypto_scalarmult_BYTES);
	crypto_generichash_update(&hash_state, client_pub, crypto_pk_BYTES);
	crypto_generichash_update(&hash_state, server_pub, crypto_pk_BYTES);
	crypto_generichash_final(&hash_state, shared_secret, output_size);
	sodium_memzero(&hash_state, sizeof hash_state);
}

void serialize_uint32(uint8_t *out, uint64_t in)
{
	uint64_t network_in = htonl(in);
	memcpy(out, &network_in, sizeof network_in);
}

uint64_t deserialize_uint64(uint8_t *in)
{
	uint64_t *ptr = (uint64_t *) in;
	return ntohl(*ptr);
}

uint64_t sizeof_serialized_bytes(uint64_t size)
{
	return size * 2 + 1;
}

ssize_t crypto_secret_nonce_seal(uint8_t *out, uint8_t *m, size_t mlen, uint8_t *k)
{
	randombytes_buf(out, crypto_NBYTES);
	unsigned long long clen;
	int res = crypto_aead_chacha20poly1305_ietf_encrypt(out + crypto_NBYTES,
	                                                    &clen,
	                                                    m,
	                                                    mlen,
	                                                    out,
	                                                    crypto_NBYTES,
	                                                    NULL,
	                                                    out,
	                                                    k);
	if (res) {
		return -1;
	}
	else {
		return (size_t) clen + crypto_NBYTES;
	}
}

int crypto_secret_nonce_open(uint8_t *out, uint8_t *c, size_t clen, uint8_t *k)
{
	return crypto_aead_chacha20poly1305_ietf_decrypt(out,
	                                                 NULL,
	                                                 NULL,
	                                                 c + crypto_NBYTES,
	                                                 clen - crypto_NBYTES,
	                                                 c,
	                                                 crypto_NBYTES,
	                                                 c,
	                                                 k);
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

uint64_t deserialize_uint32(uint8_t *in)
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
}

int byte_buffer_resize(byte_buffer_s *buf, uint64_t new_capacity)
{
	if (new_capacity <= buf->capacity) {
		fprintf(stderr, "cannot shrink buffer\n");
		return -1;
	}

	uint8_t *new_buf = realloc(buf->data, new_capacity);
	if (!new_buf) {
		fprintf(stderr, "failed to resize byte buffer, realloc failure\n");
		return -1;
	}
	buf->data = new_buf;
	buf->pos = buf->data + buf->used;
	buf->capacity = new_capacity;
	return 0;
}

int byte_buffer_put(byte_buffer_s *buf, uint8_t *data, size_t size)
{
	if (size > buf->capacity - buf->used) {
		uint64_t new_capacity = buf->capacity + (2 * size);
		int res = byte_buffer_resize(buf, new_capacity);
		if (res)
			return -1;
	}

	memcpy(buf->pos, data, size);
	buf->pos += size;
	buf->used += size;
	return 0;
}

void get_current_time(char *out_buffer)
{
	long millisec;
	struct tm *tm_info;
	struct timeval tv;
	char buffer[50];
	gettimeofday(&tv, NULL);

	millisec = lrint(tv.tv_usec / 1000.0); // Round to nearest millisec
	if (millisec >= 1000) { // Allow for rounding up to nearest second
		millisec -= 1000;
		tv.tv_sec++;
	}

	tm_info = localtime(&tv.tv_sec);

	strftime(buffer, 26, "%Y:%m:%d %H:%M:%S", tm_info);
	sprintf(out_buffer, "%s.%03ld\n", buffer, millisec);
}

int byte_buffer_put_virtual(byte_buffer_s *buf, size_t size)
{
	if (size > buf->capacity - buf->used) {
		int res = byte_buffer_resize(buf, buf->capacity + (2 * size));
		if (res)
			return -1;
	}
	buf->pos += size;
	buf->used += size;
	return 0;
}

byte_buffer_s *byte_buffer_alloc(uint64_t capacity)
{
	byte_buffer_s *buffer = calloc(1, sizeof *buffer);
	if (!buffer) {
		return NULL;
	}

	int res = byte_buffer_init(buffer, capacity);
	if (res) {
		free(buffer);
		return NULL;
	}
	return buffer;
}

int byte_buffer_init(byte_buffer_s *buf, uint64_t capacity)
{
	if (!buf) return -1;

	buf->capacity = capacity;
	buf->data = calloc(1, buf->capacity);
	buf->pos = buf->data;

	if (!buf->data) {
		fprintf(stderr, "calloc error in mix_buf_init\n");
		return -1;
	}

	buf->used = 0;
	return 0;
}

void byte_buffer_clear(byte_buffer_s *buf)
{
	if (!buf) return;

	memset(buf->data, 0, buf->capacity);
	buf->pos = buf->data;
	buf->used = 0;
}

uint64_t laplace_rand(laplace_s *l)
{
	double rand = ((double)(randombytes_random() % 10000) / 10000) - 0.5;
	int sign;
	double abs;
	if (rand < 0) {
		abs = -rand;
		sign = -1;
	}
	else {
		abs = rand;
		sign = 1;
	}
	double lv = log(1 - (2 * abs));
	lv *= sign;
	lv *= l->b;
	lv = l->mu - lv;
	if (lv < 0) {
		return laplace_rand(l);
	}
	return (uint64_t) lv;
}

double get_time()
{
	struct timeval t;
	struct timezone tzp;
	gettimeofday(&t, &tzp);
	return t.tv_sec + t.tv_usec * 1e-6;
}

