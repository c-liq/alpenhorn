#include <netinet/in.h>
#include <memory.h>
#include "utils.h"

void printhex(char *msg, byte_t *data, uint32_t len) {
  uint32_t hex_len = len * 2 + 1;
  char hex_str[hex_len];
  sodium_bin2hex(hex_str, hex_len, data, len);
  printf("%s: %s\n", msg, hex_str);
}

static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};

void print_b64(char *msg, byte_t *data,
               size_t input_length) {

  size_t output_length = 4 * ((input_length + 2) / 3);

  char encoded_data[output_length];

  for (int i = 0, j = 0; i < input_length;) {

      uint32_t octet_a = i < input_length ? data[i++] : 0;
      uint32_t octet_b = i < input_length ? data[i++] : 0;
      uint32_t octet_c = i < input_length ? data[i++] : 0;

      uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

      encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
      encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
      encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
      encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

  for (int i = 0; i < mod_table[input_length % 3]; i++)
    encoded_data[output_length - 1 - i] = '=';

  printf("%s: ", msg);
  for (int i = 0; i < sizeof encoded_data; i++) {
      printf("%c", encoded_data[i]);
    }
  printf("\n");
}
void crypto_shared_secret(byte_t *shared_secret,
                          byte_t *scalar_mult,
                          byte_t *client_pub,
                          byte_t *server_pub,
                          uint32_t output_size) {
  crypto_generichash_state hash_state;
  crypto_generichash_init(&hash_state, NULL, 0U, output_size);
  crypto_generichash_update(&hash_state, scalar_mult, crypto_scalarmult_BYTES);
  crypto_generichash_update(&hash_state, client_pub, crypto_box_PUBLICKEYBYTES);
  crypto_generichash_update(&hash_state, server_pub, crypto_box_PUBLICKEYBYTES);
  crypto_generichash_final(&hash_state, shared_secret, output_size);
};

void serialize_uint32(byte_t *out, uint32_t in) {
  uint32_t network_in = htonl(in);
  memcpy (out, &network_in, sizeof network_in);
};

uint32_t deserialize_uint32 (byte_t *in)
{
  uint32_t *ptr = (uint32_t *) in;
  return ntohl(*ptr);
}

int crypto_chacha_decrypt(unsigned char *m,
                          unsigned long long *mlen_p,
                          unsigned char *nsec,
                          const unsigned char *c,
                          unsigned long long clen,
                          const unsigned char *ad,
                          unsigned long long adlen,
                          const unsigned char *npub,
                          const unsigned char *k) {
  return crypto_aead_chacha20poly1305_ietf_decrypt(m, mlen_p, nsec, c, clen, ad, adlen, npub, k);
};