#include "alpenhorn.h"
#include "mix.h"
#include <sodium.h>

typedef unsigned char byte_t;

const char sk_hex[] = "a81e5af67012c87ea3553210c2620037f56141c6bf58df6a75da1512500865e8";
const char pk_hex[] = "dc2a5d0ad83acd9027ffc587530cc26b0eb68679783bb0145e855fb03eaf1739";

void decrypt_request(byte_t *c, size_t len) {
  byte_t sk[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
  byte_t pk[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
  byte_t msg[af_request_BYTES];
  sodium_hex2bin(sk, crypto_aead_chacha20poly1305_IETF_KEYBYTES, sk_hex, 64, NULL, NULL, NULL);
  sodium_hex2bin(pk, crypto_aead_chacha20poly1305_IETF_KEYBYTES, pk_hex, 64, NULL, NULL, NULL);
  byte_t *nonce = c + len - crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
  byte_t *client_pub_dh = nonce - crypto_aead_chacha20poly1305_IETF_KEYBYTES;
  byte_t scalar_mult[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
  int res = crypto_scalarmult(scalar_mult, sk, client_pub_dh);
  if (res) {
    printf("Scalarmult error\n");
  }
  byte_t shared_secret[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
  crypto_shared_secret(shared_secret, scalar_mult, client_pub_dh, pk);
  char shared_hex[crypto_aead_chacha20poly1305_IETF_KEYBYTES * 2 + 1];
  sodium_bin2hex(shared_hex,
                 crypto_aead_chacha20poly1305_IETF_KEYBYTES * 2 + 1,
                 shared_secret,
                 crypto_aead_chacha20poly1305_IETF_KEYBYTES);
  printf("xy: %s\n", shared_hex);
  char nonce_hex[crypto_aead_chacha20poly1305_IETF_NPUBBYTES * 2 + 1];
  sodium_bin2hex(nonce_hex,
                 crypto_aead_chacha20poly1305_IETF_NPUBBYTES * 2 + 1,
                 nonce,
                 crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
  printf("on: %s\n", nonce_hex);
  uint32_t clen = af_request_BYTES + crypto_aead_chacha20poly1305_IETF_ABYTES;
  res = crypto_aead_chacha20poly1305_ietf_decrypt(msg,
                                                  NULL,
                                                  NULL,
                                                  c,
                                                  clen,
                                                  client_pub_dh,
                                                  crypto_aead_chacha20poly1305_IETF_KEYBYTES
                                                      + crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
                                                  nonce,
                                                  shared_secret);
  if (res) {
    printf("Decrypt error\n");
  }
  printf("%s\n", msg);

}


