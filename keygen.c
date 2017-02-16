

#include <sodium.h>
int main() {
  unsigned char pk[crypto_box_PUBLICKEYBYTES];
  unsigned char sk[crypto_box_SECRETKEYBYTES];
  char pk_hex[crypto_box_PUBLICKEYBYTES * 2 + 1];
  char sk_hex[crypto_box_SECRETKEYBYTES * 2 + 1];
  printf("ED25519 keypairs\n");
  for (int i = 0; i < 10; i++) {
    randombytes_buf(sk, crypto_box_SECRETKEYBYTES);
    crypto_scalarmult_base(pk, sk);
    sodium_bin2hex(pk_hex, crypto_box_PUBLICKEYBYTES * 2 + 1, pk, crypto_box_PUBLICKEYBYTES);
    sodium_bin2hex(sk_hex, crypto_box_SECRETKEYBYTES * 2 + 1, sk, crypto_box_SECRETKEYBYTES);
    printf("pk %d: %s\n", i, pk_hex);
    printf("sk %d: %s\n", i, sk_hex);
  }

}
