

#include <sodium.h>
int main() {
  unsigned char pk[crypto_sign_PUBLICKEYBYTES];
  unsigned char sk[crypto_sign_SECRETKEYBYTES];
  char pk_hex[10][crypto_sign_PUBLICKEYBYTES * 2 + 1];
  char sk_hex[10][crypto_sign_SECRETKEYBYTES * 2 + 1];
  printf("ED25519 keypairs\n");
  for (int i = 0; i < 10; i++) {
    crypto_sign_keypair(pk, sk);
    sodium_bin2hex(pk_hex[i], crypto_sign_PUBLICKEYBYTES * 2 + 1, pk, crypto_sign_PUBLICKEYBYTES);
    sodium_bin2hex(sk_hex[i], crypto_sign_SECRETKEYBYTES * 2 + 1, sk, crypto_sign_SECRETKEYBYTES);
  }
  for (int i = 0; i < 10; i++) {
    printf("%s\n", pk_hex[i]);
  }
  for (int i = 0; i < 10; i++) {
    printf("%s\n", sk_hex[i]);
  }
}
