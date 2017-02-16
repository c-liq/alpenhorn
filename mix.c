#include "alpenhorn.h"
#include "mix.h"
#include "client.h"

const char skhex1[] = "bc8a02f200c6163ba70d0d9c377cebaa44274bb1e0da097e6c81466f8d5c3d45";
const char pkhex1[] = "b2f511269f818c10bc897845e6282fc3f17a1e861f8d080c727bfffc7393842a";

int mix_remove_encryption_layer(byte_t *c, uint32_t num_layers) {
  byte_t sk[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
  byte_t pk[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
  sodium_hex2bin(sk, crypto_aead_chacha20poly1305_IETF_KEYBYTES, skhex1, 64, NULL, NULL, NULL);
  sodium_hex2bin(pk, crypto_aead_chacha20poly1305_IETF_KEYBYTES, pkhex1, 64, NULL, NULL, NULL);

  uint32_t message_length = ibe_encrypted_request_length + mailbox_length + (num_layers * af_request_ABYTES);
  byte_t *nonce_ptr = c + message_length - crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
  byte_t *client_pub_dh_ptr = nonce_ptr - crypto_box_PUBLICKEYBYTES;
  byte_t msg[ibe_encrypted_request_length + mailbox_length + (num_layers * af_request_ABYTES)];

  byte_t scalar_mult[crypto_scalarmult_BYTES];
  int res = crypto_scalarmult(scalar_mult, sk, client_pub_dh_ptr);
  if (res) {
    printf("Scalarmult error\n");
    return -1;
  }
  printhex(":::::::: MIX SCALAR MULT", scalar_mult, crypto_scalarmult_BYTES);
  byte_t shared_secret[crypto_generichash_BYTES];
  crypto_shared_secret(shared_secret, scalar_mult, client_pub_dh_ptr, pk);
  // printhex("dh pub ptr", client_pub_dh_ptr, crypto_box_PUBLICKEYBYTES);
  // printhex("nonce", nonce_ptr, crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
  printhex("mix shared secret", shared_secret, crypto_generichash_BYTES);
  // printhex("ciphertext", c, message_length);


  uint32_t clen = request_bytes + crypto_aead_chacha20poly1305_IETF_ABYTES;
  res = crypto_aead_chacha20poly1305_ietf_decrypt(msg,
                                                  NULL,
                                                  NULL,
                                                  c,
                                                  message_length - (crypto_box_PUBLICKEYBYTES
                                                      + crypto_aead_chacha20poly1305_IETF_NPUBBYTES),
                                                  client_pub_dh_ptr,
                                                  crypto_box_PUBLICKEYBYTES
                                                      + crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
                                                  nonce_ptr,
                                                  shared_secret);
  if (res) {
    printf("Decrypt error\n");
    return -1;
  }
  printf("%s\n", msg);
  return 0;
}


