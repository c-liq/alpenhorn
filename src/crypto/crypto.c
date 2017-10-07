#include <utils.h>

int crypto_shared_secret(uint8_t *shared_secret,
                         const uint8_t *esk,
                         const uint8_t *epk,
                         const uint8_t *pk1,
                         const uint8_t *pk2,
                         uint64_t output_size) {
  if (!shared_secret || !esk || !epk || !pk1 || !pk2) {
	return -1;
  }

  uint8_t scalar_mult[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(scalar_mult, esk, epk)) {
	fprintf(stderr, "scalar mult error\n");
	return -1;
  }

  crypto_generichash_state hash_state;
  crypto_generichash_init(&hash_state, NULL, 0U, output_size);
  crypto_generichash_update(&hash_state, scalar_mult, crypto_scalarmult_BYTES);
    crypto_generichash_update(&hash_state, pk1, crypto_box_PKBYTES);
    crypto_generichash_update(&hash_state, pk2, crypto_box_PKBYTES);
  crypto_generichash_final(&hash_state, shared_secret, output_size);
  sodium_memzero(&hash_state, sizeof hash_state);
  sodium_memzero(scalar_mult, sizeof scalar_mult);
  return 0;
}

int crypto_seal_nonce(uint8_t *nonce, uint8_t *pk1, uint8_t *pk2, uint64_t output_size) {
  crypto_generichash_state state;
  crypto_generichash_init(&state, NULL, 0, output_size);
  crypto_generichash_update(&state, pk1, crypto_box_PUBLICKEYBYTES);
  crypto_generichash_update(&state, pk2, crypto_box_PUBLICKEYBYTES);
  crypto_generichash_final(&state, nonce, output_size);
  return 0;
}
