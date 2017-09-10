#ifndef ALPENHORN_CRYPTO_H
#define ALPENHORN_CRYPTO_H

#include "sodium.h"
#include "string.h"

#define crypto_ghash_BYTES crypto_generichash_BYTES
#define crypto_pk_BYTES crypto_box_PUBLICKEYBYTES
#define crypto_maxhash_BYTES crypto_generichash_BYTES_MAX
#define crypto_MACBYTES crypto_aead_chacha20poly1305_ietf_ABYTES
#define crypto_NBYTES crypto_aead_chacha20poly1305_ietf_NPUBBYTES

int crypto_seal_nonce(uint8_t *nonce, uint8_t *pk1, uint8_t *pk2, uint64_t output_size);

int crypto_shared_secret(uint8_t *shared_secret,
						 uint8_t esk[crypto_box_SECRETKEYBYTES],
						 uint8_t epk[crypto_box_PUBLICKEYBYTES],
						 uint8_t pk1[crypto_box_PUBLICKEYBYTES],
						 uint8_t pk2[crypto_box_PUBLICKEYBYTES],
						 uint64_t output_size);

#endif //ALPENHORN_CRYPTO_H
