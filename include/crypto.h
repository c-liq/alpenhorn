#ifndef ALPENHORN_CRYPTO_H
#define ALPENHORN_CRYPTO_H

#include "sodium.h"
#include "string.h"

#define crypto_ghash_BYTES crypto_generichash_BYTES
#define crypto_box_PKBYTES crypto_box_PUBLICKEYBYTES
#define crypto_maxhash_BYTES crypto_generichash_BYTES_MAX


int crypto_seal_nonce(uint8_t *nonce, uint8_t *pk1, uint8_t *pk2, uint64_t output_size);

int crypto_shared_secret(uint8_t *shared_secret,
                         const uint8_t *esk,
                         const uint8_t *epk,
                         const uint8_t *pk1,
                         const uint8_t *pk2,
                         uint64_t output_size);

#endif //ALPENHORN_CRYPTO_H
