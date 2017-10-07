#ifndef ALPENHORN_CRYPTO_CHACHA_H
#define ALPENHORN_CRYPTO_CHACHA_H

#include "crypto.h"

int crypto_salsa_onion_seal(uint8_t c[],
                            uint64_t *clen_p,
                            const uint8_t *msg,
                            uint64_t msg_len,
                            uint8_t pkeys[][crypto_box_PUBLICKEYBYTES],
                            uint64_t num_keys);

int crypto_salsa_decrypt(uint8_t *msg, const uint8_t *c, uint64_t clen, const uint8_t *key);
int crypto_salsa_encrypt(uint8_t *c, const uint8_t *m, uint64_t mlen, const uint8_t *key);

#endif //ALPENHORN_CRYPTO_CHACHA_H
