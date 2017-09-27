#ifndef ALPENHORN_CRYPTO_CHACHA_H
#define ALPENHORN_CRYPTO_CHACHA_H

#include "crypto.h"

int crypto_salsa_onion_seal(uint8_t c[],
                            unsigned long long *clen_p,
                            uint8_t msg[],
                            uint64_t msg_len,
                            uint8_t pkeys[][crypto_box_PUBLICKEYBYTES],
                            uint64_t num_keys);

int crypto_salsa_decrypt(uint8_t *msg, uint8_t *c, uint64_t clen, uint8_t key[crypto_secretbox_KEYBYTES]);
int crypto_salsa_encrypt(uint8_t *c, uint8_t *m, uint64_t mlen, uint8_t key[crypto_secretbox_KEYBYTES]);

#endif //ALPENHORN_CRYPTO_CHACHA_H
