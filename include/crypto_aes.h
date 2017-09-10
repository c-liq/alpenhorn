#ifndef ALPENHORN_CRYPTO_AES_H
#define ALPENHORN_CRYPTO_AES_H

#include "crypto.h"

#define crypto_aes_SEALBYTES (crypto_aead_aes256gcm_ABYTES + crypto_aead_aes256gcm_KEYBYTES)

int crypto_aes256gcm_seal_open(uint8_t *out, uint8_t *c, uint64_t clen, uint8_t *pk, uint8_t *sk);

int crypto_aes256gcm_seal(uint8_t *c, unsigned long long *clen_p, uint8_t *msg, uint64_t msg_len, uint8_t *pk);

int crypto_aes256gsm_onion_seal(uint8_t *c,
								unsigned long long *clen_p,
								uint8_t *msg,
								uint64_t msg_len,
								uint8_t *pkeys,
								uint64_t num_keys);

#endif //ALPENHORN_CRYPTO_AES_H
