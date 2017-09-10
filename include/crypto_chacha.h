#ifndef ALPENHORN_CRYPTO_CHACHA_H
#define ALPENHORN_CRYPTO_CHACHA_H

#include "crypto.h"

int crypto_xchacha20_onion_seal(uint8_t *c,
								unsigned long long *clen_p,
								uint8_t *msg,
								uint64_t msg_len,
								uint8_t *pkeys,
								uint64_t num_keys);

#endif //ALPENHORN_CRYPTO_CHACHA_H
