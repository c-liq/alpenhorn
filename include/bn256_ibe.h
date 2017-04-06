#ifndef ALPENHORN_BN256_IBE_H
#define ALPENHORN_BN256_IBE_H
#include "bn256.h"
#include "config.h"
#include "utils.h"
void ibe_build_secret_key(uint8_t *sk_out, uint8_t *qid, uint8_t *rp, uint8_t *pair_val);

int
ibe_decrypt(uint8_t *out,
            uint8_t *c,
            size_t clen,
            uint8_t *public_key,
            twistpoint_fp2_t private_key);

#endif //ALPENHORN_BN256_IBE_H
