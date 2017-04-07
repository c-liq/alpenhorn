#ifndef ALPENHORN_BN256_IBE_H
#define ALPENHORN_BN256_IBE_H
#include "bn256.h"
#include "config.h"
#include "utils.h"

struct ibe_identity
{
	twistpoint_fp2_t private_key;
	uint8_t serialized_public_key[g2_bytes];
};
void bn256_ibe_build_sk(uint8_t *sk_out, uint8_t *qid, uint8_t *rp, uint8_t *pair_val);

int
bn256_ibe_decrypt(uint8_t *out,
                  uint8_t *c,
                  size_t clen,
                  uint8_t *public_key,
                  twistpoint_fp2_t private_key);

void bn256_ibe_keygen(struct ibe_identity *id, uint8_t *identity, uint8_t identity_length, scalar_t master_sk);

ssize_t bn256_ibe_encrypt(uint8_t *out,
                          uint8_t *msg,
                          uint32_t msg_len,
                          curvepoint_fp_t master_pk,
                          uint8_t *recv_id,
                          size_t recv_id_len);

#endif //ALPENHORN_BN256_IBE_H
