//
// Created by chris on 05/04/17.
//

#ifndef ALPENHORN_BN256_BLS_H
#define ALPENHORN_BN256_BLS_H
#include "bn256.h"

typedef struct bn256_bls_keypair bn256_bls_keypair;

struct bn256_bls_keypair
{
  scalar_t sk;
	twistpoint_fp2_t public_key;
};
int bn256_bls_verify_multisig(twistpoint_fp2_struct_t *public_keys,
                              size_t num_participants,
                              uint8_t *signatures,
                              uint8_t *msg,
                              size_t msg_len);
int bn256_bls_verify(twistpoint_fp2_t p, uint8_t *signature, uint8_t *msg, size_t msg_len);
void bn256_bls_sign_message(uint8_t *out_buf, uint8_t *msg, uint64_t msg_len, scalar_t secret_key);
void bn256_bls_keygen(bn256_bls_keypair *kp);

#endif //ALPENHORN_BN256_BLS_H
