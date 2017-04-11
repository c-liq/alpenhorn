#ifndef ALPENHORN_BN_256_H
#define ALPENHORN_BN_256_H

#include <stdio.h>
#include "bn256/optate.h"
#include <stdint.h>
#include <sodium.h>
#include <stdbool.h>
#include <memory.h>

#include "bn256/gmp_convert.h"

#define fpe_bytes 32
#define g1_bytes fpe_bytes*2
#define g2_bytes fpe_bytes*4
#define gt_bytes fpe_bytes*12

void bn256_scalar_random(scalar_t out);
void bn256_scalarmult_bg1(curvepoint_fp_t out, scalar_t scl);
void bn256_scalarmult_bg2(twistpoint_fp2_t out, scalar_t scl);
bool bn256_init();
int bn256_hash_g1(curvepoint_fp_t rop, uint8_t *msg, size_t msg_len);
int bn256_hash_g2(twistpoint_fp2_struct_t *out, const uint8_t *msg, const ssize_t msg_len);
void bn256_deserialize_g1(curvepoint_fp_t out, void *in);
void bn256_deserialize_g2(twistpoint_fp2_t out, void *in);
void bn256_deserialize_gt(fp12e_t out, void *in);
size_t bn256_serialize_g1(void *out, curvepoint_fp_t in);
size_t bn256_serialize_g2(void *out, twistpoint_fp2_t in);
size_t bn256_serialize_gt(void *out, fp12e_t gt_elem);
void bn256_pair(fp12e_t rop, twistpoint_fp2_t op1, curvepoint_fp_t op2);
void bn256_sum_g1(curvepoint_fp_t out, curvepoint_fp_t *in, size_t count);
void bn256_sum_g2(twistpoint_fp2_t out, twistpoint_fp2_t *in, const size_t count);
void bn256_deserialize_and_sum_g1(curvepoint_fp_t out, void *in, size_t count);
void bn256_deserialize_and_sum_g2(twistpoint_fp2_t out, void *in, size_t count);

#endif //ALPENHORN_BN_256_H
