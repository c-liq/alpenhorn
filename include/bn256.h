#ifndef BN256_H
#define BN256_H

#include "bn256/gmp_convert.h"
#include "bn256/optate.h"
#include <stdio.h>
#include <stdint.h>
#include <sodium.h>
#include <stdbool.h>

#define fpe_bytes 32U
#define g1_bytes (fpe_bytes*2)
#define g2_bytes (fpe_bytes*4)
#define gt_bytes (fpe_bytes*12)

void bn256_scalar_random(scalar_t out);

void bn256_scalarmult_base_g1(curvepoint_fp_t out, scalar_t const scl);

void bn256_scalarmult_base_g2(twistpoint_fp2_t out, scalar_t scl);

/**
 * @brief Initialises the bn256 environment making it ready to use
 *
 * Initialises the GMP constants required by various library functions (hashing/serialization).
 * @return 0 on success, -1 on failure, 1 if the library has already been initialised.
 */

int bn256_init();

int bn256_hash_g1(curvepoint_fp_t out, size_t msg_len, uint8_t *msg);

int bn256_hash_g2(twistpoint_fp2_struct_t *out, size_t msg_len, const uint8_t *msg);

void bn256_deserialize_g1(curvepoint_fp_t out, uint8_t *in);

void bn256_deserialize_g2(twistpoint_fp2_t out, uint8_t *in);

void bn256_deserialize_gt(fp12e_t out, void *in);

void bn256_serialize_g1(uint8_t *out, curvepoint_fp_struct_t *in);

void bn256_serialize_g1_xonly(uint8_t *out, curvepoint_fp_struct_t *g1_elem);

void bn256_deserialize_g1_xonly(curvepoint_fp_t out, uint8_t *in);

void bn256_serialize_g2(uint8_t *out, twistpoint_fp2_t in);

void bn256_serialize_g2_xonly(uint8_t *out, twistpoint_fp2_t g2_elem);

void bn256_serialize_gt(uint8_t *out, fp12e_struct_t *gt_elem);

void bn256_pair(fp12e_t rop, twistpoint_fp2_t op1, curvepoint_fp_t op2);

void bn256_sum_g1(curvepoint_fp_t out, curvepoint_fp_t *in, size_t count);

int bn256_sum_g2(twistpoint_fp2_t out, twistpoint_fp2_struct_t *in, size_t count);

void bn256_deserialize_and_sum_g1(curvepoint_fp_t out, uint8_t *in, size_t count);

void bn256_deserialize_and_sum_g2(twistpoint_fp2_struct_t *out, uint8_t *in, size_t count);

void bn256_g1_random(curvepoint_fp_t g1_out, scalar_t scalar_out);

void bn256_clear();

#endif //BN256_H
