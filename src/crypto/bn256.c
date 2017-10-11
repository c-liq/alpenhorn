#include <string.h>
#include "bn256.h"

extern const scalar_t bn_pminus2;
extern const double bn_v;
extern const fp2e_t fp2e_one;
extern const fp2e_t fp2e_negOne;
extern const fp2e_t fp2e_i;
extern const char *bn_pstr;
extern const char *bn_nstr;
extern const char *bn_sqrt_neg3_str;
extern const char *bn_j_str;
extern const curvepoint_fp_t bn_curvegen;
extern const twistpoint_fp2_t bn_twistgen;
extern const char *b0;
extern const char *b1;
extern const scalar_t pMinus3Div4;
extern const scalar_t pMinus1Div2;
extern const scalar_t bn_n;

static fpe_t fpe_sqrt_neg3;
static fpe_t fpe_j;
static fpe_t one;
static fpe_t curve_b;
static fp2e_t twist_b;
static fpe_t fpe_b0;
static fpe_t fpe_b1;
static scalar_t cofactor;
static mpz_t mpz_bn_p;
static mpz_t mpz_sqrt_neg3;
static mpz_t mpz_j;

static bool initialised = 0;

static void fpe_cube(fpe_t rop, fpe_t op);
static void mpz2scalar(scalar_t rop, mpz_ptr op);
static void fpe_get_weierstrass(fpe_t y, const fpe_t x);
static void mpz_fpe_get_weierstrass(mpz_ptr y, mpz_ptr x);
static void fp2e_get_weierstrass(fp2e_t y, const fp2e_t x);
static void mpz_2_fpe_hash(fpe_t out, size_t msg_len, const uint8_t msg[msg_len]);

static void fpe_cube(fpe_t rop, fpe_t op) {
    fpe_t tmp;
    fpe_set(tmp, op);
    fpe_mul(rop, tmp, tmp);
    fpe_mul(rop, rop, tmp);
}

static void mpz2scalar(scalar_t rop, mpz_ptr op) {
    mpz_t tmp;
    mpz_init_set(tmp, op);
    for (int i = 0; i < 4; i++) {
        unsigned long long x = mpz_get_ui(tmp);
        rop[i] = x;
        mpz_tdiv_q_2exp(tmp, tmp, 64);
    }
    mpz_clear(tmp);
}

static void fpe_get_weierstrass(fpe_t y, const fpe_t x) {
    fpe_t t;
    fpe_square(t, x);
    fpe_mul(t, t, x);
    fpe_add(y, t, curve_b);
}

static void mpz_fpe_get_weierstrass(mpz_ptr y, mpz_ptr x) {
    mpz_t t;
    mpz_init(t);
    mpz_mul(t, x, x);
    mpz_mod(t, t, mpz_bn_p);
    mpz_mul(t, t, x);
    mpz_mod(t, t, mpz_bn_p);
    mpz_add_ui(y, t, 3);
    mpz_mod(y, y, mpz_bn_p);
    mpz_clear(t);
}

static void fp2e_get_weierstrass(fp2e_t y, const fp2e_t x) {
    fp2e_t t;
    fp2e_square(t, x);
    fp2e_mul(t, t, x);
    fp2e_add(y, t, twist_b);
}

void bn256_scalar_random(scalar_t out) {
    scalar_setrandom(out, bn_n);
}

void bn256_scalarmult_base_g1(curvepoint_fp_t out, scalar_t const scl) {
    curvepoint_fp_scalarmult_vartime(out, bn_curvegen, scl);
    curvepoint_fp_makeaffine(out);
}

void bn256_g1_random(curvepoint_fp_t g1_out, scalar_t scalar_out) {
    scalar_setrandom(scalar_out, bn_n);
    bn256_scalarmult_base_g1(g1_out, scalar_out);
    curvepoint_fp_makeaffine(g1_out);
}

void bn256_g2_random(twistpoint_fp2_t g2_out, scalar_t scalar_out) {
    scalar_setrandom(scalar_out, bn_n);
    bn256_scalarmult_base_g2(g2_out, scalar_out);
    twistpoint_fp2_makeaffine(g2_out);
}

void bn256_scalarmult_base_g2(twistpoint_fp2_t out, scalar_t scl) {
    twistpoint_fp2_scalarmult_vartime(out, bn_twistgen, scl);
    twistpoint_fp2_makeaffine(out);
}

int bn256_init() {
    if (initialised) {
        return 1;
    }

    mpz_t mpz_b0, mpz_b1;
    mpz_init_set_str(mpz_b0, b0, 10);
    mpz_init_set_str(mpz_b1, b1, 10);
    mpz2fp2(fpe_b0, mpz_b0);
    mpz2fp2(fpe_b1, mpz_b1);
    _2fpe_to_fp2e(twist_b, fpe_b0, fpe_b1);

    mpz_t mpz_bn_n;
    mpz_init_set_str(mpz_bn_n, bn_nstr, 10);

    fpe_setone(curve_b);
    fpe_triple(curve_b, curve_b);

    mpz_t cofactor_mpz;
    mpz_init(cofactor_mpz);
    mpz_mul_ui(cofactor_mpz, mpz_bn_p, 2);
    mpz_sub(cofactor_mpz, cofactor_mpz, mpz_bn_n);
    mpz2scalar(cofactor, cofactor_mpz);
    mpz_clear(cofactor_mpz);
    fpe_setone(one);

    mpz_init_set_str(mpz_sqrt_neg3, bn_sqrt_neg3_str, 10);
    mpz_init_set_str(mpz_j, bn_j_str, 10);
    mpz2fp(fpe_j, mpz_j);
    mpz2fp(fpe_sqrt_neg3, mpz_sqrt_neg3);
    mpz_clear(mpz_b0);
    mpz_clear(mpz_b1);
    mpz_clear(mpz_bn_n);
    initialised = true;
    return 0;
}

void bn256_clear() {
    if (!initialised)
        return;

    mpz_clear(mpz_j);
    mpz_clear(mpz_sqrt_neg3);
    mpz_clear(mpz_bn_p);
    initialised = false;
}

int bn256_hash_g1(curvepoint_fp_t out, size_t msg_len, uint8_t msg[msg_len]) {
    uint8_t hash[crypto_generichash_BYTES];
    crypto_generichash(hash, crypto_generichash_BYTES, msg, msg_len, NULL, 0);

    mpz_t t;
    mpz_init(t);
    mpz_import(t, crypto_generichash_BYTES, 1, 1, 1, 0, hash);
    mpz_mod(t, t, mpz_bn_p);

    mpz_t w;
    mpz_init(w);

    mpz_mul(w, t, t);
    mpz_mod(w, w, mpz_bn_p);
    mpz_add_ui(w, w, 1);
    mpz_mod(w, w, mpz_bn_p);
    mpz_add_ui(w, w, 3);
    mpz_mod(w, w, mpz_bn_p);
    mpz_invert(w, w, mpz_bn_p);
    mpz_mul(w, w, t);
    mpz_mod(w, w, mpz_bn_p);
    mpz_mul(w, w, mpz_sqrt_neg3);
    mpz_mod(w, w, mpz_bn_p);
    // gmp_printf("W: %Zd\n", w);
    mpz_t x[3];
    mpz_init(x[0]);
    mpz_init(x[1]);
    mpz_init(x[2]);
    mpz_mul(x[0], w, t);
    mpz_mod(x[0], x[0], mpz_bn_p);
    mpz_neg(x[0], x[0]);
    mpz_mod(x[0], x[0], mpz_bn_p);
    mpz_add(x[0], x[0], mpz_j);
    mpz_mod(x[0], x[0], mpz_bn_p);

    mpz_neg(x[1], x[0]);
    mpz_mod(x[1], x[1], mpz_bn_p);
    mpz_sub_ui(x[1], x[1], 1);
    mpz_mod(x[1], x[1], mpz_bn_p);

    mpz_mul(x[2], w, w);
    mpz_mod(x[2], x[2], mpz_bn_p);
    mpz_invert(x[2], x[2], mpz_bn_p);
    mpz_add_ui(x[2], x[2], 1);
    mpz_mod(x[2], x[2], mpz_bn_p);

    mpz_t xi_3_plusb[3];
    for (int i = 0; i < 3; i++) {
        mpz_init(xi_3_plusb[i]);
        mpz_fpe_get_weierstrass(xi_3_plusb[i], x[i]);
    }

    gmp_randstate_t rstate;
    gmp_randinit_default(rstate);
    mpz_t r[3];
    for (int i = 0; i < 3; i++) {
        mpz_init(r[i]);
        mpz_urandomm(r[i], rstate, mpz_bn_p);
        mpz_mul(r[i], r[i], r[i]);
        mpz_mod(r[i], r[i], mpz_bn_p);
    }

    mpz_mul(r[0], r[0], xi_3_plusb[0]);
    mpz_mod(r[0], r[0], mpz_bn_p);
    mpz_mul(r[1], r[1], xi_3_plusb[1]);
    mpz_mod(r[1], r[1], mpz_bn_p);
    mpz_mul(r[2], r[2], t);
    mpz_mod(r[2], r[2], mpz_bn_p);

    int alpha = mpz_legendre(r[0], mpz_bn_p);
    int beta = mpz_legendre(r[1], mpz_bn_p);
    int negatve = mpz_legendre(r[2], mpz_bn_p);
    int i = (alpha - 1) * beta % 3;
    i = i < 0 ? i + 3 : i;

    mpz_t y;
    mpz_init(y);
    mpz_sqrt(y, xi_3_plusb[i]);
    mpz_mod(y, y, mpz_bn_p);

    if (negatve) {
        mpz_neg(y, y);
        mpz_mod(y, y, mpz_bn_p);
    }

    mpz2fp(out->m_x, x[i]);
    mpz2fp(out->m_y, y);
    fpe_setone(out->m_z);
    fpe_setzero(out->m_t);

    mpz_clear(t);
    mpz_clear(y);
    mpz_clear(w);
    mpz_clear(x[0]);
    mpz_clear(x[1]);
    mpz_clear(x[2]);
    mpz_clear(r[0]);
    mpz_clear(r[1]);
    mpz_clear(r[2]);
    gmp_randclear(rstate);
    mpz_clear(xi_3_plusb[0]);
    mpz_clear(xi_3_plusb[1]);
    mpz_clear(xi_3_plusb[2]);
    return 0;
}

/*
int xbn256_hash_g1(curvepoint_fp_t out, uint8_t *msg, size_t msg_len) {
    fpe_t x;
    mpz_2_fpe_hash(x, msg_len, msg);
    fpe_t y;

    int is_negative = fpe_legendre(x);

    for (;;) {
        fpe_t tmp;
        fpe_cube(tmp, x);
        fpe_add(tmp, tmp, curve_b);
        if (fpe_sqrt(y, tmp)) {
            if (is_negative) {
                fpe_neg(y, y);
            }
            fpe_set(out->m_x, x);
            fpe_set(out->m_y, y);
            fpe_setone(out->m_z);
            fpe_setzero(out->m_t);
            break;
        }
        fpe_add(x, x, one);
    }
    return 0;
}
*/

static void mpz_2_fpe_hash(fpe_t out, size_t msg_len, const uint8_t msg[msg_len]) {
    mpz_t tmp_hash;
    mpz_init(tmp_hash);

    uint8_t hash[crypto_generichash_BYTES];
    crypto_generichash(hash, crypto_generichash_BYTES, msg, sizeof msg_len, NULL,
                       0);
    mpz_import(tmp_hash, crypto_generichash_BYTES, 1, 1, 1, 0, hash);
    mpz_mod(tmp_hash, tmp_hash, mpz_bn_p);
    mpz2fp(out, tmp_hash);
    mpz_clear(tmp_hash);
}

int bn256_hash_g2(twistpoint_fp2_struct_t *out, size_t msg_len, const uint8_t msg[msg_len]) {
    fpe_struct_t t_single = {{0}};

    mpz_2_fpe_hash(&t_single, msg_len, msg);

    fp2e_t t = {{{0}}};
    _2fpe_to_fp2e(t, &t_single, &t_single);

    fp2e_t w = {{{0}}};
    fp2e_mul(w, t, t);

    fp2e_add(w, w, twist_b);
    fp2e_add(w, w, fp2e_one);

    fp2e_invert(w, w);
    fp2e_mul(w, w, t);
    fp2e_t fp2e_sqrtneg3;
    fp2e_set_fpe(fp2e_sqrtneg3, fpe_sqrt_neg3);
    fp2e_mul(w, w, fp2e_sqrtneg3);

    fp2e_t x[3] = {{{{0}}}};
    fp2e_t fp2e_j = {{{0}}};
    fp2e_set_fpe(fp2e_j, fpe_j);

    fp2e_mul(x[0], w, t);
    fp2e_sub(x[0], x[0], fp2e_j);

    fp2e_neg(x[0], x[0]);

    fp2e_add(x[1], x[0], fp2e_one);
    fp2e_neg(x[1], x[1]);

    fp2e_mul(x[2], w, w);
    fp2e_invert(x[2], x[2]);
    fp2e_add(x[2], x[2], fp2e_one);

    fp2e_t x_3_plusb[3] = {{{{0}}}, {{{0}}}, {{{0}}}};
    for (int i = 0; i < 3; i++) {
        fp2e_get_weierstrass(x_3_plusb[i], x[i]);
    }

    int alpha, beta;
    alpha = fp2e_legendre(x_3_plusb[0]);
    beta = fp2e_legendre(x_3_plusb[1]);
    int i = (alpha - 1) * beta % 3;
    i = i < 0 ? i + 3 : i;
    int negative = fp2e_legendre(t);

    fp2e_t y = {{{0}}};
    fp2e_sqrt(y, x_3_plusb[i]);

    if (negative) {
        fp2e_neg(y, y);
    }

    twistpoint_fp2_affineset_fp2e(out, x[i], y);
    twistpoint_fp2_scalarmult_vartime(out, out, cofactor);

    return 0;
}

void serialize_fpe(void *out, fpe_struct_t *op) {
    mpz_t x;
    mpz_init(x);
    fp2mpz2(x, op);

    memset(out, 0, fpe_bytes);
    mpz_export(out, NULL, 1, fpe_bytes, 1, 0, x);
    mpz_clear(x);
}

void deserialize_fpe(fpe_struct_t *out, uint8_t *in) {
    mpz_t tmp;
    mpz_init(tmp);
    mpz_import(tmp, 1, 1, fpe_bytes, 1, 0, in);
    mpz2fp2(out, tmp);
    mpz_clear(tmp);
}

void bn256_deserialize_g1(curvepoint_fp_t out, uint8_t *in) {
    deserialize_fpe(out->m_x, in);
    deserialize_fpe(out->m_y, in + fpe_bytes);
    fpe_setone(out->m_z);
    fpe_setzero(out->m_t);
}

void bn256_deserialize_g2(twistpoint_fp2_t out, uint8_t *in) {
    fpe_t fp_elems[4] = {{{{0}}}};
    deserialize_fpe(fp_elems[0], in);
    deserialize_fpe(fp_elems[1], in + fpe_bytes);
    deserialize_fpe(fp_elems[2], in + fpe_bytes * 2);
    deserialize_fpe(fp_elems[3], in + fpe_bytes * 3);
    _2fpe_to_fp2e(out->m_x, fp_elems[0], fp_elems[1]);
    _2fpe_to_fp2e(out->m_y, fp_elems[2], fp_elems[3]);
    fp2e_setone(out->m_z);
    fp2e_setzero(out->m_t);
}

void bn256_serialize_g1(uint8_t *out, curvepoint_fp_struct_t *g1_elem) {
    curvepoint_fp_makeaffine(g1_elem);
    serialize_fpe(out, g1_elem->m_x);
    serialize_fpe(out + fpe_bytes, g1_elem->m_y);
}

void bn256_serialize_g1_xonly(uint8_t *out, curvepoint_fp_struct_t *g1_elem) {
    curvepoint_fp_makeaffine(g1_elem);
    serialize_fpe(out, g1_elem->m_x);
}

void bn256_serialize_g2_xonly(uint8_t *out, twistpoint_fp2_t g2_elem) {
    fpe_t tmp1, tmp2;
    fp2e_to_2fpe(tmp1, tmp2, g2_elem->m_x);
    serialize_fpe(out, tmp1);
    serialize_fpe(out + fpe_bytes, tmp2);
}

void bn256_deserialize_g1_xonly(curvepoint_fp_t out, uint8_t *in) {
    deserialize_fpe(out->m_x, in);
    fpe_get_weierstrass(out->m_y, out->m_x);
    fpe_sqrt(out->m_y, out->m_x);
    fpe_setone(out->m_z);
    fpe_setzero(out->m_t);
}

void bn256_serialize_gt(uint8_t *out, fp12e_struct_t *gt_elem) {
    fpe_t fpe_elems[12];
    fp2e_to_2fpe(fpe_elems[0], fpe_elems[1], gt_elem->m_a->m_a);
    fp2e_to_2fpe(fpe_elems[2], fpe_elems[3], gt_elem->m_a->m_b);
    fp2e_to_2fpe(fpe_elems[4], fpe_elems[5], gt_elem->m_a->m_c);
    fp2e_to_2fpe(fpe_elems[6], fpe_elems[7], gt_elem->m_b->m_a);
    fp2e_to_2fpe(fpe_elems[8], fpe_elems[9], gt_elem->m_b->m_b);
    fp2e_to_2fpe(fpe_elems[10], fpe_elems[11], gt_elem->m_b->m_c);

    for (int i = 0; i < 12; i++) {
        serialize_fpe(out, fpe_elems[i]);
        out += fpe_bytes;
    }
}

void bn256_deserialize_and_sum_g1(curvepoint_fp_struct_t *out, uint8_t *in, size_t count) {
    if (count < 1) return;

    curvepoint_fp_t tmp;
    bn256_deserialize_g1(tmp, in);
    curvepoint_fp_set(out, tmp);
    fpe_setone(out->m_z);

    for (size_t i = 1; i < count; i++) {
        in += g1_bytes;
        bn256_deserialize_g1(tmp, in);
        curvepoint_fp_add_vartime(out, out, tmp);
    }
}

void bn256_deserialize_and_sum_g2(twistpoint_fp2_struct_t *out, uint8_t *in, size_t count) {
    if (count < 1) return;

    twistpoint_fp2_t tmp;
    bn256_deserialize_g2(tmp, in);
    twistpoint_fp2_set(out, tmp);
    fp2e_setone(out->m_z);

    for (size_t i = 1; i < count; i++) {
        in += g2_bytes;
        bn256_deserialize_g2(tmp, in);
        twistpoint_fp2_add_vartime(out, out, tmp);
    }
}

void bn256_sum_g1(curvepoint_fp_t out, curvepoint_fp_t *in, size_t count) {
    if (count < 1) return;

    curvepoint_fp_set(out, in[0]);
    fpe_setone(out->m_z);

    for (size_t i = 1; i < count; i++) {
        curvepoint_fp_add_vartime(out, out, in[i]);
    }
}

int bn256_sum_g2(twistpoint_fp2_t out, twistpoint_fp2_struct_t *in, const size_t count) {
    if (count < 1) return -1;

    twistpoint_fp2_set(out, &in[0]);
    fp2e_setone(out->m_z);
    for (size_t i = 1; i < count; i++) {
        twistpoint_fp2_add_vartime(out, out, &in[i]);
    }

    return 0;
}

void bn256_serialize_g2(uint8_t *out, twistpoint_fp2_t in) {
    fpe_t fpe_elems[4];
    fp2e_to_2fpe(fpe_elems[0], fpe_elems[1], in->m_x);
    fp2e_to_2fpe(fpe_elems[2], fpe_elems[3], in->m_y);

    uint8_t *ptr = out;
    for (int i = 0; i < 4; i++) {
        serialize_fpe(ptr, fpe_elems[i]);
        ptr += fpe_bytes;
    }
}

void bn256_pair(fp12e_t rop, twistpoint_fp2_t op1, curvepoint_fp_t op2) {
    twistpoint_fp2_makeaffine(op1);
    curvepoint_fp_makeaffine(op2);
    optate(rop, op1, op2);
}
