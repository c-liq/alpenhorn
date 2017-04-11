#include <sodium.h>
#include <gmp.h>
#include <bn256/gmp_convert.h>
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

static fpe_t fpe_bn_p;
static fpe_t fpe_sqrt_neg3;
static fpe_t fpe_j;
static fpe_t one;
static fpe_t curve_b;
static fpe_t fpe_bn_n;
static fp2e_t twist_b;
static fpe_t fpe_b0;
static fpe_t fpe_b1;
static scalar_t cofactor;
static mpz_t mpz_bn_p;
static mpz_t mpz_bn_n;
static mpz_t mpz_sqrt_neg3;
static mpz_t mpz_j;

bool running = 0;

void bn256_scalar_random(scalar_t out)
{
	scalar_setrandom(out, bn_n);
}

void bn256_scalarmult_bg1(curvepoint_fp_t out, scalar_t scl)
{
	curvepoint_fp_scalarmult_vartime(out, bn_curvegen, scl);
	curvepoint_fp_makeaffine(out);
}

void bn256_scalarmult_bg2(twistpoint_fp2_t out, scalar_t scl)
{
	twistpoint_fp2_scalarmult_vartime(out, bn_twistgen, scl);
	twistpoint_fp2_makeaffine(out);
}

void fpe_cube(fpe_t rop, fpe_t op)
{
	fpe_t tmp;
	fpe_set(tmp, op);
	fpe_mul(rop, tmp, tmp);
	fpe_mul(rop, rop, tmp);
}

void mpz2scalar(scalar_t rop, mpz_t op)
{
	mpz_t tmp;
	mpz_init_set(tmp, op);
	for (int i = 0; i < 4; i++) {
		unsigned long long x = mpz_get_ui(tmp);
		rop[i] = x;
		mpz_tdiv_q_2exp(tmp, tmp, 64);
	}
	mpz_clear(tmp);
}

void fpe_get_weierstrass(fpe_t y, const fpe_t x)
{
	fpe_t t;
	fpe_square(t, x);
	fpe_mul(t, t, x);
	fpe_add(y, t, curve_b);
}

void mpz_fpe_get_weierstrass(mpz_t y, mpz_t x)
{
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

void fp2e_get_weierstrass(fp2e_t y, const fp2e_t x)
{
	fp2e_t t;
	fp2e_square(t, x);
	fp2e_mul(t, t, x);
	fp2e_add(y, t, twist_b);
}

bool bn256_init()
{
	if (running) return true;

	mpz_t mpz_b0, mpz_b1;
	mpz_init_set_str(mpz_b0, b0, 10);
	mpz_init_set_str(mpz_b1, b1, 10);
	mpz2fp2(fpe_b0, mpz_b0);
	mpz2fp2(fpe_b1, mpz_b1);
	_2fpe_to_fp2e(twist_b, fpe_b0, fpe_b1);
	mpz_init_set_str(mpz_bn_n, bn_nstr, 10);
	mpz_init_set_str(mpz_bn_p, bn_pstr, 10);
	mpz2fp2(fpe_bn_p, mpz_bn_p);
	mpz2fp2(fpe_bn_n, mpz_bn_n);
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
	running = true;
	return true;
}

int bn256_hash_g1(curvepoint_fp_t rop, uint8_t *msg, size_t msg_len)
{
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
	//gmp_printf("W: %Zd\n", w);
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

	int l1, l2, l3;
	l1 = mpz_legendre(xi_3_plusb[0], mpz_bn_p);
	l2 = mpz_legendre(xi_3_plusb[1], mpz_bn_p);
	l3 = mpz_legendre(xi_3_plusb[2], mpz_bn_p);
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

	mpz2fp(rop->m_x, x[i]);
	mpz2fp(rop->m_y, y);
	fpe_setone(rop->m_z);
	fpe_setzero(rop->m_t);
	return l1 + l2 + l3;
}

int xbn256_hash_g1(curvepoint_fp_t out, uint8_t *msg, size_t msg_len)
{
	uint8_t hash[crypto_generichash_BYTES];
	crypto_generichash(hash, crypto_generichash_BYTES, msg, sizeof msg_len, NULL, 0);

	mpz_t mpz_hash;
	mpz_init(mpz_hash);
	mpz_import(mpz_hash, crypto_generichash_BYTES, 1, 1, 1, 0, hash);
	mpz_mod(mpz_hash, mpz_hash, mpz_bn_p);

	fpe_t x, y;
	mpz2fp2(x, mpz_hash);

	int is_negative = fpe_legendre(x);

	for (;;) {
		fpe_t tmp;
		fpe_cube(tmp, x);
		fpe_add(tmp, tmp, curve_b);
		int res = fpe_sqrt(y, tmp);
		if (res) {
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

int bn256_hash_g2(twistpoint_fp2_struct_t *out, const uint8_t *msg, const ssize_t msg_len)
{
	fpe_t t_single;
	mpz_t tmp_hash;
	mpz_init(tmp_hash);

	uint8_t hash[crypto_generichash_BYTES];
	crypto_generichash(hash, crypto_generichash_BYTES, msg, sizeof msg_len, NULL, 0);
	mpz_import(tmp_hash, crypto_generichash_BYTES, 1, 1, 1, 0, hash);
	mpz_mod(tmp_hash, tmp_hash, mpz_bn_p);
	mpz2fp(t_single, tmp_hash);
	mpz_clear(tmp_hash);

	fp2e_t t;
	_2fpe_to_fp2e(t, t_single, t_single);

	fp2e_t w;
	fp2e_mul(w, t, t);

	fp2e_add(w, w, twist_b);
	fp2e_add(w, w, fp2e_one);

	fp2e_invert(w, w);
	fp2e_mul(w, w, t);
	fp2e_t fp2e_sqrtneg3;
	fp2e_set_fpe(fp2e_sqrtneg3, fpe_sqrt_neg3);
	fp2e_mul(w, w, fp2e_sqrtneg3);

	fp2e_t x[3];
	fp2e_t fp2e_j;
	fp2e_set_fpe(fp2e_j, fpe_j);

	fp2e_mul(x[0], w, t);
	fp2e_sub(x[0], x[0], fp2e_j);

	fp2e_neg(x[0], x[0]);

	fp2e_add(x[1], x[0], fp2e_one);
	fp2e_neg(x[1], x[1]);

	fp2e_mul(x[2], w, w);
	fp2e_invert(x[2], x[2]);
	fp2e_add(x[2], x[2], fp2e_one);

	fp2e_t x_3_plusb[3];
	for (int i = 0; i < 3; i++) {
		fp2e_get_weierstrass(x_3_plusb[i], x[i]);
	}

	int alpha, beta;
	alpha = fp2e_legendre(x_3_plusb[0]);
	beta = fp2e_legendre(x_3_plusb[1]);
	int i = (alpha - 1) * beta % 3;
	i = i < 0 ? i + 3 : i;
	int negative = fp2e_legendre(t);

	fp2e_t y;
	fp2e_sqrt(y, x_3_plusb[i]);

	if (negative) {
		fp2e_neg(y, y);
	}

	twistpoint_fp2_affineset_fp2e(out, x[i], y);
	twistpoint_fp2_scalarmult_vartime(out, out, cofactor);

	return 0;
}

size_t serialize_fpe(void *out, fpe_t op)
{
	mpz_t x;
	mpz_init(x);
	fp2mpz2(x, op);
	size_t count;
	mpz_export(out, &count, 1, fpe_bytes, 1, 0, x);
	mpz_clear(x);
	return count;
}

int deserialize_fpe(fpe_t out, uint8_t *in)
{
	mpz_t tmp;
	mpz_init(tmp);
	mpz_import(tmp, 1, 1, fpe_bytes, 1, 0, in);
	mpz2fp2(out, tmp);
	mpz_clear(tmp);
	return 0;
}

void bn256_deserialize_g1(curvepoint_fp_t out, void *in)
{
	deserialize_fpe(out->m_x, in);
	deserialize_fpe(out->m_y, in + fpe_bytes);
	fpe_setone(out->m_z);
	fpe_setzero(out->m_t);
}

void bn256_deserialize_g2(twistpoint_fp2_t out, void *in)
{
	fpe_t fp1, fp2, fp3, fp4;
	deserialize_fpe(fp1, in);
	deserialize_fpe(fp2, in + fpe_bytes);
	deserialize_fpe(fp3, in + fpe_bytes * 2);
	deserialize_fpe(fp4, in + fpe_bytes * 3);
	_2fpe_to_fp2e(out->m_x, fp1, fp2);
	_2fpe_to_fp2e(out->m_y, fp3, fp4);
	fp2e_setone(out->m_z);
	fp2e_setzero(out->m_t);
}

size_t bn256_serialize_g1(void *out, curvepoint_fp_t g1_elem)
{
	fpe_t fp1, fp2;
	fpe_set(fp1, g1_elem->m_x);
	fpe_set(fp2, g1_elem->m_y);
	size_t total_count = 0;
	size_t count = serialize_fpe(out, fp1);
	total_count += count;
	count = serialize_fpe(out + fpe_bytes, fp2);
	total_count += count;
	return total_count;
}

size_t bn256_serialize_gt(void *out, fp12e_t gt_elem)
{
	fpe_t fpe_elems[12];
	fp2e_to_2fpe(fpe_elems[0], fpe_elems[1], gt_elem->m_a->m_a);
	fp2e_to_2fpe(fpe_elems[2], fpe_elems[3], gt_elem->m_a->m_b);
	fp2e_to_2fpe(fpe_elems[4], fpe_elems[5], gt_elem->m_a->m_c);
	fp2e_to_2fpe(fpe_elems[6], fpe_elems[7], gt_elem->m_b->m_a);
	fp2e_to_2fpe(fpe_elems[8], fpe_elems[9], gt_elem->m_b->m_a);
	fp2e_to_2fpe(fpe_elems[10], fpe_elems[11], gt_elem->m_b->m_a);
	size_t total_count = 0;
	size_t tmp_count = 0;
	uint8_t *ptr = out;
	for (int i = 0; i < 12; i++) {
		tmp_count = serialize_fpe(ptr, fpe_elems[i]);
		ptr += fpe_bytes;
		total_count += tmp_count;
	}
	return total_count;
}

void bn256_deserialize_and_sum_g1(curvepoint_fp_t out, void *in, size_t count)
{
	if (count <= 0) return;

	void *ptr = in;
	curvepoint_fp_t tmp;
	bn256_deserialize_g1(tmp, ptr);
	curvepoint_fp_set(out, tmp);
	ptr += g1_bytes;
	fpe_setone(out->m_z);

	for (size_t i = 1; i < count; i++) {
		bn256_deserialize_g1(tmp, ptr);
		curvepoint_fp_add_vartime(out, out, tmp);
		ptr += g1_bytes;
	}
}

void bn256_deserialize_and_sum_g2(twistpoint_fp2_t out, void *in, size_t count)
{
	void *ptr = in;
	twistpoint_fp2_setneutral(out);
	fp2e_setone(out->m_z);

	twistpoint_fp2_t tmp;
	for (size_t i = 0; i < count; i++) {
		bn256_deserialize_g2(tmp, ptr);
		twistpoint_fp2_add_vartime(out, out, tmp);
		ptr += g2_bytes;
	}

}

void bn256_sum_g1(curvepoint_fp_t out, curvepoint_fp_t *in, size_t count)
{
	if (!in || count <= 0) return;

	curvepoint_fp_set(out, in[0]);
	fpe_setone(out->m_z);

	for (size_t i = 1; i < count; i++) {
		curvepoint_fp_add_vartime(out, out, in[i]);
	}
}

void bn256_sum_g2(twistpoint_fp2_t out, twistpoint_fp2_t in[], const size_t count)
{
	if (!in || count <= 0) return;

	twistpoint_fp2_set(out, in[0]);
	fp2e_setone(out->m_z);
	for (size_t i = 1; i < count; i++) {
		twistpoint_fp2_add_vartime(out, out, in[i]);
	}
}

size_t bn256_serialize_g2(void *out, twistpoint_fp2_t in)
{
	fpe_t fpe_elems[4];
	fp2e_to_2fpe(fpe_elems[0], fpe_elems[1], in->m_x);
	fp2e_to_2fpe(fpe_elems[2], fpe_elems[3], in->m_y);
	size_t total_count = 0;
	size_t tmp_count = 0;
	uint8_t *ptr = out;
	for (int i = 0; i < 4; i++) {
		tmp_count = serialize_fpe(ptr, fpe_elems[i]);
		ptr += fpe_bytes;
		total_count += tmp_count;
	}
	return total_count;
}

void bn256_pair(fp12e_t rop, twistpoint_fp2_t op1, curvepoint_fp_t op2)
{
	twistpoint_fp2_makeaffine(op1);
	curvepoint_fp_makeaffine(op2);
	optate(rop, op1, op2);
}
