#include <stdio.h>
#include <dclxci/optate.h>
#include <stdint.h>
#include <sodium.h>
#include <stdbool.h>
#include <memory.h>
#include "config.h"
#include "utils.h"

#include "dclxci/parameters.c"
#include "dclxci/gmp_convert.h"

#define fpe_bytes 32
#define g1_bytes fpe_bytes*2
#define g2_bytes fpe_bytes*4
#define gt_bytes fpe_bytes*12

struct ibe_identity
{
	twistpoint_fp2_t private_key;
	uint8_t serialized_public_key[fpe_bytes * 4];
};

fpe_t fpe_bn_p;

fpe_t fpe_sqrt_neg3;

fpe_t fpe_j;

fpe_t one;

fpe_t curve_b;

fpe_t fpe_bn_n;

fp2e_t twist_b;

fpe_t fpe_b0;

fpe_t fpe_b1;

fpe_t fpe_pplus1_div4;

scalar_t cofactor;

mpz_t mpz_bn_p;

mpz_t mpz_bn_n;

mpz_t mpz_sqrt_neg3;

mpz_t mpz_j;

void fpe_cube(fpe_t rop, fpe_t op)
{
	fpe_t tmp;
	fpe_set(tmp, op);
	fpe_mul(rop, tmp, tmp);
	fpe_mul(rop, rop, tmp);
}

void mpz2scalar(scalar_t rop, mpz_t op)
{
	for (int i = 0; i < 4; i++) {
		unsigned long long x = mpz_get_ui(op);
		rop[i] = x;
		mpz_tdiv_q_2exp(op, op, 64);
	}
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

int next_attempt(twistpoint_fp2_t out, uint8_t *msg, ssize_t msg_len, mpz_t mpz_val)
{
	fpe_t t_single;
	mpz_t hmmmm;
	mpz_init(hmmmm);
	if (!mpz_val) {
		uint8_t hash[crypto_generichash_BYTES];
		crypto_generichash(hash, crypto_generichash_BYTES, msg, sizeof msg_len, NULL, 0);
		mpz_import(hmmmm, crypto_generichash_BYTES, 1, 1, 1, 0, hash);
		mpz_mod(hmmmm, hmmmm, mpz_bn_p);
		mpz2fp(t_single, hmmmm);
	}
	else {
		mpz_set(hmmmm, mpz_val);
		mpz2fp(t_single, hmmmm);
	}

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

	int alpha, beta, charlie;
	alpha = fp2e_legendre(x_3_plusb[0]);
	beta = fp2e_legendre(x_3_plusb[1]);
	charlie = fp2e_legendre(x_3_plusb[2]);
	//printf("%d %d %d\n", alpha, beta, charlie);
	return alpha + beta + charlie;
}


bool bn_init()
{
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
	mpz_t mpz_pplus1_div4;
	mpz_init_set_str(mpz_pplus1_div4, bn_pplus1_div4_str, 10);
	mpz2fp(fpe_pplus1_div4, mpz_pplus1_div4);
	mpz_clear(mpz_pplus1_div4);

	mpz_init_set_str(mpz_sqrt_neg3, bn_sqrt_neg3_str, 10);
	mpz_init_set_str(mpz_j, bn_j_str, 10);
	mpz2fp(fpe_j, mpz_j);
	mpz2fp(fpe_sqrt_neg3, mpz_sqrt_neg3);
	mpz_clear(mpz_b0);
	mpz_clear(mpz_b1);
	return true;
}

int fp2e_hash_g2(twistpoint_fp2_t out, uint8_t *msg, ssize_t msg_len, mpz_t mpz_val)
{
	fpe_t t;
	mpz_t hmmmm;
	mpz_init(hmmmm);
	if (!mpz_val) {
		uint8_t hash[crypto_generichash_BYTES];
		crypto_generichash(hash, crypto_generichash_BYTES, msg, sizeof msg_len, NULL, 0);
		mpz_import(hmmmm, crypto_generichash_BYTES, 1, 1, 1, 0, hash);
		mpz_mod(hmmmm, hmmmm, mpz_bn_p);
		mpz2fp(t, hmmmm);
	}
	else {
		mpz_set(hmmmm, mpz_val);
		mpz2fp(t, hmmmm);
	}


	fpe_t a0, a1;
	fpe_t b0, b1;
	fp2e_to_2fpe(b0, b1, twist_b);
	fpe_set(a0, t);
	fpe_square(a0, a0);
	fpe_add(a0, a0, b0);
	fpe_add(a0, a0, one);

	fpe_set(a1, b1);

	fp2e_t A;
	_2fpe_to_fp2e(A, a0, a1);
	fp2e_invert(A, A);
	printf("A: ");
	fp2e_out_str(stdout, A);
	printf("\n");
	fpe_t c;
	fpe_mul(c, fpe_sqrt_neg3, t);

	fp2e_t W;
	fp2e_mul_fpe(W, A, c);

	fp2e_mul_fpe(A, W, t);
	fp2e_to_2fpe(a0, a1, A);
	fp2e_out_str(stdout, A);

	fp2e_t X[3];

	fpe_t x00, x01;
	fpe_sub(x00, fpe_j, a0);
	fpe_neg(x01, a1);
	fpe_out_str(stdout, a1);
	printf("\n");
	fpe_out_str(stdout, x01);
	printf("\n");
	_2fpe_to_fp2e(X[0], x00, x01);

	fpe_t x10, x11;
	fp2e_to_2fpe(x10, x11, X[0]);
	fpe_add(x10, x10, one);
	fpe_neg(x10, x10);
	fpe_neg(x11, x11);

	_2fpe_to_fp2e(X[1], x10, x11);


	fp2e_invert(X[2], W);
	fp2e_square(X[2], X[2]);
	fp2e_add(X[2], X[2], fp2e_one);

	printf("X1, X2, X3\n");
	fp2e_out_str(stdout, X[0]);
	fp2e_out_str(stdout, X[1]);
	fp2e_out_str(stdout, X[2]);


	int alpha, beta, charlie;
	fp2e_t xi_3_plusb[3];
	for (int i = 0; i < 3; i++) {
		fp2e_get_weierstrass(xi_3_plusb[i], X[i]);
	}

	alpha = fp2e_legendre(xi_3_plusb[0]);
	beta = fp2e_legendre(xi_3_plusb[1]);
	charlie = fp2e_legendre(xi_3_plusb[2]);

	if (alpha + beta + charlie == -3) {
		//printf("X[i]^3 + b\n");
		//fp2e_out_str(stdout, xi_3_plusb[0]);
		//fp2e_out_str(stdout, xi_3_plusb[1]);
		//fp2e_out_str(stdout, xi_3_plusb[2]);
	}

	int i = (alpha - 1) * beta % 3;
	i = i < 0 ? i + 3 : i;
	int negate = fpe_legendre(t);
	//printf("%d %d %d || %d\n", alpha, beta, charlie, i);
	fp2e_t y;
	fp2e_sqrt(y, xi_3_plusb[i]);

	if (negate) {
		fp2e_neg(y, y);
	}

	fp2e_set(out->m_x, X[i]);
	fp2e_set(out->m_y, y);
	fp2e_setone(out->m_z);
	fp2e_setzero(out->m_t);
	return alpha + beta + charlie;
}

void bn_hash_to_g1(curvepoint_fp_t out, uint8_t *msg, size_t msg_len)
{
	uint8_t hash[crypto_generichash_BYTES];
	crypto_generichash(hash, crypto_generichash_BYTES, msg, sizeof msg_len, NULL, 0);

	mpz_t mpz_hash;
	mpz_init(mpz_hash);
	mpz_import(mpz_hash, crypto_generichash_BYTES, 1, 1, 1, 0, hash);
	mpz_mod(mpz_hash, mpz_hash, mpz_bn_p);

	fpe_t x, y;
	mpz2fp2(x, mpz_hash);
	mpz_clear(mpz_hash);
	int is_negative = fpe_legendre(x);

	for (;;) {
		fpe_t tmp;
		fpe_cube(tmp, x);
		fpe_add(tmp, tmp, one);
		int res = fpe_sqrt(y, x);
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
}

int mpz_map_to_G1(curvepoint_fp_t rop, uint8_t *msg, size_t msg_len)
{
	uint8_t hash[crypto_generichash_BYTES];
	crypto_generichash(hash, crypto_generichash_BYTES, msg, sizeof msg_len, NULL, 0);

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
	//gmp_printf("MPZ nums\n%Zd\n%Zd\n%Zd\n", x[0], x[1], x[2]);
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
	int x3i = mpz_legendre(xi_3_plusb[2], mpz_bn_p);
	int i = (alpha - 1) * beta % 3;
	i = i < 0 ? i + 3 : i;
	printf("(%d, %d) | (%d, %d) -> I: %d || %d\n", l1, alpha, l2, beta, i, x3i);

	mpz_t y;
	mpz_init(y);
	mpz_sqrt(y, xi_3_plusb[i]);
	mpz_mod(y, y, mpz_bn_p);

	if (negatve) {
		mpz_neg(y, y);
		mpz_mod(y, y, mpz_bn_p);
	}

	mpz2fp(rop->m_x, xi_3_plusb[i]);
	mpz2fp(rop->m_y, y);
	fpe_setone(rop->m_z);
	fpe_setzero(rop->m_t);
	return l1 + l2 + l3;
}

int map_to_G1(curvepoint_fp_t rop, uint8_t *msg, size_t msg_len)
{
	uint8_t hash[crypto_generichash_BYTES];
	crypto_generichash(hash, crypto_generichash_BYTES, msg, sizeof msg_len, NULL, 0);

	mpz_t mpz_hash;
	mpz_init(mpz_hash);
	mpz_import(mpz_hash, crypto_generichash_BYTES, 1, 1, 1, 0, hash);
	mpz_mod(mpz_hash, mpz_hash, mpz_bn_p);

	fpe_t t;
	mpz_t mpz_w;
	mpz_init(mpz_w);

	mpz2fp2(t, mpz_hash);
	mpz_clear(mpz_hash);

	fpe_t w;
	fpe_setzero(w);
	fpe_square(w, t);
	fpe_add(w, w, one);
	fpe_add(w, w, curve_b);
	fp2mpz(mpz_w, w);
	gmp_printf("W after square + 1 + b: %Zd\n", mpz_w);
	fpe_invert(w, w);
	fp2mpz(mpz_w, w);
	gmp_printf("W after inversion: %Zd\n", mpz_w);
	fpe_mul(w, w, t);
	fpe_mul(w, w, fpe_sqrt_neg3);

	gmp_printf("W: %Zd\n", mpz_w);
	fpe_t x[3];
	fpe_setzero(x[0]);
	fpe_setzero(x[1]);
	fpe_setzero(x[2]);
	fpe_mul(x[0], w, t);
	fpe_neg(x[0], x[0]);
	fpe_add(x[0], x[0], fpe_j);

	fpe_neg(x[1], x[0]);
	fpe_add(x[1], x[1], one);
	fpe_square(x[2], w);
	fpe_invert(x[2], x[2]);
	fpe_add(x[2], x[2], one);

	fpe_t r1, r2, r3;
	fpe_setzero(r1);
	fpe_setzero(r2);
	fpe_setzero(r3);
	mpz_t mr1, mr2, mr3;
	mpz_init(mr1);
	mpz_init(mr2);
	mpz_init(mr3);

	gmp_randstate_t rstate;
	gmp_randinit_default(rstate);
	mpz_urandomm(mr1, rstate, mpz_bn_p);
	mpz_urandomm(mr2, rstate, mpz_bn_p);
	mpz_urandomm(mr3, rstate, mpz_bn_p);

	mpz2fp(r1, mr1);
	mpz2fp(r2, mr2);
	mpz2fp(r3, mr3);
	mpz_clear(mr1);
	mpz_clear(mr2);
	mpz_clear(mr3);
	gmp_randclear(rstate);
	int alpha, beta;

	fpe_t xi_3_plus_b[3];
	for (int i = 0; i < 3; i++) {
		fpe_get_weierstrass(xi_3_plus_b[i], x[i]);
	}
	int l1 = fpe_legendre(xi_3_plus_b[0]);
	int l2 = fpe_legendre(xi_3_plus_b[1]);
	int l3 = fpe_legendre(xi_3_plus_b[2]);
	//printf("fpe: %d %d %d\n", l1, l2, l3);

	fpe_t fpe_alpha;
	fpe_t fpe_beta;
	fpe_set(fpe_alpha, xi_3_plus_b[0]);
	fpe_set(fpe_beta, xi_3_plus_b[1]);
	fpe_square(r1, r1);
	fpe_mul(fpe_alpha, r1, fpe_alpha);
	fpe_square(r2, r2);
	fpe_mul(fpe_beta, r2, fpe_beta);

	alpha = fpe_legendre(fpe_alpha);
	beta = fpe_legendre(fpe_beta);

	int i = (((alpha - 1) * beta) % 3);
	i = i == -2 ? 1 : i;
	fpe_square(r3, r3);
	fpe_mul(r3, r3, t);

	int r3_leg = fpe_legendre(r3);
	//printf("a : %d b : %d i : %d\n", alpha, beta, i);

	fpe_t y;
	int hmm = fpe_legendre(xi_3_plus_b[i]);
	int res = fpe_sqrt(y, xi_3_plus_b[i]);

	mpz_t num1, num2, num3;
	mpz_init(num1);
	mpz_init(num2);
	mpz_init(num3);
	fp2mpz(num1, x[0]);
	fp2mpz(num2, x[1]);
	fp2mpz(num3, x[2]);
	gmp_printf("FPE Nums\n%Zd\n%Zd\n%Zd\n", num1, num2, num3);
	fp2mpz(num1, xi_3_plus_b[0]);
	fp2mpz(num2, xi_3_plus_b[1]);
	fp2mpz(num3, xi_3_plus_b[2]);
	gmp_printf("%Zd\n%Zd\n%Zd\n", num1, num2, num3);

	if (r3_leg < 0) {
		fpe_neg(x[i], x[i]);
	}

	fpe_set(rop->m_x, x[i]);
	fpe_set(rop->m_y, y);
	fpe_setone(rop->m_z);
	fpe_setzero(rop->m_t);

	return l1 + l2 + l3;
}

void hash_to_g2(twistpoint_fp2_t rop, uint8_t *msg, size_t msg_len)
{
	fp2e_t fp2e_one;
	fp2e_setone(fp2e_one);
	uint8_t key[crypto_generichash_BYTES];
	memset(key, 2, crypto_generichash_BYTES);
	uint8_t hashx[crypto_generichash_BYTES];
	uint8_t hashy[crypto_generichash_BYTES];
	crypto_generichash(hashx, crypto_generichash_BYTES, msg, sizeof msg_len, NULL, 0);
	crypto_generichash(hashy, crypto_generichash_BYTES, msg, sizeof msg_len, key, sizeof key);

	mpz_t mpz_hashx, mpz_hashy;
	mpz_init(mpz_hashx);
	mpz_init(mpz_hashy);
	mpz_import(mpz_hashx, crypto_generichash_BYTES, 1, 1, 1, 0, hashx);
	mpz_import(mpz_hashy, crypto_generichash_BYTES, 1, 1, 1, 0, hashy);

	mpz_mod(mpz_hashx, mpz_hashx, mpz_bn_p);
	mpz_mod(mpz_hashy, mpz_hashy, mpz_bn_p);

	fpe_t fpe_hashx;
	fpe_t fpe_hashy;
	mpz2fp2(fpe_hashx, mpz_hashx);
	mpz2fp2(fpe_hashy, mpz_hashy);
	mpz_clear(mpz_hashx);
	mpz_clear(mpz_hashy);

	fp2e_t x;
	_2fpe_to_fp2e(x, fpe_hashx, fpe_hashy);

	for (;;) {
		fp2e_t x3;
		fp2e_square(x3, x);
		fp2e_mul(x3, x3, x);

		fp2e_t t, y;
		fp2e_add(t, x3, twist_b);

		int res = fp2e_sqrt(y, t);
		if (res) {
			twistpoint_fp2_affineset_fp2e(rop, x, y);
			twistpoint_fp2_scalarmult_vartime(rop, rop, cofactor);
			break;
		}
		fp2e_add(x, x, fp2e_one);
	}
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

void deserialize_g1(curvepoint_fp_t out, void *in)
{
	deserialize_fpe(out->m_x, in);
	deserialize_fpe(out->m_y, in + fpe_bytes);
	fpe_setone(out->m_z);
	fpe_setzero(out->m_t);
}

void deserialize_g2(twistpoint_fp2_t out, void *in)
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

size_t serialize_g1(uint8_t *out, curvepoint_fp_t g1_elem)
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

size_t serialize_gt(void *out, fp12e_t gt_elem)
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

size_t serialize_g2(void *out, fp2e_t op1, fp2e_t op2)
{
	fpe_t fpe_elems[4];
	fp2e_to_2fpe(fpe_elems[0], fpe_elems[1], op1);
	fp2e_to_2fpe(fpe_elems[2], fpe_elems[3], op2);
	size_t total_count = 0;
	size_t tmp_count = 0;
	uint8_t *ptr = out;
	for (int i = 0; i < 4; i++) {
		tmp_count = serialize_fpe(ptr, fpe_elems[i]);
		ptr += fpe_bytes;
		total_count += tmp_count;
	}
	//printf("G2 bytes serialized: %ld\n", total_count);
	return total_count;
}

void ibe_crypto_sk_from_hashes(uint8_t *sk_out, uint8_t *qid, uint8_t *rp, uint8_t *pair_val)
{
	crypto_generichash_state hash_state;
	crypto_generichash_init(&hash_state, 0, 0, crypto_ghash_BYTES);
	crypto_generichash_update(&hash_state, qid, g2_bytes);
	crypto_generichash_update(&hash_state, rp, g1_bytes);
	crypto_generichash_update(&hash_state, pair_val, gt_bytes);
	crypto_generichash_final(&hash_state, sk_out, crypto_ghash_BYTES);
}

void pair(fp12e_t rop, twistpoint_fp2_t op1, curvepoint_fp_t op2)
{
	twistpoint_fp2_makeaffine(op1);
	curvepoint_fp_makeaffine(op2);
	optate(rop, op1, op2);
}

ssize_t ibe_encrypt(uint8_t *out,
                    uint8_t *msg,
                    uint32_t msg_len,
                    curvepoint_fp_t public_key,
                    uint8_t *recv_id,
                    size_t recv_id_len)
{
	twistpoint_fp2_t q_id;
	twistpoint_fp2_setneutral(q_id);
	hash_to_g2(q_id, recv_id, recv_id_len);

	uint8_t qid_serialized[fpe_bytes * 4];
	memset(qid_serialized, 0, sizeof qid_serialized);
	serialize_g2(qid_serialized, q_id->m_x, q_id->m_y);

	scalar_t r;
	scalar_setrandom(r, bn_n);
	curvepoint_fp_t rp;
	curvepoint_fp_scalarmult_vartime(rp, bn_curvegen, r);
	curvepoint_fp_makeaffine(rp);
	serialize_g1(out, rp);

	fp12e_t pairing_qid_ppub;
	fp12e_setzero(pairing_qid_ppub);
	pair(pairing_qid_ppub, q_id, public_key);
	fp12e_pow_vartime(pairing_qid_ppub, pairing_qid_ppub, r);

	uint8_t pair_qid_ppub_serialized[fpe_bytes * 12];
	serialize_gt(pair_qid_ppub_serialized, pairing_qid_ppub);

	uint8_t secret_key[crypto_ghash_BYTES];
	ibe_crypto_sk_from_hashes(secret_key, qid_serialized, out, pair_qid_ppub_serialized);
	ssize_t res = crypto_secret_nonce_seal(out + g1_bytes, msg, msg_len, secret_key);
	sodium_memzero(secret_key, sizeof secret_key);
	if (res < 0) {
		fprintf(stderr, "[IBE encrypt] failure during symmetric encyrption\n");
		return -1;
	}
	return res + fpe_bytes * 2;
}

int
ibe_decrypt(uint8_t *out,
            uint8_t *c,
            size_t clen,
            uint8_t *public_key,
            twistpoint_fp2_t private_key)
{
	curvepoint_fp_t rp;
	deserialize_g1(rp, c);

	fp12e_t pair_val;
	pair(pair_val, private_key, rp);
	uint8_t pair_val_serialized[fpe_bytes * 12];
	serialize_gt(pair_val_serialized, pair_val);

	uint8_t secret_key[crypto_ghash_BYTES];
	ibe_crypto_sk_from_hashes(secret_key, public_key, c, pair_val_serialized);
	int res = crypto_secret_nonce_open(out, c + fpe_bytes * 2, clen - fpe_bytes * 2, secret_key);
	sodium_memzero(secret_key, crypto_ghash_BYTES);
	return res;
}

void keygen(struct ibe_identity *id, uint8_t *identity, uint8_t identity_length, scalar_t master_sk)
{
	hash_to_g2(id->private_key, identity, identity_length);
	serialize_g2(id->serialized_public_key, id->private_key->m_x, id->private_key->m_y);
	twistpoint_fp2_scalarmult_vartime(id->private_key, id->private_key, master_sk);
	twistpoint_fp2_makeaffine(id->private_key);
}

int main()
{
	bn_init();
	scalar_t s2;
	twistpoint_fp2_t p3;
	scalar_t master_sk;
	curvepoint_fp_t master_pk;
	scalar_setrandom(master_sk, bn_n);
	curvepoint_fp_scalarmult_vartime(master_pk, bn_curvegen, master_sk);
	curvepoint_fp_makeaffine(master_pk);

	uint8_t user_id[60] = "chris";
	uint8_t msg[128] = "This is a test message\n";
	uint8_t out[2048];
	struct ibe_identity id;
	keygen(&id, user_id, sizeof user_id, master_sk);
	int count = 0;
	int fails = 0;
	for (int i = 0; i < 10; i++) {
		memset(out, 0, sizeof out);
		ssize_t res = ibe_encrypt(out, msg, sizeof msg, master_pk, user_id, sizeof user_id);
		uint8_t decrypted[2048];
		memset(decrypted, 0, sizeof decrypted);
		res = ibe_decrypt(decrypted, out, (size_t) res, id.serialized_public_key, id.private_key);
		if (res) {
			fails++;
		}
		count++;
	}
	printf("%d reps, %d fails\n", count, fails);

	uint8_t msg_rand[60];
	curvepoint_fp_t temp;
	int mpz_sum = 0;
	int fpe_sum = 0;
	twistpoint_fp2_t temp2;
	for (int i = 0; i < 100; i++) {
		randombytes_buf(msg_rand, sizeof msg_rand);
		int res = next_attempt(temp2, msg_rand, sizeof msg_rand, NULL);
		printf("%d ", res);
		if (res == -3) fpe_sum++;
	}
	printf("\n\nsum: %d\n\n\n", fpe_sum);





}