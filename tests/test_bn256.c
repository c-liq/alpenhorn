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

struct ibe_identity
{
	twistpoint_fp2_t private_key;
	uint8_t serialized_public_key[32 * 4];
};

mpz_t mpz_bn_p;

fpe_t fpe_bn_p;

mpz_t bn_g;

mpz_t p_plus_1_div_4;

mpz_t s;

mpz_t mpz_sqrt_minus_3;

fpe_t fpe_sqtr_minus_3;

mpz_t mpz_j;

fpe_t fpe_j;

int r;

fpe_t one;

fpe_t two_inverted;

fpe_t curve_b;

scalar_t cofactor;

mpz_t mpz_bn_n;

fpe_t fpe_bn_n;

fp2e_t twist_b;

fpe_t fpe_b0;

fpe_t fpe_b1;

size_t last_enc_gt = 0;

size_t last_dec_gt = 0;

size_t last_enc_g1 = 0;

size_t last_dec_g1 = 0;

uint8_t last_enc_buf[64];

uint8_t last_dec_buf[64];

curvepoint_fp_t last_enc_cp;

curvepoint_fp_t last_dec_cp;

size_t lg1countx;

size_t lg1county;

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

void get_weierstrass(fpe_t y, const fpe_t x)
{
	fpe_t t;
	fpe_square(t, x);
	fpe_mul(t, t, x);
	fpe_add(y, t, curve_b);
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
	r = 1;
	mpz_init_set(p_plus_1_div_4, mpz_bn_p);
	mpz_add_ui(p_plus_1_div_4, p_plus_1_div_4, 1);
	mpz_div_ui(p_plus_1_div_4, p_plus_1_div_4, 4);
	mpz_t minus3;
	mpz_init_set_si(minus3, -3);
	//square_root(mpz_sqrt_minus_3, minus3);
	fpe_t fpe_min3;
	mpz2fp2(fpe_min3, minus3);
	fpe_sqrt(fpe_sqtr_minus_3, fpe_min3);
	fpe_set(fpe_j, fpe_sqtr_minus_3);

	fpe_setone(one);
	fpe_setone(two_inverted);
	fpe_add(two_inverted, two_inverted, one);
	fpe_setone(curve_b);
	fpe_triple(curve_b, curve_b);
	fpe_invert(two_inverted, two_inverted);
	fpe_sub(fpe_j, fpe_j, one);
	fpe_mul(fpe_j, fpe_j, two_inverted);
	fpe_t two;
	fpe_add(two, one, one);
	mpz_t cofactor_mpz;
	mpz_init(cofactor_mpz);
	mpz_mul_ui(cofactor_mpz, mpz_bn_p, 2);
	mpz_sub(cofactor_mpz, cofactor_mpz, mpz_bn_n);
	mpz2scalar(cofactor, cofactor_mpz);
	mpz_clear(cofactor_mpz);
	mpz_clear(minus3);
	mpz_clear(mpz_b0);
	mpz_clear(mpz_b1);
	return true;
}

void hash_to_G1(curvepoint_fp_t out, uint8_t *msg, size_t msg_len)
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

/*void hash_to_G1(curvepoint_fp_t out, uint8_t *msg, size_t msg_len)
{
	uint8_t hash[crypto_generichash_BYTES];
	crypto_generichash(hash, crypto_generichash_BYTES, msg, sizeof msg_len, NULL, 0);

	mpz_t mpz_hash;
	mpz_init(mpz_hash);
	mpz_import(mpz_hash, crypto_generichash_BYTES, 1, 1, 1, 0, hash);
	mpz_mod(mpz_hash, mpz_hash, mpz_bn_p);

	fpe_t t;
	mpz2fp2(t, mpz_hash);

	fpe_t w;
	fpe_setzero(w);
	fpe_set(w, t);
	fpe_square(w, w);
	fpe_add(w, w, one);
	fpe_add(w, w, curve_b);
	fpe_invert(w, w);
	fpe_mul(w, w, t);
	fpe_mul(w, w, fpe_sqtr_minus_3);

	fpe_t x[3];
	fpe_setzero(x[0]);
	fpe_setzero(x[1]);
	fpe_setzero(x[2]);
	fpe_mul(x[0], w, t);
	fpe_neg(x[0], x[0]);
	fpe_add(x[0], x[0], fpe_j);

	fpe_neg(x[1], x[0]);
	fpe_sub(x[1], x[1], one);

	fpe_square(x[2], w);
	fpe_invert(x[2], x[2]);
	fpe_add(x[2], x[2], one);

	fpe_t y1, y2, y3;
	int ly1, ly2, ly3;
	get_weierstrass(y1, x[0]);
	get_weierstrass(y2, x[1]);
	get_weierstrass(y3, x[2]);
	ly1 = fpe_legendre(y1);
	ly2 = fpe_legendre(y2);
	ly3 = fpe_legendre(y3);
	printf("%d %d %d\n", ly1, ly2, ly3);
	fpe_print(stdout, y1);
	fpe_print(stdout, y2);
	fpe_print(stdout, y3);
	mpz_t mpz_y[3];
	mpz_init(mpz_y[0]);
	mpz_init(mpz_y[1]);
	mpz_init(mpz_y[2]);
	fp2mpz2(mpz_y[0], y1);
	fp2mpz2(mpz_y[1], y2);
	fp2mpz2(mpz_y[2], y3);
	int mp1 = mpz_legendre(mpz_y[0], mpz_bn_p);
	int mp2 = mpz_legendre(mpz_y[1], mpz_bn_p);
	int mp3 = mpz_legendre(mpz_y[2], mpz_bn_p);
	printf("%d %d %d\n", mp1, mp2, mp3);
}*/

void map_to_G1(curvepoint_fp_t rop, fpe_t t)
{
	// w = sqrt(-3) * t / (1+b+t^2)
	fpe_t w;
	fpe_setzero(w);
	fpe_set(w, t);
	fpe_square(w, w);
	fpe_add(w, w, one);
	fpe_add(w, w, curve_b);
	fpe_invert(w, w);
	fpe_mul(w, w, t);
	fpe_mul(w, w, fpe_sqtr_minus_3);

	fpe_t x[3];
	fpe_setzero(x[0]);
	fpe_setzero(x[1]);
	fpe_setzero(x[2]);
	fpe_mul(x[0], w, t);
	fpe_neg(x[0], x[0]);
	fpe_add(x[0], x[0], fpe_j);

	fpe_neg(x[1], x[0]);
	fpe_sub(x[1], x[1], one);
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
	mpz_urandomm(mr1, rstate, mpz_bn_n);
	mpz_urandomm(mr2, rstate, mpz_bn_n);
	mpz_urandomm(mr3, rstate, mpz_bn_n);

	mpz2fp2(r1, mr1);
	mpz2fp2(r2, mr2);
	mpz2fp2(r3, mr3);
	mpz_clear(mr1);
	mpz_clear(mr2);
	mpz_clear(mr3);
	gmp_randclear(rstate);
	int alpha, beta;

	fpe_t xi_3_plus_b[3];
	fpe_setzero(xi_3_plus_b[0]);
	fpe_setzero(xi_3_plus_b[1]);
	fpe_setzero(xi_3_plus_b[2]);

	fpe_cube(xi_3_plus_b[0], x[0]);
	fpe_cube(xi_3_plus_b[1], x[1]);
	fpe_cube(xi_3_plus_b[2], x[2]);
	fpe_add(xi_3_plus_b[0], xi_3_plus_b[0], curve_b);
	fpe_add(xi_3_plus_b[1], xi_3_plus_b[1], curve_b);
	fpe_add(xi_3_plus_b[2], xi_3_plus_b[2], curve_b);
	int l1 = fpe_legendre(xi_3_plus_b[0]);
	int l2 = fpe_legendre(xi_3_plus_b[1]);
	int l3 = fpe_legendre(xi_3_plus_b[2]);

	mpz_t mpz_xi_3_plus_b[3];
	mpz_init(mpz_xi_3_plus_b[0]);
	mpz_init(mpz_xi_3_plus_b[1]);
	mpz_init(mpz_xi_3_plus_b[2]);
	fp2mpz2(mpz_xi_3_plus_b[0], xi_3_plus_b[0]);
	fp2mpz2(mpz_xi_3_plus_b[1], xi_3_plus_b[1]);
	fp2mpz2(mpz_xi_3_plus_b[2], xi_3_plus_b[2]);
	int mp1 = mpz_legendre(mpz_xi_3_plus_b[0], mpz_bn_p);
	int mp2 = mpz_legendre(mpz_xi_3_plus_b[1], mpz_bn_p);
	int mp3 = mpz_legendre(mpz_xi_3_plus_b[2], mpz_bn_p);

	printf("FPE legendre: %d %d %d\n", l1, l2, l3);
	printf("MPZlegendre: %d %d %d\n", mp1, mp2, mp3);

	fpe_t fpe_alpha;
	fpe_t fpe_beta;
	fpe_setzero(fpe_alpha);
	fpe_setzero(fpe_beta);
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
	printf("alpha: %d | beta: %d | i: %d | r3_leg: %d\n", alpha, beta, i, r3_leg);

	fpe_t y;
	int hmm = fpe_legendre(xi_3_plus_b[i]);
	int res = fpe_sqrt(y, xi_3_plus_b[i]);
	if (!res) {
		printf("HMM: %d | PANIC PANIC PANIC\n", hmm);
	}
	if (r3_leg < 0) {
		fpe_neg(x[i], x[i]);
	}

	fpe_set(rop->m_x, x[i]);
	fpe_set(rop->m_y, y);
	fpe_setone(rop->m_z);
	fpe_setzero(rop->m_t);
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

	fp2e_t x;
	_2fpe_to_fp2e(x, fpe_hashx, fpe_hashy);
	for (;;) {
		fp2e_t xxx;
		fp2e_square(xxx, x);
		fp2e_mul(xxx, xxx, x);

		fp2e_t t, y;
		fp2e_add(t, xxx, twist_b);
		fp2e_isreduced(t);
		int res = fp2e_sqrt(y, t);
		if (res) {
			twistpoint_fp2_affineset_fp2e(rop, x, y);
			twistpoint_fp2_scalarmult_vartime(rop, rop, cofactor);
			break;
		}
		fp2e_add(x, x, fp2e_one);
	}
	mpz_clear(mpz_hashx);
	mpz_clear(mpz_hashy);
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

int deserialize_fpe2(fpe_t out, uint8_t *in, size_t len)
{
	mpz_t tmp;
	mpz_init(tmp);
	mpz_import(tmp, len, 1, 1, 1, 0, in);
	mpz2fp2(out, tmp);
	mpz_clear(tmp);
	return 0;
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
	lg1countx = count;
	count = serialize_fpe(out + fpe_bytes, fp2);
	lg1county = count;
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
	if (total_count < 384) {
		//printf("GT bytes serialized: %ld\n", total_count);
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
	uint8_t qid_serialized[32 * 4];
	memset(qid_serialized, 0, sizeof qid_serialized);
	serialize_g2(qid_serialized, q_id->m_x, q_id->m_y);
	scalar_t r;
	scalar_setrandom(r, bn_n);
	curvepoint_fp_t rp;
	curvepoint_fp_scalarmult_vartime(rp, bn_curvegen, r);
	curvepoint_fp_makeaffine(rp);
	curvepoint_fp_set(last_enc_cp, rp);
	last_enc_g1 = serialize_g1(out, rp);
	curvepoint_fp_t x;

	deserialize_fpe(x->m_x, out);
	deserialize_fpe(x->m_y, out + fpe_bytes);
	fpe_setone(x->m_z);
	fpe_setzero(x->m_t);

	int b1 = fpe_iseq(x->m_x, rp->m_x);
	int b2 = fpe_iseq(x->m_y, rp->m_y);
	if (!b1 || !b2) {
		printf("iseq: %d %d || %ld %ld\n", b1, b2, lg1countx, lg1county);
		printf("x->mx: ");
		fpe_print(stdout, x->m_x);
		printf("x->my: ");
		fpe_print(stdout, x->m_y);
		printf("rp->mx: ");
		fpe_print(stdout, rp->m_x);
		printf("rp->my: ");
		fpe_print(stdout, rp->m_y);

	}

	memcpy(last_enc_buf, out, fpe_bytes * 2);
	fp12e_t pairing_qid_ppub;
	fp12e_setzero(pairing_qid_ppub);
	pair(pairing_qid_ppub, q_id, public_key);
	fp12e_pow_vartime(pairing_qid_ppub, pairing_qid_ppub, r);
	uint8_t pair_qid_ppub_serialized[32 * 12];
	memset(pair_qid_ppub_serialized, 0, sizeof pair_qid_ppub_serialized);
	last_enc_gt = serialize_gt(pair_qid_ppub_serialized, pairing_qid_ppub);
	crypto_generichash_state hash_state;
	crypto_generichash_init(&hash_state, 0, 0, crypto_ghash_BYTES);
	crypto_generichash_update(&hash_state, qid_serialized, sizeof qid_serialized);
	crypto_generichash_update(&hash_state, out, 32 * 2);
	crypto_generichash_update(&hash_state, pair_qid_ppub_serialized, 32 * 12);
	uint8_t secret_key[crypto_ghash_BYTES];
	crypto_generichash_final(&hash_state, secret_key, crypto_ghash_BYTES);
	ssize_t res = crypto_secret_nonce_seal(out + 32 * 2, msg, msg_len, secret_key);
	sodium_memzero(secret_key, sizeof secret_key);
	if (res < 0) {
		fprintf(stderr, "[IBE encrypt] failure during symmetric encyrption\n");
		return -1;
	}

	else {
		//printhex("ciphertext", out + 32 * 2, (uint32_t) res);
		return res + 32 * 2;
	}
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
	curvepoint_fp_set(last_dec_cp, rp);
	memcpy(last_dec_buf, c, fpe_bytes * 2);
	fp12e_t pair_val;
	fp12e_setzero(pair_val);
	pair(pair_val, private_key, rp);
	uint8_t pair_val_serialized[32 * 12];
	memset(pair_val_serialized, 0, sizeof pair_val_serialized);
	last_dec_gt = serialize_gt(pair_val_serialized, pair_val);
	crypto_generichash_state hash_state;
	crypto_generichash_init(&hash_state, 0, 0, crypto_ghash_BYTES);
	crypto_generichash_update(&hash_state, public_key, 32 * 4);
	crypto_generichash_update(&hash_state, c, 32 * 2);
	crypto_generichash_update(&hash_state, pair_val_serialized, 32 * 12);
	uint8_t secret_key[crypto_ghash_BYTES];
	crypto_generichash_final(&hash_state, secret_key, crypto_ghash_BYTES);
	int res = crypto_secret_nonce_open(out, c + 32 * 2, clen - 32 * 2, secret_key);
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
	//scalar_print(stdout, master_sk);
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
			printf("failure: last enc gt: %ld | last dec gt: %ld | last enc g1: %ld\n--------\n",
			       last_enc_gt,
			       last_dec_gt,
			       last_enc_g1);
			if (last_enc_g1 == 64) {

			}

		}
		count++;
	}
	printf("%d reps, %d fails\n", count, fails);
	uint8_t hmm[60];
	randombytes_buf(hmm, 60);
	curvepoint_fp_t blah;
	hash_to_G1(blah, hmm, sizeof hmm);

}