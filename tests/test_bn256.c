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

struct ibe_identity
{
	twistpoint_fp2_t private_key;
	uint8_t serialized_public_key[32 * 4];
};

mpz_t mpz_bn_p;

mpz_t bn_q;

fpe_t fpe_bn_p;

mpz_t bn_g;

mpz_t p_plus_1_div_4;

mpz_t s;

mpz_t mpz_sqrt_minus_3;

fpe_t fpe_sqtr_minus_3;

mpz_t mpz_j;

fpe_t fpe_j;

int r;

bool square_root(mpz_t x, mpz_t a);

fpe_t one;

fpe_t two_inverted;

fpe_t curve_b;

scalar_t cofactor;

mpz_t mpz_bn_n;

fpe_t fpe_bn_n;

fp2e_t twist_b;

fpe_t fpe_b0;

fpe_t fpe_b1;

void fpe_cube(fpe_t rop, fpe_t op)
{
	fpe_t tmp;
	fpe_set(tmp, op);
	fpe_mul(rop, tmp, tmp);
	fpe_mul(rop, rop, tmp);
}
void map_to_G2(twistpoint_fp2_t rop, fpe_t op1, fpe_t op2);

void mpz2scalar(scalar_t rop, mpz_t op)
{
	for (int i = 0; i < 4; i++) {
		unsigned long long x = mpz_get_ui(op);
		rop[i] = x;
		mpz_tdiv_q_2exp(op, op, 64);
	}
}

bool bn_init()
{
	mpz_t mpz_b0, mpz_b1;
	mpz_init_set_str(mpz_b0, b0, 10);
	mpz_init_set_str(mpz_b1, b1, 10);
	mpz2fp(fpe_b0, mpz_b0);
	mpz2fp(fpe_b1, mpz_b1);
	_2fpe_to_fp2e(twist_b, fpe_b0, fpe_b1);
	mpz_init(mpz_bn_n);
	mpz_init_set_str(mpz_bn_n, bn_nstr, 10);
	mpz_init_set_str(mpz_bn_p, bn_pstr, 10);
	mpz2fp(fpe_bn_p, mpz_bn_p);
	mpz2fp(fpe_bn_n, mpz_bn_n);
	r = 1;
	mpz_init_set(p_plus_1_div_4, mpz_bn_p);
	mpz_add_ui(p_plus_1_div_4, p_plus_1_div_4, 1);
	mpz_div_ui(p_plus_1_div_4, p_plus_1_div_4, 4);
	mpz_t minus3;
	mpz_init_set_si(minus3, -3);
	square_root(mpz_sqrt_minus_3, minus3);
	mpz2fp(fpe_sqtr_minus_3, mpz_sqrt_minus_3);
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
	return true;
}

void map_to_G1(curvepoint_fp_t rop, fpe_t t)
{
	// w = sqrt(-3) * t / (1+b+t^2)
	fpe_t w;
	fpe_set(w, t);
	fpe_square(w, w);
	fpe_add(w, w, one);
	fpe_add(w, w, curve_b);
	fpe_invert(w, w);
	fpe_mul(w, w, t);
	fpe_mul(w, w, fpe_sqtr_minus_3);

	fpe_t x[3];
	fpe_mul(x[0], w, t);
	fpe_neg(x[0], x[0]);
	fpe_add(x[0], x[0], fpe_j);

	fpe_neg(x[1], x[0]);
	fpe_add(x[1], x[1], one);
	fpe_square(x[2], w);
	fpe_invert(x[2], x[2]);
	fpe_add(x[2], x[2], one);

	fpe_t r1, r2, r3;
	mpz_t mr1, mr2, mr3;
	mpz_init(mr1);
	mpz_init(mr2);
	mpz_init(mr3);

	gmp_randstate_t rstate;
	gmp_randinit_default(rstate);
	mpz_urandomm(mr1, rstate, mpz_bn_n);
	mpz_urandomm(mr2, rstate, mpz_bn_n);
	mpz_urandomm(mr3, rstate, mpz_bn_n);

	mpz2fp(r1, mr1);
	mpz2fp(r2, mr2);
	mpz2fp(r3, mr3);
	int alpha, beta;

	fpe_t fpe_alpha;
	fpe_t fpe_beta;

	fpe_cube(fpe_alpha, x[0]);
	fpe_add(fpe_alpha, fpe_alpha, one);
	fpe_square(r1, r1);
	fpe_mul(fpe_alpha, r1, fpe_alpha);

	fpe_cube(fpe_beta, x[1]);
	fpe_add(fpe_beta, fpe_beta, one);
	fpe_square(r2, r2);
	fpe_mul(fpe_beta, r2, fpe_beta);

	mpz_t mpz_alpha, mpz_beta;
	mpz_init(mpz_alpha);
	mpz_init(mpz_beta);
	fp2mpz(mpz_alpha, fpe_alpha);
	fp2mpz(mpz_beta, fpe_beta);

	alpha = mpz_legendre(mpz_alpha, mpz_bn_n);
	beta = mpz_legendre(mpz_beta, mpz_bn_n);

	int i = ((alpha - 1) * beta % 3);
	//printf("alpha: %d | beta: %d | i: %d\n", alpha, beta, i);
	fpe_square(r3, r3);
	fpe_mul(r3, r3, t);
	fp2mpz(mr3, r3);

	int r3_leg = mpz_legendre(mr3, mpz_bn_n);

	fpe_t fpe_xi;
	fpe_set(fpe_xi, x[i]);
	fpe_cube(fpe_xi, fpe_xi);
	fpe_add(fpe_xi, fpe_xi, curve_b);

	mpz_t xi;
	mpz_init(xi);
	fp2mpz(xi, fpe_xi);
	square_root(xi, xi);
	mpz2fp(fpe_xi, xi);


	printf("\n");
	if (r3_leg < 0) {
		fpe_neg(fpe_xi, fpe_xi);
	}
	printf("\nx[i]: ");
	fpe_print(stdout, x[i]);
	printf("\n");
	printf("y: ");
	fpe_print(stdout, fpe_xi);
	printf("\n");
	fpe_set(rop->m_x, x[i]);
	fpe_set(rop->m_y, fpe_xi);
	fpe_setone(rop->m_z);
	fpe_setzero(rop->m_t);

	mpz_clear(mr1);
	mpz_clear(mr2);
	mpz_clear(mr3);
	mpz_clear(mpz_alpha);
	mpz_clear(mpz_beta);
	mpz_clear(xi);
	gmp_randclear(rstate);

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
	mpz2fp(fpe_hashx, mpz_hashx);
	mpz2fp(fpe_hashy, mpz_hashy);

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
			//printf("-----\n");
			//twistpoint_fp2_print(stdout, rop);
			//printf("-----\n");
			//printf("is a squre\n");
			twistpoint_fp2_scalarmult_vartime(rop, rop, cofactor);
			break;
		}
		fp2e_add(x, x, fp2e_one);
	}
}

void map_to_G2(twistpoint_fp2_t rop, fpe_t op1, fpe_t op2)
{
	curvepoint_fp_t x;
	curvepoint_fp_setneutral(x);
	curvepoint_fp_t y;
	curvepoint_fp_setneutral(y);
	map_to_G1(x, op1);
	map_to_G1(y, op2);
	printf("x: ");
	curvepoint_fp_print(stdout, x);
	//printf("\ny: ");
	//curvepoint_fp_print(stdout, y);
	printf("\n");

	fp2e_t tw1, tw2;
	_2fpe_to_fp2e(tw1, x->m_x, y->m_x);
	_2fpe_to_fp2e(tw2, x->m_y, y->m_y);
	twistpoint_fp2_affineset_fp2e(rop, tw1, tw2);
	//twistpoint_fp2_print(stdout, rop);

	printf("\ng2 before mul:");
	//twistpoint_fp2_print(stdout, rop);
	printf("\n\n\n");
	//twistpoint_fp2_scalarmult_vartime(rop, rop, bn_n);

	printf("\ng2: ");
	//twistpoint_fp2_print(stdout, rop);
	printf("\n");
}

bool square_root(mpz_t x, mpz_t a)
{
	int res = mpz_probab_prime_p(a, 25);
	if (!res) return false;

	res = mpz_legendre(a, mpz_bn_p);
	if (res < 0) return false;

	if (r == 1) {
		mpz_powm(x, a, p_plus_1_div_4, mpz_bn_p);
		return true;
	}

	mpz_t c;
	mpz_init_set(c, s);
	mpz_t d;
	int e = r;

	mpz_powm(d, a, bn_q, mpz_bn_p);
	mpz_powm(x, a, p_plus_1_div_4, mpz_bn_p);

	mpz_t dd, b;
	while (mpz_cmp_si(d, 1) != 0) {
		int i = 1;
		mpz_mul(dd, d, d);
		mpz_mod(dd, dd, mpz_bn_p);
		while (mpz_cmp_si(dd, 1) != 0) {
			mpz_mul(dd, dd, dd);
			mpz_mod(dd, dd, mpz_bn_p);
			i++;
		}

		mpz_t cpow;
		mpz_t e_minus_i_minus_1;
		mpz_init_set_si(e_minus_i_minus_1, e - i - 1);
		mpz_init_set_si(cpow, 2);
		mpz_powm(cpow, cpow, e_minus_i_minus_1, mpz_bn_p);
		mpz_powm(b, c, cpow, mpz_bn_p);

		mpz_mul(x, x, b);
		mpz_mod(x, x, mpz_bn_p);

		mpz_mul(c, b, b);
		mpz_mod(c, c, mpz_bn_p);

		mpz_mul(d, d, c);
		mpz_mod(d, d, mpz_bn_p);
		e = i;
	}
	return true;
}

size_t serialize_fpe(void *out, fpe_t op)
{
	mpz_t x;
	mpz_init(x);
	fp2mpz(x, op);
	size_t count;
	mpz_export(out, &count, 1, 1, 1, 0, x);
	mpz_clear(x);
	return count;
}

int deserialize_fpe(fpe_t out, uint8_t *in)
{
	mpz_t tmp;
	mpz_init(tmp);
	mpz_import(tmp, 32, 1, 1, 1, 0, in);
	mpz2fp(out, tmp);
	mpz_clear(tmp);
	return 0;
}

void deserialize_g1(curvepoint_fp_t out, void *in)
{
	deserialize_fpe(out->m_x, in);
	deserialize_fpe(out->m_y, in + 32);
	fpe_setone(out->m_z);
	fpe_setzero(out->m_t);
}

void deserialize_g2(twistpoint_fp2_t out, void *in)
{
	fpe_t fp1, fp2, fp3, fp4;
	deserialize_fpe(fp1, in);
	deserialize_fpe(fp2, in + 32);
	deserialize_fpe(fp3, in + 32);
	deserialize_fpe(fp4, in + 32);
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
	uint8_t *ptr = out;
	size_t total_count = 0;
	size_t count = serialize_fpe(ptr, fp1);
	ptr += count;
	total_count += count;
	count = serialize_fpe(ptr, fp2);
	total_count += count;

	printf("G1 bytes serialized: %ld\n", total_count);
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
		ptr += tmp_count;
		total_count += tmp_count;
	}
	printf("GT bytes serialized: %ld\n", total_count);
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
		ptr += tmp_count;
		total_count += tmp_count;
	}
	printf("G2 bytes serialized: %ld\n", total_count);
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
                    size_t recv_id_len,
                    fp12e_t pair_val)
{
	twistpoint_fp2_t q_id;
	hash_to_g2(q_id, recv_id, recv_id_len);
	uint8_t qid_serialized[32 * 4];
	serialize_g2(qid_serialized, q_id->m_x, q_id->m_y);

	scalar_t r;
	scalar_setrandom(r, bn_n);
	curvepoint_fp_t rp;
	curvepoint_fp_scalarmult_vartime(rp, bn_curvegen, r);
	curvepoint_fp_makeaffine(rp);
	serialize_g1(out, rp);
	fp12e_t pairing_qid_ppub;
	pair(pairing_qid_ppub, q_id, public_key);
	fp12e_pow_vartime(pairing_qid_ppub, pairing_qid_ppub, r);
	fp12e_set(pair_val, pairing_qid_ppub);
	uint8_t pair_qid_ppub_serialized[32 * 12];
	serialize_gt(pair_qid_ppub_serialized, pairing_qid_ppub);
	printf("Hashing in encryption: \n");
	printhex("Q_id", qid_serialized, 32 * 4);
	printhex("rP", out, 32 * 2);
	printhex("e(Q_id, P_pub", pair_qid_ppub_serialized, 32 * 12);
	printf("\n------------------\n");
	crypto_generichash_state hash_state;
	crypto_generichash_init(&hash_state, 0, 0, crypto_ghash_BYTES);
	crypto_generichash_update(&hash_state, qid_serialized, sizeof qid_serialized);
	crypto_generichash_update(&hash_state, out, 32 * 2);
	crypto_generichash_update(&hash_state, pair_qid_ppub_serialized, 32 * 12);
	uint8_t secret_key[crypto_ghash_BYTES];
	crypto_generichash_final(&hash_state, secret_key, crypto_ghash_BYTES);
	printf("\n--------------SECRET KEY\n");
	printhex("SK", secret_key, crypto_ghash_BYTES);
	ssize_t res = crypto_secret_nonce_seal(out + 32 * 2, msg, msg_len, secret_key);
	sodium_memzero(secret_key, sizeof secret_key);
	if (res < 0) {
		fprintf(stderr, "[IBE encrypt] failure during symmetric encyrption\n");
		return -1;
	}

	else {
		printhex("ciphertext", out + 32 * 2, (uint32_t) res);
		return res + 32 * 2;
	}
}

int
ibe_decrypt(uint8_t *out,
            uint8_t *c,
            size_t clen,
            uint8_t *public_key,
            twistpoint_fp2_t private_key,
            fp12e_t pair_val_out)
{
	curvepoint_fp_t rp;
	deserialize_g1(rp, c);
	fp12e_t pair_val;
	fp12e_setone(pair_val);
	pair(pair_val, private_key, rp);
	fp12e_set(pair_val_out, pair_val);
	//printf("\n\n");
	//fp12e_print(stdout, pair_val);
	printf("\n");
	uint8_t pair_val_serialized[32 * 12];
	serialize_gt(pair_val_serialized, pair_val);
	printf("Hashing in encryption: \n");
	printhex("Q_id", public_key, 32 * 4);
	printhex("rP", c, 32 * 2);
	printhex("e(Q_id, P_pub", pair_val_serialized, 32 * 12);
	printf("\n------------------\n");
	crypto_generichash_state hash_state;
	crypto_generichash_init(&hash_state, 0, 0, crypto_ghash_BYTES);
	crypto_generichash_update(&hash_state, public_key, 32 * 4);
	crypto_generichash_update(&hash_state, c, 32 * 2);
	crypto_generichash_update(&hash_state, pair_val_serialized, 32 * 12);
	uint8_t secret_key[crypto_ghash_BYTES];
	crypto_generichash_final(&hash_state, secret_key, crypto_ghash_BYTES);
	printf("\n--------------SECRET KEY\n");
	printhex("SK", secret_key, crypto_ghash_BYTES);
	uint8_t msg[2048];
	printhex("ciphertext before decryption", c + 32 * 2, (uint32_t) clen - 32 * 2);
	int res = crypto_secret_nonce_open(out, c + 32 * 2, clen - 32 * 2, secret_key);
	printf("res: %d\n", res);
	if (!res) {
		printf("%s.10\n", msg);
	}


	return 0;
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
	twistpoint_fp2_t arggggh;
	hash_to_g2(arggggh, user_id, sizeof user_id);
	twistpoint_fp2_t secret_arghhhhhh;
	twistpoint_fp2_scalarmult_vartime(secret_arghhhhhh, arggggh, master_sk);
	twistpoint_fp2_makeaffine(secret_arghhhhhh);
	fp12e_t pair1, pair2;
	scalar_t rand;
	scalar_setrandom(rand, bn_n);
	curvepoint_fp_t randp;
	curvepoint_fp_scalarmult_vartime(randp, bn_curvegen, rand);
	curvepoint_fp_makeaffine(randp);
	pair(pair1, arggggh, master_pk);
	fp12e_pow_vartime(pair1, pair1, rand);
	pair(pair2, secret_arghhhhhh, randp);
	printf("I WONDER IF THESE MIGHT BE EQUAL??????? %d\n", fp12e_iseq(pair1, pair2));

	uint8_t msg[128] = "This is a test message\n";
	uint8_t out[2048];
	fp12e_t p1, p2;
	ssize_t res = ibe_encrypt(out, msg, sizeof msg, master_pk, user_id, sizeof user_id, p1);
//	printf("size of ciphertext: %ld\n", res);
	struct ibe_identity id;
	keygen(&id, user_id, sizeof user_id, master_sk);
	uint8_t decrypted[2048];
	ibe_decrypt(decrypted, out, (size_t) res, id.serialized_public_key, secret_arghhhhhh, p2);
	printf("\n--------\nEQUALITY OF PAIRING VALUES: %d\n", fp12e_iseq(p1, p2));

	fp12e_t x;
	twistpoint_fp2_t blah;
	twistpoint_fp2_scalarmult_vartime(blah, bn_twistgen, master_sk);
	pair(x, blah, master_pk);
	uint8_t pair_out[32 * 12];
	serialize_gt(pair_out, x);

	fp12e_t x2;
	//deserialize_fp

	twistpoint_fp2_t user_public_key;
	hash_to_g2(user_public_key, user_id, 60);

	twistpoint_fp2_t dummypk;
	scalar_t rnd;
	scalar_setrandom(rnd, bn_n);
	printf("\n----------------------\n");
	twistpoint_fp2_print(stdout, user_public_key);
	printf("\n\n\n");
	twistpoint_fp2_scalarmult_vartime(user_public_key, bn_twistgen, rnd);
	twistpoint_fp2_makeaffine(user_public_key);
	twistpoint_fp2_print(stdout, user_public_key);
	printf("\n----------------------\n");
	twistpoint_fp2_t user_secret_key;
	twistpoint_fp2_scalarmult_vartime(user_secret_key, user_public_key, master_sk);
	twistpoint_fp2_makeaffine(user_public_key);
	twistpoint_fp2_makeaffine(user_secret_key);
	scalar_t r;
	scalar_setrandom(r, bn_n);

	curvepoint_fp_t rp;
	curvepoint_fp_scalarmult_vartime(rp, bn_curvegen, r);
	curvepoint_fp_makeaffine(rp);

	fp12e_t e1;
	fp12e_setone(e1);
	optate(e1, user_public_key, master_pk);
	fp12e_pow_vartime(e1, e1, r);

	fp12e_t e2;
	fp12e_setone(e2);
	optate(e2, user_secret_key, rp);
	printf("\n%d %d\n", fp12e_iseq(e1, e2), fp12e_iseq(e1, e1));
	fp12e_print(stdout, e1);
	printf("\n\n\n");
	fp12e_print(stdout, e2);

}