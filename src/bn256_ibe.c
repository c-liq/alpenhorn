#include <sodium.h>
#include <bn256/twistpoint_fp2.h>
#include <bn256.h>
#include "bn256_ibe.h"


void bn256_ibe_build_sk(uint8_t *sk_out, uint8_t *qid, uint8_t *rp, uint8_t *pair_val)
{
	crypto_generichash_state hash_state;
	crypto_generichash_init(&hash_state, 0, 0, crypto_ghash_BYTES);
	crypto_generichash_update(&hash_state, qid, g2_bytes);
	crypto_generichash_update(&hash_state, rp, g1_bytes);
	crypto_generichash_update(&hash_state, pair_val, gt_bytes);
	crypto_generichash_final(&hash_state, sk_out, crypto_ghash_BYTES);
}

int bn256_ibe_decrypt(uint8_t *out,
                      uint8_t *c,
                      size_t clen,
                      uint8_t *public_key,
                      twistpoint_fp2_t private_key)
{
	curvepoint_fp_t rp;
	bn256_deserialize_g1(rp, c);
	fp12e_t pair_val;
	fp12e_setzero(pair_val);
	bn256_pair(pair_val, private_key, rp);
	uint8_t pair_val_serialized[gt_bytes];
	memset(pair_val_serialized, 0, gt_bytes);
	bn256_serialize_gt(pair_val_serialized, pair_val);
	uint8_t secret_key[crypto_ghash_BYTES];
	bn256_ibe_build_sk(secret_key, public_key, c, pair_val_serialized);
	int res = crypto_secret_nonce_open(out, c + g1_bytes, clen - g1_bytes, secret_key);
/*	printhex("secret key", secret_key, crypto_ghash_BYTES);
	printhex("rp", c, g1_serialized_bytes);
	printhex("public key", public_key, crypto_ghash_BYTES);
	printhex("pairing", pair_val_serialized, gt_bytes);*/
	sodium_memzero(secret_key, crypto_ghash_BYTES);
	return res;
}

ssize_t bn256_ibe_encrypt(uint8_t *out,
                          uint8_t *msg,
                          uint32_t msg_len,
                          curvepoint_fp_t master_pk,
                          uint8_t *recv_id,
                          size_t recv_id_len)
{
	twistpoint_fp2_t q_id;
	twistpoint_fp2_setneutral(q_id);
	bn256_hash_g2(q_id, recv_id, recv_id_len);
	uint8_t qid_serialized[fpe_bytes * 4];
	memset(qid_serialized, 0, sizeof qid_serialized);
	bn256_serialize_g2(qid_serialized, q_id);
	scalar_t r;
	bn256_scalar_random(r);
	curvepoint_fp_t rp;
	curvepoint_fp_setneutral(rp);
	bn256_scalarmult_base_g1(rp, r);
	bn256_serialize_g1(out, rp);
	fp12e_t pairing_qid_ppub;
	fp12e_setzero(pairing_qid_ppub);
	bn256_pair(pairing_qid_ppub, q_id, master_pk);
	fp12e_pow_vartime(pairing_qid_ppub, pairing_qid_ppub, r);
	uint8_t pair_qid_ppub_serialized[fpe_bytes * 12];
	bn256_serialize_gt(pair_qid_ppub_serialized, pairing_qid_ppub);
	uint8_t secret_key[crypto_ghash_BYTES];
	bn256_ibe_build_sk(secret_key, qid_serialized, out, pair_qid_ppub_serialized);
	ssize_t res = crypto_secret_nonce_seal(out + g1_bytes, msg, msg_len, secret_key);
/*	printhex("secret key", secret_key, crypto_ghash_BYTES);
	printhex("rp", out, g1_serialized_bytes);
	printhex("public key", qid_serialized, crypto_ghash_BYTES);
	printhex("pairing", pair_qid_ppub_serialized, gt_bytes);*/
	sodium_memzero(secret_key, sizeof secret_key);
	if (res < 0) {
		fprintf(stderr, "[IBE encrypt] failure during symmetric encyrption\n");
		return -1;
	}
	return res + fpe_bytes * 2;
}

void bn256_ibe_keygen(struct ibe_identity *id, uint8_t *identity, uint8_t identity_length, scalar_t master_sk)
{
	bn256_hash_g2(id->private_key, identity, identity_length);
	bn256_serialize_g2(id->serialized_public_key, id->private_key);
	twistpoint_fp2_scalarmult_vartime(id->private_key, id->private_key, master_sk);
	twistpoint_fp2_makeaffine(id->private_key);
}
