#include <sodium.h>
#include "bn256_ibe.h"

struct ibe_identity
{
	twistpoint_fp2_t private_key;
	uint8_t serialized_public_key[g2_bytes];
};

void ibe_build_secret_key(uint8_t *sk_out, uint8_t *qid, uint8_t *rp, uint8_t *pair_val)
{
	crypto_generichash_state hash_state;
	crypto_generichash_init(&hash_state, 0, 0, crypto_ghash_BYTES);
	crypto_generichash_update(&hash_state, qid, g2_bytes);
	crypto_generichash_update(&hash_state, rp, g1_bytes);
	crypto_generichash_update(&hash_state, pair_val, gt_bytes);
	crypto_generichash_final(&hash_state, sk_out, crypto_ghash_BYTES);
}

int
ibe_decrypt(uint8_t *out,
            uint8_t *c,
            size_t clen,
            uint8_t *public_key,
            twistpoint_fp2_t private_key)
{
	curvepoint_fp_t rp;
	bn256_deserialize_g1(rp, c);
	fpe_out_str(stdout, rp->m_x);
	fpe_out_str(stdout, rp->m_y);
	printhex("serialied public key: ", public_key, g2_bytes);
	fp12e_t pair_val;
	bn256_pair(pair_val, private_key, rp);
	//fp12e_out_str(stdout, pair_val);
	uint8_t pair_val_serialized[fpe_bytes * 12];
	bn256_serialize_gt(pair_val_serialized, pair_val);
	printhex("serialied pairing: ", pair_val_serialized, gt_bytes);
	uint8_t secret_key[crypto_ghash_BYTES];
	ibe_build_secret_key(secret_key, public_key, c, pair_val_serialized);
	int res = crypto_secret_nonce_open(out, c + fpe_bytes * 2, clen - fpe_bytes * 2, secret_key);
	sodium_memzero(secret_key, crypto_ghash_BYTES);
	return res;
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
	bn256_hash_g2(q_id, recv_id, recv_id_len, NULL);
	uint8_t qid_serialized[fpe_bytes * 4];
	memset(qid_serialized, 0, sizeof qid_serialized);
	bn256_serialize_g2(qid_serialized, q_id->m_x, q_id->m_y);
	printhex("serialied public key: ", qid_serialized, g2_bytes);
	scalar_t r;
	bn256_scalar_random(r);
	curvepoint_fp_t rp;
	curvepoint_fp_setneutral(rp);
	bn256_scalarmult_bg1(rp, r);
	bn256_serialize_g1(out, rp);
	fpe_out_str(stdout, rp->m_x);
	fpe_out_str(stdout, rp->m_y);
	fp12e_t pairing_qid_ppub;
	fp12e_setzero(pairing_qid_ppub);
	bn256_pair(pairing_qid_ppub, q_id, public_key);
	fp12e_pow_vartime(pairing_qid_ppub, pairing_qid_ppub, r);
	//printf("Pairing:\n");
	//fp12e_out_str(stdout, pairing_qid_ppub);
	uint8_t pair_qid_ppub_serialized[fpe_bytes * 12];
	bn256_serialize_gt(pair_qid_ppub_serialized, pairing_qid_ppub);
	printhex("serialied pairing: ", pair_qid_ppub_serialized, gt_bytes);
	uint8_t secret_key[crypto_ghash_BYTES];
	ibe_build_secret_key(secret_key, qid_serialized, out, pair_qid_ppub_serialized);
	ssize_t res = crypto_secret_nonce_seal(out + g1_bytes, msg, msg_len, secret_key);
	sodium_memzero(secret_key, sizeof secret_key);
	if (res < 0) {
		fprintf(stderr, "[IBE encrypt] failure during symmetric encyrption\n");
		return -1;
	}
	return res + fpe_bytes * 2;
}

void ibe_keygen(struct ibe_identity *id, uint8_t *identity, uint8_t identity_length, scalar_t master_sk)
{
	bn256_hash_g2(id->private_key, identity, identity_length, NULL);
	bn256_serialize_g2(id->serialized_public_key, id->private_key->m_x, id->private_key->m_y);
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
	bn256_scalar_random(master_sk);
	bn256_scalarmult_bg1(master_pk, master_sk);
	uint8_t user_id[60] = "chris";
	uint8_t msg[128] = "This is a test message\n";
	uint8_t out[2048];
	struct ibe_identity id;
	ibe_keygen(&id, user_id, sizeof user_id, master_sk);
	int count = 0;
	int fails = 0;
	for (int i = 0; i < 1; i++) {
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


/*
	uint8_t msg_rand[60];
	curvepoint_fp_t temp;
	int mpz_sum = 0;
	int fpe_sum = 0;
	twistpoint_fp2_t temp2;
	for (int i = 0; i < 100; i++) {
		randombytes_buf(msg_rand, sizeof msg_rand);
		int res = bn256_hash_g2(temp2, msg_rand, sizeof msg_rand, NULL);
		printf("%d ", res);
		if (res == -3) fpe_sum++;
	}
	printf("\n\nsum: %d\n\n\n", fpe_sum);*/
}