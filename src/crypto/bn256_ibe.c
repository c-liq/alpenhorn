#include "bn256_ibe.h"

void bn256_ibe_master_keypair(scalar_t sk, curvepoint_fp_struct_t *pk) {
    bn256_g1_random(pk, sk);
}

void bn256_ibe_build_sk(uint8_t *out, uint8_t *id_hash, uint8_t *rp, uint8_t *pair_hash)
{
	crypto_generichash_state hash_state;
    crypto_generichash_init(&hash_state, 0, 0, crypto_secretbox_KEYBYTES);
    crypto_generichash_update(&hash_state, id_hash, g2_bytes);
	crypto_generichash_update(&hash_state, rp, g1_bytes);
    crypto_generichash_update(&hash_state, pair_hash, gt_bytes);
    crypto_generichash_final(&hash_state, out, crypto_secretbox_KEYBYTES);
}

int bn256_ibe_decrypt(uint8_t *out, uint8_t *c, size_t clen, uint8_t *pk, twistpoint_fp2_t sk)
{
    curvepoint_fp_t rp = {{{{{0}}}}};
	bn256_deserialize_g1(rp, c);

    fp12e_t pairing;
    fp12e_setzero(pairing);
    bn256_pair(pairing, sk, rp);

    uint8_t pairing_bytes[gt_bytes];
    memset(pairing_bytes, 0, gt_bytes);
    bn256_serialize_gt(pairing_bytes, pairing);

    uint8_t secret_key[crypto_secretbox_KEYBYTES];
    bn256_ibe_build_sk(secret_key, pk, c, pairing_bytes);

    int result = crypto_salsa_decrypt(out, c + g1_bytes, clen - g1_bytes, secret_key);
    sodium_memzero(secret_key, crypto_ghash_BYTES);
    return result;
}

int bn256_ibe_encrypt(uint8_t *out, uint8_t *msg, uint64_t msg_len, curvepoint_fp_t master_pk,
                      uint8_t *id, size_t id_len) {
    twistpoint_fp2_t id_hash;
    bn256_hash_g2(id_hash, id, id_len);
    uint8_t id_hash_bytes[g2_bytes];
    memset(id_hash_bytes, 0, sizeof id_hash_bytes);
    bn256_serialize_g2(id_hash_bytes, id_hash);

	scalar_t r;
	curvepoint_fp_t rp;
    bn256_g1_random(rp, r);
	bn256_serialize_g1(out, rp);

    fp12e_t pairing;
    fp12e_setzero(pairing);
    bn256_pair(pairing, id_hash, master_pk);

    fp12e_pow_vartime(pairing, pairing, r);
    uint8_t pairing_bytes[gt_bytes];
    bn256_serialize_gt(pairing_bytes, pairing);

    uint8_t secret_key[crypto_ghash_BYTES];
    bn256_ibe_build_sk(secret_key, id_hash_bytes, out, pairing_bytes);

    int result = crypto_salsa_encrypt(out + g1_bytes, msg, msg_len, secret_key);
	sodium_memzero(secret_key, sizeof secret_key);
    return result;
}

void bn256_ibe_keygen(twistpoint_fp2_t id_pk, twistpoint_fp2_t id_sk, uint8_t *id, size_t id_len, scalar_t master_sk) {
    bn256_hash_g2(id_pk, id, id_len);
    bn256_serialize_g2(id, id_pk);
    twistpoint_fp2_scalarmult_vartime(id_sk, id_pk, master_sk);
    twistpoint_fp2_makeaffine(id_sk);
}

