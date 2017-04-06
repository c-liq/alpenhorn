#include "ibe.h"

struct ibe_params
{
	pairing_s pairing;
	element_s gemerator;
	element_s public_key;
	element_s private_key;
};

struct bn_params
{

};

typedef struct ibe_params ibe_params;

ibe_params *ibe_alloc(char *pb_params, const char *gen)
{
	ibe_params *params = malloc(sizeof(ibe_params));
	pairing_init_set_str(&params->pairing, pb_params);
	element_init(&params->gemerator, params->pairing.G2);
	element_init(&params->private_key, params->pairing.Zr);
	element_init(&params->public_key, params->pairing.G1);
	element_set_str(&params->gemerator, gen, 10);
	return params;
}

int ibe_pbc_extract(element_s *out, element_s *master_priv_key, const uint8_t *id, const uint32_t id_length)
{
	uint8_t id_hash[crypto_ghash_BYTES];
	int res = crypto_generichash(id_hash, crypto_ghash_BYTES, id, id_length, NULL, 0);
	if (res) {
		fprintf(stderr, "Hash error\n");
		return res;
	}
	element_from_hash(out, id_hash, crypto_ghash_BYTES);
	element_pow_zn(out, out, master_priv_key);
	return 0;
}

void ibe_pbc_sk_from_hashes(uint8_t *sk_out,
                            uint8_t *qid,
                            size_t qid_bytes,
                            uint8_t *rp,
                            size_t rp_bytes,
                            uint8_t *pair_val,
                            size_t pair_bytes)
{
	crypto_generichash_state hash_state;
	crypto_generichash_init(&hash_state, 0, 0, crypto_ghash_BYTES);
	crypto_generichash_update(&hash_state, qid, qid_bytes);
	crypto_generichash_update(&hash_state, rp, rp_bytes);
	crypto_generichash_update(&hash_state, pair_val, pair_bytes);
	crypto_generichash_final(&hash_state, sk_out, crypto_ghash_BYTES);
}

ssize_t ibe_pbc_encrypt(uint8_t *out, uint8_t *msg, uint32_t msg_len, element_s *public_key,
                        element_s *gen, uint8_t *recv_id, size_t recv_id_len, pairing_s *pairing)
{

	uint8_t recv_id_hash[crypto_ghash_BYTES];
	crypto_generichash(recv_id_hash, crypto_ghash_BYTES, recv_id, recv_id_len, NULL, 0);
	element_s q_id;
	element_init(&q_id, pairing->G2);
	element_from_hash(&q_id, recv_id_hash, crypto_ghash_BYTES);
	unsigned long long qid_length = (unsigned long long) element_length_in_bytes_compressed(&q_id);
	uint8_t qid_serialized[qid_length];
	element_to_bytes_compressed(qid_serialized, &q_id);

	element_s r;
	element_init(&r, pairing->Zr);
	element_random(&r);

	element_s rp;
	element_init(&rp, pairing->G1);
	element_pow_zn(&rp, gen, &r);
	unsigned long long rp_length = (unsigned long long) element_length_in_bytes_compressed(&rp);
	element_to_bytes_compressed(out, &rp);
	element_s pairing_value;
	element_init(&pairing_value, pairing->GT);
	element_pairing(&pairing_value, public_key, &q_id);
	element_pow_zn(&pairing_value, &pairing_value, &r);
	unsigned long long pairing_val_length = (unsigned long long) element_length_in_bytes(&pairing_value);
	uint8_t pairing_value_serialized[pairing_val_length];
	element_to_bytes(pairing_value_serialized, &pairing_value);
	uint8_t secret_key[crypto_ghash_BYTES];
	ibe_pbc_sk_from_hashes(secret_key,
	                       qid_serialized,
	                       qid_length,
	                       out,
	                       rp_length,
	                       pairing_value_serialized,
	                       pairing_val_length);
	printhex("sk enc", secret_key, crypto_ghash_BYTES);
	ssize_t res = crypto_secret_nonce_seal(out + rp_length, msg, msg_len, secret_key);
	if (res < 0) {
		fprintf(stderr, "[IBE encrypt] failure during symmetric encyrption\n");
	}
	sodium_memzero(secret_key, sizeof secret_key);
	return res + g1_elem_compressed_BYTES;
}

ssize_t
ibe_pbc_decrypt(uint8_t *out,
                uint8_t *c,
                uint32_t clen,
                element_s *private_key,
                uint8_t *public_key,
                pairing_s *pairing)
{
	element_s rp;
	element_init(&rp, pairing->G1);
	int read = element_from_bytes_compressed(&rp, c);
	if (read != element_length_in_bytes_compressed(&rp)) {
		fprintf(stderr, "could not deserialize element during ibe decryption\n");
		element_clear(&rp);
		return -1;
	}

	element_s pairing_val;
	element_init(&pairing_val, pairing->GT);
	element_pairing(&pairing_val, &rp, private_key);
	size_t u_priv_pairing_size = (size_t) element_length_in_bytes(&pairing_val);
	uint8_t u_priv_pairing[u_priv_pairing_size];
	element_to_bytes(u_priv_pairing, &pairing_val);

	uint8_t secret_key[crypto_ghash_BYTES];
	ibe_pbc_sk_from_hashes(secret_key,
	                       public_key,
	                       g2_elem_compressed_BYTES,
	                       c,
	                       (size_t) read,
	                       u_priv_pairing,
	                       u_priv_pairing_size);
	printhex("sk dec", secret_key, crypto_ghash_BYTES);
	ssize_t
		res = crypto_secret_nonce_open(out, c + g1_elem_compressed_BYTES, clen - g1_elem_compressed_BYTES, secret_key);
	sodium_memzero(secret_key, sizeof secret_key);

	if (res < 0) {
		return -1;
	}
	return 0;
}

/*
int main() {
	uint8_t user_id[user_id_BYTES] = "chris";
	uint8_t user_hash[crypto_ghash_BYTES];
	crypto_generichash(user_hash, crypto_ghash_BYTES, user_id, user_id_BYTES, NULL, 0);
	element_t qid;
	pairing_s pairing;
	pairing_init_set_str(&pairing, pbc_params);

	element_init(qid, pairing.G2);
	element_from_hash(qid, user_hash, crypto_ghash_BYTES);

	uint8_t qid_serialized[1024];
	element_to_bytes_compressed(qid_serialized, qid);


	element_s gen;
	element_init(&gen, pairing.G1);
	element_set_str(&gen, ibe_generator, 10);
	element_s master_sk;
	element_s master_pk;
	element_init(&master_sk, pairing.Zr);
	element_init(&master_pk, pairing.G1);
	element_random(&master_sk);
	element_pow_zn(&master_pk, &gen, &master_sk);

	element_s user_sk;
	element_init(&user_sk, pairing.G2);
	element_pow_zn(&user_sk, qid, &master_sk);

	uint8_t msg[128] = "test msg";
	uint8_t out[1024];
	ssize_t res = ibe_pbc_encrypt(out, msg, sizeof msg, &master_pk, &gen, user_id, user_id_BYTES, &pairing);
	printf("Res: %ld %ld\n", res, sizeof msg);
	uint8_t dec[1024];
	res = ibe_pbc_decrypt(dec, out, (uint32_t)res, &user_sk, qid_serialized, &pairing);
	printf("Res: %ld\n", res);
	printf("%s\n", dec);

}
*/

