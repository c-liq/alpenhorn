#include "ibe.h"

struct ibe_params
{
	pairing_s pairing;
	element_s gemerator;
	element_s public_key;
	element_s private_key;
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

int ibe_extract(element_s *out, element_s *master_priv_key, const uint8_t *id, const uint32_t id_length)
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

int ibe_encrypt(uint8_t *out, uint8_t *msg, uint32_t msg_len, element_s *public_key,
                element_s *gen, uint8_t *recv_id, size_t recv_id_len, pairing_s *pairing)
{

	// Hash the recipient's user_id to a point in G2
	uint8_t id_hash[crypto_ghash_BYTES];
	crypto_generichash(id_hash, crypto_ghash_BYTES, recv_id, recv_id_len, NULL, 0);

	element_t id_hash_elem;
	element_init(id_hash_elem, pairing->G2);
	element_from_hash(id_hash_elem, id_hash, crypto_ghash_BYTES);

	element_t Gid;
	element_init(Gid, pairing->GT);

	element_pairing(Gid, public_key, id_hash_elem);
	// Generate random value within Zq then multiply pairing value by it
	element_t r;
	element_init(r, pairing->Zr);
	element_random(r);
	element_pow_zn(Gid, Gid, r);

	size_t elem_length = (size_t) element_length_in_bytes(Gid);
	uint8_t Gid_bytes[elem_length];
	element_to_bytes(Gid_bytes, Gid);
	uint8_t Gid_hash[crypto_ghash_BYTES];
	crypto_generichash(Gid_hash, crypto_ghash_BYTES, Gid_bytes, elem_length, NULL, 0);

	element_t rP;
	element_init(rP, pairing->G1);
	element_pow_zn(rP, gen, r);
	int rP_length = element_length_in_bytes_compressed(rP);
	element_to_bytes_compressed(out, rP);
	// Symmetric key_state encryption setup
	uint8_t *ibe_encrypted_symm_key = out + rP_length;
	uint8_t *nonce = ibe_encrypted_symm_key + crypto_ghash_BYTES;
	uint8_t *symm_ciphertext = nonce + crypto_NBYTES;
	// Generate fresh random one-time-use key_state and nonce
	randombytes_buf(ibe_encrypted_symm_key, crypto_ghash_BYTES);
	randombytes_buf(nonce, crypto_NBYTES);
	// Encrypt the plaintext message
	int res = crypto_aead_chacha20poly1305_ietf_encrypt(symm_ciphertext,
	                                                    NULL,
	                                                    msg,
	                                                    msg_len,
	                                                    nonce,
	                                                    crypto_NBYTES,
	                                                    NULL,
	                                                    nonce,
	                                                    ibe_encrypted_symm_key);

	if (res) {
		fprintf(stderr, "chacha20 encryption failure in ibe encryption request\n");
		return res;
	}
	// The symmetric encryption key is the IBE plaintext. Create the ciphertext by XOR'ing with the hash derived from G_id^r
	for (int i = 0; i < crypto_ghash_BYTES; i++) {
		ibe_encrypted_symm_key[i] = ibe_encrypted_symm_key[i] ^ Gid_hash[i];
	}

	element_clear(id_hash_elem);
	element_clear(rP);
	element_clear(r);
	element_clear(Gid);
	return 0;
}

int ibe_encryp2(uint8_t *out, uint8_t *msg, uint32_t msg_len, element_s *public_key,
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
	unsigned long long r_length = (unsigned long long) element_length_in_bytes_compressed(&r);
	uint8_t r_serialized[r_length];
	element_to_bytes_compressed(r_serialized, &r);

	element_s rp;
	element_init(&rp, pairing->G1);
	element_pow_zn(&rp, gen, &r);
	element_to_bytes_compressed(out, &rp);

	element_s pairing_value;
	element_init(&pairing_value, pairing->GT);
	element_pairing(&pairing_value, public_key, &q_id);
	element_pow_zn(&pairing_value, &pairing_value, &r);
	unsigned long long pairing_val_length = (unsigned long long) element_length_in_bytes(&pairing_value);
	uint8_t pairing_value_serialized[pairing_val_length];
	element_to_bytes_compressed(pairing_value_serialized, &pairing_value);

	crypto_generichash_state hash_state;
	crypto_generichash_init(&hash_state, 0, 0, crypto_ghash_BYTES);
	crypto_generichash_update(&hash_state, qid_serialized, qid_length);
	crypto_generichash_update(&hash_state, out, r_length);
	crypto_generichash_update(&hash_state, pairing_value_serialized, pairing_val_length);
	uint8_t secret_key[crypto_ghash_BYTES];
	crypto_generichash_final(&hash_state, secret_key, crypto_ghash_BYTES);

	int res = crypto_secret_nonce_seal(out + r_length, msg, msg_len, secret_key);
	if (res) {
		fprintf(stderr, "[IBE encrypt] failure during symmetric encyrption\n");
	}
	sodium_memzero(secret_key, sizeof secret_key);
	return res;
}

int
ibe_decrypt2(uint8_t *out, uint8_t *c, uint32_t clen, element_s *private_key, pairing_s *pairing)
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


	return 0;
}
int ibe_decrypt(uint8_t *out, uint8_t *c, uint32_t clen, element_s *private_key, pairing_s *pairing)
{
	element_t u, prg;
	element_init(u, pairing->G1);
	int read = element_from_bytes_compressed(u, c);
	if (read != element_length_in_bytes_compressed(u) || element_is0(u)) {
		fprintf(stderr, "invalid Rp when attempting ibe decryption\n");
		element_clear(u);
		return -1;
	}
	//element_printf("u dec: %B\n", u);
	element_init(prg, pairing->GT);
	element_pairing(prg, u, private_key);
	//element_printf("prg: %B\n", prg);
	size_t u_priv_pairing_size = (size_t) element_length_in_bytes(prg);
	uint8_t u_priv_pairing[u_priv_pairing_size];
	element_to_bytes(u_priv_pairing, prg);
	uint8_t *encrypted_symm_key_ptr = c + element_length_in_bytes_compressed(u);
	uint8_t *symm_enc_nonce_ptr = encrypted_symm_key_ptr + crypto_ghash_BYTES;
	uint8_t *symm_enc_ctext_ptr = symm_enc_nonce_ptr + crypto_NBYTES;
	uint8_t secret_key[crypto_ghash_BYTES];
	crypto_generichash(secret_key, crypto_ghash_BYTES, u_priv_pairing, u_priv_pairing_size, NULL, 0);

	for (int i = 0; i < crypto_aead_chacha20poly1305_ietf_KEYBYTES; i++) {
		secret_key[i] = secret_key[i] ^ encrypted_symm_key_ptr[i];
	}
	int res = crypto_chacha_decrypt(out,
	                                NULL,
	                                NULL,
	                                symm_enc_ctext_ptr,
	                                clen,
	                                symm_enc_nonce_ptr,
	                                crypto_NBYTES,
	                                symm_enc_nonce_ptr,
	                                secret_key);

	element_clear(u);
	element_clear(prg);
	return res;
}
