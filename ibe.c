//#define PBC_DEBUG

#include "ibe.h"
#include "config.h"

struct ibe_params {
  pairing_s pairing;
  element_s gemerator;
  element_s public_key;
  element_s private_key;
};

typedef struct ibe_params ibe_params;

ibe_params *ibe_init(char *pb_params, const char *gen) {
  ibe_params *params = malloc(sizeof(ibe_params));
  pairing_init_set_str(&params->pairing, pb_params);
  element_init(&params->gemerator, params->pairing.G2);
  element_init(&params->private_key, params->pairing.Zr);
  element_init(&params->public_key, params->pairing.G1);
  element_set_str(&params->gemerator, gen, 10);
  return params;
}

int ibe_extract(element_s *out, element_s *master_priv_key, const byte_t *id, const uint32_t id_length) {
  byte_t id_hash[crypto_ghash_BYTES];
  int res = crypto_generichash(id_hash, crypto_ghash_BYTES, id, id_length, NULL, 0);
  if (res) {
    fprintf(stderr, "Hash error\n");
    return res;
  }
  element_from_hash(out, id_hash, crypto_ghash_BYTES);
  element_pow_zn(out, out, master_priv_key);
  return 0;
}

int ibe_encrypt(byte_t *out, byte_t *msg, uint32_t msg_len, element_s *public_key,
                element_s *gen, byte_t *recv_id, size_t recv_id_len, pairing_s *pairing) {

  // Hash the recipient's user_id to a point in G2
  byte_t id_hash[crypto_ghash_BYTES];
  crypto_generichash(id_hash, crypto_ghash_BYTES, recv_id, recv_id_len, NULL, 0);

  element_t id_hash_elem;
  element_init(id_hash_elem, pairing->G2);
  element_from_hash(id_hash_elem, id_hash, crypto_ghash_BYTES);
  //element_printf("hashed id elem when encrypting: %B\n", id_hash_elem);
  // Calculate  e(H1(id), Ppub)
  element_t Gid;
  element_init(Gid, pairing->GT);

  element_pairing(Gid, public_key, id_hash_elem);
  // Generate random value within Zq then multiply pairing value by it
  element_t r;
  element_init(r, pairing->Zr);
  element_random(r);
  element_pow_zn(Gid, Gid, r);
  // Serialize H2(Gid^R)
  size_t elem_length = (size_t) element_length_in_bytes(Gid);
  byte_t Gid_bytes[elem_length];
  element_to_bytes(Gid_bytes, Gid);
  byte_t Gid_hash[crypto_ghash_BYTES];
  crypto_generichash(Gid_hash, crypto_ghash_BYTES, Gid_bytes, elem_length, NULL, 0);

  element_t rP;
  element_init(rP, pairing->G1);
  element_pow_zn(rP, gen, r);
  int rP_length = element_length_in_bytes_compressed(rP);
  element_to_bytes_compressed(out, rP);
  //element_printf("rP enc: %B\n", rP);
  // Symmetric key_state encryption setup
  byte_t *ibe_encrypted_symm_key_ptr = out + rP_length;
  byte_t *chacha_nonce_ptr = ibe_encrypted_symm_key_ptr + crypto_ghash_BYTES;
  byte_t *chacha_ciphertext_ptr = chacha_nonce_ptr + crypto_NBYTES;
  // Generate fresh random one-time-use key_state and nonce
  randombytes_buf(ibe_encrypted_symm_key_ptr, crypto_ghash_BYTES);
  // //printhex("Symm key_state (before encrption)", ibe_encrypted_symm_key_ptr, crypto_ghash_BYTES);
  randombytes_buf(chacha_nonce_ptr, crypto_NBYTES);
  // Encrypt the plaintext message
  unsigned long long ctextlen;
  // //printhex("ibe secret key enc", ibe_encrypted_symm_key_ptr, crypto_ghash_BYTES);
  // //printhex("nonce enc", chacha_nonce_ptr, crypto_NBYTES);
  int res = crypto_aead_chacha20poly1305_ietf_encrypt(chacha_ciphertext_ptr,
                                                      &ctextlen,
                                                      msg,
                                                      msg_len,
                                                      chacha_nonce_ptr,
                                                      crypto_NBYTES,
                                                      NULL,
                                                      chacha_nonce_ptr,
                                                      ibe_encrypted_symm_key_ptr);

  //printhex("ctext enc", out, ctextlen + crypto_NBYTES + g1_elem_compressed_BYTES + crypto_ghash_BYTES);

  if (res) {
    fprintf(stderr, "chacha20 encryption failure in ibe encryption request\n");
    return res;
  }
  // The symmetric encryption key is the IBE plaintext. Create the ciphertext by XOR'ing with the hash derived from G_id^r
  for (int i = 0; i < crypto_ghash_BYTES; i++) {
    ibe_encrypted_symm_key_ptr[i] = ibe_encrypted_symm_key_ptr[i] ^ Gid_hash[i];
  }

  element_clear(id_hash_elem);
  element_clear(rP);
  element_clear(r);
  element_clear(Gid);
  return (int) ctextlen;
}

int ibe_decrypt(byte_t *out, byte_t *c, uint32_t clen, element_s *private_key, pairing_s *pairing) {
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
  byte_t u_priv_pairing[u_priv_pairing_size];
  element_to_bytes(u_priv_pairing, prg);
  byte_t *encrypted_symm_key_ptr = c + element_length_in_bytes_compressed(u);
  byte_t *symm_enc_nonce_ptr = encrypted_symm_key_ptr + crypto_ghash_BYTES;
  byte_t *symm_enc_ctext_ptr = symm_enc_nonce_ptr + crypto_NBYTES;
  byte_t secret_key[crypto_ghash_BYTES];
  crypto_generichash(secret_key, crypto_ghash_BYTES, u_priv_pairing, u_priv_pairing_size, NULL, 0);

  for (int i = 0; i < crypto_aead_chacha20poly1305_ietf_KEYBYTES; i++) {
    secret_key[i] = secret_key[i] ^ encrypted_symm_key_ptr[i];
  }

  int res = crypto_aead_chacha20poly1305_ietf_decrypt(out,
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
