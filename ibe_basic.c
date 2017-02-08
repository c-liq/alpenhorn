//#define PBC_DEBUG
#include "ibe_basic.h"

#include <sodium.h>
#include "ibe_basic.h"

struct ibe_params {
  pairing_ptr pairing;
  element_ptr P;
  element_ptr Ppub;
  element_ptr public_key;
  element_ptr private_key;
};

void print_hex(const char *msg, byte_t *in, size_t in_len) {
  char hex[in_len * 2 + 1];
  sodium_bin2hex(hex, in_len * 2 + 1, in, in_len);
  printf("%s: %s\n", msg, hex);
}

int ibe_init(struct ibe_params ibe_params, pairing_t pairing) {
  return 0;
}

int ibe_extract(element_t out, element_t master_priv_key, const byte_t *id, uint32_t id_length, pairing_t pairing) {
  element_init(out, pairing->G2);
  byte_t id_hash[crypto_generichash_BYTES];
  int res = crypto_generichash(id_hash, crypto_generichash_BYTES, id, id_length, NULL, 0);
  if (res) {
    fprintf(stderr, "Hash error\n");
    return res;
  }
  element_from_hash(out, id_hash, crypto_generichash_BYTES);
  element_pow_zn(out, out, master_priv_key);
  return 0;
}
int ibe_encrypt(byte_t *out, byte_t *msg, size_t msg_len, element_ptr public_key,
                element_ptr P, byte_t *recv_id, size_t recv_id_len, pairing_t pairing) {

  // Hash the recipient's userid to a point in G2
  byte_t id_hash[crypto_generichash_BYTES];
  crypto_generichash(id_hash, crypto_generichash_BYTES, recv_id, recv_id_len, NULL, 0);
  print_hex("hash for generating public key for bob", id_hash, crypto_generichash_BYTES);
  element_t id_hash_elem;
  element_init(id_hash_elem, pairing->G2);
  element_from_hash(id_hash_elem, id_hash, crypto_generichash_BYTES);
  // Calculate the pairing value of (H1(id), Ppub)
  element_t Gid;
  element_init(Gid, pairing->GT);
  element_pairing(Gid, public_key, id_hash_elem);
  // Generate random value within Zq then multiply pairing value by it
  element_t r;
  element_init(r, pairing->Zr);
  element_random(r);
  element_pow_zn(Gid, Gid, r);
  // Convert H2(Gid^R) to bytes and hash the output
  size_t elem_length = (size_t) element_length_in_bytes(Gid);
  byte_t Gid_bytes[elem_length];
  element_to_bytes(Gid_bytes, Gid);
  element_printf("G^r: %B\n", Gid);
  byte_t Gid_hash[crypto_generichash_BYTES];
  crypto_generichash(Gid_hash, crypto_generichash_BYTES, Gid_bytes, elem_length, NULL, 0);
  // Multiply generator by r, convert result to bytes. Included with ciphertext for decryption
  element_t rP;
  element_init(rP, pairing->G1);
  element_pow_zn(rP, P, r);
  element_printf("rP: %B\n", rP);
  int rP_length = element_length_in_bytes(rP);
  element_to_bytes(out, rP);
  printf("rP_Length: %d\n", rP_length);
  // Symmetric key encryption setup
  byte_t *ibe_encrypted_symm_key_ptr = out + rP_length;
  byte_t *chacha_nonce_ptr = ibe_encrypted_symm_key_ptr + crypto_aead_chacha20poly1305_KEYBYTES;
  byte_t *chacha_ciphertext_ptr = chacha_nonce_ptr + crypto_aead_chacha20poly1305_NPUBBYTES;
  // Generate fresh random one-time-use key and nonce
  randombytes_buf(ibe_encrypted_symm_key_ptr, crypto_aead_chacha20poly1305_KEYBYTES);
  print_hex("Symm key (before encrption)", ibe_encrypted_symm_key_ptr, crypto_aead_chacha20poly1305_KEYBYTES);
  randombytes_buf(chacha_nonce_ptr, crypto_aead_chacha20poly1305_NPUBBYTES);
  // Encrypt the plaintext message
  unsigned long long ctextlen;
  int res = crypto_aead_chacha20poly1305_encrypt(chacha_ciphertext_ptr,
                                                 &ctextlen,
                                                 msg,
                                                 msg_len,
                                                 chacha_nonce_ptr,
                                                 crypto_aead_chacha20poly1305_NPUBBYTES,
                                                 NULL,
                                                 chacha_nonce_ptr,
                                                 ibe_encrypted_symm_key_ptr
  );

  if (res)
    return res;
  printf("cipherext len: %llu", ctextlen);
  // The symmetric key is the IBE plaintext. Create the ciphertext by XOR'ing with the hash derived from G_id^r
  for (int i = 0; i < crypto_aead_chacha20poly1305_KEYBYTES; i++) {
    ibe_encrypted_symm_key_ptr[i] = ibe_encrypted_symm_key_ptr[i] ^ Gid_hash[i];
  }
  element_clear(id_hash_elem);
  element_clear(rP);
  element_clear(r);
  element_clear(Gid);
  return (int) ctextlen;
}

int ibe_decrypt(byte_t *out, byte_t *c, byte_t clen, element_t private_key, pairing_t pairing) {
  element_t u, prg;
  element_init(u, pairing->G1);
  element_from_bytes(u, c);
  element_printf("U/rP: %B\n", u);
  element_init(prg, pairing->GT);
  element_pairing(prg, u, private_key);
  size_t u_priv_pairing_size = (size_t) element_length_in_bytes(prg);
  byte_t u_priv_pairing[u_priv_pairing_size];
  element_to_bytes(u_priv_pairing, prg);
  byte_t *encrypted_symm_key_ptr = c + element_length_in_bytes(u);
  byte_t *symm_enc_nonce_ptr = encrypted_symm_key_ptr + crypto_aead_chacha20poly1305_KEYBYTES;
  byte_t *symm_enc_ctext_ptr = symm_enc_nonce_ptr + crypto_aead_chacha20poly1305_NPUBBYTES;

  element_printf("e(Did, U): %B\n", prg);
  byte_t secret_key[crypto_aead_chacha20poly1305_KEYBYTES];
  crypto_generichash(secret_key, crypto_aead_chacha20poly1305_KEYBYTES, u_priv_pairing, u_priv_pairing_size, NULL, 0);

  for (int i = 0; i < crypto_aead_chacha20poly1305_KEYBYTES; i++) {
    secret_key[i] = secret_key[i] ^ encrypted_symm_key_ptr[i];
  }

  print_hex("Secret key after decryption", secret_key, crypto_aead_chacha20poly1305_KEYBYTES);

  int res = crypto_aead_chacha20poly1305_decrypt(out,
                                                 NULL,
                                                 NULL,
                                                 symm_enc_ctext_ptr,
                                                 clen,
                                                 symm_enc_nonce_ptr,
                                                 crypto_aead_chacha20poly1305_NPUBBYTES,
                                                 symm_enc_nonce_ptr,
                                                 secret_key);

  element_clear(u);
  element_clear(prg);

  return res;
}
#if 0
int main(int argc, char **argv) {
  int res = sodium_init();
  if (res) {
    printf("Sodium init failed\n");
  }

  pairing_t pairing;
  pbc_demo_pairing_init(pairing, argc, argv);
  element_t P;
  element_init(P, pairing->G1);
  element_random(P);
  element_t s;
  element_init(s, pairing->Zr);
  element_random(s);
  element_t Ppub;
  element_init(Ppub, pairing->G1);
  element_pow_zn(Ppub, P, s);

  struct ibe_params ibe;
  ibe.pairing = pairing;
  ibe.P = P;
  ibe.Ppub = Ppub;

  byte_t ciphertext[2048];
  sodium_memzero(ciphertext, 2048);
  byte_t rec_id[] = {'b', 'o', 'b'};
  byte_t msg[] = {'T', 'e', 's', 't', ' ', 'M', 'e', 's', 's', 'a', 'g', 'e'};
  printf("%lu\n", sizeof msg);
  ibe_encrypt(ciphertext, msg, sizeof msg, ibe.Ppub, ibe.P, rec_id, sizeof rec_id, ibe.pairing);

  byte_t id_hash[crypto_generichash_BYTES];
  crypto_generichash(id_hash, crypto_generichash_BYTES, rec_id, sizeof rec_id, NULL, 0);
  print_hex("hash for generating private key for bob", id_hash, crypto_generichash_BYTES);
  element_t id_elem;
  element_init(id_elem, pairing->G2);
  element_from_hash(id_elem, id_hash, crypto_generichash_BYTES);
  element_t d_id;
  element_init(d_id, pairing->G2);
  element_pow_zn(d_id, id_elem, s);


  byte_t plaintext[2048];
  sodium_memzero(plaintext, 2048);
  res = ibe_decrypt(plaintext, ciphertext, 28, d_id, pairing);

  for (int i = 0; i<25; i++) {
    printf("%c", plaintext[i]);
  }
  printf("\n");

  element_clear(P);
  element_clear(Ppub);
  element_clear(s);
  element_clear(id_elem);
  element_clear(d_id);
  pairing_clear(pairing);

  #if 0
  const byte_t *id = (byte_t *) "chris";
  byte_t id_hash[crypto_generichash_BYTES];
  crypto_generichash(id_hash, crypto_generichash_BYTES, id, sizeof id, NULL, 0);
  element_t Qid;
  element_init(Qid, pairing->G2);
  element_from_hash(Qid, id_hash, crypto_generichash_BYTES);

  byte_t msg[32U];
  randombytes_buf(msg, 32U);
  size_t msglength = sizeof msg;

  element_t r;
  element_init(r, pairing->Zr);
  element_random(r);

  element_t g_id;
  element_init(g_id, pairing->GT);
  element_printf("Qid: %B\n", Qid);
  element_printf("Ppub: %B\n", Ppub);
  element_pairing(g_id, Ppub, Qid);

  element_t gR;
  element_init(gR, pairing->GT);
  element_pow_zn(gR, g_id, r);

  element_t rP;
  element_init(rP, pairing->G1);
  element_pow_zn(rP, P, r);

  size_t gR_length_in_bytes = (size_t) element_length_in_bytes(gR);
  byte_t elem_bytes[gR_length_in_bytes];
  element_to_bytes(elem_bytes, gR);

  byte_t byte_th2_hash[crypto_generichash_BYTES];
  crypto_generichash(byte_th2_hash, crypto_generichash_BYTES, elem_bytes, gR_length_in_bytes, NULL, 0);

  byte_t msg_xor[crypto_generichash_BYTES];
  for (int i = 0; i < crypto_generichash_BYTES; i++) {
    msg_xor[i] = byte_th2_hash[i] ^ msg[i];
  }

  element_t Did;
  element_init(Did, pairing->G2);
  element_pow_zn(Did, Qid, s);

  element_t pair_Did_U;
  element_init(pair_Did_U, pairing->GT);
  element_pairing(pair_Did_U, rP, Did);

  byte_t pDu_bytes[gR_length_in_bytes];
  element_to_bytes(pDu_bytes, pair_Did_U);

  byte_t pDu_hash[crypto_generichash_BYTES];
  crypto_generichash(pDu_hash, crypto_generichash_BYTES, pDu_bytes, gR_length_in_bytes, NULL, 0);

  byte_t decrypted_msg[crypto_generichash_BYTES];
  for (int i = 0; i < crypto_generichash_BYTES; i++) {
    decrypted_msg[i] = msg_xor[i] ^ pDu_hash[i];
  }

  size_t hex_len = crypto_generichash_BYTES * 2 + 1;
  char msg_before[hex_len];
  char msg_after[hex_len];
  sodium_bin2hex(msg_before, hex_len, msg, crypto_generichash_BYTES);
  sodium_bin2hex(msg_after, hex_len, decrypted_msg, crypto_generichash_BYTES);

  printf("before: %s\n", msg_before);
  printf("after: %s\n", msg_after);
  element_clear(Qid);
  element_clear(r);
  element_clear(Did);
  element_clear(P);
  element_clear(Ppub);
  element_clear(rP);
  element_clear(gR);
  element_clear(g_id);
  element_clear(s);
  element_clear(pair_Did_U);

  pairing_clear(pairing);
  #endif

}
#endif