//#define PBC_DEBUG
#include "alpenhorn.h"
#include <memory.h>
#include "ibe.h"
#include "client.h"

struct ibe_params {
  pairing_s pairing;
  element_s gemerator;
  element_s public_key;
  element_s private_key;
};

typedef struct ibe_params ibe_params;

ibe_params *ibe_init(char *cfg_file, const char *gen) {
  ibe_params *params = malloc(sizeof(ibe_params));

  if (!cfg_file) {
    free(params);
    return NULL;
  }

  char s[16384];
  FILE *fp = fopen(cfg_file, "r");
  if (!fp)
    pbc_die("error opening %s", cfg_file);
  size_t count = fread(s, 1, 16384, fp);
  if (!count)
    pbc_die("input error");
  fclose(fp);

  if (pairing_init_set_buf(&params->pairing, s, count))
    pbc_die("pairing client_init failed");

  element_init(&params->gemerator, params->pairing.G2);
  element_init(&params->private_key, params->pairing.Zr);
  element_init(&params->public_key, params->pairing.G1);
  return params;
}

int ibe_extract(element_t out, element_t master_priv_key, const byte_t *id, uint32_t id_length) {
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

int ibe_encrypt(byte_t *out, byte_t *msg, uint32_t msg_len, element_s *public_key,
                element_s *P, byte_t *recv_id, size_t recv_id_len, pairing_s *pairing) {

  // Hash the recipient's user_id to a point in G2
  byte_t id_hash[crypto_generichash_BYTES];
  crypto_generichash(id_hash, crypto_generichash_BYTES, recv_id, recv_id_len, NULL, 0);
  printhex("hash for generating public key_state for chris", id_hash, crypto_generichash_BYTES);

  element_t id_hash_elem;
  element_init(id_hash_elem, pairing->G2);
  element_from_hash(id_hash_elem, id_hash, crypto_generichash_BYTES);

  // Calculate the pairing value of (H1(id), Ppub)
  element_t Gid;
  // element_printf("Pub key_state: %B\n", public_key);
  // element_printf("Encrypting: ID hash elem: %B\n", id_hash_elem);
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
  //element_printf("G^r: %B\n", Gid);
  byte_t Gid_hash[crypto_generichash_BYTES];
  crypto_generichash(Gid_hash, crypto_generichash_BYTES, Gid_bytes, elem_length, NULL, 0);
  // Multiply gen_elem by r, convert result to bytes. Included with ciphertext for decryption
  //element_printf("generator: %B\n", P);
  element_t rP;
  element_init(rP, pairing->G1);
  element_pow_zn(rP, P, r);
  int rP_length = element_length_in_bytes_compressed(rP);
  element_to_bytes_compressed(out, rP);
  element_printf("\n------\nrP: %B\n-----\n", rP);
  // Symmetric key_state encryption setup
  byte_t *ibe_encrypted_symm_key_ptr = out + rP_length;
  byte_t *chacha_nonce_ptr = ibe_encrypted_symm_key_ptr + crypto_generichash_BYTES;
  byte_t *chacha_ciphertext_ptr = chacha_nonce_ptr + crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
  // Generate fresh random one-time-use key_state and nonce
  randombytes_buf(ibe_encrypted_symm_key_ptr, crypto_generichash_BYTES);
  printhex("Symm key_state (before encrption)", ibe_encrypted_symm_key_ptr, crypto_generichash_BYTES);
  randombytes_buf(chacha_nonce_ptr, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
  // Encrypt the plaintext message
  unsigned long long ctextlen;
  //printhex("message to encrypt in encrypt function", msg, msg_len);

  int res = crypto_aead_chacha20poly1305_ietf_encrypt(chacha_ciphertext_ptr,
                                                      &ctextlen,
                                                      msg,
                                                      msg_len,
                                                      chacha_nonce_ptr,
                                                      crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
                                                      NULL,
                                                      chacha_nonce_ptr,
                                                      ibe_encrypted_symm_key_ptr
  );

  if (res)
    return res;

  // The symmetric key_state is the IBE plaintext. Create the ciphertext by XOR'ing with the hash derived from G_id^r
  for (int i = 0; i < crypto_generichash_BYTES; i++) {
    ibe_encrypted_symm_key_ptr[i] = ibe_encrypted_symm_key_ptr[i] ^ Gid_hash[i];
  }
  /*printf("%p -> ", &out); printhex("rP compressed bytes", out, (uint32_t)rP_length);
  printf("%p -> ", &ibe_encrypted_symm_key_ptr); printhex("encrypted symmetric key_state", ibe_encrypted_symm_key_ptr, crypto_generichash_BYTES);
  printf("%p -> ", &chacha_nonce_ptr);printhex("chacha nonce", chacha_nonce_ptr, crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
  printf("%p -> ", &chacha_ciphertext_ptr);printhex("chacha ciphertext", chacha_ciphertext_ptr, (uint32_t)ctextlen);
*/  element_clear(id_hash_elem);
  element_clear(rP);
  element_clear(r);
  element_clear(Gid);
  return (int) ctextlen;
}

int ibe_decrypt(byte_t *out, byte_t *c, uint32_t clen, element_s *private_key, pairing_s *pairing) {
  element_printf("Client priv key_state for decrypton: %B\n", private_key);
  /*byte_t *rp_ptr = c;
  byte_t *enc_symm_key = rp_ptr + bls_signature_length;
  byte_t *chacha_nonce = enc_symm_key + crypto_generichash_BYTES;
  byte_t *chacha_text = chacha_nonce + crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
  printf("%p -> ", &rp_ptr); printhex("dec: rP compressed", c, bls_signature_length);
  printf("%p -> ", &enc_symm_key); printhex("dec encrypted symmetric key_state", enc_symm_key, crypto_generichash_BYTES);
  printf("%p -> ", &chacha_nonce); printhex("dec chacha nonce", chacha_nonce, crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
  printf("%p -> ", &chacha_text); printhex("dec chacha ciphertext", chacha_text, (uint32_t)clen);
 */ element_t u, prg;
  element_init(u, pairing->G1);
  int read = element_from_bytes_compressed(u, c);
  if (read != element_length_in_bytes_compressed(u) || element_is0(u)) {
    element_clear(u);
    return -1;
  }
  // element_printf("\n------\nU: %B\n-----\n", u);
  element_init(prg, pairing->GT);
  element_pairing(prg, u, private_key);
  size_t u_priv_pairing_size = (size_t) element_length_in_bytes(prg);
  byte_t u_priv_pairing[u_priv_pairing_size];
  element_to_bytes(u_priv_pairing, prg);
  byte_t *encrypted_symm_key_ptr = c + element_length_in_bytes_compressed(u);
  byte_t *symm_enc_nonce_ptr = encrypted_symm_key_ptr + crypto_generichash_BYTES;
  byte_t *symm_enc_ctext_ptr = symm_enc_nonce_ptr + crypto_aead_chacha20poly1305_ietf_NPUBBYTES;

  // element_printf("e(Did, U): %B\n", prg);
  byte_t secret_key[crypto_generichash_BYTES];
  crypto_generichash(secret_key,
                     crypto_generichash_BYTES,
                     u_priv_pairing,
                     u_priv_pairing_size,
                     NULL,
                     0);

  for (int i = 0; i < crypto_aead_chacha20poly1305_ietf_KEYBYTES; i++) {
    secret_key[i] = secret_key[i] ^ encrypted_symm_key_ptr[i];
  }

  //printhex("Secret key_state after decryption", secret_key, crypto_generichash_BYTES);
  int res;
  //byte_t buf[clen];
  //memcpy(buf, symm_enc_ctext_ptr, clen);
  //byte_t nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
  //memcpy(nonce, symm_enc_nonce_ptr, crypto_aead_chacha20poly1305_IETF_NPUBBYTES);

  res = crypto_aead_chacha20poly1305_ietf_decrypt(out,
                                                  NULL,
                                                  NULL,
                                                  symm_enc_ctext_ptr,
                                                  clen,
                                                  symm_enc_nonce_ptr,
                                                  crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
                                                  symm_enc_nonce_ptr,
                                                  secret_key);

  element_clear(u);
  element_clear(prg);
  if (res) {
    fprintf(stderr, "chacha20 decryption failed\n");
  }
  return res;
}

/*
int main(int argc, char **argv) {
  int res = sodium_init();
  if (res) {
    printf("Sodium client_init failed\n");
  }

  struct ibe_params ibe;
  pbc_demo_pairing_init(&ibe.pairing, argc, argv);
  element_init(&ibe.gemerator, ibe.pairing.G1);
  element_random(&ibe.gemerator);
  element_init(&ibe.private_key, ibe.pairing.Zr);
  element_random(&ibe.private_key);
  element_init(&ibe.public_key, ibe.pairing.G1);
  element_pow_zn(&ibe.public_key, &ibe.gemerator, &ibe.private_key);

  printf("Ppub length: %d\n", element_length_in_bytes_compressed(&ibe.public_key));


  byte_t ciphertext[2048];
  sodium_memzero(ciphertext, 2048);
  byte_t rec_id[] = {'b', 'o', 'b'};
  byte_t msg[] = {'T', 'e', 's', 't', ' ', 'M', 'e', 's', 's', 'a', 'g', 'e'};
  printf("%lu\n", sizeof msg);
  ibe_encrypt(ciphertext, msg, sizeof msg, &ibe.public_key, &ibe.gemerator, rec_id, sizeof rec_id, &ibe.pairing);

  byte_t id_hash[crypto_generichash_BYTES];
  crypto_generichash(id_hash, crypto_generichash_BYTES, rec_id, sizeof rec_id, NULL, 0);
  //printhex("hash for generating private key_state for bob", id_hash, crypto_generichash_BYTES);
  element_t id_elem;
  element_init(id_elem, ibe.pairing.G2);
  element_from_hash(id_elem, id_hash, crypto_generichash_BYTES);
  element_t d_id;
  element_init(d_id, ibe.pairing.G2);
  element_pow_zn(d_id, id_elem, &ibe.private_key);
  printf("Priv key_state length: %d\n", element_length_in_bytes_compressed(d_id));

  byte_t plaintext[2048];
  sodium_memzero(plaintext, 2048);
  res = ibe_decrypt(plaintext, ciphertext, 28, d_id, &ibe.pairing);

  for (int i = 0; i<25; i++) {
    printf("%c", plaintext[i]);
  }
  printf("\n");

  element_clear(&ibe.gemerator);
  element_clear(&ibe.private_key);
  element_clear(id_elem);
  element_clear(d_id);
  pairing_clear(&ibe.pairing);


}*/
