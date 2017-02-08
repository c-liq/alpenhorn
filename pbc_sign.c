#define PBC_DEBUG
#include <pbc/pbc.h>
#include "alpenhorn.h"
#include "pbc_sign.h"



void pbc_sum(element_t elem_sum, element_t *elem_ar, size_t n, pairing_t pairing) {
  if (!elem_sum || !elem_ar || !pairing) {
    return;
  }
  for (int i = 0; i < n; i++) {
    element_add(elem_sum, elem_sum, elem_ar[i]);
  }
}

void pb_sum_bytes(element_t elem_sum, byte_t **elem_bytes_ar, size_t n, pairing_t pairing) {
  element_t tmp;
  element_init_G1(tmp, pairing);
  for (int i = 0; i < n; i++) {
    element_from_bytes(tmp, elem_bytes_ar[i]);
    element_add(elem_sum, elem_sum, tmp);
  }
  element_clear(tmp);
}

void sign_message(element_t sig, byte_t *hash, int hash_len, element_t secret_key, pairing_t pairing) {
  element_t elem_from_hash;
  element_init_G1(elem_from_hash, pairing);
  element_from_hash(elem_from_hash, hash, hash_len);
  element_pow_zn(sig, elem_from_hash, secret_key);
  element_clear(elem_from_hash);
}

void signature_to_bytes(element_t sig,
                        byte_t *sig_buf,
                        byte_t *hash,
                        int hash_len,
                        element_t secret_key,
                        pairing_t pairing) {
  sign_message(sig, hash, hash_len, secret_key, pairing);
  element_to_bytes_x_only(sig_buf, sig);
}

int verify_signature(element_t sig, byte_t *hash, int hash_len, element_t public_key, element_t g, pairing_t pairing) {
  element_t u;
  element_t v;
  element_t hash_elem;
  int res = 0;
  element_init_G1(hash_elem, pairing);
  element_from_hash(hash_elem, hash, hash_len);
  element_init_GT(u, pairing);
  element_init_GT(v, pairing);
  element_pairing(u, sig, g);
  element_pairing(v, hash_elem, public_key);
  if (!element_cmp(u, v)) {
    res = 1;
  } else {
    element_invert(u, u);
    res = !(element_cmp(u, v));
  }
  element_clear(u);
  element_clear(v);
  element_clear(hash_elem);
  return res;
}

#if 0
int main(int argc, char **argv) {
  pairing_t pairing;
  pbc_demo_pairing_init(pairing, argc, argv);
  element_t g_elem;
  element_t public_keys[3];
  element_t secret_keys[3];
  element_init(g_elem, pairing->G2);
  element_init(public_keys[0], pairing->G2);
  element_init(public_keys[1], pairing->G2);
  element_init(public_keys[2], pairing->G2);
  element_init(secret_keys[0], pairing->Zr);
  element_init(secret_keys[1], pairing->Zr);
  element_init(secret_keys[2], pairing->Zr);
  element_set_str(public_keys[0], pk[0], 10);
  element_set_str(public_keys[1], pk[1], 10);
  element_set_str(public_keys[2], pk[2], 10);
  element_set_str(secret_keys[0], sk[0], 10);
  element_set_str(secret_keys[1], sk[1], 10);
  element_set_str(secret_keys[2], sk[2], 10);
  int res = element_set_str(g_elem, g, 10);
  byte_t *msg = (byte_t *) "test message";
  byte_t hash[crypto_generichash_BYTES];
  crypto_generichash(hash, crypto_generichash_BYTES, msg, sizeof msg, NULL, 0);
  element_t sigs[3];
  element_init(sigs[0], pairing->G1);
  element_init(sigs[1], pairing->G1);
  element_init(sigs[2], pairing->G1);
  sign_message(sigs[0], hash, crypto_generichash_BYTES, secret_keys[0], pairing);
  sign_message(sigs[1], hash, crypto_generichash_BYTES, secret_keys[1], pairing);

  sign_message(sigs[2], hash, crypto_generichash_BYTES, secret_keys[2], pairing);
  element_t sig_sum;
  element_init(sig_sum, pairing->G1);
  pbc_sum(sig_sum, sigs, 3, pairing);
  element_t pk_sum;

  element_init(pk_sum, pairing->G2);
  pbc_sum(pk_sum, public_keys, 3, pairing);
  int x = verify_signature(sigs[0], hash, crypto_generichash_BYTES, pk_sum, g_elem, pairing);
  printf("%d\n", x);
  for (int i = 0; i < 3; i++) {
    element_clear(secret_keys[i]);
    element_clear(public_keys[i]);
    element_clear(sigs[i]);
  }
  element_clear(g_elem);
  element_clear(pk_sum);
  element_clear(sig_sum);
  pairing_clear(pairing);
  return 0;
}
#endif