
#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include "alpenhorn.h"

static const char sk[][3] = {"01988e9f32f032dc22960f201c456b6f7370027d7d37f99199599964d94130c4",
                             "17cda9a6dcd85153969479ff6a2022ae644035cde98557af76d1843ff0c6c614",
                             "099d3ae5ad24efe4fbdc6eee3b5f6ba45cea9397b37d3d95f617e5e761540665"};

static const char pk[][3] = {"1aebfbc498858ca799b75fa5ede718539ce35461eb6bf3d9e0df67ce53279097",
                             "0476f3c675846f4128bec73d5af331e251fdf87298256bdf979593e0acc7d97b",
                             "0476f3c675846f4128bec73d5af331e251fdf87298256bdf979593e0acc7d97b"};

static const char *g =
    "04477c64ceefc3c39aa752536b6ef8428c094f74abb1ab57bcbd2dd9059adfa10702f4d33fc0d32bcca9935f1f16ac263544c49e5d3757354740131e66aebbb722beef5108b050385893da1a2a53e869957fc002f25a5136ad3c13cfc613c9730dedee0e1e8755d2c17ca2001e159e62c6510133ab94663318d9bdede80562fc";

void sum(element_t elem_sum, element_t *elem_ar, size_t n, pairing_t pairing) {
  if (!elem_sum || !elem_ar || !pairing) {
    return;
  }
  for (int i = 0; i < n; i++) {
    element_add(elem_sum, elem_sum, elem_ar[i]);
  }
}

void sum_from_bytes(element_t elem_sum, byte_t **elem_bytes_ar, size_t n, pairing_t pairing) {
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
}

int verify_signature(element_t sig, byte_t *hash, int hash_len, element_t public_key, element_t g, pairing_t pairing) {
  element_t u;
  element_t v;
  element_t hash_elem;
  element_init_G1(hash_elem, pairing);
  element_from_hash(hash_elem, hash, hash_len);
  element_init_GT(u, pairing);
  element_init_GT(v, pairing);
  element_pairing(u, sig, g);
  element_pairing(v, hash_elem, public_key);
  if (!element_cmp(u, v)) {
    return 1;
  } else {
    element_invert(u, u);

    if (!element_cmp(u, v)) {
      return 1;
    }
  }
  return 0;

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

int main(int argc, char **argv) {
  pairing_t pairing;
  pbc_demo_pairing_init(pairing, argc, argv);
  return 0;
}
