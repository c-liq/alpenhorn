#include <pbc/pbc.h>
#include <memory.h>
#include "alpenhorn.h"
#include "pbc_sign.h"
#include "aaparams.h"
struct bls_instance {
  pairing_ptr pairing;
  element_t gen_elem;
  element_t sig_elem;
  element_t sig_hash_elem;
  element_t elem_sum;
  element_t u_tmp;
  element_t v_tmp;
};

bls_instance *bls_init(pairing_t pairing) {
  bls_instance *bls_instance = malloc(sizeof(bls_instance));
  bls_instance->pairing = pairing;
  element_init_G2(bls_instance->gen_elem, pairing);
  element_init_G1(bls_instance->sig_elem, pairing);
  element_init_G1(bls_instance->sig_hash_elem, pairing);
  element_init_GT(bls_instance->u_tmp, pairing);
  element_init_GT(bls_instance->v_tmp, pairing);
  return bls_instance;
}

void pbc_sum(element_s *elem_sum, element_s elem_ar[], size_t n, pairing_t pairing) {
  if (!elem_sum || !elem_ar || !pairing) {
    return;
  }
  for (int i = 0; i < n; i++) {
    //  element_printf("sum - element %d: %B\n", i, &elem_ar[i]);
    element_mul(elem_sum, elem_sum, &elem_ar[i]);
  }
}

void pbc_sum_bytes_G1_compressed(element_s *elem_sum, byte_t *elem_bytes_ar, size_t n, pairing_t pairing) {
  element_t tmp;
  element_init_G1(tmp, pairing);
  int elem_length = element_length_in_bytes_compressed(tmp);
  for (int i = 0; i < n; i++) {
    element_from_bytes_compressed(tmp, elem_bytes_ar + (i * elem_length));
    element_add(elem_sum, elem_sum, tmp);
  }
  element_clear(tmp);
}

void pbc_sum_bytes_G2_compressed(element_s *elem_sum, byte_t *elem_bytes_ar, size_t n, pairing_t pairing) {
  element_t tmp;
  element_init_G2(tmp, pairing);
  int elem_length = element_length_in_bytes_compressed(tmp);
  for (int i = 0; i < n; i++) {
    element_from_bytes_compressed(tmp, elem_bytes_ar + (i * elem_length));
    element_add(elem_sum, elem_sum, tmp);
  }
  element_clear(tmp);
}

void bls_sign_message(byte_t *out_buf, element_s *sig_elem, element_s *hash_elem, byte_t *msg,
                      uint32_t msg_len, element_s *secret_key) {

  byte_t msg_hash[crypto_generichash_BYTES];
  crypto_generichash(msg_hash, crypto_generichash_BYTES, msg, msg_len, NULL, 0);
  element_from_hash(hash_elem, msg_hash, crypto_generichash_BYTES);

  element_pow_zn(sig_elem, hash_elem, secret_key);
  element_to_bytes_compressed(out_buf, sig_elem);
}

int bls_verify_signature(element_s *sig, element_s *hash_elem, byte_t *sig_buf, byte_t *msg, uint32_t msg_len,
                         element_s *public_key, element_s *g2, pairing_t pairing) {

  byte_t msg_hash[crypto_generichash_BYTES];
  crypto_generichash(msg_hash, crypto_generichash_BYTES, msg, msg_len, NULL, 0);
  element_from_hash(hash_elem, msg_hash, crypto_generichash_BYTES);
  element_from_bytes_compressed(sig, sig_buf);
  element_t u, v;
  element_init(u, pairing->GT);
  element_init(v, pairing->GT);
  element_pairing(u, sig, g2);
  element_pairing(v, hash_elem, public_key);

  int res = 0;
  // Signature is transmitted as just an x-coordinate, which could match one of two y coords
  // If the comparison fails initially, flip a point and compare again
  if (element_cmp(u, v)) {
    //printf("--------------\nFIRST SIG FAILED, INVERTING\n-----------\n");
    element_invert(u, u);
    res = (element_cmp(u, v));
  }
  if (res) {
    element_printf("u: %B\n", u);
    element_printf("v: %B\n", v);
  }
  element_clear(u);
  element_clear(v);
  if (res == 0) {
    return 1;
  } else {
    return 0;
  }
}

#if 0
int main(int argc, char **argv) {
  pairing_t pairing;
  pbc_demo_pairing_init(pairing, argc, argv);
  element_s g_elem;
  size_t num = 4;
  element_s public_keys[num];
  element_s secret_keys[num];
  element_s sigs_array[num];
  for (int i = 0; i<num; i++) {
    element_init(&secret_keys[i], pairing->Zr);
    element_init(&public_keys[i], pairing->G2);
    element_init(&sigs_array[i], pairing->G1);
  }
  uint32_t sig_length = (uint32_t) element_length_in_bytes_x_only(&sigs_array[0]);
  uint32_t public_key_length = (uint32_t) element_length_in_bytes_compressed(&public_keys[0]);
  element_init(&g_elem, pairing->G2);

  element_random(&g_elem);
  byte_t message[] = {'T', 'e', 's', 't'};
  uint32_t msglen = sizeof message;
  int sum = 0;
  for (int j = 0; j < 100; j++) {
    byte_t sig_buffer[num][sig_length];
    for (int i = 0; i<num; i++) {
      element_random(&secret_keys[i]);
      element_pow_zn(&public_keys[i], &g_elem, &secret_keys[i]);
    }

    element_s hash_elem;
    element_init(&hash_elem, pairing->G1);
    for (int i = 0; i<num; i++) {
      bls_sign_message(sig_buffer[i], &sigs_array[i], &hash_elem, message, msglen, &secret_keys[i]);
    }
    element_t sigsum;
    element_t pksum;
    byte_t sig_sum_buffer[sig_length];
    memset(sig_sum_buffer, 0, sig_length);

    element_init(sigsum, pairing->G1);
    element_init(pksum, pairing->G2);
    pbc_sum(pksum, public_keys, num, pairing);
    pbc_sum(sigsum, sigs_array, num, pairing);
    element_to_bytes_x_only(sig_sum_buffer, sigsum);
    int res3 = bls_verify_signature(sigsum, &hash_elem, sig_sum_buffer, message, msglen, pksum, &g_elem, pairing);
    sum += res3;
   // printf("%d += %d\n", sum, res3);
  }
  printf("Sum : %d\n", sum);
  //element_printf("sigsum: %B\n", sigsum);
  //element_printf("pk sum: %B\n", pksum);
  element_clear(&g_elem);
  element_clear(&public_keys[0]);
  element_clear(&secret_keys[0]);
  element_clear(&sigs_array[0]);
  pairing_clear(pairing);

}
#endif

