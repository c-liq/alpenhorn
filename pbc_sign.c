#include <pbc/pbc.h>
#include "pbc_sign.h"

bls_instance *bls_alloc(char *params, uint32_t params_len, char *gen_string) {
  bls_instance *bls = calloc(1, sizeof(*bls));
  if (!bls) {
    fprintf(stderr, "calloc failed when creating bls instance\n");
    return NULL;
  }
  pairing_s *pairing = &bls->pairing;
  int res = pairing_init_set_buf(&bls->pairing, params, params_len);
  if (res) {
    fprintf(stderr, "failed to configure pairing during bls setup\n");
    return NULL;
  }

  element_init_G2(&bls->gen_elem, pairing);
  element_init_G1(&bls->sig_elem, pairing);
  element_init_G1(&bls->verify_elem, pairing);
  element_init_G1(&bls->sig_hash_elem, pairing);
  element_init_G1(&bls->g1_elem_sum, pairing);
  element_init_G2(&bls->g2_elem_sum, pairing);
  element_init_G1(&bls->g1_tmp, pairing);
  element_init_G2(&bls->g2_tmp, pairing);
  element_init_GT(&bls->u_tmp, pairing);
  element_init_GT(&bls->v_tmp, pairing);
  bls->g1_elem_length = element_length_in_bytes_compressed(&bls->g1_elem_sum);
  bls->g2_elem_length = element_length_in_bytes_compressed(&bls->g2_elem_sum);
  element_set_str(&bls->gen_elem, gen_string, 10);
  return bls;
}

void bls_sum_bytes_G1_compressed(bls_instance *bls_inst, byte_t *elem_bytes_ar, uint32_t n) {
  element_s *tmp = &bls_inst->g1_tmp;
  element_s *sum_elem = &bls_inst->g1_elem_sum;
  element_set0(&bls_inst->g1_elem_sum);
  for (int i = 0; i < n; i++) {
    element_from_bytes_compressed(&bls_inst->u_tmp, elem_bytes_ar + (i * bls_inst->g1_elem_length));
    element_add(sum_elem, sum_elem, tmp);
  }
}

void bls_sum_bytes_G2_compressed(bls_instance *bls_inst, byte_t *elem_bytes_ar, uint32_t n) {
  element_s *tmp = &bls_inst->g2_tmp;
  element_s *sum_elem = &bls_inst->g2_elem_sum;
  element_set0(&bls_inst->g2_elem_sum);

  for (int i = 0; i < n; i++) {
    element_from_bytes_compressed(&bls_inst->u_tmp, elem_bytes_ar + (i * bls_inst->g2_elem_length));
    element_add(sum_elem, sum_elem, tmp);
  }
}

void bls_inst_sign_message(byte_t *out_buf,
                           bls_instance *bls_inst,
                           byte_t *msg,
                           uint32_t msg_len,
                           element_s *secret_key) {
  byte_t msg_hash[crypto_ghash_BYTES];
  crypto_generichash(msg_hash, crypto_ghash_BYTES, msg, msg_len, NULL, 0);
  element_from_hash(&bls_inst->sig_hash_elem, msg_hash, crypto_ghash_BYTES);
  element_pow_zn(&bls_inst->sig_elem, &bls_inst->sig_hash_elem, secret_key);
  element_to_bytes_compressed(out_buf, &bls_inst->sig_elem);
}

int bls_inst_verify(bls_instance *bls_inst, byte_t *sig_buf, byte_t *msg, uint32_t msg_len, element_s *public_key) {
  byte_t msg_hash[crypto_ghash_BYTES];
  crypto_generichash(msg_hash, crypto_ghash_BYTES, msg, msg_len, NULL, 0);

  element_from_hash(&bls_inst->sig_hash_elem, msg_hash, crypto_ghash_BYTES);
  element_from_bytes_compressed(&bls_inst->verify_elem, sig_buf);

  element_s *u = &bls_inst->u_tmp;
  element_s *v = &bls_inst->v_tmp;
  element_pairing(u, &bls_inst->sig_elem, &bls_inst->gen_elem);
  element_pairing(v, &bls_inst->sig_hash_elem, public_key);

  return element_cmp(u, v);
}

void pbc_sum_bytes_G1_compressed(element_s *elem_sum,
                                 byte_t *elem_bytes_ar,
                                 size_t elem_size,
                                 size_t n,
                                 pairing_t pairing) {
  element_t tmp;
  element_init_G1(tmp, pairing);
  element_clear(elem_sum);
  element_init(elem_sum, pairing->G1);
  int elem_length = element_length_in_bytes_compressed(tmp);
  for (int i = 0; i < n; i++) {
    element_from_bytes_compressed(tmp, elem_bytes_ar + (i * elem_size));
    element_add(elem_sum, elem_sum, tmp);
  }
  element_clear(tmp);
}

void pbc_sum_bytes_G2_compressed(element_s *elem_sum,
                                 byte_t *elem_bytes_ar,
                                 size_t elem_size,
                                 size_t n,
                                 pairing_t pairing) {
  element_t tmp;
  element_init_G2(tmp, pairing);
  int elem_length = element_length_in_bytes_compressed(tmp);
  for (int i = 0; i < n; i++) {
    element_from_bytes_compressed(tmp, elem_bytes_ar + (i * elem_size));
    element_add(elem_sum, elem_sum, tmp);
  }
  element_clear(tmp);
}

void bls_sign_message(byte_t *out_buf, element_s *sig_elem, element_s *hash_elem, byte_t *msg,
                      uint32_t msg_len, element_s *secret_key) {

  byte_t msg_hash[crypto_ghash_BYTES];
  crypto_generichash(msg_hash, crypto_ghash_BYTES, msg, msg_len, NULL, 0);
  element_from_hash(hash_elem, msg_hash, crypto_ghash_BYTES);

  element_pow_zn(sig_elem, hash_elem, secret_key);
  element_to_bytes_compressed(out_buf, sig_elem);
}

int bls_verify_signature(element_s *sig, element_s *hash_elem, byte_t *sig_buf, byte_t *msg, uint32_t msg_len,
                         element_s *public_key, element_s *g2, pairing_t pairing) {

  byte_t msg_hash[crypto_ghash_BYTES];
  crypto_generichash(msg_hash, crypto_ghash_BYTES, msg, msg_len, NULL, 0);
  element_from_hash(hash_elem, msg_hash, crypto_ghash_BYTES);
  element_from_bytes_compressed(sig, sig_buf);
  element_t u, v;
  element_init(u, pairing->GT);
  element_init(v, pairing->GT);
  element_pairing(u, sig, g2);
  element_pairing(v, hash_elem, public_key);

  int res = element_cmp(u, v);
  element_clear(u);
  element_clear(v);
  return res;
}


