#ifndef ALPENHORN_PBC_SIGN_H
#define ALPENHORN_PBC_SIGN_H

#include "pbc/pbc.h"
#include "config.h"
#include "utils.h"

struct bls_instance;
typedef struct bls_instance bls_instance;

void pbc_sum(element_t elem_sum, struct element_s *elem_ar, size_t n, pairing_t pairing);
void pbc_sum_bytes_G1_compressed(element_s *elem_sum, byte_t *elem_bytes_ar, size_t n, pairing_t pairing);
void pbc_sum_bytes_G2_compressed(element_s *elem_sum, byte_t *elem_bytes_ar, size_t n, pairing_t pairing);
void bls_sign_message(byte_t *out_buf, element_s *sig_elem, element_s *hash_elem, byte_t *msg,
                      uint32_t msg_len, element_s *secret_key);
int bls_verify_signature(element_s *sig, element_s *hash_elem, byte_t *sig_buf, byte_t *msg, uint32_t msg_len,
                         element_s *public_key, element_s *g2, pairing_t pairing);
#endif //ALPENHORN_PBC_SIGN_H
