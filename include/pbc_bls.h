#ifndef ALPENHORN_PBC_SIGN_H
#define ALPENHORN_PBC_SIGN_H

#include "pbc/pbc.h"
#include "config.h"
#include "utils.h"
#include "pbc_cfg.h"

struct bls_instance;

struct bls_instance
{
	pairing_s pairing;
	element_s gen_elem;
	element_s sig_elem;
	element_s verify_elem;
	element_s sig_hash_elem;
	element_s g1_elem_sum;
	element_s g2_elem_sum;
	element_s u_tmp;
	element_s v_tmp;
	int g1_elem_length;
	int g2_elem_length;
	element_s g1_tmp;
	element_s g2_tmp;
};
typedef struct bls_instance bls_instance;

void pbc_sum_bytes_G1_compressed(element_s *elem_sum,
                                 uint8_t *elem_bytes_ar,
                                 size_t elem_size,
                                 size_t n,
                                 pairing_t pairing);
void pbc_sum_bytes_G2_compressed(element_s *elem_sum,
                                 uint8_t *elem_bytes_ar,
                                 size_t elem_size,
                                 size_t n,
                                 pairing_t pairing);
void bls_sign_message(uint8_t *out_buf, element_s *sig_elem, element_s *hash_elem, uint8_t *msg,
                      uint32_t msg_len, element_s *secret_key);
int bls_verify_signature(element_s *sig, element_s *hash_elem, uint8_t *sig_buf, uint8_t *msg, uint32_t msg_len,
                         element_s *public_key, element_s *g2, pairing_t pairing);
#endif //ALPENHORN_PBC_SIGN_H
