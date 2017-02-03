//
// Created by chris on 01/02/17.
//

#ifndef ALPENHORN_IBE_BASIC_H
#define ALPENHORN_IBE_BASIC_H
#include <pbc/pbc.h>
#include "alpenhorn.h"
//
// Created by chris on 31/01/17.
//
void pbc_sum(element_t elem_sum, element_t *elem_ar, size_t n, pairing_t pairing);
void pb_sum_bytes(element_t elem_sum, byte_t **elem_bytes_ar, size_t n, pairing_t pairing);
void sign_message(element_t sig, byte_t *hash, int hash_len, element_t secret_key, pairing_t pairing);
void signature_to_bytes(element_t sig,
                        byte_t *sig_buf,
                        byte_t *hash,
                        int hash_len,
                        element_t secret_key,
                        pairing_t pairing);

#endif //ALPENHORN_IBE_BASIC_H
