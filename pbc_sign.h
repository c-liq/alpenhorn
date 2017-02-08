//
// Created by chris on 08/02/17.
//

#ifndef ALPENHORN_PBC_SIGN_H
#define ALPENHORN_PBC_SIGN_H
void pbc_sum(element_t elem_sum, element_t *elem_ar, size_t n, pairing_t pairing);
void pb_sum_bytes(element_t elem_sum, byte_t **elem_bytes_ar, size_t n, pairing_t pairing);
void sign_message(element_t sig, byte_t *hash, int hash_len, element_t secret_key, pairing_t pairing);
void signature_to_bytes(element_t sig,
                        byte_t *sig_buf,
                        byte_t *hash,
                        int hash_len,
                        element_t secret_key,
                        pairing_t pairing);
#endif //ALPENHORN_PBC_SIGN_H
