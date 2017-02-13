//
// Created by chris on 01/02/17.
//

#ifndef ALPENHORN_IBE_BASIC_H
#define ALPENHORN_IBE_BASIC_H
#include <pbc/pbc.h>
#include "alpenhorn.h"
#define ibe_elem_g1_bytes 64U
#define ibe_elem_g2_bytes 64U
//
// Created by chris on 31/01/17.
//


int ibe_extract(element_t out, element_t master_priv_key, const byte_t *id, uint32_t id_length);
int ibe_encrypt(byte_t *out, byte_t *msg, size_t msg_len, element_t public_key,
                element_t P, byte_t *recv_id, size_t recv_id_len, pairing_t pairing);
int ibe_decrypt(byte_t *out, byte_t *c, uint32_t clen, element_t private_key, pairing_t pairing);
#endif //ALPENHORN_IBE_BASIC_H
