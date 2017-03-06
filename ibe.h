#ifndef ALPENHORN_IBE_BASIC_H
#define ALPENHORN_IBE_BASIC_H
#include <pbc/pbc.h>
#include "config.h"
#include "utils.h"

int ibe_extract(element_t out, element_t master_priv_key, const uint8_t *id, uint32_t id_length);
int ibe_encrypt(uint8_t *out, uint8_t *msg, uint32_t, element_t public_key,
                element_t gen, uint8_t *recv_id, size_t recv_id_len, pairing_t pairing);
int ibe_decrypt(uint8_t *out, uint8_t *c, uint32_t clen, element_s *private_key, pairing_s *pairing);
#endif //ALPENHORN_IBE_BASIC_H
