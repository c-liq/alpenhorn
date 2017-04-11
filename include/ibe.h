#ifndef ALPENHORN_IBE_BASIC_H
#define ALPENHORN_IBE_BASIC_H
#include <pbc/pbc.h>
#include "config.h"
#include "utils.h"

int ibe_pbc_extract(element_s *out, element_s *master_priv_key, const uint8_t *id, const uint32_t id_length);

ssize_t ibe_pbc_encrypt(uint8_t *out, uint8_t *msg, uint32_t, element_s *public_key,
                        element_s *gen, uint8_t *recv_id, size_t recv_id_len, pairing_s *pairing);
ssize_t ibe_pbc_decrypt(uint8_t *out,
                        uint8_t *c,
                        uint32_t clen,
                        element_s *private_key,
                        uint8_t *public_key,
                        pairing_s *pairing);
#endif //ALPENHORN_IBE_BASIC_H
