//
// Created by chris on 31/01/17.
//
#define PBC_DEBUG
#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <sodium.h>

#include "ibe_full.h"
#include "alpenhorn.h"

int main(int argc, char **argv) {

  pairing_t pairing;
  pbc_demo_pairing_init(pairing, argc, argv);
  element_t P;
  element_init(P, pairing->G1);
  element_random(P);
  element_t s;
  element_init(s, pairing->Zr);
  element_random(s);
  element_t Ppub;
  element_init(Ppub, pairing->G1);
  element_pow_zn(Ppub, P, s);

  const byte_t *id = (byte_t *) "chris";
  byte_t id_hash[crypto_generichash_BYTES];
  crypto_generichash(id_hash, crypto_generichash_BYTES, id, sizeof id, NULL, 0);
  element_t id_hash_elem;
  element_init(id_hash_elem, pairing->G2);
  element_from_hash(id_hash_elem, id_hash, crypto_generichash_BYTES);

  byte_t msg[32U];
  randombytes_buf(msg, 32U);
  size_t msglength = sizeof msg;

  byte_t rho[msglength];
  randombytes_buf(rho, msglength);
  crypto_generichash_state hash_state;
  crypto_generichash_init(&hash_state, NULL, 0, msglength);
  crypto_generichash_update(&hash_state, msg, msglength);
  crypto_generichash_update(&hash_state, rho, msglength);

  byte_t r[msglength];
  crypto_generichash_final(&hash_state, r, msglength;
  element_t msgrho_elem;
  element_init(msgrho_elem, pairing->Zr);
  element_from_hash(msgrho_elem, r, (int) msglength);

  byte_t rho_hash[crypto_generichash_BYTES_MAX];
  crypto_generichash(rho_hash, crypto_generichash_BYTES_MAX, r, crypto_generichash_BYTES_MAX, NULL, 0);

  byte_t rhohash_msg_xor[crypto_generichash_BYTES_MAX];
  for (int i = 0; i < crypto_generichash_BYTES_MAX; i++) {
    rhohash_msg_xor[i] = msg[i] ^ rho_hash[i];
  }

}
