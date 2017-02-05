//
// Created by chris on 01/02/17.
//

#include "ibe_basic.h"
#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <sodium.h>
#include "alpenhorn.h"

struct ibe_params {
  pairing_t pairing;
  element_t P;
  element_t public_key;
  element_t private_key;
};

int encrypt_message(byte_t *out,
                    byte_t *msg,
                    size_t msg_len,
                    element_t public_key,
                    element_t g,
                    byte_t *recv_id,
                    size_t recv_id_len,
                    pairing_t pairing) {
  byte_t id_hash[crypto_generichash_BYTES];
  crypto_generichash(id_hash, crypto_generichash_BYTES, recv_id, recv_id_len, NULL, 0);
  element_t id_hash_elem;
  element_init(id_hash_elem, pairing->G2);
  element_from_hash(id_hash_elem, id_hash, crypto_generichash_BYTES);
  element_t Gid;
  element_init(Gid, pairing->GT);
  element_pairing(Gid, public_key, id_hash_elem);

  element_t r;
  element_init(r, pairing->Zr);
  element_random(r);
  element_pow_zn(Gid, Gid, r);
  size_t elem_length = (size_t) element_length_in_bytes(Gid);
  byte_t Gid_bytes[elem_length];
  element_to_bytes(Gid_bytes, Gid);
  byte_t Gid_hash[crypto_generichash_BYTES];
  crypto_generichash(Gid_hash, crypto_generichash_BYTES, Gid_bytes, elem_length, NULL, 0);

  byte_t symmetric_key[crypto_aead_chacha20poly1305_KEYBYTES];
  byte_t nonce[crypto_aead_chacha20poly1305_NPUBBYTES];
  randombytes_buf(symmetric_key, crypto_aead_chacha20poly1305_KEYBYTES);
  randombytes_buf(nonce, crypto_aead_chacha20poly1305_NPUBBYTES);

  element_t rP;
  element_init(rP, pairing->G1);
  element_pow_zn(rP, g, r);

  byte_t asym_ciphertxt[element_length_in_bytes(rP) + crypto_generichash_BYTES];


  return 0;
}

int main(int argc, char **argv) {
  int res = sodium_init();
  if (res) {
    printf("Sodium init failed\n");
  }

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
  element_t Qid;
  element_init(Qid, pairing->G2);
  element_from_hash(Qid, id_hash, crypto_generichash_BYTES);

  byte_t msg[32U];
  randombytes_buf(msg, 32U);
  size_t msglength = sizeof msg;

  element_t r;
  element_init(r, pairing->Zr);
  element_random(r);

  element_t g_id;
  element_init(g_id, pairing->GT);
  element_printf("Qid: %B\n", Qid);
  element_printf("Ppub: %B\n", Ppub);
  element_pairing(g_id, Ppub, Qid);

  element_t gR;
  element_init(gR, pairing->GT);
  element_pow_zn(gR, g_id, r);

  element_t rP;
  element_init(rP, pairing->G1);
  element_pow_zn(rP, P, r);

  size_t gR_length_in_bytes = (size_t) element_length_in_bytes(gR);
  byte_t elem_bytes[gR_length_in_bytes];
  element_to_bytes(elem_bytes, gR);

  byte_t byte_th2_hash[crypto_generichash_BYTES];
  crypto_generichash(byte_th2_hash, crypto_generichash_BYTES, elem_bytes, gR_length_in_bytes, NULL, 0);

  byte_t msg_xor[crypto_generichash_BYTES];
  for (int i = 0; i < crypto_generichash_BYTES; i++) {
    msg_xor[i] = byte_th2_hash[i] ^ msg[i];
  }

  size_t rP_length = (size_t) element_length_in_bytes(rP);
  byte_t rP_bytes[rP_length];
  element_to_bytes_x_only(rP_bytes, rP);

  element_t Did;
  element_init(Did, pairing->G2);
  element_pow_zn(Did, Qid, s);

  element_t pair_Did_U;
  element_init(pair_Did_U, pairing->GT);
  element_pairing(pair_Did_U, rP, Did);

  byte_t pDu_bytes[gR_length_in_bytes];
  element_to_bytes(pDu_bytes, pair_Did_U);

  byte_t pDu_hash[crypto_generichash_BYTES];
  crypto_generichash(pDu_hash, crypto_generichash_BYTES, pDu_bytes, gR_length_in_bytes, NULL, 0);

  byte_t decrypted_msg[crypto_generichash_BYTES];
  for (int i = 0; i < crypto_generichash_BYTES; i++) {
    decrypted_msg[i] = msg_xor[i] ^ pDu_hash[i];
  }

  size_t hex_len = crypto_generichash_BYTES * 2 + 1;
  char msg_before[hex_len];
  char msg_after[hex_len];
  sodium_bin2hex(msg_before, hex_len, msg, crypto_generichash_BYTES);
  sodium_bin2hex(msg_after, hex_len, decrypted_msg, crypto_generichash_BYTES);

  printf("before: %s\n", msg_before);
  printf("after: %s\n", msg_after);

}