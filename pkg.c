//
// Created by chris on 15/01/17.
//

#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <sodium.h>
#include <string.h>
#include "alpenhorn.h"
#include "pbc_sign.h"
#define sig_message_length af_email_string_bytes + crypto_box_PUBLICKEYBYTES + sizeof(uint32_t)

struct pkg_client_state {
  char user_id[af_email_string_bytes];
  byte_t signature_message[sig_message_length];
  element_ptr signature_elem;
  element_t eph_priv_key;
  byte_t *eph_priv_key_bytes;
  byte_t *long_term_sign_key;
  byte_t *long_term_enc_key;
  element_t hashed_id_elem;
};

struct pkg_state {
  int srv_id;
  uint32_t num_clients;
  byte_t *sig_key_public_bytes;
  element_ptr sig_key_private_elem;
  uint32_t current_round;
  pairing_t pairing;
  element_t eph_pub_key_elem;
  element_t eph_priv_key_elem;
  byte_t *eph_pub_key_bytes;
  element_ptr *client_auth_sigs;
  byte_t *client_long_term_sig_keys;
  element_t pbc_gen_element;
  struct pkg_client_state *clients;

};

int pkg_client_auth_sig(struct pkg_state *svr_state, struct pkg_client_state *cli_state) {
  byte_t *sig_dial_round_ptr = cli_state->signature_message + af_email_string_bytes + crypto_box_PUBLICKEYBYTES;
  memcpy(sig_dial_round_ptr, &svr_state->current_round, sizeof(uint32_t));
  byte_t sig_msg_hash[crypto_generichash_BYTES];
  crypto_generichash(sig_msg_hash, crypto_generichash_BYTES, cli_state->signature_message, sig_message_length, NULL, 0);
  signature_to_bytes(cli_state->signature_elem,
                     cli_state->signature_message,
                     sig_msg_hash,
                     crypto_generichash_BYTES,
                     svr_state->sig_key_private_elem,
                     svr_state->pairing);
}

int pkg_state_init(struct pkg_state *state) {
  state = malloc(sizeof(struct pkg_state));
  if (!state) {
    return -1;
  }
  state->num_clients = 1;
  state->srv_id = 1;
  state->sig_key_private_elem = malloc(crypto_box_SECRETKEYBYTES);
  state->sig_key_public_bytes = malloc(crypto_box_PUBLICKEYBYTES);

  state->current_round = 0;
  state->client_long_term_sig_keys = malloc(crypto_box_PUBLICKEYBYTES * (state->num_clients * 2));

  return 0;
}

void pkg_gen_new_master_keypair(struct pkg_state *state) {
  element_random(state->eph_priv_key_elem);
  element_pow_zn(state->eph_pub_key_elem, state->pbc_gen_element, state->eph_priv_key_elem);
  element_to_bytes_compressed(state->eph_pub_key_bytes, state->eph_pub_key_elem);
}

void pkg_extract_client_keys(struct pkg_state *state) {
  element_ptr private_key = state->eph_priv_key_elem;
  for (int i = 0; i < state->num_clients; i++) {
    element_ptr hashed_id_elem = state->clients[i].hashed_id_elem;
    element_ptr client_eph_priv_elem = state->clients[i].eph_priv_key;
    element_pow_zn(client_eph_priv_elem, hashed_id_elem, private_key);
    element_to_bytes_compressed(state->clients[i].eph_priv_key_bytes, client_eph_priv_elem);
  }
}

int main(int argc, char **argv) {

  struct pkg_state state;
  pbc_demo_pairing_init(state.pairing, argc, argv);
  uint32_t num_clients = 1;
  state.client_auth_sigs = malloc(sizeof(element_ptr) * num_clients);
  for (int i = 0; i < num_clients; i++) {
    state.client_auth_sigs[i] = malloc(sizeof(struct element_s));
    element_init(state.client_auth_sigs[i], state.pairing->G1);
  }
  element_init(state.pbc_gen_element, state.pairing->G2);
  element_set_str(state.pbc_gen_element, g, 10);
}



