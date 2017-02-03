
#include <sodium.h>
#include <sys/socket.h>
#include <string.h>
#include "alpenhorn.h"
#include "client.h"
#include "ibe_basic.h"

struct keywheel_entry {
  const char *user_id;
  byte_t *secret_key;
  size_t dialling_round;
};

struct keywheel {
  size_t num_entries;
  const struct keywheel *entries;
};

#define pbc_sig_length 32U

struct af_id_signature;

struct client_state {
  const char *user_id;
  byte_t *lt_priv_enc_key;
  byte_t *lt_pub_enc_key;
  byte_t *lt_priv_sig_key;
  byte_t *lt_pub_sig_key;
  byte_t *eph_priv_key;
  byte_t *eph_pub_key;
  size_t num_pkg_servers;
  size_t num_mix_servers;
  size_t mailbox_count;
  int *pkg_sockets;
  int *mix_sockets;
  byte_t **pkg_lt_pub_keys;
  byte_t **pkg_eph_pub_keys;
  byte_t **mix_eph_pub_keys;
  byte_t **pkg_auth_responses;
  struct keywheel *keywheel;
  byte_t *friend_request_buf;
  size_t friend_request_bytes;
  byte_t **cli_mix_dh_pub_keys;
  byte_t **cli_mix_dh_priv_keys;
  byte_t **pkg_multig_fragments;
  byte_t *pkg_multisig_combined;
  char *friend_request_id;
  size_t friend_request_id_length;
  size_t max_email_length;
  byte_t *af_dh_key;
  pairing_t sig_pairing;
  struct af_id_signature *sig_container;
  size_t dialling_round;
  size_t af_round;
  element_t lt_priv_sig_key_elem;

};

int af_calc_mailbox_num(client_state *cli_st);
int sum_signatures(client_state *cli_st);
int generate_dh_keypair(byte_t *sk_out, byte_t *pk_out, size_t key_size) {
  randombytes_buf(sk_out, key_size);
  crypto_scalarmult_base(pk_out, sk_out);
  return 0;
}

int sum_signatures(client_state *cli_st) {
  element_t sig_sum;
  element_init(sig_sum, cli_st->sig_pairing->G1);
  pb_sum_bytes(sig_sum, cli_st->pkg_multig_fragments, cli_st->num_pkg_servers, cli_st->sig_pairing);
  element_to_bytes_x_only(cli_st->pkg_multisig_combined, sig_sum);
  element_clear(sig_sum);
  return 0;
}

void af_gen_request(client_state *cli_st) {
  byte_t *friend_req_buf = cli_st->friend_request_buf + sizeof(int);
  byte_t *dh_pub_key_ptr = friend_req_buf + cli_st->max_email_length;
  byte_t *dialling_round_ptr = dh_pub_key_ptr + crypto_box_PUBLICKEYBYTES;
  byte_t *multisig_ptr = dialling_round_ptr + sizeof(size_t);
  byte_t *client_sig_ptr = multisig_ptr + pbc_sig_length;
  size_t dialling_round = cli_st->dialling_round + 3;

  memcpy(friend_req_buf, cli_st->friend_request_id, cli_st->friend_request_id_length);
  sum_signatures(cli_st);
  byte_t dh_secret[crypto_box_PUBLICKEYBYTES];
  generate_dh_keypair(dh_secret, dh_pub_key_ptr, crypto_box_SECRETKEYBYTES);
  size_t signature_input_length = (int) cli_st->max_email_length + crypto_box_PUBLICKEYBYTES + sizeof dialling_round;
  memcpy(dialling_round_ptr, &dialling_round, sizeof(dialling_round));
  memcpy(multisig_ptr, cli_st->pkg_multisig_combined, pbc_sig_length);
  element_t personal_sig;
  element_init(personal_sig, cli_st->sig_pairing->G1);
  byte_t signature_hash[crypto_generichash_BYTES];
  crypto_generichash(signature_hash, crypto_generichash_BYTES, friend_req_buf, signature_input_length, NULL, 0U);
  signature_to_bytes(personal_sig,
                     client_sig_ptr,
                     signature_hash,
                     crypto_generichash_BYTES,
                     cli_st->lt_priv_sig_key_elem,
                     cli_st->sig_pairing);
  int mailbox_num = af_calc_mailbox_num(cli_st);
  memcpy(cli_st->friend_request_buf, &mailbox_num, sizeof(int));

}

int af_onion_encrypt_request(client_state *cli_st, size_t srv_id);

size_t calc_encrypted_request_bytes(size_t num_mix_servers) {
  return af_request_BYTES + (af_request_ABYTES * num_mix_servers);
}

int socket_send_bytes(int socket, byte_t *data, size_t data_length) {
  size_t bytes_sent = 0;
  while (bytes_sent != data_length) {
    ssize_t tmp_sent = send(socket, data + bytes_sent, data_length - bytes_sent, 0);
    if (tmp_sent == 0 || tmp_sent == -1) {
      return -1;
    }
    bytes_sent += tmp_sent;
  }
  return 0;
}

int af_auth_with_pkgs(client_state *cli_st) {
  for (int i = 0; i < cli_st->num_pkg_servers; i++) {
    crypto_sign_detached(cli_st->pkg_auth_responses[i],
                         NULL,
                         cli_st->pkg_eph_pub_keys[i],
                         pkg_eph_pub_key_BYTES,
                         cli_st->lt_priv_sig_key);
    int send_res = socket_send_bytes(cli_st->pkg_sockets[i], cli_st->pkg_auth_responses[i], crypto_sign_BYTES);
    if (send_res == -1) {
      fprintf(stderr, "Socket send failure\n");
      exit(EXIT_FAILURE);
    }
  }
  return 0;
}

// The value created by the ECDH key exchange can contain weak bits, so rather than use it directly,
// hash it together with the two public keys to calculate the actual shared secret

void crypto_shared_secret(byte_t *shared_secret, byte_t *scalar_mult, byte_t *client_pub, byte_t *server_pub) {
  crypto_generichash_state hash_state;
  crypto_generichash_init(&hash_state, NULL, 0U, crypto_generichash_BYTES);
  crypto_generichash_update(&hash_state, scalar_mult, crypto_generichash_BYTES);
  crypto_generichash_update(&hash_state, client_pub, crypto_generichash_BYTES);
  crypto_generichash_update(&hash_state, server_pub, crypto_generichash_BYTES);
  crypto_generichash_final(&hash_state, shared_secret, crypto_generichash_BYTES);
};

int encrypt_friend_request(client_state *cli_st) {
  for (size_t i = 0; i < cli_st->num_mix_servers; i++) {
    int res = af_onion_encrypt_request(cli_st, i);
    if (res) return -1;
  }
  return 0;
}

int af_onion_encrypt_request(client_state *cli_st, size_t srv_id) {

  if (!cli_st || srv_id >= cli_st->num_mix_servers) return -1;
  // Add another layer of encryption to the request, append public DH key for server + nonce in clear (but authenticated)
  size_t message_length = af_request_BYTES + (af_request_ABYTES * srv_id);
  byte_t *message_end_ptr = cli_st->friend_request_buf + message_length;
  byte_t *dh_pub_ptr = message_end_ptr + crypto_aead_chacha20poly1305_IETF_ABYTES;
  byte_t *nonce_ptr = dh_pub_ptr + crypto_aead_chacha20poly1305_IETF_KEYBYTES;
  byte_t *dh_mix_pub = cli_st->mix_eph_pub_keys[srv_id];

  byte_t dh_priv[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
  byte_t scalar_mult[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
  byte_t shared_secret[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
  randombytes_buf(dh_priv, crypto_aead_chacha20poly1305_IETF_KEYBYTES);
  crypto_scalarmult_base(dh_pub_ptr, dh_priv);
  int res = crypto_scalarmult(scalar_mult, dh_priv, dh_mix_pub);
  if (res) {
    printf("Scalarmult error\n");
    return -1;
  }
  crypto_shared_secret(shared_secret, scalar_mult, dh_pub_ptr, dh_mix_pub);
  randombytes_buf(nonce_ptr, crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
  crypto_aead_chacha20poly1305_ietf_encrypt(cli_st->friend_request_buf,
                                            NULL,
                                            cli_st->friend_request_buf,
                                            message_length,
                                            dh_pub_ptr,
                                            crypto_aead_chacha20poly1305_IETF_KEYBYTES
                                                + crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
                                            NULL,
                                            nonce_ptr,
                                            shared_secret);

  return 0;
};

client_state *init() {
  client_state *cli_state = malloc(sizeof(client_state));
  cli_state->lt_priv_sig_key = malloc(sizeof(byte_t) * crypto_box_PUBLICKEYBYTES);
  cli_state->lt_pub_sig_key = malloc(sizeof(byte_t) * crypto_box_PUBLICKEYBYTES);
  cli_state->lt_priv_enc_key = malloc(sizeof(byte_t) * crypto_box_PUBLICKEYBYTES);
  cli_state->lt_priv_enc_key = malloc(sizeof(byte_t) * crypto_box_PUBLICKEYBYTES);
  cli_state->num_mix_servers = 1;
  cli_state->num_pkg_servers = 1;
  cli_state->friend_request_bytes = calc_encrypted_request_bytes(cli_state->num_mix_servers);
  cli_state->friend_request_buf = malloc(sizeof(byte_t) * cli_state->friend_request_bytes);
  cli_state->mix_sockets = malloc(sizeof(int) * cli_state->num_mix_servers);
  cli_state->pkg_sockets = malloc(sizeof(int) * cli_state->num_pkg_servers);
  cli_state->pkg_eph_pub_keys = malloc(sizeof(byte_t) * crypto_box_PUBLICKEYBYTES * cli_state->num_mix_servers);
  cli_state->pkg_lt_pub_keys = malloc(sizeof(byte_t) * crypto_box_PUBLICKEYBYTES * cli_state->num_mix_servers);
  cli_state->mix_eph_pub_keys = malloc(sizeof(byte_t) * crypto_box_PUBLICKEYBYTES * cli_state->num_mix_servers);
  cli_state->keywheel = malloc(sizeof(struct keywheel));
  byte_t *mix_pk = malloc(crypto_box_PUBLICKEYBYTES);
  sodium_hex2bin(mix_pk,
                 crypto_box_PUBLICKEYBYTES,
                 "dc2a5d0ad83acd9027ffc587530cc26b0eb68679783bb0145e855fb03eaf1739",
                 64,
                 NULL,
                 NULL,
                 NULL);
  cli_state->mix_eph_pub_keys[0] = mix_pk;
  memcpy(cli_state->friend_request_buf, "Test message", strlen("Test message"));
  return cli_state;
};

int main() {
  int res = sodium_init();
  if (res) {
    fprintf(stderr, "Failed to load sodium library\n");
    exit(EXIT_FAILURE);
  }
  client_state *client = init();
  encrypt_friend_request(client);
  decrypt_request(client->friend_request_buf, af_request_BYTES + af_request_ABYTES);
}