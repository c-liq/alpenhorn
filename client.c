#include <sodium.h>
#include <sys/socket.h>
#include <string.h>
#include "alpenhorn.h"
#include "client.h"
#include "ibe.h"
#include "pbc_sign.h"
#include "keywheel.h"
#include "xxHash-master/xxhash.h"

void crypto_shared_secret(byte_t *shared_secret, byte_t *scalar_mult, byte_t *client_pub, byte_t *server_pub) {
  crypto_generichash_state hash_state;
  crypto_generichash_init(&hash_state, NULL, 0U, crypto_generichash_BYTES);
  crypto_generichash_update(&hash_state, scalar_mult, crypto_generichash_BYTES);
  crypto_generichash_update(&hash_state, client_pub, crypto_generichash_BYTES);
  crypto_generichash_update(&hash_state, server_pub, crypto_generichash_BYTES);
  crypto_generichash_final(&hash_state, shared_secret, crypto_generichash_BYTES);
};

int af_calc_mailbox_num(client *cli_st) {
  uint64_t hash = XXH64(cli_st->friend_request_id, af_email_string_bytes, 1231234);
  return (uint32_t) hash % cli_st->mailbox_count;
}
int sum_signatures(client *cli_st);

int sum_signatures(client *cli_st) {
  element_t sig_sum;
  element_init(sig_sum, cli_st->pairing->G1);

  //element_to_bytes_x_only(cli_st->pkg_multisig_combined, sig_sum);
  element_clear(sig_sum);
  return 0;
}

void af_gen_request(client *cli_st) {
  byte_t *friend_req_buf = cli_st->friend_request_buf + 108;
  byte_t *dh_pub_key_ptr = friend_req_buf + af_email_string_bytes;
  byte_t *dialling_round_ptr = dh_pub_key_ptr + crypto_box_PUBLICKEYBYTES;
  byte_t *multisig_ptr = dialling_round_ptr + sizeof(uint32_t);
  byte_t *client_sig_ptr = multisig_ptr + pbc_sig_length;
  uint32_t dialling_round = cli_st->dialling_round + 3;

  memcpy(friend_req_buf, cli_st->friend_request_id, af_email_string_bytes);
  sum_signatures(cli_st);
  byte_t dh_secret[crypto_box_PUBLICKEYBYTES];
  crypto_box_keypair(dh_pub_key_ptr, dh_secret);
  memcpy(dialling_round_ptr, &dialling_round, sizeof(dialling_round));
  // memcpy(multisig_ptr, cli_st->pkg_multisig_combined, pbc_sig_length);

  int mailbox_num = 1;
  memcpy(cli_st->friend_request_buf, &mailbox_num, sizeof(int));
}

int af_onion_encrypt_request(client *cli_st, size_t srv_id);

size_t calc_encrypted_request_bytes() {

  return 0;
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

int af_auth_with_pkgs(client *client) {
  byte_t *cli_sig_ptr;
  byte_t *cli_pub_key_ptr;
  byte_t *pkg_pub_key_ptr;
  byte_t *symmetric_key_ptr;

  for (int i = 0; i < num_pkg_servers; i++) {
    cli_pub_key_ptr = client->pkg_auth_request[i] + crypto_sign_BYTES;
    cli_sig_ptr = client->pkg_auth_request[i];
    pkg_pub_key_ptr = client->pkg_broadcast_msgs[i] + ibe_public_key_length;
    symmetric_key_ptr = client->pkg_eph_symmetric_keys[i];

    crypto_sign_detached(cli_sig_ptr,
                         NULL,
                         client->pkg_broadcast_msgs[i],
                         broadcast_message_length,
                         client->lt_secret_sig_key);
    byte_t secret_key[crypto_box_SECRETKEYBYTES];
    byte_t scalar_mult[crypto_scalarmult_BYTES];
    randombytes_buf(secret_key, crypto_box_SECRETKEYBYTES);

    crypto_box_keypair(cli_pub_key_ptr, secret_key);
    if (crypto_scalarmult(scalar_mult, secret_key, pkg_pub_key_ptr)) {
      printf("HELP\n");
    }
    crypto_shared_secret(symmetric_key_ptr, scalar_mult, cli_pub_key_ptr, pkg_pub_key_ptr);
    printhex("cli symm key", symmetric_key_ptr, crypto_box_SECRETKEYBYTES);
    printhex("cli scalar mult", scalar_mult, crypto_scalarmult_BYTES);
    printhex("cli client pub key", cli_pub_key_ptr, crypto_box_PUBLICKEYBYTES);
    printhex("cli server pub key", pkg_pub_key_ptr, crypto_generichash_BYTES);

  }
  return 0;
}

int af_decrypt_auth_responses(client *client) {
  byte_t *auth_response;
  byte_t *nonce_ptr;

  for (int i = 0; i < num_pkg_servers; i++) {

    auth_response = client->pkg_auth_responses[i];
    nonce_ptr = auth_response + pkg_auth_res_length + crypto_aead_chacha20poly1305_IETF_ABYTES;
    int res = crypto_aead_chacha20poly1305_ietf_decrypt(auth_response,
                                                        NULL,
                                                        NULL,
                                                        auth_response,
                                                        pkg_auth_res_length + crypto_aead_chacha20poly1305_IETF_ABYTES,
                                                        nonce_ptr,
                                                        crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
                                                        nonce_ptr,
                                                        client->pkg_eph_symmetric_keys[i]);
    if (res) {
      fprintf(stderr, "Decryption failure\n");
      return -1;
    }
    memcpy(client->pkg_eph_pub_fragments[i], auth_response + bls_signature_length, ibe_public_key_length);

  }
  return 0;
}

int af_process_auth_responses(client *client) {
  pbc_sum_bytes_G1_compressed(&client->pkg_multisig_combined, client->pkg_auth_responses[0],
                              num_pkg_servers, client->pairing);
  pbc_sum_bytes_G2_compressed(&client->pkg_eph_pub_combined, client->pkg_eph_pub_fragments[0],
                              num_pkg_servers, client->pairing);
  element_printf("multisig: %B\n", &client->pkg_multisig_combined);
  return 0;
}

int encrypt_friend_request(client *cli_st) {
  for (size_t i = 0; i < num_mix_servers; i++) {
    int res = af_onion_encrypt_request(cli_st, i);
    if (res)
      return -1;
  }
  return 0;
}

int af_onion_encrypt_request(client *cli_st, size_t srv_id) {

  if (!cli_st || srv_id >= num_mix_servers)
    return -1;
  // Add another layer of encryption to the request, append public DH key for server + nonce in clear (but authenticated)
  size_t message_length = request_bytes + (af_request_ABYTES * srv_id);
  byte_t *message_end_ptr = cli_st->friend_request_buf + message_length;
  byte_t *dh_pub_ptr = message_end_ptr + crypto_aead_chacha20poly1305_ietf_ABYTES;
  byte_t *nonce_ptr = dh_pub_ptr + crypto_aead_chacha20poly1305_ietf_KEYBYTES;
  byte_t *dh_mix_pub = cli_st->mix_eph_pub_keys[srv_id];

  byte_t dh_secret[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
  byte_t scalar_mult[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
  byte_t shared_secret[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
  randombytes_buf(dh_secret, crypto_aead_chacha20poly1305_ietf_KEYBYTES);
  crypto_scalarmult_base(dh_pub_ptr, dh_secret);
  int res = crypto_scalarmult(scalar_mult, dh_secret, dh_mix_pub);
  if (res) {
    printf("Scalarmult error\n");
    return -1;
  }
  crypto_shared_secret(shared_secret, scalar_mult, dh_pub_ptr, dh_mix_pub);
  randombytes_buf(nonce_ptr, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
  crypto_aead_chacha20poly1305_ietf_encrypt(cli_st->friend_request_buf,
                                            NULL,
                                            cli_st->friend_request_buf,
                                            message_length,
                                            dh_pub_ptr,
                                            crypto_aead_chacha20poly1305_ietf_KEYBYTES
                                                + crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
                                            NULL,
                                            nonce_ptr,
                                            shared_secret);

  return 0;
};

void client_fill(client *client, int argc, char **argv) {
  pbc_demo_pairing_init(client->pairing, argc, argv);
  element_init(&client->pkg_multisig_combined, client->pairing->G1);
  element_init(&client->pkg_ibe_secret_combined, client->pairing->G1);
  element_init(&client->pkg_eph_pub_combined, client->pairing->G2);
  element_init(&client->pkg_friend_elem, client->pairing->G2);
}

client *client_init(int argc, char **argv) {
  client *cli_state = malloc(sizeof(client));
  pbc_demo_pairing_init(cli_state->pairing, argc, argv);
  return cli_state;
};
#if 0
int main(int argc, char **argv) {
  calc_encrypted_request_bytes();
  calc_encrypted_request_bytes();
  int res = sodium_init();
  if (res) {
    fprintf(stderr, "Failed to load sodium library\n");
    exit(EXIT_FAILURE);
  }
  client *client = client_init(argc, argv);
  printf("Bleep\n");
  af_gen_request(client);
  //decrypt_request(client->friend_request_buf, af_request_BYTES + af_request_ABYTES);
}
#endif