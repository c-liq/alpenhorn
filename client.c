#include <sodium.h>
#include <sys/socket.h>
#include <string.h>
#include "alpenhorn.h"
#include "client.h"
#include "ibe.h"
#include "pbc_sign.h"
#include "keywheel.h"
#include "xxHash-master/xxhash.h"

const char *sig_pk = "301537283d8e6c36fc602e4fb907e9e9a87b3476a3c5c71c0ddbfbcac100fe74";
const char *signature_pk =
    "4ba846375db0fb8dbea0d9a4b32743a54b1209c5b8aa5cd9e9bc81a875941f3e301537283d8e6c36fc602e4fb907e9e9a87b3476a3c5c71c0ddbfbcac100fe74";

void crypto_shared_secret(byte_t *shared_secret, byte_t *scalar_mult, byte_t *client_pub, byte_t *server_pub) {
  crypto_generichash_state hash_state;
  crypto_generichash_init(&hash_state, NULL, 0U, crypto_generichash_BYTES);
  crypto_generichash_update(&hash_state, scalar_mult, crypto_generichash_BYTES);
  crypto_generichash_update(&hash_state, client_pub, crypto_generichash_BYTES);
  crypto_generichash_update(&hash_state, server_pub, crypto_generichash_BYTES);
  crypto_generichash_final(&hash_state, shared_secret, crypto_generichash_BYTES);
};

uint32_t af_calc_mailbox_num(client *cli_st) {
  uint64_t hash = XXH64(cli_st->friend_request_id, af_email_string_bytes, 1231234);
  return (uint32_t) hash % cli_st->mailbox_count;
}

void serializeUint32(byte_t *out, uint32_t in) {
  out[0] = (byte_t) ((in >> 24) & 0xFF);
  out[1] = (byte_t) ((in >> 16) & 0xFF);
  out[2] = (byte_t) ((in >> 8) & 0xFF);
  out[3] = (byte_t) (in & 0xFF);
}

uint32_t deserializeUint32(byte_t *in) {
  return in[0] + (in[1] << 8) + (in[2] << 16) + (in[3] << 24);

}

void af_create_request(client *client) {
  byte_t
      *user_id_ptr = client->friend_request_buf + 4 + bls_signature_length + crypto_aead_chacha20poly1305_ietf_KEYBYTES
      + crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
  byte_t *dh_pub_ptr = user_id_ptr + af_email_string_bytes;
  byte_t *dialling_round_ptr = dh_pub_ptr + crypto_box_PUBLICKEYBYTES;
  byte_t *lt_sig_key_ptr = dialling_round_ptr + sizeof(uint32_t);
  byte_t *personal_sig_ptr = lt_sig_key_ptr + crypto_sign_PUBLICKEYBYTES;
  byte_t *multisig_ptr = personal_sig_ptr + crypto_sign_BYTES;

  byte_t dh_secret_key[crypto_box_SECRETKEYBYTES];
  crypto_box_keypair(dh_pub_ptr, dh_secret_key);
  uint32_t dialling_round = client->dialling_round + 2;
  memcpy(user_id_ptr, client->user_id, af_email_string_bytes);
  serializeUint32(dialling_round_ptr, dialling_round);

  memcpy(lt_sig_key_ptr, client->lt_pub_sig_key, crypto_sign_PUBLICKEYBYTES);
  crypto_sign_detached(personal_sig_ptr,
                       NULL,
                       user_id_ptr,
                       af_email_string_bytes + crypto_box_PUBLICKEYBYTES + sizeof dialling_round,
                       client->lt_secret_sig_key);
  element_to_bytes_compressed(multisig_ptr, &client->pkg_multisig_combined_g1);
  //printf("------------------------------\n");
  //element_printf("IBE Gen element: %B\n", &client->ibe_gen_element_g1);
  //element_printf("EPH ibe pub key: %B\n--------\n", &client->pkg_eph_pub_combined_g1);
  //element_printf("")
  printf("request bytes: %d, sum: %ld\n",
         request_bytes,
         af_email_string_bytes + crypto_box_PUBLICKEYBYTES + sizeof(uint32_t) + crypto_sign_PUBLICKEYBYTES
             + bls_signature_length + crypto_sign_BYTES);
  printhex("userid", user_id_ptr, af_email_string_bytes);
  printhex("dh_pub", dh_pub_ptr, crypto_box_PUBLICKEYBYTES);
  printhex("lt_sig_key", lt_sig_key_ptr, crypto_sign_PUBLICKEYBYTES);
  printhex("personal sig", personal_sig_ptr, crypto_sign_BYTES);
  printhex("multisig ptr", multisig_ptr, bls_signature_length);
  printhex("everything", user_id_ptr, request_bytes);
  ibe_encrypt(client->friend_request_buf + 4,
              user_id_ptr,
              request_bytes,
              &client->pkg_eph_pub_combined_g1,
              &client->ibe_gen_element_g1,
              client->friend_request_id,
              af_email_string_bytes,
              &client->pairing);
  uint32_t mn = af_calc_mailbox_num(client);
  memcpy(client->friend_request_buf, &mn, sizeof(uint32_t));

}

int af_onion_encrypt_request(client *cli_st, size_t srv_id);

size_t calc_encrypted_request_bytes() {

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
    //printhex("cli symm key", symmetric_key_ptr, crypto_box_SECRETKEYBYTES);
    //printhex("cli scalar mult", scalar_mult, crypto_scalarmult_BYTES);
    //printhex("cli client pub key", cli_pub_key_ptr, crypto_box_PUBLICKEYBYTES);
    //printhex("cli server pub key", pkg_pub_key_ptr, crypto_generichash_BYTES);

  }
  pbc_sum_bytes_G1_compressed(&client->pkg_eph_pub_combined_g1,
                              client->pkg_broadcast_msgs[0],
                              num_pkg_servers,
                              &client->pairing);
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
    memcpy(client->pkg_eph_ibe_sk_fragments_g2[i], auth_response + bls_signature_length, ibe_secret_key_length);

  }
  return 0;
}

int af_process_auth_responses(client *client) {
  printhex("sig from srv", client->pkg_auth_responses[0], bls_signature_length);
  printhex("sk from serv,", client->pkg_eph_ibe_sk_fragments_g2[0], ibe_secret_key_length);
  pbc_sum_bytes_G1_compressed(&client->pkg_multisig_combined_g1, client->pkg_auth_responses[0],
                              num_pkg_servers, &client->pairing);
  pbc_sum_bytes_G2_compressed(&client->pkg_ibe_secret_combined_g2, client->pkg_eph_ibe_sk_fragments_g2[0],
                              num_pkg_servers, &client->pairing);
  element_printf("multisig: %B\n", &client->pkg_multisig_combined_g1);
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
  memset(client->friend_request_buf, 0, sizeof client->friend_request_buf);
  byte_t user_id[af_email_string_bytes] = {'c', 'h', 'r', 'i', 's'};
  client->mailbox_count = 7;
  memcpy(client->user_id, user_id, af_email_string_bytes);
  pbc_demo_pairing_init(&client->pairing, argc, argv);
  element_init(&client->pkg_multisig_combined_g1, client->pairing.G1);
  element_init(&client->pkg_ibe_secret_combined_g2, client->pairing.G2);
  element_init(&client->pkg_eph_pub_combined_g1, client->pairing.G1);
  element_init(&client->pkg_friend_elem, client->pairing.G2);
  element_init(&client->ibe_gen_element_g1, client->pairing.G1);
  sodium_hex2bin(client->lt_pub_sig_key,
                 crypto_sign_PUBLICKEYBYTES,
                 sig_pk,
                 64,
                 NULL,
                 NULL,
                 NULL);

  sodium_hex2bin(client->lt_secret_sig_key,
                 crypto_sign_SECRETKEYBYTES,
                 signature_pk,
                 128,
                 NULL,
                 NULL,
                 NULL);
}

client *client_init(int argc, char **argv) {
  client *cli_state = malloc(sizeof(client));
  pbc_demo_pairing_init(&cli_state->pairing, argc, argv);
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