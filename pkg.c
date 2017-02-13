#include <pbc/pbc.h>
#include <sodium.h>
#include <string.h>
#include "alpenhorn.h"
#include "pbc_sign.h"
#include "pkg.h"
#include "ibe.h"
#include "client.h"

void printhex(char *msg, byte_t *data, uint32_t len) {
  uint32_t hex_len = len * 2 + 1;
  char hex_str[hex_len];
  sodium_bin2hex(hex_str, hex_len, data, len);
  printf("%s: %s\n", msg, hex_str);
}

const char *sig_secret_key_str = "11925701675428628347810627595119364991989298471383931751402582285036321419915";
const char *sig_public_key_str =
    "[[9884060615355735211368403213287673066079436215290194494543558437670844560407, "
        "8121618399279148174368171471366479950927004194771649427652677851313587015552], "
        "[12451578048915991056034570678370679751900958237475812725104114877155650140690, "
        "14127887932490664181502737977576361892832625945657535575920396999735606756994]]";
const char *client_sig_pk = "cb89f5d191c92c17089c822a6bd81d015530212be63a9c4d0f5ba2011f663552";
//const char *client_sig_sk = "4e1fb8a8d307c25c201f0ee9738eaee512a0af6f6df254f2c6109394584985e6";
//const char *client_enc_pk = "1ca5dd3e00819cfa168906e2857aec29d983f413ba1475a2b36dc8a76d0f3144";
//const char *client_enc_sk = "c86da06d27a8c8e6984a28e26b66fc23f0c0183bd754dcbbcb3a0fd539d70c16";



int pkg_server_init(pkg_server *server, char *cfg_file) {
  if (!cfg_file)
    return -1;

  char s[16384];
  FILE *fp = fopen(cfg_file, "r");
  if (!fp)
    pbc_die("error opening %s", cfg_file);
  size_t count = fread(s, 1, 16384, fp);
  if (!count)
    pbc_die("input error");
  fclose(fp);

  if (pairing_init_set_buf(server->pairing, s, count))
    pbc_die("pairing client_init failed");

  server->current_round = malloc(sizeof(uint32_t));
  *server->current_round = 0;
  server->num_clients = 1;
  server->srv_id = 1;
  pairing_ptr pairing = server->pairing;
  // Initialise gen_elem element + long term ibe public/secret signature keypair
  element_init(server->pbc_gen_element, pairing->G2);
  element_set_str(server->pbc_gen_element, GENERATOR, 10);
  element_init(server->lt_secret_sig_key_elem, pairing->Zr);
  element_set_str(server->lt_secret_sig_key_elem, sig_secret_key_str, 10);
  element_init(server->lt_public_sig_key_elem, pairing->G2);
  element_set_str(server->lt_public_sig_key_elem, sig_public_key_str, 10);
  server->broadcast_dh_pkey_ptr = server->eph_broadcast_message + ibe_public_key_length;

  // Initialise elements for epheremal IBE key generation and create an initial keypair
  element_init(server->eph_secret_key_elem, pairing->Zr);
  element_init(server->eph_pub_key_elem, pairing->G1);
  // Allocate and initialise clients
  server->clients = malloc(sizeof(pkg_client) * server->num_clients);
  for (int i = 0; i < server->num_clients; i++) {
    memset(&server->clients[i], 0, sizeof(pkg_client));
    pkg_client_init(&server->clients[i], server);
  }
  pkg_new_round(server);
  return 0;
}

void pkg_client_init(pkg_client *client, pkg_server *server) {
  memset(client->user_id, 0, af_email_string_bytes);
  memset(client->round_signature_message, 0, round_sig_message_length);
  byte_t userid[100] = "chris@fmail.co.uk\0";
  memcpy(client->user_id, userid, sizeof userid);
  memset(client->long_term_sig_pub_key, 0, crypto_box_PUBLICKEYBYTES);
  memset(client->auth_msg_from_client, 0, crypto_box_PUBLICKEYBYTES + crypto_sign_BYTES);
  client->round_signature_numptr = client->round_signature_message + round_sig_message_length - sizeof(uint32_t);
  client->auth_response_ibe_key_ptr = client->eph_client_data + bls_signature_length;
  memcpy(client->round_signature_message, userid, sizeof userid);
  sodium_hex2bin(client->long_term_sig_pub_key, crypto_box_PUBLICKEYBYTES, client_sig_pk,
                 crypto_box_PUBLICKEYBYTES * 2 + 1, NULL, NULL, NULL);
  memcpy(client->round_signature_message + af_email_string_bytes,
         client->long_term_sig_pub_key, crypto_box_PUBLICKEYBYTES);
  memcpy(client->round_signature_numptr, server->current_round, sizeof(uint32_t));

  element_init(client->eph_secret_key, server->pairing->G2);
  element_init(client->eph_signature_elem, server->pairing->G1);
  element_init(client->eph_sig_hash_elem, server->pairing->G1);
  element_init(client->hashed_id_elem, server->pairing->G2);
  element_init(server->eph_pub_key_elem, server->pairing->G2);
  element_init(server->eph_secret_key_elem, server->pairing->Zr);
  element_init(server->pbc_gen_element, server->pairing->G2);
  element_set_str(server->pbc_gen_element, GENERATOR, 10);

  byte_t id_hash[crypto_generichash_BYTES];
  memset(id_hash, 0, crypto_generichash_BYTES);
  crypto_generichash(id_hash, crypto_generichash_BYTES, userid, af_email_string_bytes, NULL, 0);
  element_from_hash(client->hashed_id_elem, id_hash, crypto_generichash_BYTES);

}

void pkg_server_shutdown(pkg_server *server) {
  free(server->current_round);
  element_clear(server->lt_secret_sig_key_elem);
  element_clear(server->lt_public_sig_key_elem);
  element_clear(server->eph_pub_key_elem);
  element_clear(server->eph_secret_key_elem);
  element_clear(server->pbc_gen_element);
  for (int i = 0; i < server->num_clients; i++) {
    pkg_client_clear(&server->clients[i]);
  }
  pairing_clear(server->pairing);
}

void pkg_client_clear(pkg_client *client) {
  element_clear(client->hashed_id_elem);
  element_clear(client->eph_signature_elem);
  element_clear(client->eph_sig_hash_elem);
  element_clear(client->eph_secret_key);
  free(client);
}

void pkg_new_round(pkg_server *server) {
  // Generate epheremal IBE + DH keypairs, place public keys into broadcast message buffer
  pkg_new_ibe_keypair(server);
  randombytes_buf(server->eph_secret_dh_key, crypto_box_SECRETKEYBYTES);
  crypto_scalarmult_base(server->broadcast_dh_pkey_ptr, server->eph_secret_dh_key);
  // Increment round counter
  (*server->current_round)++;
  // Extract secret keys and generate signatures for each client
  for (int i = 0; i < server->num_clients; i++) {
    pkg_extract_client_sk(server, &server->clients[i]);
    pkg_sign_for_client(server, &server->clients[i]);
  }
  element_printf("server public ibe elem: %B\n", server->eph_pub_key_elem);
  printhex("broadcast msg at srv", server->eph_broadcast_message, broadcast_message_length);
}

int pkg_auth_client(pkg_server *server, pkg_client *client) {

  int s = crypto_sign_verify_detached(client->auth_msg_from_client, server->eph_broadcast_message,
                                      broadcast_message_length,
                                      client->long_term_sig_pub_key);

  if (s) {
    printf("%d sig verification failed\n", s);
    return -1;
  }
  byte_t *client_dh_ptr = client->auth_msg_from_client + crypto_sign_BYTES;
  byte_t scalar_mult[crypto_scalarmult_BYTES];
  int suc = crypto_scalarmult(scalar_mult, server->eph_secret_dh_key, client_dh_ptr);
  printf("%d\n", suc);
  crypto_shared_secret(client->eph_symmetric_key, scalar_mult, client_dh_ptr, server->broadcast_dh_pkey_ptr);
  printhex("symm key", client->eph_symmetric_key, crypto_box_SECRETKEYBYTES);
  printhex("scalar mult", scalar_mult, crypto_scalarmult_BYTES);
  printhex("client pub key", client_dh_ptr, crypto_box_PUBLICKEYBYTES);
  printhex("server pub key", server->broadcast_dh_pkey_ptr, crypto_generichash_BYTES);
  pkg_encrypt_client_response(server, client);
  //send response
  return 0;
}

void pkg_encrypt_client_response(pkg_server *server, pkg_client *client) {
  byte_t *nonce_ptr = client->eph_client_data + bls_signature_length + ibe_secret_key_length
      + crypto_aead_chacha20poly1305_IETF_ABYTES;
  randombytes_buf(nonce_ptr, crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
  //randombytes_buf(client->eph_symmetric_key, crypto_box_SECRETKEYBYTES);
  crypto_aead_chacha20poly1305_ietf_encrypt(client->eph_client_data,
                                            NULL,
                                            client->eph_client_data,
                                            pkg_auth_res_length,
                                            nonce_ptr,
                                            crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
                                            NULL,
                                            nonce_ptr,
                                            client->eph_symmetric_key);

}

void pkg_new_ibe_keypair(pkg_server *server) {
  element_random(server->eph_secret_key_elem);
  element_pow_zn(server->eph_pub_key_elem, server->pbc_gen_element, server->eph_secret_key_elem);
  element_to_bytes_compressed(server->eph_broadcast_message, server->eph_pub_key_elem);
}

void pkg_extract_client_sk(pkg_server *server, pkg_client *client) {
  element_pow_zn(client->eph_secret_key, client->hashed_id_elem, server->eph_secret_key_elem);
  element_to_bytes_compressed(client->auth_response_ibe_key_ptr, client->eph_secret_key);
}

void pkg_sign_for_client(pkg_server *server, pkg_client *client) {
  memcpy(client->round_signature_numptr, server->current_round, sizeof(uint32_t));
  bls_sign_message(client->eph_client_data, client->eph_signature_elem,
                   client->eph_sig_hash_elem, client->round_signature_message,
                   round_sig_message_length, server->lt_secret_sig_key_elem);
  element_printf("sig elem from srv: %B\n", client->eph_signature_elem);

}
#if 0
int main(int argc, char **argv) {
  pkg_server state;
  uint32_t num_clients = 1;
  pkg_server_init(&state, argv[1]);
  pkg_new_round(&state);
  printhex("response buffer before encryption", (state.clients[0]).eph_client_data, pkg_encr_auth_re_length);
  pkg_encrypt_client_response(&state, &state.clients[0]);
  printhex("response buffer after encryption", (state.clients[0]).eph_client_data, pkg_encr_auth_re_length);
  byte_t buf[pkg_auth_res_length];
  pkg_client *cli = &state.clients[0];
  byte_t *nonce_ptr = cli->eph_client_data + pkg_auth_res_length + crypto_aead_chacha20poly1305_IETF_ABYTES;
  int res = crypto_aead_chacha20poly1305_ietf_decrypt(buf,
                                                      NULL,
                                                      NULL,
                                                      cli->eph_client_data,
                                                      pkg_auth_res_length + crypto_aead_chacha20poly1305_IETF_ABYTES,
                                                      nonce_ptr,
                                                      crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
                                                      nonce_ptr,
                                                      cli->eph_symmetric_key);
  printf("%d\n", res);
  printhex("buffer after decryption", buf, pkg_auth_res_length);
  pkg_server_shutdown(&state);

}
#endif


