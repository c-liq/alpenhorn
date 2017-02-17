#include <pbc/pbc.h>
#include <sodium.h>
#include <string.h>
#include <pbc/pbc_test.h>
#include "pbc_sign.h"
#include "pkg.h"

byte_t fid[user_id_BYTES] = "chris@fmail.co.uk";
byte_t ltsig[] = "301537283d8e6c36fc602e4fb907e9e9a87b3476a3c5c71c0ddbfbcac100fe74";


int pkg_server_init(pkg_server *server, int argc, char **argv) {
  pbc_demo_pairing_init(server->pairing, argc, argv);
  server->current_round = 0;
  server->num_clients = 1;
  server->srv_id = 1;
  pairing_ptr pairing = server->pairing;
  // Initialise gen_elem element + long term ibe public/secret signature keypair
  element_init(&server->bls_gen_element_g2, pairing->G2);
  element_init(&server->ibe_gen_element_g1, pairing->G1);
  element_set_str(&server->ibe_gen_element_g1, ibe_gen_g3, 10);
  element_set_str(&server->bls_gen_element_g2, bls_generator, 10);
  element_init(server->lt_secret_sig_key_elem_zr, pairing->Zr);
  element_set_str(server->lt_secret_sig_key_elem_zr, sk[0], 10);
  element_init(server->lt_public_sig_key_elem_g2, pairing->G2);
  element_set_str(server->lt_public_sig_key_elem_g2, pk[0], 10);
  server->broadcast_dh_pkey_ptr = server->eph_broadcast_message + g2_elem_compressed_BYTES;

  // Initialise elements for epheremal IBE key_state generation and create an initial keypair
  element_init(server->eph_secret_key_elem_zr, pairing->Zr);
  element_init(server->eph_pub_key_elem_g1, pairing->G1);
  // Allocate and initialise clients
  server->clients = malloc(sizeof(pkg_client) * server->num_clients);
  for (int i = 0; i < server->num_clients; i++) {
    memset(&server->clients[i], 0, sizeof(pkg_client));
    pkg_client_init(&server->clients[i], server, fid, ltsig);
  }
  pkg_new_round(server);
  return 0;
}

void pkg_client_init(pkg_client *client, pkg_server *server, byte_t *user_id, byte_t *lt_sig_key) {

  client->auth_response_ibe_key_ptr = client->eph_client_data + g1_elem_compressed_BYTES;

  memcpy(client->user_id, user_id, user_id_BYTES);
  sodium_hex2bin(client->long_term_sig_pub_key,
                 crypto_sign_PUBLICKEYBYTES,
                 (char *) lt_sig_key,
                 crypto_sign_PUBLICKEYBYTES * 2,
                 NULL,
                 NULL,
                 NULL);
  memcpy(client->round_signature_message + dialling_round_BYTES, client->user_id, user_id_BYTES);
  memcpy(client->round_signature_message + dialling_round_BYTES + user_id_BYTES,
         client->long_term_sig_pub_key,
         crypto_sign_PUBLICKEYBYTES);

  element_init(client->eph_secret_key_g2, server->pairing->G2);
  element_init(client->eph_signature_elem_g1, server->pairing->G1);
  element_init(client->eph_sig_hash_elem_g1, server->pairing->G1);
  element_init(client->hashed_id_elem_g2, server->pairing->G2);

  byte_t id_hash[crypto_generichash_BYTES];
  crypto_generichash(id_hash, crypto_generichash_BYTES, client->user_id, user_id_BYTES, NULL, 0);
  //printhex("generating id hash:::::", id_hash, crypto_generichash_BYTES);
  element_from_hash(client->hashed_id_elem_g2, id_hash, crypto_generichash_BYTES);

}

void pkg_server_shutdown(pkg_server *server) {
  element_clear(server->lt_secret_sig_key_elem_zr);
  element_clear(server->lt_public_sig_key_elem_g2);
  element_clear(server->eph_pub_key_elem_g1);
  element_clear(server->eph_secret_key_elem_zr);
  element_clear(&server->bls_gen_element_g2);
  for (int i = 0; i < server->num_clients; i++) {
    pkg_client_clear(&server->clients[i]);
  }
  pairing_clear(server->pairing);
}

void pkg_client_clear(pkg_client *client) {
  element_clear(client->hashed_id_elem_g2);
  element_clear(client->eph_signature_elem_g1);
  element_clear(client->eph_sig_hash_elem_g1);
  element_clear(client->eph_secret_key_g2);
  free(client);
}

void pkg_new_round(pkg_server *server) {
  // Generate epheremal IBE + DH keypairs, place public keys into broadcast message buffer
  pkg_new_ibe_keypair(server);
  randombytes_buf(server->eph_secret_dh_key, crypto_box_SECRETKEYBYTES);
  crypto_scalarmult_base(server->broadcast_dh_pkey_ptr, server->eph_secret_dh_key);
  // Increment round counter
  server->current_round++;
  // Extract secret keys and generate signatures for each client
  for (int i = 0; i < server->num_clients; i++) {
    pkg_extract_client_sk(server, &server->clients[i]);
    pkg_sign_for_client(server, &server->clients[i]);
  }

  //printhex("broadcast msg at srv", server->eph_broadcast_message, broadcast_message_length);
}

int pkg_auth_client(pkg_server *server, pkg_client *client) {

  int s = crypto_sign_verify_detached(client->auth_msg_from_client, server->eph_broadcast_message,
                                      pkg_broadcast_msg_BYTES,
                                      client->long_term_sig_pub_key);

  if (s) {
    printf("%d sig verification failed\n", s);
    return -1;
  }
  byte_t *client_dh_ptr = client->auth_msg_from_client + crypto_sign_BYTES;
  byte_t scalar_mult[crypto_scalarmult_BYTES];
  int suc = crypto_scalarmult(scalar_mult, server->eph_secret_dh_key, client_dh_ptr);
  printf("%d\n", suc);
  crypto_shared_secret(client->eph_symmetric_key,
                       scalar_mult,
                       client_dh_ptr,
                       server->broadcast_dh_pkey_ptr,
                       crypto_generichash_BYTES);
  //printhex("symm key_state", client->eph_symmetric_key, crypto_box_SECRETKEYBYTES);
  //printhex("scalar mult", scalar_mult, crypto_scalarmult_BYTES);
  //printhex("client pub key_state", client_dh_ptr, crypto_box_PUBLICKEYBYTES);
  //printhex("server pub key_state", server->broadcast_dh_pkey_ptr, crypto_generichash_BYTES);
  pkg_encrypt_client_response(server, client);
  //send response
  return 0;
}

void pkg_encrypt_client_response(pkg_server *server, pkg_client *client) {
  //printhex("sig 4 client", client->eph_client_data, bls_signature_length);
  //printhex("sk 4 client,", client->eph_client_data + bls_signature_length, ibe_secret_key_length);
  byte_t *nonce_ptr = client->eph_client_data + g1_elem_compressed_BYTES + g2_elem_compressed_BYTES + crypto_MACBYTES;
  randombytes_buf(nonce_ptr, crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
  crypto_aead_chacha20poly1305_ietf_encrypt(client->eph_client_data,
                                            NULL,
                                            client->eph_client_data,
                                            pkg_auth_res_BYTES,
                                            nonce_ptr,
                                            crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
                                            NULL,
                                            nonce_ptr,
                                            client->eph_symmetric_key);

}

void pkg_new_ibe_keypair(pkg_server *server) {
  element_random(server->eph_secret_key_elem_zr);
  element_pow_zn(server->eph_pub_key_elem_g1, &server->ibe_gen_element_g1, server->eph_secret_key_elem_zr);
  // element_printf("Server Gen: %B\n", &server->ibe_gen_element_g1);
  //element_printf("Server Priv: %B\n", server->eph_secret_key_elem_zr);
  // element_printf("Server IBE Public: %B\n", server->eph_pub_key_elem_g1);
  element_to_bytes_compressed(server->eph_broadcast_message, server->eph_pub_key_elem_g1);
}

void pkg_extract_client_sk(pkg_server *server, pkg_client *client) {
//  element_printf("Extractin SK for client from hash elem: %B\n", client->hashed_id_elem_g2);
  element_pow_zn(client->eph_secret_key_g2, client->hashed_id_elem_g2, server->eph_secret_key_elem_zr);
  element_to_bytes_compressed(client->auth_response_ibe_key_ptr, client->eph_secret_key_g2);
  // element_printf("Client epheremal secret key_state: %B\n", client->eph_secret_key_g2);
}

void pkg_sign_for_client(pkg_server *server, pkg_client *client) {
  serialize_uint32(client->round_signature_message, server->current_round);
  //printhex("srv signing msg", client->round_signature_message, round_sig_message_BYTES);
  bls_sign_message(client->eph_client_data, client->eph_signature_elem_g1,
                   client->eph_sig_hash_elem_g1, client->round_signature_message,
                   pkg_sig_message_BYTES, server->lt_secret_sig_key_elem_zr);
  //element_printf("sig elem from srv: %B\n", client->eph_signature_elem_g1);

}
/*#if 0
int main(int argc, char **argv) {
  pkg_server state;
  uint32_t num_clients = 1;
  pkg_server_init(&state, argv[1]);
  pkg_new_round(&state);
  printhex("response buffer before encryption", (state.clients[0]).eph_client_data, pkg_enc_auth_res_BYTES);
  pkg_encrypt_client_response(&state, &state.clients[0]);
  printhex("response buffer after encryption", (state.clients[0]).eph_client_data, pkg_enc_auth_res_BYTES);
  byte_t buf[pkg_auth_res_BYTES];
  pkg_client *cli = &state.clients[0];
  byte_t *nonce_ptr = cli->eph_client_data + pkg_auth_res_BYTES + crypto_aead_chacha20poly1305_IETF_ABYTES;
  int res = crypto_aead_chacha20poly1305_ietf_decrypt(buf,
                                                      NULL,
                                                      NULL,
                                                      cli->eph_client_data,
                                                      pkg_auth_res_BYTES + crypto_aead_chacha20poly1305_IETF_ABYTES,
                                                      nonce_ptr,
                                                      crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
                                                      nonce_ptr,
                                                      cli->eph_symmetric_key);
  printf("%d\n", res);
  printhex("buffer after decryption", buf, pkg_auth_res_BYTES);
  pkg_server_shutdown(&state);

}
#endif*/


