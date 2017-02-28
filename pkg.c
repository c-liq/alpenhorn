#include <pbc/pbc.h>
#include <sodium.h>
#include <string.h>
#include <pbc/pbc_test.h>
#include "pbc_sign.h"
#include "pkg.h"
#include "net_common.h"

int pkg_server_init(pkg_server *server, uint32_t server_id) {
  pairing_init_set_str(server->pairing, pbc_params);
  server->current_round = 0;
  server->num_clients = 10;
  server->srv_id = server_id;
  pairing_ptr pairing = server->pairing;
  // Initialise gen_elem element + long term ibe public/secret signature keypair
  element_init(&server->bls_gen_elem_g2, pairing->G2);
  element_init(&server->ibe_gen_elem_g1, pairing->G1);
  element_set_str(&server->ibe_gen_elem_g1, ibe_generator, 10);
  element_set_str(&server->bls_gen_elem_g2, bls_generator, 10);
  element_init(server->lt_sig_sk_elem, pairing->Zr);
  element_set_str(server->lt_sig_sk_elem, sk[server_id], 10);
  element_init(server->lt_sig_pk_elem, pairing->G2);
  element_set_str(server->lt_sig_pk_elem, pk[server_id], 10);
  server->broadcast_dh_pkey_ptr = server->eph_broadcast_message + net_batch_prefix + g1_elem_compressed_BYTES;
  // Initialise elements for epheremal IBE key_state generation and create an initial keypair
  element_init(server->eph_secret_key_elem_zr, pairing->Zr);
  element_init(server->eph_pub_key_elem_g1, pairing->G1);
  // Allocate and initialise clients
  server->clients = malloc(sizeof(pkg_client) * server->num_clients);
  for (int i = 0; i < server->num_clients; i++) {
    memset(&server->clients[i], 0, sizeof(pkg_client));
    pkg_client_init(&server->clients[i], server, user_ids[i], user_lt_pub_sig_keys[i]);
  }
  pkg_new_round(server);
  return 0;
}

int pkg_client_lookup (pkg_server *server, byte_t *user_id)
{
  int index = -1;
  for (int i = 0; i < server->num_clients; i++)
    {
      if (!(strncmp((char *) user_id, (char *) server->clients[i].user_id, user_id_BYTES)))
        {
          index = i;
          break;
        }
    }
  return index;
}

void pkg_client_init(pkg_client *client, pkg_server *server, const byte_t *user_id, const byte_t *lt_sig_key) {

  client->auth_response_ibe_key_ptr = client->eph_client_data + net_batch_prefix + g1_elem_compressed_BYTES;
  serialize_uint32 (client->eph_client_data, PKG_AUTH_RES_MSG);
  memcpy(client->user_id, user_id, user_id_BYTES);
  sodium_hex2bin(client->long_term_sig_pub_key,
                 crypto_sign_PUBLICKEYBYTES,
                 (char *) lt_sig_key,
                 crypto_sign_PUBLICKEYBYTES * 2,
                 NULL,
                 NULL,
                 NULL);
  memcpy(client->rnd_sig_msg + dialr_BYTES, client->user_id, user_id_BYTES);
  memcpy(client->rnd_sig_msg + dialr_BYTES + user_id_BYTES,
         client->long_term_sig_pub_key, crypto_sign_PUBLICKEYBYTES);

  element_init(client->eph_secret_key_g2, server->pairing->G2);
  element_init(client->eph_signature_elem_g1, server->pairing->G1);
  element_init(client->eph_sig_hash_elem_g1, server->pairing->G1);
  element_init(client->hashed_id_elem_g2, server->pairing->G2);

  byte_t id_hash[crypto_generichash_BYTES];
  crypto_generichash(id_hash, crypto_generichash_BYTES, client->user_id, user_id_BYTES, NULL, 0);
  element_from_hash(client->hashed_id_elem_g2, id_hash, crypto_generichash_BYTES);
}

void pkg_server_shutdown(pkg_server *server) {
  element_clear(server->lt_sig_sk_elem);
  element_clear(server->lt_sig_pk_elem);
  element_clear(server->eph_pub_key_elem_g1);
  element_clear(server->eph_secret_key_elem_zr);
  element_clear(&server->bls_gen_elem_g2);
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
  serialize_uint32 (server->eph_broadcast_message, PKG_BR_MSG);
  serialize_uint32 (server->eph_broadcast_message + sizeof (u32), server->current_round);
  // Extract secret keys and generate signatures for each client_s
  for (int i = 0; i < server->num_clients; i++) {
    pkg_extract_client_sk(server, &server->clients[i]);
    pkg_sign_for_client(server, &server->clients[i]);
  }
}

int pkg_auth_client(pkg_server *server, pkg_client *client) {
  int s = crypto_sign_verify_detached(client->auth_msg_from_client,
                                      server->eph_broadcast_message + net_batch_prefix,
                                      pkg_broadcast_msg_BYTES,
                                      client->long_term_sig_pub_key);

  if (s) {
      //printhex("pkg sig", client->auth_msg_from_client, crypto_sign_BYTES);
      fprintf (stderr, "failed to verify signature during client auth\n");
    return -1;
  }
  byte_t *client_dh_ptr = client->auth_msg_from_client + crypto_sign_BYTES;
  byte_t scalar_mult[crypto_scalarmult_BYTES];
  int suc = crypto_scalarmult(scalar_mult, server->eph_secret_dh_key, client_dh_ptr);
  if (suc)
    {
      fprintf (stderr, "scalarmult error\n");
      return -1;
    }
  crypto_shared_secret(client->eph_symmetric_key,
                       scalar_mult,
                       client_dh_ptr,
                       server->broadcast_dh_pkey_ptr,
                       crypto_generichash_BYTES);
  pkg_encrypt_client_response(server, client);
  //send response*/
  return 0;
}

void pkg_encrypt_client_response(pkg_server *server, pkg_client *client) {
  //printhex("sig 4 client_s", client_s->eph_client_data, bls_signature_length);
  //printhex("sk 4 client_s,", client_s->eph_client_data + bls_signature_length, ibe_secret_key_length);
  serialize_uint32 (client->eph_client_data + sizeof (u32), server->current_round);
  byte_t *nonce_ptr = client->eph_client_data + net_batch_prefix + g1_elem_compressed_BYTES + g2_elem_compressed_BYTES
                      + crypto_MACBYTES;
  randombytes_buf(nonce_ptr, crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
  crypto_aead_chacha20poly1305_ietf_encrypt (client->eph_client_data + net_batch_prefix,
                                             NULL,
                                             client->eph_client_data + net_batch_prefix,
                                             pkg_auth_res_BYTES,
                                             nonce_ptr,
                                             crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
                                             NULL,
                                             nonce_ptr,
                                             client->eph_symmetric_key);

}

void pkg_new_ibe_keypair(pkg_server *server) {
  element_random(server->eph_secret_key_elem_zr);
  element_pow_zn(server->eph_pub_key_elem_g1, &server->ibe_gen_elem_g1, server->eph_secret_key_elem_zr);
  element_to_bytes_compressed (server->eph_broadcast_message + net_batch_prefix, server->eph_pub_key_elem_g1);

}

void pkg_extract_client_sk(pkg_server *server, pkg_client *client) {
  element_pow_zn(client->eph_secret_key_g2, client->hashed_id_elem_g2, server->eph_secret_key_elem_zr);
  element_to_bytes_compressed(client->auth_response_ibe_key_ptr, client->eph_secret_key_g2);
}

void pkg_sign_for_client(pkg_server *server, pkg_client *client) {
  serialize_uint32(client->rnd_sig_msg, server->current_round);
  bls_sign_message (client->eph_client_data + net_batch_prefix, client->eph_signature_elem_g1,
                    client->eph_sig_hash_elem_g1, client->rnd_sig_msg,
                    pkg_sig_message_BYTES, server->lt_sig_sk_elem);

}


