#include <sodium.h>
#include <string.h>
#include "client.h"
#include "ibe.h"
#include "xxHash-master/xxhash.h"
#include "pbc/pbc_test.h"


uint32_t af_calc_mailbox_num(client *cli_st) {
  uint64_t hash = XXH64(cli_st->friend_request_id, user_id_BYTES, 0);
  return (uint32_t) hash % cli_st->mailbox_count;
}

int dial_call_friend(client *client, byte_t *user_id, uint32_t intent) {
  //verify userid string
  uint64_t mailbox = XXH64(user_id, user_id_BYTES, 0);
  serialize_uint32(client->dial_request_buf, (uint32_t) mailbox);
  int res = kw_generate_dialling_token(client->dial_request_buf + mailbox_BYTES, &client->keywheel, user_id, intent);
  if (res) {
    fprintf(stderr, "could not create dialling token for %s\n", user_id);
    return -1;
  }

  res = kw_generate_session_key(client->session_key_buf, &client->keywheel, user_id);
  if (res) {
    fprintf(stderr, "could not generate session key for %s\n", user_id);
  }

  return 0;
}

void af_add_friend(client *client, char *user_id) {
  // verify userid string
  memcpy(client->friend_request_id, user_id, user_id_BYTES);
  af_create_request(client);
}

void af_create_request(client *client) {
  byte_t *dialling_round_ptr =
      client->friend_request_buf + mailbox_BYTES + g1_elem_compressed_BYTES + crypto_ghash_BYTES + crypto_NBYTES;
  byte_t *user_id_ptr = dialling_round_ptr + dialling_round_BYTES;
  byte_t *dh_pub_ptr = user_id_ptr + user_id_BYTES;
  byte_t *lt_sig_key_ptr = dh_pub_ptr + crypto_box_PUBLICKEYBYTES;
  byte_t *personal_sig_ptr = lt_sig_key_ptr + crypto_sign_PUBLICKEYBYTES;
  byte_t *multisig_ptr = personal_sig_ptr + crypto_sign_BYTES;

  // Generate a DH keypair that forms the basis of the shared keywheel state with the friend being added
  byte_t dh_secret_key[crypto_box_SECRETKEYBYTES];
  crypto_box_keypair(dh_pub_ptr, dh_secret_key);
  // Both parties need to agree on the dialling round to synchronise their keywheel
  uint32_t dialling_round = client->dialling_round + 2;
  // Serialise userid/dial round/signature key
  memcpy(user_id_ptr, client->user_id, user_id_BYTES);
  serialize_uint32(dialling_round_ptr, dialling_round);
  memcpy(lt_sig_key_ptr, client->lt_pub_sig_key, crypto_sign_PUBLICKEYBYTES);
  // Sign our information with our LT signing key as a second/backup verification for recipient
  crypto_sign_detached(personal_sig_ptr, NULL, dialling_round_ptr,
                       dialling_round_BYTES + user_id_BYTES + crypto_box_PUBLICKEYBYTES,
                       client->lt_secret_sig_key);
  // Also include the multisignature from PKG servers, primary source of verification
  element_to_bytes_compressed(multisig_ptr, &client->pkg_multisig_combined_g1);
  // Encrypt the request using IBE
  ibe_encrypt(client->friend_request_buf + mailbox_BYTES, dialling_round_ptr, af_request_BYTES,
              &client->pkg_eph_pub_combined_g1, &client->ibe_gen_element_g1,
              client->friend_request_id, user_id_BYTES, &client->pairing);
  // Only information identifying the destination of a request, the mailbox no. of the recipient
  uint32_t mn = af_calc_mailbox_num(client);
  serialize_uint32(client->friend_request_buf, mn);
  // Encrypt the request in layers ready for the mixnet

  af_onion_encrypt_request(client);
}

int af_decrypt_request(client *client, byte_t *request_buf) {
  byte_t request_buffer[af_request_BYTES];
  int res;
  res = ibe_decrypt(request_buffer, request_buf, af_request_BYTES + crypto_MACBYTES,
                    &client->pkg_ibe_secret_combined_g2, &client->pairing);

  if (res) {
    fprintf(stderr, "%s: ibe decryption failure\n", client->user_id);
    return -1;
  }

  byte_t *dialling_round_ptr = request_buffer;
  byte_t *user_id_ptr = dialling_round_ptr + dialling_round_BYTES;
  byte_t *dh_pub_ptr = user_id_ptr + user_id_BYTES;
  byte_t *lt_sig_key_ptr = dh_pub_ptr + crypto_box_PUBLICKEYBYTES;
  byte_t *personal_sig_ptr = lt_sig_key_ptr + crypto_sign_PUBLICKEYBYTES;
  byte_t *multisig_ptr = personal_sig_ptr + crypto_sign_BYTES;

  // Reconstruct the message signed by the PKG's so we can verify the signature
  byte_t multisig_message[pkg_sig_message_BYTES];
  serialize_uint32(multisig_message, client->af_round);
  memcpy(multisig_message + dialling_round_BYTES, user_id_ptr, user_id_BYTES);
  memcpy(multisig_message + dialling_round_BYTES + user_id_BYTES, lt_sig_key_ptr, crypto_sign_PUBLICKEYBYTES);

  element_t sig_verify_elem, hash_elem;
  element_init(sig_verify_elem, client->pairing.G1);
  element_init(hash_elem, client->pairing.G1);

  res = bls_verify_signature(sig_verify_elem,
                             hash_elem,
                             multisig_ptr,
                             multisig_message,
                             pkg_sig_message_BYTES,
                             &client->pkg_lt_sig_keys_combined,
                             &client->bls_gen_element_g2,
                             &client->pairing);

  if (res) {
    printf("Multisig verification failed\n");
    return -1;
  }

  res = crypto_sign_verify_detached(personal_sig_ptr, dialling_round_ptr,
                                    sizeof(uint32_t) + user_id_BYTES + crypto_sign_PUBLICKEYBYTES,
                                    lt_sig_key_ptr);

  if (res) {
    printf("Personal sig verification failed\n");
    return -1;
  }
  // Both signatures verified, copy the relevant information into a new structure
  // Ultimately to be passed on to the higher level application
  friend_request *new_req = malloc(sizeof(friend_request));
  memcpy(new_req->user_id, user_id_ptr, user_id_BYTES);
  memcpy(new_req->dh_public_key, dh_pub_ptr, crypto_box_PUBLICKEYBYTES);
  memcpy(new_req->lt_sig_key, lt_sig_key_ptr, crypto_sign_PUBLICKEYBYTES);
  new_req->dialling_round = deserialize_uint32(dialling_round_ptr);
  print_friend_request(new_req);

  return 0;
}

int af_create_pkg_auth_request(client *client) {
  byte_t *cli_sig_ptr;
  byte_t *cli_pub_key_ptr;
  byte_t *pkg_pub_key_ptr;
  byte_t *symmetric_key_ptr;

  for (int i = 0; i < num_pkg_servers; i++) {
    cli_pub_key_ptr = client->pkg_auth_requests[i] + crypto_sign_BYTES;
    cli_sig_ptr = client->pkg_auth_requests[i];
    pkg_pub_key_ptr = client->pkg_broadcast_msgs[i] + g1_elem_compressed_BYTES;
    symmetric_key_ptr = client->pkg_eph_symmetric_keys[i];

    crypto_sign_detached(cli_sig_ptr, NULL, client->pkg_broadcast_msgs[i],
                         pkg_broadcast_msg_BYTES, client->lt_secret_sig_key);

    byte_t secret_key[crypto_box_SECRETKEYBYTES];
    byte_t scalar_mult[crypto_scalarmult_BYTES];
    randombytes_buf(secret_key, crypto_box_SECRETKEYBYTES);

    crypto_box_keypair(cli_pub_key_ptr, secret_key);
    if (crypto_scalarmult(scalar_mult, secret_key, pkg_pub_key_ptr)) {
      fprintf(stderr, "Scalar mult error while authing with PKG's\n");
      return -1;
    }
    crypto_shared_secret(symmetric_key_ptr, scalar_mult, cli_pub_key_ptr, pkg_pub_key_ptr, crypto_box_SECRETKEYBYTES);
  }

  pbc_sum_bytes_G1_compressed(&client->pkg_eph_pub_combined_g1, client->pkg_broadcast_msgs[0],
                              num_pkg_servers, &client->pairing);
  return 0;
}

int af_decrypt_auth_responses(client *client) {
  byte_t *auth_response;
  byte_t *nonce_ptr;

  for (int i = 0; i < num_pkg_servers; i++) {

    auth_response = client->pkg_auth_responses[i];
    nonce_ptr = auth_response + pkg_auth_res_BYTES + crypto_MACBYTES;
    int res = crypto_aead_chacha20poly1305_ietf_decrypt(auth_response, NULL, NULL, auth_response,
                                                        pkg_auth_res_BYTES + crypto_MACBYTES,
                                                        nonce_ptr, crypto_NBYTES,
                                                        nonce_ptr, client->pkg_eph_symmetric_keys[i]);
    if (res) {
      fprintf(stderr, "%s: Decryption failure\n", client->user_id);
      return -1;
    }
    memcpy(client->pkg_eph_ibe_sk_fragments_g2[i], auth_response + g1_elem_compressed_BYTES, g2_elem_compressed_BYTES);
  }
  return 0;
}

int af_process_auth_responses(client *client) {
  pbc_sum_bytes_G1_compressed(&client->pkg_multisig_combined_g1, client->pkg_auth_responses[0],
                              num_pkg_servers, &client->pairing);
  pbc_sum_bytes_G2_compressed(&client->pkg_ibe_secret_combined_g2, client->pkg_eph_ibe_sk_fragments_g2[0],
                              num_pkg_servers, &client->pairing);
  return 0;
}

int af_onion_encrypt_request(client *cli_st) {
  for (uint32_t i = 0; i < num_mix_servers; i++) {
    int res = add_onion_layer(cli_st, i);
    if (res)
      return -1;
  }
  return 0;
}

int add_onion_layer(client *cli_st, uint32_t srv_id) {
  // Add another layer of encryption to the request, append public DH key_state for server + nonce in clear (but authenticated)
  uint32_t message_length = af_ibeenc_request_BYTES + mailbox_BYTES + (onion_layer_BYTES * srv_id);
  byte_t *message_end_ptr = cli_st->friend_request_buf + message_length;
  byte_t *dh_pub_ptr = message_end_ptr + crypto_MACBYTES;
  byte_t *nonce_ptr = dh_pub_ptr + crypto_box_PUBLICKEYBYTES;
  byte_t *dh_mix_pub = cli_st->mix_eph_pub_keys[num_mix_servers - 1 - srv_id];

  byte_t dh_secret[crypto_box_SECRETKEYBYTES];
  byte_t scalar_mult[crypto_scalarmult_BYTES];
  byte_t shared_secret[crypto_ghash_BYTES];
  randombytes_buf(dh_secret, crypto_box_SECRETKEYBYTES);
  crypto_scalarmult_base(dh_pub_ptr, dh_secret);

  int res = crypto_scalarmult(scalar_mult, dh_secret, dh_mix_pub);
  if (res) {
    fprintf(stderr, "Scalarmult error while oniong encrypting friend request\n");
    return -1;
  }
  crypto_shared_secret(shared_secret, scalar_mult, dh_pub_ptr, dh_mix_pub, crypto_ghash_BYTES);
  randombytes_buf(nonce_ptr, crypto_NBYTES);
  crypto_aead_chacha20poly1305_ietf_encrypt(cli_st->friend_request_buf, NULL, cli_st->friend_request_buf,
                                            message_length, dh_pub_ptr, crypto_box_PUBLICKEYBYTES + crypto_NBYTES,
                                            NULL, nonce_ptr, shared_secret);
  return 0;
};

void client_fill(client *client, const byte_t *user_id, const byte_t *ltp_key, const byte_t *lts_key) {
  memset(client->friend_request_buf, 0, sizeof client->friend_request_buf);
  client->mailbox_count = 1;
  client->dialling_round = 1;
  memcpy(client->user_id, user_id, user_id_BYTES);
  pairing_init_set_str(&client->pairing, pbc_params);
  element_init(&client->pkg_multisig_combined_g1, client->pairing.G1);
  element_init(&client->pkg_ibe_secret_combined_g2, client->pairing.G2);
  element_init(&client->pkg_eph_pub_combined_g1, client->pairing.G1);
  element_init(&client->pkg_friend_elem, client->pairing.G2);
  element_init(&client->ibe_gen_element_g1, client->pairing.G1);
  element_init(&client->bls_gen_element_g2, client->pairing.G2);
  element_set_str(&client->ibe_gen_element_g1, ibe_generator, 10);
  element_set_str(&client->bls_gen_element_g2, bls_generator, 10);
  element_init(&client->pkg_lt_sig_keys_combined, client->pairing.G2);
  element_s pkg_sig_keys[num_pkg_servers];
  byte_t pkg_sig_key_bytes[num_pkg_servers][g2_elem_compressed_BYTES];
  for (int i = 0; i < num_pkg_servers; i++) {
    element_init(&pkg_sig_keys[i], client->pairing.G2);
    element_set_str(&pkg_sig_keys[i], pk[i], 10);
    element_to_bytes_compressed(pkg_sig_key_bytes[i], &pkg_sig_keys[i]);
  }
  pbc_sum_bytes_G2_compressed(&client->pkg_lt_sig_keys_combined,
                              pkg_sig_key_bytes[0],
                              num_pkg_servers,
                              &client->pairing);
  client->af_round = 1;
  sodium_hex2bin(client->lt_pub_sig_key,
                 crypto_sign_PUBLICKEYBYTES,
                 (char *) ltp_key,
                 64,
                 NULL,
                 NULL,
                 NULL);

  sodium_hex2bin(client->lt_secret_sig_key,
                 crypto_sign_SECRETKEYBYTES,
                 (char *) lts_key,
                 128,
                 NULL,
                 NULL,
                 NULL);

  kw_table_init(&client->keywheel);
}

client *client_init(int argc, char **argv) {
  client *cli_state = malloc(sizeof(client));
  pbc_demo_pairing_init(&cli_state->pairing, argc, argv);
  return cli_state;
};

void print_friend_request(friend_request *req) {
  printf("Sender id: %s\n", req->user_id);
  printhex("Sender DH key_state", req->dh_public_key, crypto_box_PUBLICKEYBYTES);
  printhex("Sender signing key_state: ", req->lt_sig_key, crypto_sign_PUBLICKEYBYTES);
  printf("Dialling round: %d\n", req->dialling_round);
}
