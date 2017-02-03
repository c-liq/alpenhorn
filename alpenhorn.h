//
// Created by chris on 26/01/17.
//

#ifndef ALPENHORN_ALPENHORN_H
#define ALPENHORN_ALPENHORN_H
#include <stddef.h>
#define pkg_eph_pub_key_BYTES 32U
#define af_email_bytes 64U
#define af_sig_bytes 32U
#define af_request_ABYTES (crypto_aead_chacha20poly1305_IETF_NPUBBYTES + crypto_aead_chacha20poly1305_IETF_KEYBYTES + crypto_aead_chacha20poly1305_IETF_ABYTES)
#define af_request_BYTES af_email_bytes + af_sig_bytes + af_sig_bytes + crypto_box_PUBLICKEYBYTES
typedef unsigned char byte_t;

void decrypt_request(byte_t *c, size_t len);
void crypto_shared_secret(byte_t *shared_secret, byte_t *scalar_mult, byte_t *client_pub, byte_t *server_pub);

#endif //ALPENHORN_ALPENHORN_H
