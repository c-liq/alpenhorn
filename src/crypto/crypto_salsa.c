#include <utils.h>

int crypto_salsa_onion_seal(uint8_t *c,
                            uint64_t *clen_p,
                            const uint8_t *msg,
                            uint64_t msg_len,
                            uint8_t pkeys[][crypto_box_PUBLICKEYBYTES],
                            uint64_t num_keys) {

    if (!c || !msg || msg_len <= 0 || !pkeys || num_keys <= 0) {
        return -1;
    }

    uint8_t *current_offset = c + (crypto_box_SEALBYTES * (num_keys - 1));
    uint64_t current_msg_len = msg_len;
    crypto_box_seal(current_offset, msg, current_msg_len, pkeys[num_keys - 1]);

    for (int i = 2; i <= num_keys; i++) {
        current_msg_len += crypto_box_SEALBYTES;
        current_offset -= crypto_box_SEALBYTES;
        crypto_box_seal(current_offset, current_offset + crypto_box_SEALBYTES, current_msg_len, pkeys[num_keys - i]);
    }

    if (clen_p) {
        *clen_p = msg_len + (crypto_box_SEALBYTES * num_keys);
    }
    return 0;
}

int crypto_salsa_encrypt(uint8_t *c, const uint8_t *m, uint64_t mlen, const uint8_t *key) {
    randombytes_buf(c, crypto_secretbox_NONCEBYTES);
    return crypto_secretbox_easy(c + crypto_secretbox_NONCEBYTES, m, mlen, c, key);
}

int crypto_salsa_decrypt(uint8_t *msg, const uint8_t *c, uint64_t clen, const uint8_t *key) {
    return crypto_secretbox_open_easy(msg, c + crypto_secretbox_NONCEBYTES, clen - crypto_secretbox_NONCEBYTES, c, key);
}
