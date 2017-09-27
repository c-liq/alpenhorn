#include "crypto_salsa.h"

int crypto_salsa_onion_seal(uint8_t *c,
                            unsigned long long *clen_p,
                            uint8_t *msg,
                            uint64_t msg_len,
                            uint8_t pkeys[][crypto_box_PUBLICKEYBYTES],
                            uint64_t num_keys) {

    if (!c || !msg || msg_len <= 0 || !pkeys || num_keys <= 0) {
        return -1;
    }

    uint8_t *current_offset = c + crypto_box_SEALBYTES * (num_keys - 1);
    uint64_t current_msg_len = msg_len;
    crypto_box_seal(current_offset, msg, current_msg_len, pkeys[0]);

    for (int i = 1; i < num_keys; i++) {
        current_msg_len += crypto_box_SEALBYTES;
        current_offset -= crypto_box_SEALBYTES;
        crypto_box_seal(current_offset, current_offset + crypto_box_SEALBYTES,
                        current_msg_len,
                        pkeys[i]);
    }

    if (clen_p) {
        *clen_p = msg_len + (crypto_box_SEALBYTES * num_keys);
    }
    return 0;
}

int crypto_salsa_encrypt(uint8_t *c, uint8_t *m, uint64_t mlen, uint8_t key[crypto_secretbox_KEYBYTES]) {
    randombytes_buf(c, crypto_secretbox_NONCEBYTES);
    return crypto_secretbox_easy(c + crypto_secretbox_NONCEBYTES, m, mlen, c, key);
}

int crypto_salsa_decrypt(uint8_t *msg, uint8_t *c, uint64_t clen, uint8_t key[crypto_secretbox_KEYBYTES]) {
    return crypto_secretbox_open_easy(msg, c + crypto_secretbox_NONCEBYTES, clen, c, key);
}
