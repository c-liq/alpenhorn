#include "crypto_chacha.h"

int crypto_xchacha20_onion_seal(uint8_t *c,
								unsigned long long *clen_p,
								uint8_t *msg,
								uint64_t msg_len,
								uint8_t *pkeys,
								uint64_t num_keys) {

  if (!c || !msg || msg_len <= 0 || !pkeys || num_keys <= 0) {
	return -1;
  }

  uint64_t current_offset = crypto_box_SEALBYTES*(num_keys - 1);
  crypto_box_seal(c + current_offset, msg, msg_len, pkeys);

  uint64_t current_msg_len = msg_len;
  uint64_t current_key_offset = 0;

  for (int i = 1; i < num_keys; i++) {
	current_key_offset += crypto_box_PUBLICKEYBYTES;
	current_msg_len += crypto_box_SEALBYTES;
	current_offset -= crypto_box_SEALBYTES;
	crypto_box_seal(c + current_offset, c + current_offset + crypto_box_SEALBYTES,
					current_msg_len,
					pkeys + current_key_offset);
  }

  if (clen_p) {
	*clen_p = msg_len + (crypto_box_SEALBYTES*num_keys);
  }
  return 0;
}
