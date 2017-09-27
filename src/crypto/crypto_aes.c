#include <sodium.h>

#include "crypto_aes.h"

int crypto_aes256gcm_seal_open(uint8_t *out, uint8_t *c, uint64_t clen, uint8_t *pk, uint8_t *sk) {

  uint8_t nonce[crypto_aead_aes256gcm_NPUBBYTES];
  crypto_seal_nonce(nonce, c, pk, crypto_aead_aes256gcm_NPUBBYTES);

  uint8_t eph_shared[crypto_aead_aes256gcm_KEYBYTES];

  if (crypto_shared_secret(eph_shared, sk, c, c, pk, crypto_aead_aes256gcm_KEYBYTES)) {
	sodium_memzero(eph_shared, sizeof eph_shared);
	return -1;
  }

  int res = crypto_aead_aes256gcm_decrypt(out,
										  NULL,
										  NULL,
										  c + crypto_box_PUBLICKEYBYTES,
										  clen - crypto_box_PUBLICKEYBYTES,
										  NULL,
										  0,
										  nonce,
										  eph_shared);
  sodium_memzero(eph_shared, sizeof eph_shared);
  return res;
}

int crypto_aes256gcm_seal(uint8_t *c, unsigned long long *clen_p, uint8_t *msg, uint64_t msg_len, uint8_t *pk) {
  if (!c || !msg | msg_len <= 0 || !pk) {
	return -1;
  }

  uint8_t eph_pk[crypto_box_PUBLICKEYBYTES];
  uint8_t eph_sk[crypto_box_SECRETKEYBYTES];
  if (crypto_box_keypair(eph_pk, eph_sk)) {
	return -1;
  }

  uint8_t eph_shared[crypto_aead_aes256gcm_KEYBYTES];
  if (crypto_shared_secret(eph_shared, eph_sk, pk, eph_pk, pk, crypto_aead_aes256gcm_KEYBYTES)) {
	sodium_memzero(eph_pk, sizeof eph_pk);
	sodium_memzero(eph_sk, sizeof eph_sk);
	sodium_memzero(eph_shared, sizeof eph_shared);
	return -1;
  }

  memcpy(c, eph_pk, sizeof eph_pk);
  uint8_t nonce[crypto_aead_aes256gcm_NPUBBYTES];
  crypto_seal_nonce(nonce, eph_pk, pk, crypto_aead_aes256gcm_NPUBBYTES);

  int res = crypto_aead_aes256gcm_encrypt(c + crypto_box_PUBLICKEYBYTES,
										  clen_p,
										  msg,
										  msg_len,
										  NULL,
										  0,
										  NULL,
										  nonce,
										  eph_shared);

  if (clen_p) {
	*clen_p += crypto_box_PUBLICKEYBYTES;
  }

  sodium_memzero(eph_sk, sizeof eph_sk);
  sodium_memzero(eph_shared, sizeof eph_shared);
  return res;
}

int crypto_aes256gsm_onion_seal(uint8_t *c,
								unsigned long long *clen_p,
								uint8_t *msg,
								uint64_t msg_len,
								uint8_t *pkeys,
								uint64_t num_keys) {
  if (!c || !msg || msg_len <= 0 || !pkeys || num_keys <= 0) {
	return -1;
  }

  uint64_t current_offset = crypto_aes_SEALBYTES*(num_keys - 1);
  crypto_aes256gcm_seal(c + current_offset, NULL, msg, msg_len, pkeys);

  uint64_t current_msg_len = msg_len;
  uint64_t current_key_offset = 0;

  for (int i = 1; i < num_keys; i++) {
	current_key_offset += crypto_box_PUBLICKEYBYTES;
	current_msg_len += crypto_aes_SEALBYTES;
	current_offset -= crypto_aes_SEALBYTES;
	crypto_aes256gcm_seal(c + current_offset, NULL,
						  c + current_offset + crypto_aes_SEALBYTES,
						  current_msg_len,
						  pkeys + current_key_offset);
  }

  if (clen_p) {
	*clen_p = msg_len + (crypto_aes_SEALBYTES*num_keys);
  }
  return 0;
}


