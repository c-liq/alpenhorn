#include <bn256_ibe.h>

#include "greatest.h"

SUITE (suite);

TEST test_bn256_ibe_crypto(void)
{
	bn256_ibe_master_kp kp;
	bn256_ibe_master_keypair(&kp);

	uint8_t id1_str[] = "alice@mail.com";
	uint8_t id2_str[] = "bob@mail2.com";

	struct ibe_identity id1, id2;
	bn256_ibe_keygen(&id1, id1_str, sizeof id1_str, kp.secret_key);
	bn256_ibe_keygen(&id2, id2_str, sizeof id2_str, kp.secret_key);

	uint8_t msg[] = "test message";
	uint32_t msg_len = sizeof msg;

	uint8_t ciphertext[1024];
	uint8_t decrypt_buffer[1024];

	ssize_t ciphertext_length = bn256_ibe_encrypt(ciphertext, msg, msg_len, kp.public_key, id2_str, sizeof id2_str);
	uint32_t expected_ciphertext_length = msg_len + bn256_ibe_oh;

		ASSERT_EQ_FMT(ciphertext_length, expected_ciphertext_length, "a: %u | b: %u\n");

	int res =
		bn256_ibe_decrypt(decrypt_buffer, ciphertext, ciphertext_length, id2.serialized_public_key, id2.secret_key);
	if (res) {
			FAIL();
	}
	else {
			PASS();
	}
}

GREATEST_MAIN_DEFS();
int main(int argc, char **argv)
{
	GREATEST_MAIN_BEGIN();
	bn256_init();
	int rs = sodium_init();
	if (rs) { exit(EXIT_FAILURE); };

		RUN_TEST(test_bn256_ibe_crypto);

	GREATEST_MAIN_END();
}
