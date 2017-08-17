#include <config.h>

static const uint8_t first_names[18][user_id_BYTES] = {
	"chris", "alice", "bob", "eve", "charlie",
	"jim", "megan", "john", "jill", "steve", "andy", "bill", "dave", "mike", "katy", "tess", "caroline", "mark"};

struct user
{
	char uid[user_id_BYTES];
	char public_key[crypto_sign_PUBLICKEYBYTES * 2 + 1];
	char secret_key[crypto_sign_SECRETKEYBYTES * 2 + 1];
};

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "invalid arguments\n");
		exit(EXIT_FAILURE);
	}
	FILE *out_file = fopen("users", "wb");
	if (!out_file) {
		fprintf(stderr, "couldn't open file\n");
		exit(EXIT_FAILURE);
	}

	long num_users = strtol(argv[1], NULL, 10);

	for (long i = 0; i < num_users; i++) {
		uint8_t pk_binary[crypto_sign_PUBLICKEYBYTES];
		uint8_t sk_binary[crypto_sign_SECRETKEYBYTES];
		crypto_sign_keypair(pk_binary, sk_binary);
		char user_id[user_id_BYTES];
		sodium_memzero(user_id, user_id_BYTES);
		sprintf(user_id, "user%ld", i);
		fwrite(user_id, user_id_BYTES, 1, out_file);
		fwrite(pk_binary, sizeof pk_binary, 1, out_file);
		fwrite(sk_binary, sizeof sk_binary, 1, out_file);
	}
	fclose(out_file);

}
