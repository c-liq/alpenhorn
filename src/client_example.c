#include "client.h"

int main(int argc, char **argv)
{
	#if !USE_PBC
	bn256_init();
	#endif

	int uid;
	if (argc < 2) {
		uid = 0;
	}
	else {
		uid = atoi(argv[1]);
	}

	sign_keypair sig_keys;

	sodium_hex2bin(sig_keys.public_key, crypto_sign_PUBLICKEYBYTES, (char *) user_publickeys[uid],
	               64, NULL, NULL, NULL);
	sodium_hex2bin(sig_keys.secret_key, crypto_sign_SECRETKEYBYTES, (char *) user_lt_secret_sig_keys[uid],
	               128, NULL, NULL, NULL);


	client_s *c = client_alloc(user_ids[uid], &sig_keys);
	client_run(c);

	int running = 1;
	char buf[user_id_BYTES + 1];
	while (running) {
		memset(buf, 0, sizeof buf);
		fgets(buf, 3, stdin);
		size_t id_len;
		switch (buf[0]) {
		case ADD_FRIEND:
			printf("Enter friend's user ID: ");
			fflush(stdout);
			fflush(stdin);
			fgets(buf, sizeof buf, stdin);
			id_len = strlen(buf) - 1;
			if (buf[id_len] != '\0') {
				buf[id_len] = '\0';
			}
			client_add_friend(c, (uint8_t *) buf);
			break;
		case CONFIRM_FRIEND:
			printf("Enter friend's user ID: ");
			fflush(stdout);
			fflush(stdin);
			fgets(buf, sizeof buf, stdin);
			id_len = strlen(buf) - 1;
			if (buf[id_len] == '\n') {
				buf[id_len] = '\0';
			}
			client_confirm_friend(c, (uint8_t *) buf);
			fflush(stdin);
			break;
		case DIAL_FRIEND: {
			printf("Enter friend's user ID: ");
			fflush(stdout);
			fgets(buf, sizeof buf, stdin);
			fflush(stdin);
			id_len = strlen(buf) - 1;
			if (buf[id_len] == '\n') {
				buf[id_len] = '\0';
			}
			printf("Enter intent: ");
			fflush(stdout);
			char intent_buf[4];
			fgets(intent_buf, sizeof intent_buf, stdin);
			int i = atoi(intent_buf);
			if (i > c->num_intents - 1 || i < 0) {
				fprintf(stderr, "Invalid intent\n");
				break;
			}
			client_call_friend(c, (uint8_t *) buf, (uint32_t) i);
			fflush(stdin);
			break;
		}
		case PRINT_KW_TABLE:
			kw_print_table(&c->keywheel);
			break;
		default:
			if (buf[0] == 'Q') {
				running = 0;
			}
			fflush(stdin);
			break;
		}
	}
}
