#include "client.h"

void print_friend_request(friend_request_s *req)
{
	if (!req)
		return;

	printf("------------\n");
	printf("Sender id: %s\n", req->user_id);
	printhex("Sender DH key", req->dh_pk, crypto_pk_BYTES);
	printhex("Sender signing key: ", req->lt_sig_key, crypto_sign_PUBLICKEYBYTES);
	printf("Dialling round: %ld\n", req->dialling_round);
	printf("------------\n");
}

void print_call(incoming_call_s *call)
{
	if (!call)
		return;

	printf("------------\nIncoming call\n------------\n");
	printf("User ID: %s\n", call->user_id);
	printf("Round: %ld\n", call->round);
	printf("Intent: %d\n", call->intent);
	printhex("Session Key", call->session_key, crypto_ghash_BYTES);
	printf("------------\n");
}


void run_registration(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "Invalid number of arguments for registration\n");
		exit(EXIT_FAILURE);
	}

	size_t id_length = strlen(argv[2]);
	if (id_length > 60 || id_length < 2) {
		fprintf(stderr, "Invalid username: too long or too short\n");
	}

	sign_keypair keypair;
	client_register(&keypair, argv[2]);

}

void run_main(int argc, char **argv)
{
	if (argc != 5) {
		fprintf(stderr, "Usage: client_example [1|2|3] \n");
		exit(EXIT_FAILURE);
	}

	size_t id_length = strlen(argv[2]);
	if (id_length > 60 || id_length < 2) {
		fprintf(stderr, "Invalid username: too long or too short\n");
	}

	size_t sk_hex_length = strlen(argv[3]);
	size_t pk_hex_length = strlen(argv[4]);

	if (sk_hex_length != crypto_sign_SECRETKEYBYTES * 2 || pk_hex_length != crypto_sign_PUBLICKEYBYTES * 2) {
		fprintf(stderr, "invalid key\n");
		exit(EXIT_FAILURE);
	}

	sign_keypair sig_keys;

	sodium_hex2bin(sig_keys.public_key, crypto_sign_PUBLICKEYBYTES, argv[4],
	               64, NULL, NULL, NULL);
	sodium_hex2bin(sig_keys.secret_key, crypto_sign_SECRETKEYBYTES, argv[3],
	               128, NULL, NULL, NULL);


	client_s *c = client_alloc((uint8_t *) argv[2], &sig_keys, print_call, print_friend_request, print_friend_request);
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
			client_call_friend(c, (uint8_t *) buf, (uint64_t) i);
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

void run_confirm_registration(int argc, char **argv)
{
	if (argc != 4) {
		fprintf(stderr, "Invalid number of arguments for registration\n");
		exit(EXIT_FAILURE);
	}

	size_t id_length = strlen(argv[2]);
	if (id_length > 60 || id_length < 2) {
		fprintf(stderr, "Invalid username: too long or too short\n");
		exit(EXIT_FAILURE);
	}

	size_t sk_hex_length = strlen(argv[3]);
	if (sk_hex_length != crypto_sign_SECRETKEYBYTES * 2) {
		fprintf(stderr, "Invalid username: too long or too short\n");
		exit(EXIT_FAILURE);
	}

	uint8_t sk_bytes[crypto_sign_SECRETKEYBYTES];
	sodium_hex2bin(sk_bytes, crypto_sign_SECRETKEYBYTES, argv[3], sk_hex_length, NULL, NULL, NULL);

	byte_buffer_s buffer;
	int res = byte_buffer_init(&buffer, 2000);
	if (res) {
		fprintf(stderr, "error initing byte buffer\n");
	}

	for (uint64_t i = 0; i < num_pkg_servers; i++) {
		uint64_t msg_size = sizeof_serialized_bytes(crypto_ghash_BYTES);
		char msg_hex[msg_size];
		printf("Enter value from pkg %u: ", i);
		fgets(msg_hex, sizeof msg_hex, stdin);
		fflush(stdin);
		size_t len = strlen(msg_hex);
		if (len != crypto_ghash_BYTES * 2) {
			fprintf(stderr, "invalid nonce hex entered\n");
			exit(EXIT_FAILURE);
		}
		byte_buffer_put(&buffer, (uint8_t *) msg_hex, crypto_ghash_BYTES * 2);
	}

	res = client_confirm_registration((uint8_t *) argv[2], sk_bytes, buffer.data);
	fprintf(stderr, "MOOOOOOOOOOOOOOOOOOOOOOO\n");

	if (res) {
		fprintf(stderr, "ERORROROROR\n");
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "MOOOOOOOOOOOOOOOOOOOOOOO\n");

	exit(EXIT_SUCCESS);

}

int main(int argc, char **argv)
{
	#if !USE_PBC
	bn256_init();
	#endif

	int uid;
	if (argc < 2) {
		fprintf(stderr, "Usage: \n");
		exit(EXIT_FAILURE);
	}

	switch (atoi(argv[1])) {
	case 1:
		run_main(argc, argv);
		break;
	case 2:
		run_registration(argc, argv);
		break;
	case 3:
		run_confirm_registration(argc, argv);
		break;
	default:
		fprintf(stderr, "Invalid option\n");
		exit(EXIT_FAILURE);
	}

}
