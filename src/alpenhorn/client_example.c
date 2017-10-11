#include "alpenhorn/client.h"

void print_friend_request(friend_request *req)
{
	if (!req)
		return;

	printf("------------\n");
	printf("Sender id: %s\n", req->user_id);
    printhex("Sender DH key", req->dh_pk, crypto_box_PKBYTES);
    printhex("Sender signing key: ", req->sig_pk, crypto_sign_PUBLICKEYBYTES);
	printf("Dialling round: %ld\n", req->dialling_round);
	printf("------------\n");
}

void print_sent_request(friend_request *req) {
    printf("Sent friend request to %s\n", req->user_id);
}

void print_call(call *call)
{
	if (!call)
		return;

	printf("------------\nIncoming call\n------------\n");
	printf("User ID: %s\n", call->user_id);
	printf("Round: %ld\n", call->round);
    printf("Intent: %ld\n", call->intent);
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

    u8 sig_pk[crypto_sign_PUBLICKEYBYTES];
    u8 sig_sk[crypto_sign_SECRETKEYBYTES];
    alp_register(argv[2], sig_pk, sig_sk);

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

  size_t sk_hex_length = strlen(argv[4]);
  size_t pk_hex_length = strlen(argv[3]);

	if (sk_hex_length != crypto_sign_SECRETKEYBYTES * 2 || pk_hex_length != crypto_sign_PUBLICKEYBYTES * 2) {
	  fprintf(stderr, "invalid key %ld %ld\n", sk_hex_length, pk_hex_length);
		exit(EXIT_FAILURE);
	}

    u8 sig_pk[crypto_sign_PUBLICKEYBYTES];
    u8 sig_sk[crypto_sign_SECRETKEYBYTES];

    sodium_hex2bin(sig_pk, crypto_sign_PUBLICKEYBYTES, argv[3],
				 64, NULL, NULL, NULL);
    sodium_hex2bin(sig_sk, crypto_sign_SECRETKEYBYTES, argv[4],
                   128, NULL, NULL, NULL);

    client_event_fns fns;
    fns.call_sent = print_call;
    fns.call_received = print_call;
    fns.friend_request_sent = print_friend_request;
    fns.friend_request_confirmed = print_friend_request;
    fns.friend_request_received = print_friend_request;
    client *c = client_alloc((uint8_t *) argv[2], &fns, sig_pk, sig_sk);
	client_run(c);

	int running = 1;
	char buf[user_id_BYTES + 1];
	while (running) {
		memset(buf, 0, sizeof buf);
		fgets(buf, 3, stdin);
		size_t id_len;
		switch (buf[0]) {
            case '0':
			printf("Enter friend's user ID: ");
			fflush(stdout);
			fflush(stdin);
			fgets(buf, sizeof buf, stdin);
			id_len = strlen(buf) - 1;
			if (buf[id_len] != '\0') {
				buf[id_len] = '\0';
			}
                alp_add_friend(c, (uint8_t *) buf);
			break;
            case '1':
			printf("Enter friend's user ID: ");
			fflush(stdout);
			fflush(stdin);
			fgets(buf, sizeof buf, stdin);
			id_len = strlen(buf) - 1;
			if (buf[id_len] == '\n') {
				buf[id_len] = '\0';
			}
                alp_add_friend(c, (uint8_t *) buf);
			fflush(stdin);
			break;
            case '2': {
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
                long i = strtol(intent_buf, NULL, 0);
			if (i > c->num_intents - 1 || i < 0) {
				fprintf(stderr, "Invalid intent\n");
				break;
			}
                alp_call_friend(c, (uint8_t *) buf, (uint64_t) i);
			fflush(stdin);
			break;
		}
            case '3': kw_print_table(&c->kw_table);
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

    byte_buffer buffer;
    int res = bb_init(&buffer, 2000, false);
	if (res) {
		fprintf(stderr, "error initing byte buffer\n");
	}

	for (uint64_t i = 0; i < num_pkg_servers; i++) {
		uint64_t msg_size = sizeof_serialized_bytes(crypto_ghash_BYTES);
		char msg_hex[msg_size];
        printf("Enter value from pkg %lu: ", i);
		fgets(msg_hex, sizeof msg_hex, stdin);
		fflush(stdin);
		size_t len = strlen(msg_hex);
		if (len != crypto_ghash_BYTES * 2) {
			fprintf(stderr, "invalid nonce hex entered\n");
			exit(EXIT_FAILURE);
		}
        bb_write(&buffer, (uint8_t *) msg_hex, crypto_ghash_BYTES * 2);
    }

    res = alp_confirm_registration((uint8_t *) argv[2], sk_bytes, buffer.data);
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
	bn256_init();

	if (argc < 2) {
		fprintf(stderr, "Usage: \n");
		exit(EXIT_FAILURE);
	}

    switch (strtol(argv[1], NULL, 10)) {
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
