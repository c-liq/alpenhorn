#include <pkg.h>
#include <mixnet.h>

#include "client.h"
#include "greatest.h"


#define num_clients 2

TEST test_client_af()
{

	client_s *clients = calloc(num_clients, sizeof *clients);
	sign_keypair *sig_keypairs = calloc(num_clients, sizeof *sig_keypairs);
	pkg_server *pkg_servers = calloc(num_pkg_servers, sizeof *pkg_servers);
	mix_s *mix_servers = calloc(num_mix_servers, sizeof *mix_servers);

	for (uint32_t i = 0; i < num_mix_servers; i++) {
		mix_init(&mix_servers[i], i, 4, 0);
	}

	for (uint32_t i = 0; i < num_pkg_servers; i++) {
		pkg_server_init(&pkg_servers[i], i, 0, 4, NULL);
		pkg_client_init(&pkg_servers[i].clients[0], &pkg_servers[i], user_ids[0], user_publickeys[0], true);
		pkg_client_init(&pkg_servers[i].clients[1], &pkg_servers[i], user_ids[1], user_publickeys[1], true);
	}

	for (uint32_t i = 0; i < num_clients; i++) {
		sodium_hex2bin(sig_keypairs[i].public_key, crypto_sign_PUBLICKEYBYTES, (char *) user_publickeys[i],
		               64, NULL, NULL, NULL);
		sodium_hex2bin(sig_keypairs[i].secret_key, crypto_sign_SECRETKEYBYTES, (char *) user_lt_secret_sig_keys[i],
		               128, NULL, NULL, NULL);
		client_init(&clients[i], user_ids[i], &sig_keypairs[i], NULL, NULL, NULL);
		clients[i].af_round = 1;
		clients[i].dialling_round = 1;
	}


	for (uint32_t j = 0; j < num_clients; j++) {
		for (uint32_t i = 0; i < num_mix_servers; i++) {
			memcpy(clients[j].mix_af_pks[i], mix_servers[i].mix_af_dh_pks[0], crypto_box_PUBLICKEYBYTES);
		}
	}

	memcpy(mix_servers[0].mix_af_dh_pks[1], mix_servers[1].mix_af_dh_pks[0], crypto_pk_BYTES);

	for (uint j = 0; j < num_clients; j++) {
		for (uint32_t i = 0; i < num_pkg_servers; i++) {
			memcpy(clients[j].pkg_broadcast_msgs[i],
			       pkg_servers[i].eph_broadcast_message + net_header_BYTES,
			       pkg_broadcast_msg_BYTES);
			//printhex("BROADCAST MSG AT CLIENT", clients[j].pkg_broadcast_msgs[i], pkg_broadcast_msg_BYTES);
		}

		af_update_pkg_public_keys(&clients[j]);
		af_create_pkg_auth_request(&clients[j]);

		for (uint32_t i = 0; i < num_pkg_servers; i++) {

			pkg_auth_client(&pkg_servers[i],
			                &pkg_servers[i].clients[j],
			                clients[j].pkg_auth_requests[i] + net_header_BYTES);
			memcpy(clients[j].pkg_auth_responses[i],
			       pkg_servers[i].clients[j].eph_client_data + net_header_BYTES,
			       pkg_enc_auth_res_BYTES);
		};

		af_process_auth_responses(&clients[j]);

	}

	af_add_friend(&clients[0], clients[1].user_id);
	af_build_request(&clients[0]);

	mix_af_add_noise(&mix_servers[0]);
	mix_af_add_noise(&mix_servers[1]);

	mix_entry_add_af_message(&mix_servers[0], clients[0].friend_request_buf + net_header_BYTES);
	mix_af_decrypt_messages(&mix_servers[0]);
	//mix_af_shuffle(&mix_servers[0]);

	byte_buffer_put(&mix_servers[1].af_data.in_buf,
	                mix_servers[0].af_data.out_buf.data + net_header_BYTES,
	                mix_servers[0].af_data.out_buf.used - net_header_BYTES);
	mix_servers[1].af_data.num_inc_msgs = mix_servers[0].af_data.num_out_msgs;
	mix_af_decrypt_messages(&mix_servers[1]);
	mix_af_distribute(&mix_servers[1]);

	af_mailbox_s *mailbox = &mix_servers[1].af_mb_container.mailboxes[0];
	printf("NUM MSGS: %lu\n", mailbox->num_messages);

	af_process_mb(&clients[1], mailbox->data + net_header_BYTES, mailbox->num_messages, mix_servers[1].af_data.round);
	af_confirm_friend(&clients[1], clients[0].user_id);

	mix_af_newround(&mix_servers[0]);
	mix_af_newround(&mix_servers[1]);


	pkg_new_round(&pkg_servers[0]);

	clients[0].af_round++;
	clients[1].af_round++;

	for (uint32_t j = 0; j < num_clients; j++) {
		for (uint32_t i = 0; i < num_mix_servers; i++) {
			memcpy(clients[j].mix_af_pks[i], mix_servers[i].mix_af_dh_pks[0], crypto_box_PUBLICKEYBYTES);
		}
	}

	for (uint j = 0; j < num_clients; j++) {
		for (uint32_t i = 0; i < num_pkg_servers; i++) {
			memcpy(clients[j].pkg_broadcast_msgs[i],
			       pkg_servers[i].eph_broadcast_message + net_header_BYTES,
			       pkg_broadcast_msg_BYTES);
			//printhex("BROADCAST MSG AT CLIENT", clients[j].pkg_broadcast_msgs[i], pkg_broadcast_msg_BYTES);
		}

		af_update_pkg_public_keys(&clients[j]);
		af_create_pkg_auth_request(&clients[j]);

		for (uint32_t i = 0; i < num_pkg_servers; i++) {

			pkg_auth_client(&pkg_servers[i],
			                &pkg_servers[i].clients[j],
			                clients[j].pkg_auth_requests[i] + net_header_BYTES);
			memcpy(clients[j].pkg_auth_responses[i],
			       pkg_servers[i].clients[j].eph_client_data + net_header_BYTES,
			       pkg_enc_auth_res_BYTES);
		};

		af_process_auth_responses(&clients[j]);

	}

	af_build_request(&clients[1]);
	mix_entry_add_af_message(&mix_servers[0], clients[1].friend_request_buf + net_header_BYTES);
	mix_af_decrypt_messages(&mix_servers[0]);
	mix_af_shuffle(&mix_servers[0]);

	byte_buffer_put(&mix_servers[1].af_data.in_buf,
	                mix_servers[0].af_data.out_buf.data + net_header_BYTES,
	                mix_servers[0].af_data.out_buf.used - net_header_BYTES);
	mix_servers[1].af_data.num_inc_msgs = 1;
	mix_af_decrypt_messages(&mix_servers[1]);
	mix_af_distribute(&mix_servers[1]);

	mailbox = &mix_servers[1].af_mb_container.mailboxes[0];
	af_process_mb(&clients[0], mailbox->data + net_header_BYTES, mailbox->num_messages, mix_servers[1].af_data.round);


	kw_print_table(&clients[0].keywheel);
	kw_print_table(&clients[1].keywheel);

		PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
	#if !USE_PBC
	bn256_init();
	#endif
	GREATEST_MAIN_BEGIN();
		RUN_TESTp(test_client_af);
	GREATEST_MAIN_END();
}

