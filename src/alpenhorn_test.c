#include <memory.h>
#include "pbc/pbc.h"
#include "pkg.h"
#include "client.h"
#include "mix.h"

int main()
{

	int rs = sodium_init();
	if (rs) { exit(EXIT_FAILURE); };

	pkg_server *pkg_servers = calloc(num_pkg_servers, sizeof *pkg_servers);
	mix_s *mix_servers = calloc(num_mix_servers, sizeof *mix_servers);
	client_s clients[3];
	client_s *chris = &clients[0];
	client_s *bob = &clients[2];
	mix_s *m0 = &mix_servers[0];
	mix_s *m1 = &mix_servers[1];
	for (uint32_t i = 0; i < num_pkg_servers; i++) {
		pkg_server_init(&pkg_servers[i], i);
	}

	for (uint32_t i = 0; i < num_mix_servers; i++) {
		mix_init(&mix_servers[i], i);
	}

	for (uint32_t i = 0; i < 3; i++) {
		client_init(&clients[i], user_ids[i], user_publickeys[i], user_lt_secret_sig_keys[i]);
	}

	// Mix broadcast
	for (uint32_t i = 0; i < 3; i++) {
		for (int j = 0; j < num_mix_servers; j++) {
			memcpy(&clients[i].mix_eph_pub_keys[j], mix_servers[j].mix_dh_pks[0], crypto_box_PUBLICKEYBYTES);

		}
	}

	memcpy(mix_servers[0].mix_dh_pks[1], m1->mix_dh_pks[0], crypto_box_PUBLICKEYBYTES);

	// PKG broadcast
	for (int i = 0; i < num_pkg_servers; i++) {
		for (int j = 0; j < 3; j++) {
			memcpy(&clients[j].pkg_broadcast_msgs[i],
			       pkg_servers[i].eph_broadcast_message + net_header_BYTES,
			       pkg_broadcast_msg_BYTES);
		}
	}

	// Client auth requests
	for (int i = 0; i < 3; i++) {
		af_create_pkg_auth_request(&clients[i]);
		for (int j = 0; j < num_pkg_servers; j++) {
			memcpy(&pkg_servers[j].clients[i].auth_msg_from_client,
			       clients[i].pkg_auth_requests[j] + net_header_BYTES + user_id_BYTES,
			       crypto_box_PUBLICKEYBYTES + crypto_sign_BYTES);
			//printhex("client aut", clients[i].pkg_auth_requests[j]+net_batch_prefix+user_id_BYTES, crypto_box_PUBLICKEYBYTES + crypto_sign_BYTES);
		}
	}

	// PKG auth responses
	for (int i = 0; i < num_pkg_servers; i++) {
		for (int j = 0; j < 3; j++) {
			pkg_auth_client(&pkg_servers[i], &pkg_servers[i].clients[j]);
			memcpy(clients[j].pkg_auth_responses[i],
			       pkg_servers[i].clients[j].eph_client_data + net_header_BYTES,
			       pkg_enc_auth_res_BYTES);
		}
	}

	// Clients process auth responses
	for (int i = 0; i < 3; i++) {
		af_process_auth_responses(&clients[i]);
	}

	//printhex("mix0 dh key", mix_servers[0].eph_pk, crypto_box_PUBLICKEYBYTES);
	//printhex("mix1 dh key", mix_servers[1].eph_pk, crypto_box_PUBLICKEYBYTES);
	af_add_friend(chris, (char *) user_ids[2]);
	mix_af_add_noise(m0);
	mix_af_add_inc_msg(m0, clients[0].friend_request_buf);
	//mix_dial_add_noise(&mix_servers[0]);
	mix_af_decrypt_messages(m0);
	mix_af_shuffle(m0);
	//mix_dial_shuffle(m0);

	memcpy(m1->af_data.in_buf.base,
	       m0->af_data.out_buf.base + net_header_BYTES,
	       (m0->af_data.num_out_msgs * m0->af_data.out_msg_length));

	m1->af_data.num_inc_msgs = m0->af_data.num_out_msgs;
	//printf("Decrypting dial msgs\n");
	mix_af_add_noise(m1);
	//mix_dial_add_noise(m1);
	//mix_dial_decrypt_messages(m1);
	// printf("Decryptiong af messages\n");
	mix_af_decrypt_messages(m1);
	//mix_dial_distribute(m1);
	mix_af_distribute(&mix_servers[1]);
	af_mailbox_s *mb = &mix_servers[1].af_mb_container.mailboxes[0];
	af_process_mb(&clients[2], mb->data + net_header_BYTES, mb->num_messages, 0);
	//af_accept_request(&clients[2], bob->friend_requests->user_id);
	//kw_print_table(&bob->keywheel);
	af_decrypt_request(chris, bob->friend_request_buf + mb_BYTES, 0);
	friend_request_s *fr = chris->friend_requests;
	print_friend_request(fr);
	kw_complete_keywheel(&chris->keywheel, fr->user_id, fr->dh_pk, 0);
	kw_advance_table(&chris->keywheel);
	kw_advance_table(&bob->keywheel);
	//kw_print_table(&chris->keywheel);
	//kw_print_table(&bob->keywheel);
	dial_call_friend(chris, user_ids[2], 1);
	mix_dial_add_noise(m0);
	mix_dial_add_inc_msg(m0, chris->dial_request_buf);
	mix_dial_decrypt_messages(m0);
	printf("Bloop\n");
	memcpy(m1->dial_data.in_buf.base,
	       m0->dial_data.out_buf.base + net_header_BYTES,
	       (m0->dial_data.out_msg_length * m0->dial_data.num_out_msgs));
	m1->dial_data.num_inc_msgs = m0->dial_data.num_out_msgs;
	mix_dial_add_noise(m1);
	mix_dial_decrypt_messages(m1);
	mix_dial_distribute(m1);
	dial_process_mb(bob, m1->dial_mb_containers[0].mailboxes[0].bloom.base_ptr + 8, 0, 0);
	kw_save(&chris->keywheel);
	keywheel_table_s tbl;
	kw_load(&tbl, 0, "keywheel.table");
	kw_print_table(&tbl);
}
