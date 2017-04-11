#include <bn256.h>
#include <bn256_ibe.h>
#include <sys/time.h>
#include "pkg.h"

double get_time()
{
	struct timeval t;
	struct timezone tzp;
	gettimeofday(&t, &tzp);
	return t.tv_sec + t.tv_usec * 1e-6;
}

int main()
{
	bn256_init();
	int rs = sodium_init();
	if (rs) { exit(EXIT_FAILURE); };
/*

	pkg_server *pkg_servers = calloc(num_pkg_servers, sizeof *pkg_servers);
	client_s clients[3];
	client_s *chris = &clients[0];
	client_s *bob = &clients[2];

	for (uint32_t i = 0; i < num_pkg_servers; i++) {
		pkg_server_init(&pkg_servers[i], i);
	}
	for (uint32_t i = 0; i < 3; i++) {
		client_init(&clients[i], user_ids[i], user_publickeys[i], user_lt_secret_sig_keys[i]);
	}
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

	for (int i = 0; i < 3; i++) {
		af_process_auth_responses(&clients[i]);
	}

	af_add_friend(chris, (char *) user_ids[2]);
	//chris->curr_ibe = !chris->curr_ibe;
	bob->curr_ibe = !bob->curr_ibe;
	af_decrypt_request(bob, chris->friend_request_buf + mb_BYTES + net_header_BYTES, 1);



	scalar_t master_sk;
	curvepoint_fp_t master_pk;

	bn256_scalar_random(master_sk);
	bn256_scalarmult_bg1(master_pk, master_sk);
	curvepoint_fp_makeaffine(master_pk);
	twistpoint_fp2_t q_id;
	twistpoint_fp2_t user_sk;

	uint8_t user_id[60] = "chris";
	uint8_t user_id_bob[60] = "bob";
	uint8_t msg[128] = "This is a test message\n";
	twistpoint_fp2_t chris_pk;
	twistpoint_fp2_t chris_sk;
	twistpoint_fp2_t bob_pk, bob_sk;
	bn256_hash_g2(chris_pk, user_id, sizeof user_id, NULL);
	bn256_hash_g2(bob_pk, user_id_bob, sizeof user_id_bob, NULL);
	twistpoint_fp2_scalarmult_vartime(chris_sk, chris_pk, master_sk);
	twistpoint_fp2_scalarmult_vartime(bob_sk, bob_pk, master_sk);
	uint8_t chris_hash_userid[g2_bytes];
	uint8_t bob_hash_userid[g2_bytes];
	bn256_serialize_g2(chris_hash_userid, chris_pk->m_x, chris_pk->m_y);
	bn256_serialize_g2(bob_hash_userid, bob_pk->m_x, bob_pk->m_y);
	memcpy(clients[0].hashed_id, chris_hash_userid, g2_bytes);
	memcpy(bob, bob_hash_userid, g2_bytes);
	curvepoint_fp_set(clients[0].pkg_eph_pub_combined_g1, master_pk);
	twistpoint_fp2_set(chris->pkg_ibe_secret_combined_g2[!chris->curr_ibe], chris_sk);
	curvepoint_fp_set(bob->pkg_eph_pub_combined_g1, master_pk);
	twistpoint_fp2_set(bob->pkg_ibe_secret_combined_g2[!bob->curr_ibe], bob_sk);

	af_add_friend(chris, (char*)user_id_bob);
	af_decrypt_request(bob, chris->friend_request_buf + net_header_BYTES + mb_BYTES, 1);

*/
/*	int count = 0;
	int fails = 0;
	ssize_t res = 0;
	uint8_t ciphertext[1280];
	uint8_t decrypted[1024];
	for (int i = 0; i < 20; i++) {
		randombytes_buf(msg, sizeof msg);
		res = bn256_ibe_encrypt(ciphertext, msg, sizeof msg, master_pk, user_id, sizeof user_id);
		uint8_t dec[2048];
		memset(decrypted, 0, sizeof decrypted);
		res = bn256_ibe_decrypt(dec, ciphertext, (size_t) res, hash_userid, chris_sk);
		if (res) {
			fails++;
		}
		count++;
	}
	printf("%d reps, %d fails\n", count, fails);

	uint8_t msg_rand[60];
	curvepoint_fp_t temp;
	int mpz_sum = 0;
	int fpe_sum = 0;
	twistpoint_fp2_t temp2;
	for (int i = 0; i < 100; i++) {
		randombytes_buf(msg_rand, sizeof msg_rand);
		res = bn256_hash_g2(temp2, msg_rand, sizeof msg_rand, NULL);
		printf("%ld ", res);
		if (res == -3) fpe_sum++;
	}
	printf("\n\nsum: %d\n\n\n", fpe_sum);*/


	pkg_server server;
	pkg_server_init(&server, 0, 0, 0);
	double start = get_time();
	//pkg_new_round(&server);
	double end = get_time();
	//printf("Benchmarking PKG key extration/client signing for %d clients: %f\n", server.num_clients, end - start);
	pkg_new_ibe_keypair(&server);


	randombytes_buf(server.eph_secret_dh_key, crypto_box_SECRETKEYBYTES);
	crypto_scalarmult_base(server.broadcast_dh_pkey_ptr, server.eph_secret_dh_key);
	// Increment round counter
	server.current_round++;
	serialize_uint32(server.eph_broadcast_message, 10);
	serialize_uint32(server.eph_broadcast_message + net_msg_type_BYTES, pkg_broadcast_msg_BYTES);
	serialize_uint64(server.eph_broadcast_message + 8, server.current_round);
	start = get_time();
	pkg_parallel_extract(&server);
	end = get_time();

	printf("Benchmarking PKG key extraction for %d clients: %f\n", server.num_clients, end - start);

}
