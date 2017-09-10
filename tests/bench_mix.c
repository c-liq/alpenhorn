#include <alpenhorn/mixnet.h>
int main(int argc, char **argv)
{
	mix_s *mix_servers = calloc(num_mix_servers, sizeof *mix_servers);

	for (uint32_t i = 0; i < num_mix_servers; i++) {
		mix_init(&mix_servers[i], i, 6, 0);
		mix_servers[i].af_data.laplace.mu = 100000;
		mix_servers[i].dial_data.laplace.mu = 100000;
	}

	memcpy(mix_servers[0].mix_af_dh_pks[1], mix_servers[1].mix_af_dh_pks[0], crypto_pk_BYTES);
	memcpy(mix_servers[0].mix_dial_dh_pks[1], mix_servers[1].mix_dial_dh_pks[0], crypto_pk_BYTES);

	mix_af_add_noise(&mix_servers[0]);
	mix_af_decrypt_messages(&mix_servers[0]);
	mix_af_shuffle(&mix_servers[0]);

	byte_buffer_put(&mix_servers[1].af_data.in_buf,
	                mix_servers[0].af_data.out_buf.data + net_header_BYTES,
	                mix_servers[0].af_data.out_buf.used - net_header_BYTES);
	mix_servers[1].af_data.num_inc_msgs = mix_servers[0].af_data.num_out_msgs;
	double start = get_time();
	mix_af_decrypt_messages(&mix_servers[1]);
	fprintf(stdout,
	        "Time taken to decrypt %u messages (%u successful): %f\n",
	        mix_servers[1].af_data.num_inc_msgs,
	        mix_servers[1].af_data.num_out_msgs,
	        get_time() - start);

	/*mix_dial_add_noise(&mix_servers[0]);
	mix_dial_decrypt_messages(&mix_servers[0]);
	mix_dial_shuffle(&mix_servers[0]);

	byte_buffer_put(&mix_servers[1].dial_data.in_buf, mix_servers[0].dial_data.out_buf.data + net_header_BYTES, mix_servers[0].dial_data.out_buf.used - net_header_BYTES);
	mix_servers[1].dial_data.num_inc_msgs = mix_servers[0].dial_data.num_out_msgs;
	double start = get_time();
	mix_dial_decrypt_messages(&mix_servers[1]);
	fprintf(stdout, "Time taken to decrypt %u messages (%u successful): %f\n", mix_servers[1].dial_data.num_inc_msgs, mix_servers[1].dial_data.num_out_msgs, get_time() - start);*/
}

