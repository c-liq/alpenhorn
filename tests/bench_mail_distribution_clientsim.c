#include <net_common.h>
#include <client_config.h>


#define sim_num_clients 200

static uint64_t num_completed_connections = 0;
static uint64_t num_responses = 0;
uint8_t uid[user_id_BYTES] = {};
int mix_clientsim_process(void *client_ptr, connection *conn)
{

	switch (conn->msg_type) {
	case DIAL_MB: {
		char time_buffer[40];
		get_current_time(time_buffer);
		LOG_OUT(stdout, "MB received at %s\n", time_buffer);
		num_responses++;
		struct timespec spec;
		spec.tv_sec = 0;
		spec.tv_nsec = 19999999;
		nanosleep(&spec, NULL);
		break;
	}
	case AF_MB: {
		char time_buffer[40];
		get_current_time(time_buffer);
		num_responses++;
		LOG_OUT(stdout, "MB received at %s (%ld of %ld)\n", time_buffer, num_completed_connections, num_responses);

		struct timespec spec;
		spec.tv_sec = 0;
		spec.tv_nsec = 19999999;
		nanosleep(&spec, NULL);
		break;
	}
	case NEW_AFMB_AVAIL: {
		net_epoll_send(conn, conn->sock_fd);
		struct timespec spec;
		spec.tv_sec = 0;
		spec.tv_nsec = 19999999;
		nanosleep(&spec, NULL);
		break;
	}
	case NEW_DMB_AVAIL: {
		net_serialize_header(conn->write_buf.data,
		                     CLIENT_DIAL_MB_REQUEST,
		                     user_id_BYTES,
		                     1,
		                     1);
		net_epoll_send(conn, conn->sock_fd);
		struct timespec spec;
		spec.tv_sec = 0;
		spec.tv_nsec = 19999999;
		nanosleep(&spec, NULL);
		break;
	}
	default:
		fprintf(stderr, "Invalid message from Mix distribution server %lu\n", conn->msg_type);
		return -1;
	}
	return 0;
}

int main()
{

	int epoll_fd = epoll_create1(0);
	uid[0] = 'u';
	uid[1] = 's';
	uid[2] = 'e';
	uid[3] = 'r';
	struct epoll_event event;
	memset(&event, 0, sizeof event);
	event.events = EPOLLIN | EPOLLET;
	while (num_completed_connections < sim_num_clients) {
		int sock_fd = net_connect(mix_server_ips[num_mix_servers - 1], mix_listen_ports[num_mix_servers - 1], 1);
		if (sock_fd <= 0) {
			printf("Connection failed, sleeping..\n");
			struct timespec spec;
			spec.tv_sec = 0;
			spec.tv_nsec = 19999999;
			continue;
		}
		connection *conn = calloc(1, sizeof *conn);
		connection_init(conn, 2048, 2048, mix_clientsim_process, epoll_fd, sock_fd);
		net_serialize_header(conn->write_buf.data,
		                     CLIENT_AF_MB_REQUEST,
		                     user_id_BYTES,
		                     1,
		                     1);

		serialize_uint64(&uid[5], num_completed_connections);
		memcpy(conn->write_buf.data + net_header_BYTES, uid, user_id_BYTES);
		conn->write_remaining += user_id_BYTES + net_header_BYTES;
		struct timespec spec;
		spec.tv_sec = 0;
		spec.tv_nsec = 19999999;
		nanosleep(&spec, NULL);
		num_completed_connections++;
	}

	struct epoll_event *events = calloc(epoll_num_events, sizeof event);
	printf("Completed connections: %ld\n", num_completed_connections);
	while (num_responses < num_completed_connections) {
		int num_events = epoll_wait(epoll_fd, events, epoll_num_events, 5000);
		for (int i = 0; i < num_events; i++) {
			connection *conn = events[i].data.ptr;
			net_epoll_read(NULL, conn);
		}
	}
	char time_buffer[100];
	get_current_time(time_buffer);
	printf("All responses received (%ld of %d) at %s\n", num_completed_connections, sim_num_clients, time_buffer);
	return 0;
}

