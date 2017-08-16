#include <net_common.h>
#include <client_config.h>
#include <time.h>

#define sim_num_clients 1800

static int num_completed_connections = 0;
static int num_responses = 0;

int mix_clientsim_process(void *client_ptr, connection *conn)
{

	switch (conn->msg_type) {
	case DIAL_MB:
//
		break;
	case AF_MB:
		num_responses++;
		break;
	case NEW_AFMB_AVAIL: {
		net_epoll_send(NULL, conn, conn->sock_fd);
		break;
	}
	case NEW_DMB_AVAIL: {
//
		break;
	}
	default:
		fprintf(stderr, "Invalid message from Mix distribution server\n");
		return -1;
	}
	return 0;
}

int main()
{

	int epoll_fd = epoll_create1(0);
	struct epoll_event event;
	memset(&event, 0, sizeof event);
	event.events = EPOLLIN | EPOLLET;
	while (num_completed_connections < sim_num_clients) {
		int sock_fd = net_connect("127.0.0.1", mix_listen_ports[num_mix_servers - 1], 1);
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
		randombytes_buf(conn->write_buf.data + net_header_BYTES, user_id_BYTES);
		conn->write_remaining += user_id_BYTES + net_header_BYTES;
		struct timespec spec;
		spec.tv_sec = 0;
		spec.tv_nsec = 19999999;
		nanosleep(&spec, NULL);
		num_completed_connections++;
	}

	struct epoll_event *events = calloc(sim_num_clients * 2, sizeof event);
	printf("Complected connections: %d\n", num_completed_connections);
	while (num_responses < num_completed_connections) {
		int num_events = epoll_wait(epoll_fd, events, 20000, 5000);
		for (int i = 0; i < num_events; i++) {
			connection *conn = events[i].data.ptr;
			net_epoll_read(NULL, conn);
		}
	}

	printf("All responses received (%d of %d\n", num_completed_connections, sim_num_clients);
	return 0;
}

