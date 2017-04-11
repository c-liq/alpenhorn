
#include "pkg.h"
#include "net_common.h"
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>

typedef struct pkg_connection pkg_connection;

struct pkg_connection
{
	uint32_t id;
	int sock_fd;
	byte_buffer_s *read_buf;
	size_t curr_msg_len;
	size_t bytes_read;
	uint32_t msg_type;
	uint8_t write_buf[buf_size];
	size_t bytes_written;
	size_t write_remaining;
	struct epoll_event event;
	void (*on_read)(void *owner, pkg_connection *conn, ssize_t count);
	void (*on_write)(void *owner, pkg_connection *conn, ssize_t count);
	pkg_connection *next;
	pkg_connection *prev;
	pkg_client *client_state;
};


#define CLI_AUTH_REQ 50

struct pkg_net
{
	pkg_server *pkg;
	struct epoll_event *events;
	int epoll_inst;
	pkg_connection mix_conn;
	int listen_fd;
	pkg_connection *clients;
};

typedef struct pkg_net pkg_net_s;

void epoll_pkg_send(pkg_net_s *s, pkg_connection *conn);

bool net_pkg_auth_client(pkg_net_s *s, pkg_connection *conn)
{
	if (!conn->client_state) {
		int index = pkg_client_lookup(s->pkg, conn->read_buf->base + net_header_BYTES + round_BYTES);
		if (index == -1) {
			return false;
		}
		conn->client_state = &s->pkg->clients[index];
	}

	pkg_client *client = conn->client_state;
	memcpy(conn->client_state->auth_msg_from_client,
	       conn->read_buf->base + net_header_BYTES,
	       cli_pkg_single_auth_req_BYTES);
	int authed = pkg_auth_client(s->pkg, client);
	if (!authed) {
		memcpy(conn->write_buf + conn->bytes_written,
		       client->eph_client_data,
		       net_header_BYTES + pkg_enc_auth_res_BYTES);
		conn->write_remaining += net_header_BYTES + pkg_enc_auth_res_BYTES;
		epoll_pkg_send(s, conn);
	}
	return true;
}

void remove_client(pkg_net_s *s, pkg_connection *conn)
{
	epoll_ctl(s->epoll_inst, EPOLL_CTL_DEL, conn->sock_fd, &conn->event);
	if (conn == s->clients) {
		s->clients = conn->next;
	}
	if (conn->next) {
		conn->next->prev = conn->prev;
	}
	if (conn->prev) {
		conn->prev->next = conn->next;
	}
	free(conn);
}

void epoll_broadcast_msg(pkg_net_s *s, pkg_connection *conn)
{
	memcpy(conn->write_buf + conn->bytes_written + conn->write_remaining,
	       s->pkg->eph_broadcast_message,
	       net_header_BYTES + pkg_broadcast_msg_BYTES);
	conn->write_remaining += net_header_BYTES + pkg_broadcast_msg_BYTES;
	epoll_pkg_send(s, conn);
}

void epoll_pkg_send(pkg_net_s *s, pkg_connection *conn)
{
	int close_connection = 0;
	while (conn->write_remaining > 0) {
		ssize_t count = send(conn->sock_fd, conn->write_buf + conn->bytes_written, conn->write_remaining, 0);
		if (count == -1) {
			if (errno != EAGAIN) {
				perror("send");
				close_connection = 1;
			}
			break;
		}
		else if (count == 0) {
			close_connection = 1;
			break;
		}
		else {
			conn->bytes_written += count;
			conn->write_remaining -= count;
		}
	}
	if (close_connection) {
		//close(conn->sock_fd);
		//free(conn);
	}

	if (conn->write_remaining == 0) {
		conn->bytes_written = 0;
	}

	// If we haven't finished writing, make sure EPOLLOUT is set
	if (conn->write_remaining != 0 && !(conn->event.events & EPOLLOUT)) {
		conn->event.events = EPOLLOUT;
		epoll_ctl(s->epoll_inst, EPOLL_CTL_MOD, conn->sock_fd, &conn->event);
	}
		// If we have finished writing, make sure to unset EPOLLOUT
	else if (conn->write_remaining == 0 && conn->event.events & EPOLLOUT) {
		conn->event.events = EPOLLIN;
		epoll_ctl(s->epoll_inst, EPOLL_CTL_MOD, conn->sock_fd, &conn->event);
	}
}

void pkg_mix_read(void *srv, pkg_connection *conn, ssize_t count)
{
	pkg_net_s *s = (pkg_net_s *) srv;
	pkg_new_round(s->pkg);
	pkg_connection *curr = s->clients;
	printf("PKG advanced to round %ld\n", s->pkg->current_round);
	while (curr) {
		epoll_broadcast_msg(s, curr);
		curr = curr->next;
	}
}

void pkg_client_read(void *srv, pkg_connection *conn, ssize_t count)
{
	pkg_net_s *s = (pkg_net_s *) srv;
	conn->bytes_read += count;
	if (conn->curr_msg_len == 0) {
		if ((count < net_header_BYTES)) {
			return;
		}
		uint32_t msg_type = deserialize_uint32(conn->read_buf->base);
		if (msg_type == CLI_AUTH_REQ) {
			conn->msg_type = CLI_AUTH_REQ;
			conn->curr_msg_len = cli_pkg_single_auth_req_BYTES;
		}
		else if (msg_type == CLIENT_REG_REQUEST) {
			conn->msg_type = CLIENT_REG_REQUEST;
			conn->curr_msg_len = cli_pkg_reg_request_BYTES;
		}
		else if (msg_type == CLIENT_REG_CONFIRM) {
			conn->msg_type = CLIENT_REG_CONFIRM;
			conn->curr_msg_len = cli_pkg_reg_confirm_BYTES;
		}
		else {
			fprintf(stderr, "Invalid message\n");
			close(conn->sock_fd);
			return;
		}

	}

	if (conn->bytes_read < conn->curr_msg_len + net_header_BYTES) {
		return;
	}
	if (conn->msg_type == CLI_AUTH_REQ) {
		printf("Authentication request received from %s\n", conn->read_buf->base + net_header_BYTES + round_BYTES);
		int res = net_pkg_auth_client(s, conn);
		if (!res) {
			fprintf(stderr, "Authentication failed for %s\n", conn->read_buf->base + net_header_BYTES + round_BYTES);
		}
	}
	else if (conn->msg_type == CLIENT_REG_REQUEST) {
		pkg_registration_request(s->pkg,
		                         conn->read_buf->data + net_header_BYTES,
		                         conn->read_buf->data + net_header_BYTES + user_id_BYTES);
	}

	else if (conn->msg_type == CLIENT_REG_CONFIRM) {
		pkg_confirm_registration(s->pkg,
		                         conn->read_buf->data + net_header_BYTES,
		                         conn->read_buf->data + net_header_BYTES + user_id_BYTES);
	}

	conn->msg_type = 0;
	conn->curr_msg_len = 0;
	conn->bytes_read = 0;

}

int net_cli_epread(pkg_net_s *s, pkg_connection *conn)
{
	int close_connection = 0;
	for (;;) {
		ssize_t count;
		count = read(conn->sock_fd,
		             conn->read_buf->base + conn->bytes_read,
		             conn->read_buf->capacity - conn->bytes_read);

		if (count == -1) {
			if (errno != EAGAIN) {
				perror("read");
				close_connection = 1;
			}
			break;
		}
		else if (count == 0) {
			close_connection = 1;
			break;
		}
		if (conn->on_read) {
			conn->on_read(s, conn, count);
		}
	}

	if (close_connection) {
		close(conn->sock_fd);
	}
	return 0;
}

int pkg_server_startup(pkg_net_s *s, pkg_server *pkg)
{
	memset(&s->mix_conn, 0, sizeof s->mix_conn);
	s->clients = NULL;
	struct epoll_event event;
	s->pkg = pkg;
	s->epoll_inst = epoll_create1(0);
	s->mix_conn.read_buf = calloc(1, sizeof *s->mix_conn.read_buf);
	byte_buffer_init(s->mix_conn.read_buf, 16384, 0);
	s->events = calloc(1000, sizeof *s->events);
	int mix_fd = net_connect("127.0.0.1", "3000", 1);
	if (mix_fd == -1) {
		printf("failed to connect to mix entry server\n");
		return -1;
	}
	s->mix_conn.sock_fd = mix_fd;
	s->mix_conn.on_read = pkg_mix_read;
	event.data.ptr = &s->mix_conn;
	event.events = EPOLLIN | EPOLLET;
	epoll_ctl(s->epoll_inst, EPOLL_CTL_ADD, mix_fd, &event);

	int listen_sfd = net_start_listen_socket(pkg_cl_listen_ports[s->pkg->srv_id], 1);
	if (listen_sfd == -1) {
		fprintf(stderr, "failed to establish listening socket for pkg server\n");
		return -1;
	}

	s->listen_fd = listen_sfd;

	event.data.fd = listen_sfd;
	event.events = EPOLLIN | EPOLLET;
	epoll_ctl(s->epoll_inst, EPOLL_CTL_ADD, listen_sfd, &event);

	return 0;
}

int epoll_paccept(pkg_net_s *s)
{
	for (;;) {

		struct epoll_event event;
		int status;
		int new_sock;
		new_sock = net_accept(s->listen_fd, 1);
		if (new_sock == -1) {
			// All new connections processed
			if ((errno == EAGAIN || errno == EWOULDBLOCK)) {
				break;
			}
			// Something broke
			perror("client accept");
			continue;
		}

		pkg_connection *new_conn = calloc(1, sizeof(*new_conn));
		if (!new_conn) {
			perror("malloc");
			return -1;
		}
		if (s->clients) {
			s->clients->prev = new_conn;
		}
		new_conn->next = s->clients;
		new_conn->prev = NULL;
		new_conn->read_buf = calloc(1, sizeof *new_conn->read_buf);
		byte_buffer_init(new_conn->read_buf, 16384, 0);
		s->clients = new_conn;
		new_conn->on_read = pkg_client_read;
		new_conn->sock_fd = new_sock;
		event.data.ptr = new_conn;
		event.events = EPOLLIN | EPOLLET;
		status = epoll_ctl(s->epoll_inst, EPOLL_CTL_ADD, new_sock, &event);

		if (status == -1) {
			perror("epoll_ctl");
			return -1;
		}

		printf("Accepted connection on listening socket, %d\n", new_conn->sock_fd);
		epoll_broadcast_msg(s, new_conn);
	}
	return 0;
}

void net_pkg_server_loop(pkg_net_s *es, void(*on_read)(pkg_net_s *, pkg_connection *, ssize_t))
{

	struct epoll_event *events = es->events;

	for (;;) {
		int n = epoll_wait(es->epoll_inst, es->events, 100, 5000);
		pkg_connection *conn = NULL;
		// Error of some sort on the socket
		for (int i = 0; i < n; i++) {
			if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
				conn = (pkg_connection *) events[i].data.ptr;
				close(conn->sock_fd);
				remove_client(es, conn);
				continue;
			}
			else if (es->listen_fd == events[i].data.fd) {
				int res = epoll_paccept(es);
				if (res) {
					fprintf(stderr, "fatal server error\n");
					exit(1);
				}
			}
				// Read from a socket
			else if (events[i].events & EPOLLIN) {
				conn = events[i].data.ptr;
				net_cli_epread(es, conn);
			}
			else if (events[i].events & EPOLLOUT) {
				epoll_pkg_send(es, conn);
			}
		}
	}
}

int main(int argc, char **argv)
{
	#if !USE_PBC
	bn256_init();
	#endif

	int sid;
	if (argc < 2) {
		fprintf(stderr, "No server id provided\n");
		return 1;
	}

	sid = atoi(argv[1]);
	if (sid > num_pkg_servers) {
		fprintf(stderr, "Invalid server id %d\n", sid);
		return 1;
	}

	pkg_server s;
	pkg_server_init(&s, (uint32_t) sid, 10, 4);
	pkg_net_s pkg_s;
	pkg_server_startup(&pkg_s, &s);
	printf("[PKG %d successfully initialised]\n", s.srv_id);
	net_pkg_server_loop(&pkg_s, NULL);
}



