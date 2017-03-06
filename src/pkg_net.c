#include "pkg_net.h"

#include "pkg.h"
#include "net_common.h"
#include <sys/epoll.h>
#include <unistd.h>
#include <sys/socket.h>
#include <memory.h>
#include <errno.h>

struct pkg_conn
{
	int sock_fd;
	uint32_t type;
	uint32_t id;
	uint8_t read_buf[buf_size];
	uint32_t read_remaining;
	uint32_t curr_msg_len;
	uint32_t bytes_read;
	uint32_t msg_type;
	uint8_t write_buf[buf_size];
	uint32_t bytes_written;
	uint32_t write_remaining;
	struct epoll_event event;
	uint32_t broadcast_remaining;
};

typedef struct pkg_conn pkg_conn_s;

#define CLI_AUTH_REQ 50

struct pkg_net
{
	pkg_server *pkg;
	struct epoll_event *events;
	int epoll_inst;
	connection mix_conn;
	int listen_fd;
};

typedef struct pkg_net pkg_net_s;

void epoll_pkg_send(pkg_net_s *s, pkg_conn_s *conn);

void net_pkg_auth_client(pkg_net_s *s, pkg_conn_s *conn, pkg_client *client)
{
	int res = pkg_auth_client(s->pkg, client);
	if (!res) {
		memcpy(conn->write_buf, client->eph_client_data, net_header_BYTES + pkg_enc_auth_res_BYTES);
		conn->write_remaining = net_header_BYTES + pkg_enc_auth_res_BYTES;
		epoll_pkg_send(s, conn);
	}
}

void epoll_broadcast_msg(pkg_net_s *s, pkg_conn_s *conn)
{
	ssize_t count = send(conn->sock_fd, s->pkg->eph_broadcast_message, net_header_BYTES + pkg_broadcast_msg_BYTES, 0);
	printf("Sent %ld bytes of broadcast msg to  client\n", count);
}

void epoll_pkg_send(pkg_net_s *s, pkg_conn_s *conn)
{
	int close_connection = 0;
	for (;;) {
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

	// If we haven't finished writing, make sure EPOLLOUT is set
	if (conn->write_remaining != 0 && !(conn->event.events & EPOLLOUT)) {
		conn->event.events = EPOLLOUT | EPOLLERR | EPOLLERR;
		epoll_ctl(s->epoll_inst, EPOLL_CTL_MOD, conn->sock_fd, &conn->event);
	}
		// If we have finished writing, make sure to unset EPOLLOUT
	else if (conn->write_remaining == 0 && conn->event.events & EPOLLOUT) {
		conn->event.events = EPOLLIN | EPOLLERR | EPOLLHUP;
		epoll_ctl(s->epoll_inst, EPOLL_CTL_MOD, conn->sock_fd, &conn->event);
	}
}

void pkg_client_read(pkg_net_s *s, pkg_conn_s *conn, ssize_t count)
{
	ssize_t c_read = count;
	if (conn->curr_msg_len == 0) {
		if ((count < net_header_BYTES)) {
			return;
		}
		uint32_t msg_type = deserialize_uint32(conn->read_buf);
		if (msg_type == CLI_AUTH_REQ) {
			conn->msg_type = CLI_AUTH_REQ;
			conn->curr_msg_len = cli_pkg_single_auth_req_BYTES;
			conn->read_remaining = cli_pkg_single_auth_req_BYTES;
		}
		else {
			fprintf(stderr, "Invalid message\n");
			close(conn->sock_fd);
			return;
		}
		c_read -= net_header_BYTES;
	}

	conn->read_remaining -= c_read;
	conn->bytes_read += count;
	printf("Just read %lu of %u | %d remaining | Message type: %d\n",
	       c_read,
	       conn->curr_msg_len,
	       conn->read_remaining,
	       conn->msg_type);
	if (conn->read_remaining <= 0) {
		if (conn->msg_type == CLI_AUTH_REQ) {
			int index = pkg_client_lookup(s->pkg, conn->read_buf + net_header_BYTES);
			if (index != -1) {
				pkg_client *cl = &s->pkg->clients[index];
				printf("Received auth request from %s for round %d\n",
				       conn->read_buf + net_header_BYTES, deserialize_uint32(conn->read_buf + 4));
				memcpy(cl->auth_msg_from_client,
				       conn->read_buf + net_header_BYTES + user_id_BYTES,
				       cli_pkg_single_auth_req_BYTES - user_id_BYTES);
				int res = pkg_auth_client(s->pkg, cl);
				if (!res) {
					net_pkg_auth_client(s, conn, cl);
				}
			}
			else {
				fprintf(stderr, "User lookup failed for %s\n", conn->read_buf + net_header_BYTES);
			}
		}

		conn->msg_type = 0;
		conn->curr_msg_len = 0;
		conn->bytes_read = 0;
	}
}

int net_cli_epread(pkg_net_s *s, pkg_conn_s *conn)
{
	int close_connection = 0;
	for (;;) {
		ssize_t count;
		count = read(conn->sock_fd, conn->read_buf + conn->bytes_read, sizeof conn->read_buf - conn->bytes_read);

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
		printf("Just read %ld from socket %d\n", count, conn->sock_fd);
		pkg_client_read(s, conn, count);
	}

	if (close_connection) {
		close(conn->sock_fd);
	}
	return 0;
}

int pkg_server_startup(pkg_net_s *s, pkg_server *pkg)
{
	memset(&s->mix_conn, 0, sizeof s->mix_conn);
	struct epoll_event event;
	s->pkg = pkg;
	s->epoll_inst = epoll_create1(0);
	s->events = calloc(1000, sizeof *s->events);
	int mix_fd = net_connect("127.0.0.1", "3000", 1);
	if (mix_fd == -1) {
		printf("failed to connect to mix entry server\n");
		return -1;
	}
	s->mix_conn.sock_fd = mix_fd;
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

		pkg_conn_s *new_conn = calloc(1, sizeof(*new_conn));
		if (!new_conn) {
			perror("malloc");
			return -1;
		}
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

void net_pkg_server_loop(pkg_net_s *es, void(*on_read)(pkg_net_s *, pkg_conn_s *, ssize_t))
{

	struct epoll_event *events = es->events;

	for (;;) {
		int n = epoll_wait(es->epoll_inst, es->events, 100, 5000);
		pkg_conn_s *conn = NULL;
		// Error of some sort on the socket
		for (int i = 0; i < n; i++) {
			if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
				conn = (pkg_conn_s *) events[i].data.ptr;
				close(conn->sock_fd);
				free(events[i].data.ptr);
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

int main()
{
	pkg_server s;
	pkg_server_init(&s, 0);
	pkg_net_s pkg_s;
	printf("Starting pkg server\n");
	pkg_server_startup(&pkg_s, &s);
	printf("Starting pkg server loop\n");
	net_pkg_server_loop(&pkg_s, NULL);

}



