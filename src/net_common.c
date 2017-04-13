#include "net_common.h"
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <pthread.h>

int net_epoll_accept(int listen_sfd, int set_nb)
{
	struct sockaddr_storage client_addr;
	int new_sfd, status;
	socklen_t addr_size = sizeof client_addr;
	//printf("Listen socket: %d\n", listen_sfd);
	new_sfd = accept(listen_sfd, (struct sockaddr *) &client_addr, &addr_size);
	if (new_sfd == -1) {
		return -1;
	}

	if (set_nb) {
		status = socket_set_nonblocking(new_sfd);
		if (status == -1) {
			perror("setting non blocking option on socket");
			return -1;
		}
	}
	return new_sfd;
}

int connection_init(connection *conn)
{

	int result = byte_buffer_init(&conn->read_buf, 16384);
	if (result) return -1;

	result = byte_buffer_init(&conn->write_buf, 16384);
	if (result) return -1;

	pthread_mutex_init(&conn->send_queue_lock, NULL);
	conn->bytes_read = 0;
	conn->msg_type = 0;
	conn->bytes_written = 0;
	conn->write_remaining = 0;
	conn->sock_fd = -1;
	conn->event.data.ptr = conn;
	conn->curr_msg_len = 0;
	conn->process = NULL;
	conn->event.events = 0;
	conn->connected = 1;
	conn->send_queue_head = NULL;
	conn->send_queue_tail = NULL;
	return 0;
}

int net_send_nonblock(int sock_fd, uint8_t *buf, size_t n)
{
	ssize_t bytes_sent = 0;
	while (bytes_sent < n) {
		ssize_t tmp_sent = send(sock_fd, buf + bytes_sent, n - bytes_sent, 0);
		if (tmp_sent <= 0) {
			fprintf(stderr, "socket write error\n");
			return -1;
		}
		bytes_sent += tmp_sent;
	}
	return 0;
}

int net_read_nonblock(int sock_fd, uint8_t *buf, size_t n)
{
	int bytes_read = 0;
	while (bytes_read < n) {
		ssize_t tmp_read = read(sock_fd, buf + bytes_read, n - bytes_read);
		if (tmp_read <= 0) {
			fprintf(stderr, "socket read error\n");
			return -1;
		}
		bytes_read += tmp_read;

	}
	return 0;
}

int net_connect(const char *addr, const char *port, int set_nb)
{
	struct addrinfo hints, *servinfo, *p;
	int sock_fd;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	int res = getaddrinfo(addr, port, &hints, &servinfo);
	if (res) {
		gai_strerror(res);
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(res));
		return -1;
	}

	for (p = servinfo; p != NULL; p = p->ai_next) {
		if ((sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			continue;
		}
		if (connect(sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sock_fd);
			perror("client: connect");
			return -1;
		}
		break;
	}

	if (set_nb) {
		res = socket_set_nonblocking(sock_fd);
		if (res) {
			fprintf(stderr, "error setting non blocking mode on socket\n");
			close(sock_fd);
			return -1;
		}
	}
	return sock_fd;
}

int socket_set_nonblocking(int socket)
{
	int flags, status;

	flags = fcntl(socket, F_GETFL, 0);
	if (flags == -1) {
		perror("fcntl");
		return -1;
	}

	flags |= O_NONBLOCK;
	status = fcntl(socket, F_SETFL, flags);
	if (status == -1) {
		perror("fcntl");
		return -1;
	}
	return 0;
}

void net_process_read(void *owner, connection *conn, ssize_t count)
{
	conn->bytes_read += count;
	conn->read_buf.pos += count;
	conn->read_buf.used += count;

	while (conn->bytes_read > 0) {
		if (conn->curr_msg_len == 0) {
			if ((count < net_header_BYTES)) {
				return;
			}

			conn->msg_type = deserialize_uint32(conn->read_buf.data);
			conn->curr_msg_len = deserialize_uint32(conn->read_buf.data + net_msg_type_BYTES);
		}
		// Message hasn't been fully received
		if (conn->bytes_read < conn->curr_msg_len + net_header_BYTES) {
			printf("Full messagen not yet read: %u read, %d total\n", conn->bytes_read, conn->curr_msg_len + net_header_BYTES);
			return;
		}

		conn->process(owner, conn);

		uint32_t read_remaining = (conn->bytes_read - conn->curr_msg_len - net_header_BYTES);

		if (read_remaining > 0) {
			memcpy(conn->read_buf.data,
			       conn->read_buf.data + net_header_BYTES + conn->curr_msg_len,
			       read_remaining);
		}

		conn->curr_msg_len = 0;
		conn->msg_type = 0;
		conn->bytes_read = read_remaining;
		conn->read_buf.used = read_remaining;
		conn->read_buf.pos = conn->read_buf.data + read_remaining;
	}
}

int net_epoll_read(void *owner, connection *conn)
{
	int close_client_connection = 0;
	for (;;) {
		ssize_t count;
		byte_buffer_s *read_buf = &conn->read_buf;
		ssize_t buf_space = read_buf->capacity - read_buf->used;

		if (buf_space <= 0) {
			byte_buffer_resize(read_buf, conn->curr_msg_len * 2);
			buf_space = read_buf->capacity - conn->bytes_read;
		}

		count = read(conn->sock_fd, read_buf->pos, (size_t) buf_space);

		if (count == -1) {
			if (errno != EAGAIN) {
				perror("read");
				close_client_connection = 1;
			}
			break;
		}
		else if (count == 0) {
			printf("Sock read 0 in epoll read, sock %d\n", conn->sock_fd);
			close_client_connection = 1;
			break;
		}

		net_process_read(owner, conn, count);
	}

	if (close_client_connection) {
		fprintf(stderr, "Epoll read: closing client_connection on sock %d\n", conn->sock_fd);
		return -1;
	}
	return 0;
}

int net_epoll_send(void *c, connection *conn, int epoll_fd)
{
	if (!c || !conn) return -1;

	int close = 0;

	while (conn->write_remaining > 0) {
		ssize_t count = send(conn->sock_fd, conn->write_buf.data + conn->bytes_written, conn->write_remaining, 0);
		if (count == -1) {
			if (errno != EAGAIN) {
				fprintf(stderr, "socket send error %d on %d\n", errno, conn->sock_fd);
				close = 1;
			}
			break;
		}
		else if (count == 0) {
			fprintf(stderr, "Socket send 0 bytes on %d\n", conn->sock_fd);
			close = 1;
			break;
		}
		else {
			conn->bytes_written += count;
			conn->write_remaining -= count;

			if (conn->write_remaining == 0) {
				conn->bytes_written = 0;
			}
		}
	}

	if (close) {
		fprintf(stderr, "Closing socket %d in epoll send\n", conn->sock_fd);
		return -1;
	}

	if (conn->write_remaining != 0 && !(conn->event.events & EPOLLOUT)) {
		conn->event.events = EPOLLOUT | EPOLLET;
		epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->sock_fd, &conn->event);
	}

	else if (conn->write_remaining == 0 && conn->event.events & EPOLLOUT) {
		conn->event.events = EPOLLIN | EPOLLET;
		epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->sock_fd, &conn->event);
	}
	return 0;
}

int net_start_listen_socket(const char *port, int set_nb)
{
	int listen_sfd;
	struct addrinfo hints;
	struct addrinfo *serverinfo;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	int status = getaddrinfo(NULL, port, &hints, &serverinfo);
	if (status != 0) {
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
		freeaddrinfo(serverinfo);
		return -1;
	}
	// Iterate through addrinfo structures until a socket is created
	struct addrinfo *p;
	for (p = serverinfo; p != NULL; p = p->ai_next) {
		listen_sfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (listen_sfd != -1)
			break;
	}

	if (listen_sfd == -1) {
		perror("couldn't establish socket");
		freeaddrinfo(serverinfo);
		return -1;
	}

	int y = 1;
	if (setsockopt(listen_sfd, SOL_SOCKET, SO_REUSEADDR, &y, sizeof y) == -1) {
		perror("setoption");
		return -1;
	}

	if (set_nb) {
		status = socket_set_nonblocking(listen_sfd);
		if (status == -1) {
			close(listen_sfd);
			return -1;
		}
	}

	status = bind(listen_sfd, p->ai_addr, p->ai_addrlen);
	if (status == -1) {
		perror("bind failure");
		return -1;
	}

	status = listen(listen_sfd, 5);
	if (status == -1) {
		perror("listen failure");
		return -1;
	}

	freeaddrinfo(serverinfo);
	return listen_sfd;
}