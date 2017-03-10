#include <string.h>
#include "mix.h"
#include <sys/socket.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <errno.h>
#include <time.h>
#include "mixnet_server.h"
#include "../lib/xxhash/xxhash.h"


struct mixnet_server
{
	mix_s *mix;
	int epoll_inst;
	int listen_socket;
	struct epoll_event *events;
	int running;
	connection prev_mix;
	connection next_mix;
	time_t next_af_round;
	time_t next_dial_round;
	connection pkg_conns[num_pkg_servers];
	byte_buffer_s bc_buf;
	connection *clients;
};

void net_mix_new_dr(net_server_s *s)
{
	if (!s->mix->is_last) {
		if (s->next_mix.write_buf) {
			uint8_t *write_buf_end = s->next_mix.write_buf->pos + s->next_mix.write_remaining;
			serialize_uint32(write_buf_end, NEW_DIAL_ROUND);
			s->next_mix.write_buf->pos += sizeof(uint32_t);
			s->next_mix.write_remaining += sizeof(uint32_t);
			epoll_send(s, &s->next_mix);
		}
		else {
			serialize_uint32(s->next_mix.internal_write_buf, NEW_DIAL_ROUND);
			s->next_mix.write_remaining = sizeof(uint32_t);
			epoll_send(s, &s->next_mix);
		}
	}
	mix_dial_newround(s->mix);
}

void net_mix_last_read(void *server, connection *conn, ssize_t count)
{
	net_server_s *s = (net_server_s *) server;
	conn->bytes_read += count;

	while (conn->bytes_read > 0) {
		if (conn->curr_msg_len == 0) {
			if (conn->bytes_read < net_header_BYTES) {
				return;
			}

			uint32_t msg_type = deserialize_uint32(conn->internal_read_buf);
			if (msg_type == CLIENT_DIAL_MB_REQUEST) {
				conn->msg_type = CLIENT_DIAL_MB_REQUEST;
				conn->curr_msg_len = user_id_BYTES;
			}

			else if (msg_type == CLIENT_AF_MB_REQUEST) {
				conn->msg_type = CLIENT_AF_MB_REQUEST;
				conn->curr_msg_len = user_id_BYTES;
			}

		}
		printf("Client msg bytes read: %ld | remaining: %ld\n", conn->bytes_read, conn->read_remaining);
		if (conn->bytes_read < net_header_BYTES + conn->curr_msg_len) {
			return;
		}

		if (conn->msg_type == CLIENT_DIAL_MB_REQUEST) {
			uint32_t round_num = deserialize_uint32(conn->internal_read_buf + net_msg_type_BYTES);
			printf("Received dr mailbox download request for round %d from %.60s\n",
			       round_num,
			       conn->internal_read_buf + net_header_BYTES);
			uint32_t mb_round = deserialize_uint32(conn->internal_read_buf + 4);
			dial_mailbox_s
				*request_mb = mix_dial_get_mailbox_buffer(s->mix, mb_round, conn->internal_read_buf + net_header_BYTES);
			if (!request_mb) {
				//Invalid request
			}
			else {
				byte_buffer_s *buf = calloc(1, sizeof *buf);
				buf->base = request_mb->bloom.base_ptr;
				buf->pos = request_mb->bloom.base_ptr;
				conn->write_buf = buf;
				conn->write_remaining = request_mb->bloom.total_size_bytes;
				conn->bytes_written = 0;
				epoll_send(s, conn);
			}
		}
		else if (conn->msg_type == CLIENT_AF_MB_REQUEST) {
			uint32_t round_num = deserialize_uint32(conn->internal_read_buf + net_msg_type_BYTES);
			printf("Received af mailbox download request for round %d from %.60s\n",
			       round_num,
			       conn->internal_read_buf + net_header_BYTES);
			uint32_t mb = (uint32_t) (XXH64(conn->internal_read_buf + 8, user_id_BYTES, 0)
				% s->mix->af_mb_container.num_mailboxes);
			af_mailbox_s *mailbox = &s->mix->af_mb_container.mailboxes[mb];
			byte_buffer_s *buf = calloc(1, sizeof *buf);
			buf->base = mailbox->data;
			buf->pos = buf->base;
			conn->write_buf = buf;
			conn->bytes_written = 0;
			conn->write_remaining = mailbox->size_bytes;
			epoll_send(s, conn);
		}

		ssize_t remaining = conn->bytes_read - (conn->curr_msg_len + net_header_BYTES);
		if (remaining > 0) {
			memcpy(conn->internal_read_buf,
			       conn->internal_read_buf + conn->curr_msg_len + net_header_BYTES,
			       (size_t) remaining);
		}

		conn->bytes_read = remaining;
		conn->msg_type = 0;
		conn->curr_msg_len = 0;

	}

}

void net_client_lastmix_read(void *s, connection *conn, ssize_t count)
{
	net_server_s *srv = (net_server_s *) s;
	conn->bytes_read += count;
	// Reading the start of the message, so will be using internal buffer
	// determine the message type
	while (conn->bytes_read > 0) {
		if (conn->curr_msg_len == 0) {
			if ((count < net_header_BYTES)) {
				return;
			}
			uint32_t msg_type = deserialize_uint32(conn->internal_read_buf);
			uint32_t num_msgs = deserialize_uint32(conn->internal_read_buf + 4);
			if (msg_type == AF_BATCH) {
				conn->msg_type = AF_BATCH;
				conn->read_buf = &srv->mix->af_data.in_buf;
				uint32_t message_len = num_msgs * conn->read_buf->msg_len_bytes;
				conn->curr_msg_len = message_len;
				conn->read_buf->num_msgs = num_msgs;
			}
			else if (msg_type == DIAL_BATCH) {
				conn->msg_type = DIAL_BATCH;
				conn->read_buf = &srv->mix->dial_data.in_buf;
				uint32_t message_len = num_msgs * conn->read_buf->msg_len_bytes;
				conn->curr_msg_len = message_len;
				conn->read_buf->num_msgs = num_msgs;
			}

			else {
				fprintf(stderr, "Invalid message %c\n", conn->internal_read_buf[0]);
				close(conn->sock_fd);
				return;
			}
			//printf("Read status | Bytes read: %d | Message length: %d | Num msgs: %d\n", conn->bytes_read, conn->curr_msg_len, conn->read_buf->num_msgs);
			size_t data_bytes = (size_t) count - net_header_BYTES;
			memcpy(conn->read_buf->pos, conn->internal_read_buf + net_header_BYTES, data_bytes);
			conn->read_buf->pos += data_bytes;
		}

		if (conn->bytes_read < conn->curr_msg_len + net_header_BYTES) {
			return;
		}

		if (conn->bytes_read >= conn->curr_msg_len + net_header_BYTES) {
			if (conn->msg_type == AF_BATCH) {
				int z = srv->mix->af_data.out_buf.num_msgs;
				mix_af_decrypt_messages(srv->mix);

				if (srv->mix->is_last) {
					mix_af_distribute(srv->mix);
					net_broadcast_new_afmb(srv, srv->mix->af_data.round);
				}
				else {
					fprintf(stderr, "HELLO WHY ARE WE FORWARDING HERE\n");
					byte_buffer_s *buf = &srv->mix->af_data.out_buf;
					net_mix_batch_forward(s, buf);
				}
				mix_af_newround(srv->mix);
			}
			else if (conn->msg_type == DIAL_BATCH) {
				mix_dial_decrypt_messages(srv->mix);

				if (srv->mix->is_last) {
					mix_dial_distribute(srv->mix);
					net_broadcast_new_dmb(srv, srv->mix->dial_data.round);
				}
				else {
					byte_buffer_s *buf = &srv->mix->af_data.out_buf;
					net_mix_batch_forward(s, buf);
				}
				mix_dial_newround(srv->mix);

			}

			size_t remaining = (size_t) conn->bytes_read - (conn->curr_msg_len + net_header_BYTES);
			if (remaining > 0) {
				memcpy(conn->internal_read_buf, conn->read_buf->base + conn->curr_msg_len, remaining);
				conn->bytes_read = remaining;
			}
			conn->read_buf = NULL;
			conn->msg_type = 0;
			conn->curr_msg_len = 0;
			conn->bytes_read = remaining;
		}
	}
}

int net_mix_connect_prev(int srv_id)
{
	if (srv_id <= 0) {
		fprintf(stderr, "invalid server id %d\n", srv_id);
		return -1;
	}
	const char *port = mix_listen_ports[srv_id - 1];
	int sock_fd = net_connect("127.0.0.1", port, 0);
	if (sock_fd == -1) {
		fprintf(stderr, "could not connect to neighbouring mixnet server\n");
		return -1;
	}
	return sock_fd;
}

int net_mix_sync(net_server_s *es)
{
	uint32_t srv_id = es->mix->server_id;
	int res;
	if (es->mix->is_last) {
		int listen_socket = net_start_listen_socket(mix_listen_ports[srv_id], 1);
		if (listen_socket == -1) {
			fprintf(stderr, "failed to start listen socket\n");
			return -1;
		}
		es->listen_socket = listen_socket;
		printf("Listen socket for last mix %s: %d\n", mix_listen_ports[srv_id], es->listen_socket);
		connection *listen_conn = calloc(1, sizeof *listen_conn);
		listen_conn->sock_fd = es->listen_socket;
		struct epoll_event event;
		event.data.ptr = listen_conn;
		event.events = EPOLLIN | EPOLLET;
		epoll_ctl(es->epoll_inst, EPOLL_CTL_ADD, es->listen_socket, &event);

	}
		// Unless we're the last server in the mixnet chain, setup a temp listening socket to allow the next server
		// to establish a connection
	else {
		int listen_socket = net_start_listen_socket(mix_listen_ports[srv_id], 0);
		es->listen_socket = listen_socket;
		int next_mix_sfd = net_accept(listen_socket, 0);

		if (next_mix_sfd == -1) {
			fprintf(stderr, "fatal error on listening socket\n");
			return -1;
		}

		es->next_mix.sock_fd = next_mix_sfd;
		res = net_read_nb(es->next_mix.sock_fd,
		                  es->bc_buf.data + crypto_box_PUBLICKEYBYTES,
		                  es->bc_buf.capacity_bytes - crypto_box_PUBLICKEYBYTES);
		close(listen_socket);

		if (res) {
			fprintf(stderr, "fatal socket error during mix startup\n");
			return -1;
		}

		uint8_t *ptr = es->bc_buf.data + es->bc_buf.prefix_size + crypto_box_PUBLICKEYBYTES;
		for (int i = 1; i <= es->mix->num_out_onion_layers; i++) {
			memcpy(es->mix->mix_dh_pks[i], ptr, crypto_box_PUBLICKEYBYTES);
			ptr += es->bc_buf.prefix_size + crypto_box_PUBLICKEYBYTES;
		}
		mix_dial_add_noise(es->mix);
		mix_af_add_noise(es->mix);
		es->next_mix.event.events = EPOLLIN | EPOLLET;
		es->next_mix.event.data.ptr = &es->next_mix;
		res = epoll_ctl(es->epoll_inst, EPOLL_CTL_ADD, es->next_mix.sock_fd, &es->next_mix.event);
		if (res) {
			fprintf(stderr, "epoll_ctl error\n");
			return -1;
		}
		res = socket_set_nb(es->next_mix.sock_fd);
		if (res) {
			fprintf(stderr, "error when setting socket to non blocking\n");
		}
	}

	if (es->mix->server_id > 0) {
		es->prev_mix.sock_fd = net_mix_connect_prev(es->mix->server_id);
		es->prev_mix.on_read = net_client_lastmix_read;
		res = net_send_nb(es->prev_mix.sock_fd, es->bc_buf.base, es->bc_buf.prefix_size + es->bc_buf.capacity_bytes);
		if (res) {
			fprintf(stderr, "socker error writing to previous server in mixnet chain\n");
			return -1;
		}
		es->prev_mix.event.events = EPOLLIN | EPOLLET;
		es->prev_mix.event.data.ptr = &es->prev_mix;
		res = epoll_ctl(es->epoll_inst, EPOLL_CTL_ADD, es->prev_mix.sock_fd, &es->prev_mix.event);
		if (res) {
			fprintf(stderr, "epoll_ctrl error\n");
			return -1;
		}
		res = socket_set_nb(es->prev_mix.sock_fd);
		if (res) {
			fprintf(stderr, "failure setting socket to non blocking mode\n");
			return -1;
		}
	}
	return 0;
}

void net_client_sync(net_server_s *s, connection *conn)
{
	//conn->write_buf = &s->bc_buf;
	//conn->bytes_written = 0;
	//conn->write_remaining = s->bc_buf.capacity_bytes;
	printf("Client connected, sockfd = %d, sending initial sync message\n", conn->sock_fd);
	send(conn->sock_fd, s->bc_buf.base, s->bc_buf.prefix_size + s->bc_buf.capacity_bytes, 0);
}

void remove_client(net_server_s *s, connection *conn)
{
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

void net_broadcast_new_dr(net_server_s *s)
{
	connection *conn = s->clients;
	uint8_t bc_buf[net_header_BYTES];
	serialize_uint32(bc_buf, NEW_DIAL_ROUND);
	serialize_uint32(bc_buf + 4, s->mix->dial_data.round);
	while (conn) {
		ssize_t count = send(conn->sock_fd, bc_buf, sizeof bc_buf, 0);
		//printf("Broadcast new DR round \n");
		conn = conn->next;
	}
}

void net_broadcast_new_dmb(net_server_s *s, uint32_t round)
{
	uint8_t bc_buff[net_header_BYTES];
	serialize_uint32(bc_buff, NEW_DMB_AVAIL);
	serialize_uint32(bc_buff + 4, round);
	connection *conn = s->clients;
	while (conn) {
		send(conn->sock_fd, bc_buff, sizeof bc_buff, 0);
		//printf("Broadcast new dial mailbox avail to client\n");
		conn = conn->next;
	}
}

void net_broadcast_new_afmb(net_server_s *s, uint32_t round)
{
	uint8_t bc_buff[net_header_BYTES];
	serialize_uint32(bc_buff, NEW_AFMB_AVAIL);
	serialize_uint32(bc_buff + 4, round);
	connection *conn = s->clients;
	while (conn) {
		send(conn->sock_fd, bc_buff, sizeof bc_buff, 0);
		//printf("Broadcast new af mailbox avail to client\n");
		conn = conn->next;
	}
}

void net_broadcast_new_afr(net_server_s *s)
{
	uint8_t bc_buf[net_header_BYTES];
	serialize_uint32(bc_buf, NEW_AF_ROUND);
	serialize_uint32(bc_buf + 4, s->mix->af_data.round);

	connection *conn = s->clients;
	while (conn) {
		send(conn->sock_fd, bc_buf, sizeof bc_buf, 0);
		//printf("Broadcast new af round to clientt\n");
		conn = conn->next;
	}
}

int net_entry_sync(net_server_s *es)
{
	int res;
	struct epoll_event event;
	event.events = EPOLLIN | EPOLLET;
	int listen_fd = net_start_listen_socket("3000", 0);
	// Wait for PKG servers to connect
	for (int i = 0; i < num_pkg_servers; i++) {
		int fd = net_accept(listen_fd, 1);
		es->pkg_conns[i].sock_fd = fd;
		event.data.ptr = &es->pkg_conns[i];
		epoll_ctl(es->epoll_inst, EPOLL_CTL_ADD, fd, &event);
	}
	//close(listen_fd);
	// Wait for the rest of the mixnet servers to start and connect to us
	res = net_mix_sync(es);
	if (res) {
		fprintf(stderr, "fatal error during mixnet startup\n");
		return -1;
	}

	// Start main listening socket for client connections
	es->listen_socket = net_start_listen_socket("7000", 1);
	if (es->listen_socket == -1) {
		fprintf(stderr, "entry mix error when starting listensocket\n");
		return -1;
	}
	connection *listen_conn = calloc(1, sizeof *listen_conn);
	listen_conn->sock_fd = es->listen_socket;
	event.data.ptr = listen_conn;
	event.events = EPOLLIN | EPOLLET;
	epoll_ctl(es->epoll_inst, EPOLL_CTL_ADD, es->listen_socket, &event);

	return 0;
}

void net_mix_entry_clientread(void *server, connection *conn, ssize_t count)
{
	net_server_s *s = (net_server_s *) server;
	conn->bytes_read += count;

	while (conn->bytes_read > 0) {
		if (conn->curr_msg_len == 0) {
			if (conn->bytes_read < net_header_BYTES) {
				return;
			}

			uint32_t msg_type = deserialize_uint32(conn->internal_read_buf);
			if (msg_type == CLIENT_DIAL_MSG) {
				conn->msg_type = CLIENT_DIAL_MSG;
				conn->curr_msg_len = onionenc_dial_token_BYTES;
			}
			else if (msg_type == CLIENT_AF_MSG) {
				conn->msg_type = CLIENT_AF_MSG;
				conn->curr_msg_len = onionenc_friend_request_BYTES;
			}

		}
		printf("Client msg bytes read: %ld | remaining: %ld\n", conn->bytes_read, conn->read_remaining);
		if (conn->bytes_read < net_header_BYTES + conn->curr_msg_len) {
			return;
		}

		if (conn->msg_type == CLIENT_DIAL_MSG) {
			//printf("Adding dial msg from client...\n");
			mix_dial_add_inc_msg(s->mix, conn->internal_read_buf + net_header_BYTES);
		}
		else if (conn->msg_type == CLIENT_AF_MSG) {
			//printf("Adding AF msg from client\n");
			mix_af_add_inc_msg(s->mix, conn->internal_read_buf + net_header_BYTES);
		}

		ssize_t remaining = conn->bytes_read - (conn->curr_msg_len + net_header_BYTES);
		if (remaining > 0) {
			memcpy(conn->internal_read_buf,
			       conn->internal_read_buf + conn->curr_msg_len + net_header_BYTES,
			       (size_t) remaining);
		}

		conn->bytes_read = remaining;
		conn->msg_type = 0;
		conn->curr_msg_len = 0;

	}

}

int es_init(net_server_s *server, mix_s *mix)
{
	server->mix = mix;
	server->epoll_inst = epoll_create1(0);

	if (server->epoll_inst == -1) {
		fprintf(stderr, "Entry Server: failure when creating epoll instance\n");
		return -1;
	}

	uint32_t buffer_size = (12 + crypto_box_PUBLICKEYBYTES) * (num_mix_servers - server->mix->server_id);
	byte_buffer_init(&server->bc_buf, 1, buffer_size, 12);
	serialize_uint32(server->bc_buf.base, MIX_SYNC);
	serialize_uint32(server->bc_buf.base + 4, mix->af_data.round);
	serialize_uint32(server->bc_buf.base + 8, mix->dial_data.round);
	memcpy(server->bc_buf.data, server->mix->mix_dh_pks[0], crypto_box_PUBLICKEYBYTES);

	server->events = calloc(2000, sizeof *server->events);
	connection_init(&server->prev_mix);
	connection_init(&server->next_mix);
	server->clients = NULL;
	return 0;
}

int epoll_accept(net_server_s *es,
                 void on_accept(net_server_s *, connection *),
                 void on_read(void *, connection *, ssize_t))
{
	for (;;) {

		struct epoll_event event;
		int status;
		int new_sock;
		new_sock = net_accept(es->listen_socket, 1);
		if (new_sock == -1) {
			// All new connections processed
			if ((errno == EAGAIN || errno == EWOULDBLOCK)) {
				break;
			}
			// Something broke
			perror("client accept");
			continue;
		}

		connection *new_conn = calloc(1, sizeof(*new_conn));
		if (!new_conn) {
			perror("malloc");
			return -1;
		}

		new_conn->sock_fd = new_sock;
		event.data.ptr = new_conn;
		event.events = EPOLLIN | EPOLLET;
		status = epoll_ctl(es->epoll_inst, EPOLL_CTL_ADD, new_sock, &event);

		if (status == -1) {
			perror("epoll_ctl");
			return -1;
		}
		if (es->clients) {
			es->clients->prev = new_conn;
		}
		new_conn->next = es->clients;
		new_conn->prev = NULL;
		es->clients = new_conn;
		new_conn->on_read = on_read;
		printf("Connection accepted on %d, new sockfd: %d\n", es->listen_socket, new_conn->sock_fd);
		if (on_accept) {
			on_accept(es, new_conn);
		}

	}
	return 0;
}

void net_mix_batch_forward(net_server_s *s, byte_buffer_s *buf)
{
	connection *conn = &s->next_mix;
	if (s->next_mix.sock_fd == -1) {
		fprintf(stderr, "STOP TRYING TO FORWARD PLS\n");
		return;
	}
	conn->write_buf = buf;
	conn->bytes_written = 0;
	conn->write_remaining = net_header_BYTES + (buf->num_msgs * buf->msg_len_bytes);
	buf->pos = buf->base;
	epoll_send(s, conn);
}

void net_mix_af_forward(net_server_s *s)
{
	mix_af_decrypt_messages(s->mix);
	net_broadcast_new_afr(s);
	byte_buffer_s *buf = &s->mix->af_data.out_buf;
	net_mix_batch_forward(s, buf);
	mix_af_newround(s->mix);
	mix_af_add_noise(s->mix);
}

void net_mix_dial_forward(net_server_s *s)
{
	mix_dial_decrypt_messages(s->mix);
	net_broadcast_new_dr(s);
	net_mix_batch_forward(s, &s->mix->dial_data.out_buf);
	mix_dial_newround(s->mix);
	mix_dial_add_noise(s->mix);
}

void epoll_send(net_server_s *s, connection *conn)
{
	int close_connection = 0;
	while (conn->write_remaining > 0) {
		ssize_t count = send(conn->sock_fd, conn->write_buf->pos, (size_t) conn->write_remaining, 0);
		if (count == -1) {
			if (errno != EAGAIN) {
				fprintf(stderr, "socket send error %d on %d\n", errno, conn->sock_fd);
				close_connection = 1;
			}
			break;
		}
		else if (count == 0) {
			fprintf(stderr, "Socket send 0 bytes on %d\n", conn->sock_fd);
			close_connection = 1;
			break;
		}
		else {
			conn->bytes_written += count;
			conn->write_buf->pos += count;
			conn->write_remaining -= count;
			//printf("Sent %ld, %ld remaining on sock %d\n", count, conn->write_remaining, conn->sock_fd);
			if (conn->on_write) {
				conn->on_write(s, conn, count);
			}

		}
	}
	if (close_connection) {
		fprintf(stderr, "Closing socket %d in epoll send\n", conn->sock_fd);
		//close(conn->sock_fd);
		return;
		//free(conn);
	}

	// If we haven't finished writing, make sure EPOLLOUT is set
	if (conn->write_remaining != 0 && !(conn->event.events & EPOLLOUT)) {
		conn->event.events = EPOLLOUT | EPOLLET;
		epoll_ctl(s->epoll_inst, EPOLL_CTL_MOD, conn->sock_fd, &conn->event);
	}
		// If we have finished writing, make sure to unset EPOLLOUT
	else if (conn->write_remaining == 0 && conn->event.events & EPOLLOUT) {
		conn->event.events = EPOLLIN | EPOLLET;
		epoll_ctl(s->epoll_inst, EPOLL_CTL_MOD, conn->sock_fd, &conn->event);
	}
}

int epoll_read(net_server_s *es, connection *conn)
{
	int close_connection = 0;
	for (;;) {
		ssize_t count;
		if (conn->read_buf != NULL) {
			byte_buffer_s *read_buf = conn->read_buf;
			count = read(conn->sock_fd, read_buf->pos, (size_t) read_buf->capacity_bytes - conn->bytes_read);
		}
		else {
			count = read(conn->sock_fd,
			             conn->internal_read_buf + conn->bytes_read,
			             sizeof conn->internal_read_buf - conn->bytes_read);
		}
		if (count == -1) {
			if (errno != EAGAIN) {
				perror("read");
				close_connection = 1;
			}
			break;
		}
		else if (count == 0) {
			printf("Sock read 0 in epoll read, sock %d\n", conn->sock_fd);
			close_connection = 1;
			break;
		}
		if (conn->on_read) {
			conn->on_read(es, conn, count);
		}
	}

	if (close_connection) {
		fprintf(stderr, "Epoll read: closing connection on sock %d..\n", conn->sock_fd);
		//close(conn->sock_fd);
	}
	return 0;
}

void check_time(net_server_s *s)
{
	time_t rem = s->next_dial_round - time(0);
	if (rem <= 0) {
		net_mix_dial_forward(s);
		s->next_dial_round = time(0) + s->mix->dial_data.round_duration;
		printf("New dial round started: %u\n", s->mix->dial_data.round);
	}

	rem = s->next_af_round - time(0);
	if (rem <= 0) {
		net_mix_af_forward(s);
		s->next_af_round = time(0) + s->mix->af_data.round_duration;
		printf("New add friend round started: %u\n", s->mix->af_data.round);
	}
}

/*void net_mix_loop(net_server_s *es)
{

	struct epoll_event *events = es->events;
	es->running = 1;
	while (es->running) {
		int n = epoll_wait(es->epoll_inst, es->events, 100, 5000);
		connection *conn = NULL;
		// Error of some sort on the socket
		for (int i = 0; i < n; i++) {
			if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
				conn = events[i].data.ptr;
				fprintf(stderr, "Mix loop: Closing connection on sock %d\n", conn->sock_fd);
				close(conn->sock_fd);
				free(events[i].data.ptr);
				continue;
			}
				// Read from a socket
			else if (events[i].events & EPOLLIN) {
				conn = events[i].data.ptr;
				epoll_read(es, conn);
			}
			else if (events[i].events & EPOLLOUT) {
				conn = events[i].data.ptr;
				epoll_send(es, conn);
			}
		}
	}

}*/

void net_srv_loop(net_server_s *es,
                  void on_accept(net_server_s *, connection *),
                  void on_read(void *, connection *, ssize_t))
{

	struct epoll_event *events = es->events;
	es->running = 1;
	es->next_af_round = time(0) + es->mix->af_data.round_duration;
	es->next_dial_round = time(0) + es->mix->dial_data.round_duration;
	while (es->running) {
		if (es->mix->server_id == 0) {
			check_time(es);
		}
		int n = epoll_wait(es->epoll_inst, es->events, 100, 100);

		// Error of some sort on the socket
		for (int i = 0; i < n; i++) {
			connection *conn = events[i].data.ptr;
			if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
				fprintf(stderr, "Error on socket %d\n", conn->sock_fd);
				close(conn->sock_fd);
				remove_client(es, conn);
				continue;
			}
			else if (es->listen_socket == conn->sock_fd) {
				int res = epoll_accept(es, on_accept, on_read);
				if (res) {
					fprintf(stderr, "fatal server error\n");
					es->running = 0;
					exit(1);
				}
			}
				// Read from a socket
			else if (events[i].events & EPOLLIN) {
				conn = events[i].data.ptr;
				epoll_read(es, conn);
			}
			else if (events[i].events & EPOLLOUT) {
				epoll_send(es, conn);
			}
		}
	}
}

int main(int argc, char **argv)
{
	if (*argv[1] == '0') {
		net_server_s es;
		mix_s mix;
		mix_init(&mix, 0);
		es_init(&es, &mix);
		net_entry_sync(&es);
		net_srv_loop(&es, net_client_sync, net_mix_entry_clientread);
	}
	else {
		mix_s mix;
		mix_init(&mix, 1);
		net_server_s es;
		es_init(&es, &mix);
		net_mix_sync(&es);
		net_srv_loop(&es, NULL, net_mix_last_read);
	}
}

