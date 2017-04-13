/*
#include <string.h>
#include "mix.h"
#include <sys/socket.h>
#include <sys/epoll.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
//#include "mixnet_server.h"
*/
/**//*


struct remove_conn_list
{
	connection *conn;
	connection *next;
};

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
	struct remove_conn_list *remove_list;
};

void mix_pkg_broadcast(mix_s *s)
{
	uint8_t buf[net_header_BYTES];
	memset(buf, 0, net_header_BYTES);
	serialize_uint32(buf, NEW_AF_ROUND);
	serialize_uint64(buf + 8, s->mix->af_data.round);
	for (int i = 0; i < num_pkg_servers; i++) {
		send(s->pkg_conns[i].sock_fd, buf, net_header_BYTES, 0);
	}
}

void mix_exit_process_client_msg(void *server, connection *conn)
{
	net_server_s *s = (net_server_s *) server;

	if (conn->msg_type == CLIENT_DIAL_MB_REQUEST) {
		uint64_t mb_round = deserialize_uint64(conn->read_buf->data + 8);
		printf("Received Dial mailbox download request for round %ld from %.60s\n", mb_round, conn->read_buf->data + net_header_BYTES);
		dial_mailbox_s *request_mb = mix_dial_get_mailbox_buffer(s->mix, mb_round, conn->read_buf->data + net_header_BYTES);
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
		uint64_t round_num = deserialize_uint64(conn->read_buf->data + 8);
		printf("Received AF mailbox download request for round %ld from %.60s\n", round_num, conn->read_buf->data + net_header_BYTES);
		af_mailbox_s *mailbox = &s->mix->af_mb_container.mailboxes[0];
		byte_buffer_s *buf = calloc(1, sizeof *buf);
		buf->base = mailbox->data;
		buf->pos = buf->base;
		conn->write_buf = buf;
		conn->bytes_written = 0;
		conn->write_remaining = mailbox->size_bytes;
		epoll_send(s, conn);
	}

	else {
		fprintf(stderr, "Invalid message\n");
	}
}

void mix_process_mix_msg(void *s, connection *conn)
{
	net_server_s *srv = (net_server_s *) s;

	if (conn->msg_type == AF_BATCH) {
		srv->mix->af_data.num_inc_msgs = conn->curr_msg_len / srv->mix->af_data.inc_msg_length;
		byte_buffer_put(&srv->mix->af_data.in_buf, conn->read_buf->data + net_header_BYTES, (size_t) conn->curr_msg_len);
		mix_af_decrypt_messages(srv->mix);
		if (srv->mix->is_last) {
			mix_af_s *af = &srv->mix->af_data;
			printf("AF Round %ld: Received %ld msgs, added %ld noise, discarded %ld cover msgs -> Distributing %ld\n", af->round, af->num_inc_msgs,
			       af->last_noise_count, af->num_inc_msgs + af->last_noise_count - af->num_out_msgs, af->num_out_msgs);
			mix_af_distribute(srv->mix);
			mix_broadcast_new_afmb(srv, srv->mix->af_data.round);
		}
		else {
			byte_buffer_s *buf = &srv->mix->af_data.out_buf;
			mix_batch_forward(srv, buf);
		}
		mix_af_newround(srv->mix);
	}

	else if (conn->msg_type == DIAL_BATCH) {
		srv->mix->dial_data.num_inc_msgs = (uint32_t) conn->curr_msg_len / srv->mix->dial_data.inc_msg_length;
		byte_buffer_put(&srv->mix->dial_data.in_buf, conn->read_buf->data + net_header_BYTES, conn->curr_msg_len);
		mix_dial_decrypt_messages(srv->mix);

		if (srv->mix->is_last) {
			mix_dial_s *dd = &srv->mix->dial_data;
			printf("Dial Round %ld: Received %d msgs, added %lu noisem, discarded %lu noise -> Distributing %d\n",
			       dd->round,
			       dd->num_inc_msgs,
			       dd->last_noise_count,
			       dd->num_inc_msgs + dd->last_noise_count - dd->num_out_msgs,
			       dd->num_out_msgs);
			mix_dial_distribute(srv->mix);
			mix_broadcast_new_dialmb(srv, srv->mix->dial_data.round);
		}
		else {
			byte_buffer_s *buf = &srv->mix->af_data.out_buf;
			mix_batch_forward(srv, buf);
		}
		mix_dial_newround(srv->mix);
	}
}

int mix_connect_neighbour(int srv_id)
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

int net_mix_sync(mix_s *es)
{
	uint32_t srv_id = es->mix->server_id;
	int res;
	if (es->mix->is_last) {
		int listen_socket = net_start_listen_socket(mix_listen_ports[srv_id], 1);
		if (listen_socket == -1) {
			fprintf(stderr, "failed to start listen socket\n");
			return -1;
		}
		printf("[Mix distribution: initialised]\n");
		es->listen_socket = listen_socket;
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

		res = net_read_nonblock(es->next_mix.sock_fd,
		                  es->next_mix.read_buf->data,
		                  (size_t) net_header_BYTES + es->bc_buf.capacity - crypto_box_PUBLICKEYBYTES);
		byte_buffer_put(&es->bc_buf,
		                es->next_mix.read_buf->data + net_header_BYTES,
		                (size_t) es->bc_buf.capacity - crypto_box_PUBLICKEYBYTES);

		close(listen_socket);

		if (res) {
			fprintf(stderr, "fatal socket error during mix startup\n");
			return -1;
		}

		uint8_t *ptr = es->bc_buf.data + crypto_box_PUBLICKEYBYTES;
		for (int i = 1; i <= es->mix->num_out_onion_layers; i++) {
			memcpy(es->mix->mix_dh_pks[i], ptr, crypto_box_PUBLICKEYBYTES);
			ptr += crypto_box_PUBLICKEYBYTES;
		}

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
		es->prev_mix.sock_fd = mix_connect_neighbour(es->mix->server_id);
		es->prev_mix.process = mix_process_mix_msg;
		res = net_send_nonblock(es->prev_mix.sock_fd, es->bc_buf.base, (size_t) es->bc_buf.prefix_size + es->bc_buf.capacity);
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
		res = socket_set_nonblocking(es->prev_mix.sock_fd);
		if (res) {
			fprintf(stderr, "failure setting socket to non blocking mode\n");
			return -1;
		}
	}
	mix_dial_add_noise(es->mix);
	mix_af_add_noise(es->mix);
	return 0;
}

void mix_client_onconnect(net_server_s *s, connection *conn)
{
	send(conn->sock_fd, s->bc_buf.base, net_header_BYTES + net_client_connect_BYTES, 0);
}

void mix_remove_client(net_server_s *s, connection *conn)
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

void mix_broadcast_dialround(net_server_s *s)
{
	connection *conn = s->clients;
	uint8_t bc_buf[net_header_BYTES];
	memset(bc_buf, 0, net_header_BYTES);
	serialize_uint32(bc_buf, NEW_DIAL_ROUND);
	serialize_uint32(s->bc_buf.base, NEW_DIAL_ROUND);
	serialize_uint64(s->bc_buf.base + 16, s->mix->dial_data.round);
	serialize_uint32(bc_buf + net_msg_type_BYTES, 0);
	serialize_uint64(bc_buf + 8, s->mix->dial_data.round);
	while (conn) {
		send(conn->sock_fd, bc_buf, sizeof bc_buf, 0);
		conn = conn->next;
	}
}

void mix_broadcast_new_dialmb(net_server_s *s, uint64_t round)
{
	uint8_t bc_buff[net_header_BYTES];
	serialize_uint32(bc_buff, NEW_DMB_AVAIL);
	serialize_uint32(bc_buff + 4, 0);
	serialize_uint32(bc_buff + net_msg_type_BYTES, 0);
	serialize_uint64(bc_buff + 8, round);
	connection *conn = s->clients;
	while (conn) {
		send(conn->sock_fd, bc_buff, sizeof bc_buff, 0);
		//printf("Broadcast new dial mailbox avail to client\n");
		conn = conn->next;
	}
}

void mix_broadcast_new_afmb(net_server_s *s, uint64_t round)
{
	uint8_t bc_buff[net_header_BYTES];
	serialize_uint32(bc_buff, NEW_AFMB_AVAIL);
	serialize_uint32(bc_buff + 4, 0);
	serialize_uint64(bc_buff + 8, round);
	connection *conn = s->clients;
	while (conn) {
		send(conn->sock_fd, bc_buff, sizeof bc_buff, 0);
		//printf("Broadcast new af mailbox avail to client\n");
		conn = conn->next;
	}
}

void mix_broadcast_new_afr(net_server_s *s)
{
	uint8_t bc_buf[net_header_BYTES];
	memset(bc_buf, 0, net_header_BYTES);
	serialize_uint32(bc_buf, NEW_AF_ROUND);
	serialize_uint32(s->bc_buf.base, NEW_AF_ROUND);
	serialize_uint64(s->bc_buf.base + 8, s->mix->af_data.round);
	serialize_uint64(bc_buf + 8, s->mix->af_data.round);
	connection *conn = s->clients;
	while (conn) {
		send(conn->sock_fd, bc_buf, sizeof bc_buf, 0);
		conn = conn->next;
	}
}

int mix_entry_sync(net_server_s *es)
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
	es->listen_socket = net_start_listen_socket(mix_client_listen, 1);
	if (es->listen_socket == -1) {
		fprintf(stderr, "entry mix error when starting listensocket\n");
		return -1;
	}
	connection *listen_conn = calloc(1, sizeof *listen_conn);
	listen_conn->sock_fd = es->listen_socket;
	event.data.ptr = listen_conn;
	event.events = EPOLLIN | EPOLLET;
	epoll_ctl(es->epoll_inst, EPOLL_CTL_ADD, es->listen_socket, &event);
	printf("[Mix entry: established connection to mixnet and PKG servers]\n");
	printf("[Mix entry: system initialised]\n");
	return 0;
}
void net_process_read(net_server_s *s, connection *conn, ssize_t count)
{
	conn->bytes_read += count;
	conn->read_buf->pos += count;
	conn->read_buf->used += count;

	while (conn->bytes_read > 0) {
		if (conn->curr_msg_len == 0) {
			if ((count < net_header_BYTES)) {
				return;
			}

			conn->msg_type = deserialize_uint32(conn->read_buf->data);
			conn->curr_msg_len = deserialize_uint32(conn->read_buf->data + net_msg_type_BYTES);
		}
		// Message hasn't been fully received
		if (conn->bytes_read < conn->curr_msg_len + net_header_BYTES) {
			return;
		}

		conn->process(s, conn);

		size_t read_remaining = (conn->bytes_read - conn->curr_msg_len - net_header_BYTES);

		if (read_remaining > 0) {
			memcpy(conn->read_buf->data,
			       conn->read_buf->data + net_header_BYTES + conn->curr_msg_len,
			       read_remaining);
		}

		conn->curr_msg_len = 0;
		conn->msg_type = 0;
		conn->bytes_read = read_remaining;
		conn->read_buf->used = read_remaining;
		conn->read_buf->pos = conn->read_buf->data + read_remaining;
	}
}

void mix_process_client_msg(void *server, connection *conn)
{
	net_server_s *s = (net_server_s *) server;

	if (conn->msg_type == CLIENT_DIAL_MSG) {
		mix_dial_add_inc_msg(s->mix, conn->read_buf->data + net_header_BYTES);
	}
	else if (conn->msg_type == CLIENT_AF_MSG) {
		mix_af_add_inc_msg(s->mix, conn->read_buf->data + net_header_BYTES);
	}
	else {
		fprintf(stderr, "Invalid client msg\n");
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
	signal(SIGPIPE, SIG_IGN);
	uint32_t buffer_size = crypto_box_PUBLICKEYBYTES * (num_mix_servers - server->mix->server_id);
	byte_buffer_init(&server->bc_buf, buffer_size, net_header_BYTES);
	serialize_uint32(server->bc_buf.base, MIX_SYNC);
	serialize_uint32(server->bc_buf.base + net_msg_type_BYTES, buffer_size);
	serialize_uint64(server->bc_buf.base + 8, mix->af_data.round);
	serialize_uint64(server->bc_buf.base + 16, mix->dial_data.round);
	byte_buffer_put(&server->bc_buf, server->mix->mix_dh_pks[0], crypto_box_PUBLICKEYBYTES);

	server->events = calloc(2000, sizeof *server->events);
	connection_init(&server->prev_mix);
	connection_init(&server->next_mix);
	server->clients = NULL;
	return 0;
}

int epoll_accept(void *es,
                 void on_accept(net_server_s *, connection *),
                 void on_read(void *, connection *))
{
	for (;;) {

		struct epoll_event event;
		int status;
		int new_sock;
		new_sock = net_epoll_accept(es->listen_socket, 1);
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
		connection_init(new_conn);
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
		new_conn->process = on_read;
		printf("Connection accepted on %d, new sockfd: %d\n", es->listen_socket, new_conn->sock_fd);
		if (on_accept) {
			on_accept(es, new_conn);
		}

	}
	return 0;
}

void mix_batch_forward(net_server_s *s, byte_buffer_s *buf)
{
	connection *conn = &s->next_mix;

	conn->write_buf = buf;
	conn->bytes_written = 0;
	conn->write_remaining = buf->prefix_size + buf->used;

	buf->pos = buf->base;
	epoll_send(s, conn);
}

void mix_af_forward(net_server_s *s)
{
	mix_af_decrypt_messages(s->mix);
	mix_af_s *af_data = &s->mix->af_data;
	printf("AF Round %ld: Received %ld msgs, added %ld noise -> Forwarding %ld\n",
	       af_data->round,
	       af_data->num_inc_msgs,
	       af_data->last_noise_count,
	       af_data->num_out_msgs);
	byte_buffer_s *buf = &s->mix->af_data.out_buf;
	mix_batch_forward(s, buf);
	mix_af_newround(s->mix);
	mix_broadcast_new_afr(s);
	mix_pkg_broadcast(s);
}

void mix_dial_forward(net_server_s *s)
{
	mix_dial_decrypt_messages(s->mix);
	mix_dial_s *dial_data = &s->mix->dial_data;
	printf("Dial Round %ld: Received %d msgs, added %lu noise -> Forwarding %d\n",
	       dial_data->round,
	       dial_data->num_inc_msgs,
	       dial_data->last_noise_count,
	       dial_data->num_out_msgs);
	mix_batch_forward(s, &s->mix->dial_data.out_buf);
	mix_dial_newround(s->mix);
	mix_broadcast_dialround(s);
}

void epoll_send(mix_s *s, connection *conn)
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
			if (conn->on_write)
				conn->on_write(s, conn, count);
		}
	}
	if (close_connection) {
		//close(conn->sock_fd);
		return;
		//free(conn);
	}

	if (conn->write_remaining != 0 && !(conn->event.events & EPOLLOUT)) {
		conn->event.events = EPOLLOUT | EPOLLET;
		epoll_ctl(s->epoll_inst, EPOLL_CTL_MOD, conn->sock_fd, &conn->event);
	}

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
		byte_buffer_s *read_buf = conn->read_buf;
		if (conn->read_buf->capacity == read_buf->used) {
			byte_buffer_resize(read_buf, read_buf->capacity * 2);
		}
		count = read(conn->sock_fd, read_buf->pos, read_buf->capacity - read_buf->used);

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

		net_process_read(es, conn, count);
	}

	if (close_connection) {
		fprintf(stderr, "Epoll read: closing connection on sock %d..\n", conn->sock_fd);
	}
	return 0;
}

void check_time(net_server_s *s)
{
	time_t rem = s->next_dial_round - time(0);
	if (rem <= 0) {
		mix_dial_forward(s);
		s->next_dial_round = time(0) + s->mix->dial_data.round_duration;
		printf("New dial round started: %lu\n", s->mix->dial_data.round);
	}

	rem = s->next_af_round - time(0);
	if (rem <= 0) {
		mix_entry_forward_af_batch(s);
		s->next_af_round = time(0) + s->mix->af_data.round_duration;
		printf("New add friend round started: %lu\n", s->mix->af_data.round);
	}
}

void mix_run(net_server_s *es,
             void on_accept(net_server_s *, connection *),
             void on_read(void *, connection *))
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
				mix_remove_client(es, conn);
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
				if (conn) {
					epoll_read(es, conn);
				}
			}
			else if (events[i].events & EPOLLOUT) {
				if (conn) {
					epoll_read(es, conn);
				}
			}
		}
	}
}

int main(int argc, char **argv)
{
	#if !USE_PBC
	bn256_init();
	#endif
	if (*argv[1] == '0') {
		net_server_s es;
		mix_s mix;
		mix_init(&mix, 0);
		es_init(&es, &mix);
		mix_entry_sync(&es);
		mix_run(&es, mix_client_onconnect, mix_process_client_msg);
	}
	else {
		mix_s mix;
		mix_init(&mix, 1);
		net_server_s es;
		mix_net_init(&es, &mix);
		mix_net_sync(&es);
		mix_run(&es, NULL, mix_exit_process_client_msg);
	}
}

*/
