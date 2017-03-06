#include <sys/epoll.h>
#include "client_net.h"
#include "client.h"
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include "net_common.h"



typedef struct client_net client_net_s;

struct client_net
{
	connection mix_entry;
	connection pkg_connections[num_pkg_servers];
	client_s *client;
	struct epoll_event *events;
	int epoll_inst;
	int num_broadcast_responses;
	int num_auth_responses;
	bool running;
};

int net_client_init(client_net_s *cs, client_s *c)
{
	cs->client = c;
	cs->epoll_inst = epoll_create1(0);
	cs->events = calloc(100, sizeof *cs->events);
	cs->num_auth_responses = 0;
	cs->num_broadcast_responses = 0;
	cs->running = 0;
	connection_init(&cs->mix_entry);
	for (int i = 0; i < num_pkg_servers; i++) {
		connection_init(&cs->pkg_connections[i]);
	}
	return 0;
}

void epoll_csend(client_net_s *c, connection *conn)
{
	int close_connection = 0;
	for (;;) {
		ssize_t count =
			send(conn->sock_fd, conn->internal_write_buf + conn->bytes_written, (size_t) conn->write_remaining, 0);
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
		epoll_ctl(c->epoll_inst, EPOLL_CTL_MOD, conn->sock_fd, &conn->event);
	}
		// If we have finished writing, make sure to unset EPOLLOUT
	else if (conn->write_remaining == 0 && conn->event.events & EPOLLOUT) {
		conn->event.events = EPOLLIN | EPOLLERR | EPOLLHUP;
		epoll_ctl(c->epoll_inst, EPOLL_CTL_MOD, conn->sock_fd, &conn->event);
	}
}

void epoll_send(client_net_s *c, connection *conn)
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
			printf("Sent %ld, %ld remaining on sock %d\n", count, conn->write_remaining, conn->sock_fd);
			if (conn->on_write) {
				conn->on_write(c, conn, count);
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
		epoll_ctl(c->epoll_inst, EPOLL_CTL_MOD, conn->sock_fd, &conn->event);
	}
		// If we have finished writing, make sure to unset EPOLLOUT
	else if (conn->write_remaining == 0 && conn->event.events & EPOLLOUT) {
		conn->event.events = EPOLLIN | EPOLLET;
		epoll_ctl(c->epoll_inst, EPOLL_CTL_MOD, conn->sock_fd, &conn->event);
	}
}

void net_client_mix_read(void *cl_ptr, connection *conn, ssize_t count)
{
	client_net_s *c = (client_net_s *) cl_ptr;
	ssize_t count_read = count;

	if (conn->curr_msg_len == 0) {

		uint32_t msg_type = deserialize_uint32(conn->internal_read_buf);
		if (msg_type == NEW_DIAL_ROUND) {
			serialize_uint32(conn->internal_write_buf, CLIENT_DIAL_MSG);
			serialize_uint32(conn->internal_write_buf + 4, c->client->dialling_round);
			memcpy(conn->internal_write_buf + 8, c->client->dial_request_buf, onionenc_dial_token_BYTES);
			conn->write_remaining = net_header_BYTES + onionenc_dial_token_BYTES;
			c->client->dialling_round++;
			ssize_t res = send(conn->sock_fd, conn->internal_write_buf, (size_t) conn->write_remaining, 0);
			printf("Client received new DR msg from mix (%ld), sent %ld in return\n", count, res);
			dial_fake_request(c->client);

		}
		else if (msg_type == NEW_AF_ROUND) {
			serialize_uint32(conn->internal_write_buf, CLIENT_AF_MSG);
			serialize_uint32(conn->internal_write_buf + 4, c->client->af_round);
			memcpy(conn->internal_write_buf + 8, c->client->friend_request_buf, onionenc_friend_request_BYTES);
			conn->write_remaining = net_header_BYTES + onionenc_friend_request_BYTES;
			c->client->dialling_round++;
			ssize_t res = send(conn->sock_fd, conn->internal_write_buf, (size_t) conn->write_remaining, 0);
			printf("Client received ner AF msg from mix, sending AF request (%ld bytes)\n", res);
			af_add_friend(c->client, (char *) user_ids[2]);
		}

	}
}

void net_client_pkg_read(void *cl_ptr, connection *conn, ssize_t count)
{
	client_net_s *client = (client_net_s *) cl_ptr;
	ssize_t c_read = count;
	if (conn->curr_msg_len == 0) {
		if ((count < net_header_BYTES)) {
			return;
		}

		uint32_t msg_type = deserialize_uint32(conn->internal_read_buf);
		if (msg_type == PKG_BR_MSG) {
			conn->msg_type = PKG_BR_MSG;
			conn->curr_msg_len = pkg_broadcast_msg_BYTES;
			conn->read_remaining = pkg_broadcast_msg_BYTES;
		}

		else if (msg_type == PKG_AUTH_RES_MSG) {
			conn->msg_type = PKG_AUTH_RES_MSG;
			conn->curr_msg_len = pkg_enc_auth_res_BYTES;
			conn->read_remaining = pkg_enc_auth_res_BYTES;
		}

		else {
			fprintf(stderr,
			        "Invalid message: %d | %ld bytes read\n",
			        deserialize_uint32(conn->internal_read_buf),
			        count);
			close(conn->sock_fd);
			return;
		}
		c_read -= net_header_BYTES;
	}

	conn->read_remaining -= c_read;
	conn->bytes_read += count;
	printf("Just read %lu of %ld | %ld remaining | Message type: %d\n",
	       c_read,
	       conn->curr_msg_len,
	       conn->read_remaining,
	       conn->msg_type);
	if (conn->read_remaining <= 0) {
		if (conn->msg_type == PKG_BR_MSG) {
			memcpy(client->client->pkg_broadcast_msgs[conn->id],
			       conn->internal_read_buf + net_header_BYTES, pkg_broadcast_msg_BYTES);
			client->num_broadcast_responses++;
		}
		else if (conn->msg_type == PKG_AUTH_RES_MSG) {
			memcpy(client->client->pkg_auth_responses[conn->id],
			       conn->internal_read_buf + net_header_BYTES, pkg_enc_auth_res_BYTES);
			client->num_auth_responses++;
		}

		conn->msg_type = 0;
		conn->curr_msg_len = 0;
		conn->bytes_read = 0;
	}
}

int net_cli_epread(client_net_s *client, connection *conn)
{
	int close_connection = 0;
	for (;;) {
		ssize_t count;
		count = read(conn->sock_fd,
		             conn->internal_read_buf + conn->bytes_read,
		             sizeof conn->internal_read_buf - conn->bytes_read);

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
			conn->on_read(client, conn, count);
		}
	}

	if (close_connection) {
		close(conn->sock_fd);
	}
	return 0;
}

int net_client_startup(client_net_s *cn)
{
	struct epoll_event event;
	int mix_sfd = net_connect("127.0.0.1", mix_client_listen, 0);
	if (mix_sfd == -1) {
		fprintf(stderr, "could not connect to mix entry server\n");
		return -1;
	}
	cn->mix_entry.sock_fd = mix_sfd;
	cn->mix_entry.on_read = net_client_mix_read;
	int res;
	res = net_read_nb(mix_sfd, cn->mix_entry.internal_read_buf, 12 + net_client_connect_BYTES);
	if (res == -1) {
		perror("client read");
	}
	cn->client->af_round = deserialize_uint32(cn->mix_entry.internal_read_buf + 4);
	cn->client->dialling_round = deserialize_uint32(cn->mix_entry.internal_read_buf + 8);

	uint8_t *dh_ptr = cn->mix_entry.internal_read_buf + 12;
	for (uint32_t i = 0; i < num_mix_servers; i++) {
		memcpy(cn->client->mix_eph_pub_keys[i], dh_ptr, crypto_box_PUBLICKEYBYTES);
		printhex("mix pk", cn->client->mix_eph_pub_keys[i], crypto_box_PUBLICKEYBYTES);
		dh_ptr += crypto_box_PUBLICKEYBYTES + 12;
	}
	af_fake_request(cn->client);
	dial_fake_request(cn->client);
	socket_set_nb(cn->mix_entry.sock_fd);
	event.data.ptr = &cn->mix_entry;
	event.events = EPOLLIN | EPOLLHUP;
	epoll_ctl(cn->epoll_inst, EPOLL_CTL_ADD, cn->mix_entry.sock_fd, &event);

	cn->client->af_round = deserialize_uint32(cn->mix_entry.internal_read_buf + 4);
	cn->client->dialling_round = deserialize_uint32(cn->mix_entry.internal_read_buf + 8);
	//TODO copy mix dh keys
	//TODO sync keywheels
	for (uint32_t i = 0; i < num_pkg_servers; i++) {
		connection *pkg_conn = &cn->pkg_connections[i];
		pkg_conn->sock_fd = net_connect("127.0.0.1", pkg_cl_listen_ports[i], 1);
		if (cn->pkg_connections[i].sock_fd == -1) {
			return -1;
		}
		pkg_conn->type = PKG;
		pkg_conn->id = i;
		pkg_conn->bytes_read = 0;
		pkg_conn->read_remaining = 0;
		pkg_conn->write_remaining = 0;
		pkg_conn->bytes_written = 0;
		pkg_conn->on_read = net_client_pkg_read;
		event.data.ptr = &cn->pkg_connections[i];
		event.events = EPOLLIN | EPOLLET;
		epoll_ctl(cn->epoll_inst, EPOLL_CTL_ADD, cn->pkg_connections[i].sock_fd, &event);
	}

	struct epoll_event *events = cn->events;
	while (cn->num_broadcast_responses < num_pkg_servers) {
		int n = epoll_wait(cn->epoll_inst, cn->events, 100, 5000);
		printf("Looping..\n");
		connection *conn = NULL;
		// Error of some sort on the socket
		for (int i = 0; i < n; i++) {
			conn = events[i].data.ptr;
			if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
				close(conn->sock_fd);
				free(events[i].data.ptr);
				continue;
			}
				// Read from a socket
			else if (events[i].events & EPOLLIN) {
				net_cli_epread(cn, conn);
			}
			else if (events[i].events & EPOLLOUT) {
				epoll_csend(cn, conn);
			}
		}
	}

	res = af_create_pkg_auth_request(cn->client);
	if (res) {
		fprintf(stderr, "Error creating authentication request\n");
	}

	for (int i = 0; i < num_pkg_servers; i++) {
		connection *conn = &cn->pkg_connections[i];
		memcpy(conn->internal_write_buf,
		       cn->client->pkg_auth_requests[i],
		       net_header_BYTES + cli_pkg_single_auth_req_BYTES);
		conn->bytes_written = 0;
		serialize_uint32(conn->internal_write_buf, CLI_AUTH_REQ);
		serialize_uint32(conn->internal_write_buf + sizeof(uint32_t), cn->client->af_round);
		conn->write_remaining = net_header_BYTES + cli_pkg_single_auth_req_BYTES;
		epoll_csend(cn, &cn->pkg_connections[i]);
	}

	while (cn->num_auth_responses < num_pkg_servers) {
		int n = epoll_wait(cn->epoll_inst, cn->events, 100, 5000);
		connection *conn = NULL;
		// Error of some sort on the socket
		for (int i = 0; i < n; i++) {
			conn = events[i].data.ptr;
			if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
				close(conn->sock_fd);
				free(events[i].data.ptr);
				continue;
			}
				// Read from a socket
			else if (events[i].events & EPOLLIN) {
				net_cli_epread(cn, conn);
			}
			else if (events[i].events & EPOLLOUT) {
				epoll_csend(cn, conn);
			}
		}
	}
	af_process_auth_responses(cn->client);
	return 0;
}

void net_client_loop(client_net_s *c)
{

	struct epoll_event *events = c->events;
	c->running = true;

	while (c->running) {
		int n = epoll_wait(c->epoll_inst, c->events, 100, 5000);
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
				net_cli_epread(c, conn);
			}
			else if (events[i].events & EPOLLOUT) {
				conn = events[i].data.ptr;
				epoll_send(c, conn);
			}
		}
	}

}

int main()
{
	client_s c;
	client_init(&c, user_ids[0], user_lt_pub_sig_keys[0], user_lt_secret_sig_keys[0]);
	client_net_s s;
	net_client_init(&s, &c);
	net_client_startup(&s);
	net_client_loop(&s);

}