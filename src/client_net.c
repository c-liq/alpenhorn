#include <sys/epoll.h>
#include "client_net.h"
#include "client.h"
#include <unistd.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include "net_common.h"

typedef struct client_connection client_connection;

enum actions
{
	ADD_FRIEND = '1',
	CONFIRM_FRIEND = '2',
	DIAL_FRIEND = '3',
	PRINT_KW_TABLE = '4',
};

typedef struct action action;

struct action
{
	enum actions type;
	char user_id[user_id_BYTES];
	uint32_t intent;
	action *next;
};

struct client_connection
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
	void (*on_read)(void *owner, client_connection *conn, ssize_t count);
	void (*on_write)(void *owner, client_connection *conn, ssize_t count);
	unsigned char conn_type;
};

typedef struct client_net client_net_s;

struct client_net
{
	client_connection mix_entry;
	client_connection mix_last;
	client_connection pkg_client_connections[num_pkg_servers];
	client_s *client;
	struct epoll_event *events;
	int epoll_inst;
	int num_broadcast_responses;
	int num_auth_responses;
	bool running;
	action *action_stack;
	pthread_mutex_t aq_lock;
};

void do_action(client_net_s *c, action *a)
{
	switch (a->type) {
	case ADD_FRIEND:
		printf("Doing action add friend.\n");
		af_add_friend(c->client, a->user_id);
		break;
	case CONFIRM_FRIEND:
		af_accept_request(c->client, a->user_id);
		break;
	case DIAL_FRIEND:
		dial_call_friend(c->client, (uint8_t *) a->user_id, a->intent);
		break;
	case PRINT_KW_TABLE:
		kw_print_table(&c->client->keywheel);
	}
	free(a);
}

action *action_stack_pop(client_net_s *c)
{
	pthread_mutex_lock(&c->aq_lock);
	if (!c->action_stack) {
		pthread_mutex_unlock(&c->aq_lock);
		return NULL;
	}

	action *popped = c->action_stack;
	c->action_stack = c->action_stack->next;
	pthread_mutex_unlock(&c->aq_lock);

	return popped;
}

void *action_stack_push(client_net_s *c, action *new_action)
{
	pthread_mutex_lock(&c->aq_lock);
	printf("Pushing action type %c | userid: %s\n", new_action->type, new_action->user_id);
	new_action->next = c->action_stack;
	c->action_stack = new_action;
	pthread_mutex_unlock(&c->aq_lock);
}

void client_connection_init(client_connection *conn)
{
	conn->bytes_read = 0;
	conn->msg_type = 0;
	conn->bytes_written = 0;
	conn->write_remaining = 0;
	conn->sock_fd = -1;
	conn->event.data.ptr = conn;
	conn->curr_msg_len = 0;
	conn->on_write = NULL;
	conn->on_read = NULL;
	conn->event.events = 0;
	conn->read_buf = calloc(1, sizeof *conn->read_buf);
	byte_buffer_init(conn->read_buf, 1, 16384, 0);
	memset(conn->write_buf, 0, sizeof conn->write_buf);
}

int net_client_init(client_net_s *cs, client_s *c)
{
	pthread_mutex_init(&cs->aq_lock, NULL);
	cs->action_stack = NULL;
	cs->client = c;
	cs->epoll_inst = epoll_create1(0);
	cs->events = calloc(100, sizeof *cs->events);
	cs->num_auth_responses = 0;
	cs->num_broadcast_responses = 0;
	cs->running = 0;


	client_connection_init(&cs->mix_entry);
	client_connection_init(&cs->mix_last);
	for (int i = 0; i < num_pkg_servers; i++) {
		client_connection_init(&cs->pkg_client_connections[i]);
	}
	return 0;
}

void epoll_csend(client_net_s *c, client_connection *conn)
{
	int close_client_connection = 0;
	for (;;) {
		ssize_t count =
			send(conn->sock_fd, conn->write_buf + conn->bytes_written, (size_t) conn->write_remaining, 0);
		if (count == -1) {
			if (errno != EAGAIN) {
				perror("send");
				close_client_connection = 1;
			}
			break;
		}
		else if (count == 0) {
			close_client_connection = 1;
			break;
		}
		else {
			conn->bytes_written += count;
			conn->write_remaining -= count;
		}
	}
	if (close_client_connection) {
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

void epoll_send(client_net_s *c, client_connection *conn)
{
	int close_client_connection = 0;
	while (conn->write_remaining > 0) {
		ssize_t count = send(conn->sock_fd, conn->write_buf + conn->bytes_written, conn->write_remaining, 0);
		if (count == -1) {
			if (errno != EAGAIN) {
				fprintf(stderr, "socket send error %d on %d\n", errno, conn->sock_fd);
				close_client_connection = 1;
			}
			break;
		}
		else if (count == 0) {
			fprintf(stderr, "Socket send 0 bytes on %d\n", conn->sock_fd);
			close_client_connection = 1;
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

	if (close_client_connection) {
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
//Todo

void net_process_read(void *s, client_connection *conn, ssize_t count)
{
	client_net_s *net_cli = (client_net_s *) s;
	conn->bytes_read = count;

}

void net_client_lastmix_read(void *s, client_connection *conn, ssize_t count)
{
	client_net_s *c = (client_net_s *) s;
	conn->bytes_read += count;

	while (conn->bytes_read > 0) {
		if (conn->curr_msg_len == 0) {
			if ((count < net_header_BYTES)) {
				return;
			}
			uint32_t msg_type = deserialize_uint32(conn->read_buf->base);
			if (msg_type == NEW_AFMB_AVAIL) {
				conn->curr_msg_len = 0;
				conn->msg_type = NEW_AFMB_AVAIL;
				printf("Client received AF avail msg for round %d\n",
				       deserialize_uint32(conn->read_buf->base + net_msg_type_BYTES));
			}
			else if (msg_type == NEW_DMB_AVAIL) {
				conn->curr_msg_len = 0;
				conn->msg_type = NEW_DMB_AVAIL;
				printf("Client received Dial avail msg for round %d\n",
				       deserialize_uint32(conn->read_buf->base + net_msg_type_BYTES));
			}

			else if (msg_type == DIAL_MB) {
				conn->msg_type = DIAL_MB;
				uint32_t msg_len = deserialize_uint32(conn->read_buf->base + net_msg_type_BYTES);
				conn->curr_msg_len = msg_len;
				conn->read_buf->pos += count;
			}

			else if (msg_type == AF_MB) {
				conn->msg_type = AF_MB;
				uint32_t num_msgs = deserialize_uint32(conn->read_buf->base + net_msg_type_BYTES);
				conn->curr_msg_len = af_ibeenc_request_BYTES * num_msgs;
				conn->read_buf->pos += count;
				conn->read_buf->num_msgs = num_msgs;
			}
			else {
				fprintf(stderr, "Invalid message\n");
				close(conn->sock_fd);
				return;
			}
		}

		if (conn->bytes_read < conn->curr_msg_len + net_header_BYTES) {
			printf("Mix last read: %ld (%ld)of %ld | Buf capacity: %d\n",
			       count,
			       conn->bytes_read,
			       conn->curr_msg_len,
			       conn->read_buf->capacity_bytes);
			return;
		}

		if (conn->msg_type == DIAL_MB) {
			dial_process_mb(c->client, conn->read_buf->base + net_header_BYTES);
		}
		else if (conn->msg_type == AF_MB) {
			uint32_t round = deserialize_uint32(conn->read_buf->base + net_msg_type_BYTES);
			af_process_mb(c->client, conn->read_buf->base + net_header_BYTES, conn->read_buf->num_msgs, round);
			c->client->last_mailbox_read++;
			if (c->num_auth_responses == num_pkg_servers) {
				printf("Processed mailbox -> Replace IBE keys by processing auth responses\n");
				af_process_auth_responses(c->client);
				c->num_auth_responses = 0;
			}
		}
		else if (conn->msg_type == NEW_AFMB_AVAIL) {
			serialize_uint32(conn->write_buf + conn->bytes_written + conn->write_remaining, CLIENT_AF_MB_REQUEST);
			memcpy(conn->write_buf + conn->bytes_written + conn->write_remaining + 4,
			       conn->read_buf->base + net_msg_type_BYTES,
			       round_BYTES);
			memcpy(conn->write_buf + conn->bytes_written + conn->write_remaining + 8,
			       c->client->user_id,
			       user_id_BYTES);
			conn->write_remaining += net_header_BYTES + user_id_BYTES;
			epoll_send(c, conn);
		}
		else if (conn->msg_type == NEW_DMB_AVAIL) {
			serialize_uint32(conn->write_buf + conn->bytes_written + conn->write_remaining, CLIENT_DIAL_MB_REQUEST);
			memcpy(conn->write_buf + conn->bytes_written + conn->write_remaining + net_msg_type_BYTES,
			       conn->read_buf->base + net_msg_type_BYTES,
			       round_BYTES);
			memcpy(conn->write_buf + conn->bytes_written + conn->write_remaining + net_header_BYTES,
			       c->client->user_id,
			       user_id_BYTES);
			conn->write_remaining += net_header_BYTES + user_id_BYTES;
			epoll_send(c, conn);
		}

		size_t remaining = (size_t) conn->bytes_read - (conn->curr_msg_len + net_header_BYTES);
		if (remaining > 0) {
			if (conn->read_buf) {
				memcpy(conn->read_buf->base, conn->read_buf->base + conn->curr_msg_len + net_header_BYTES, remaining);
				conn->read_buf->pos = conn->read_buf->base + remaining;
			}
		}
		conn->msg_type = 0;
		conn->curr_msg_len = 0;
		conn->bytes_read = remaining;
		conn->read_buf->pos = conn->read_buf->base + remaining;
	}

}

void net_client_mixentry_read(void *cl_ptr, client_connection *conn, ssize_t count)
{
	client_net_s *c = (client_net_s *) cl_ptr;
	if (conn->curr_msg_len == 0) {

		uint32_t msg_type = deserialize_uint32(conn->read_buf->base);
		if (msg_type == NEW_DIAL_ROUND) {
			serialize_uint32(conn->write_buf + conn->bytes_written + conn->write_remaining, CLIENT_DIAL_MSG);
			serialize_uint32(conn->write_buf + conn->bytes_written + conn->write_remaining + 4,
			                 c->client->dialling_round);
			memcpy(conn->write_buf + conn->bytes_written + conn->write_remaining + 8,
			       c->client->dial_request_buf,
			       onionenc_dial_token_BYTES);
			conn->write_remaining += net_header_BYTES + onionenc_dial_token_BYTES;
			c->client->dialling_round++;
			epoll_send(c, conn);
			dial_fake_request(c->client);
		}
		else if (msg_type == NEW_AF_ROUND) {
			serialize_uint32(conn->write_buf + conn->bytes_written + conn->write_remaining, CLIENT_AF_MSG);
			serialize_uint32(conn->write_buf + conn->bytes_written + conn->write_remaining + 4,
			                 c->client->af_round);
			memcpy(conn->write_buf + conn->bytes_written + conn->write_remaining + 8,
			       c->client->friend_request_buf,
			       onionenc_friend_request_BYTES);
			conn->write_remaining += net_header_BYTES + onionenc_friend_request_BYTES;

			c->client->authed = false;
			c->num_broadcast_responses = 0;
			c->num_auth_responses = 0;
			c->client->af_round++;
			epoll_send(c, conn);
			af_fake_request(c->client);
		}
	}
}

void net_client_pkg_auth(client_net_s *cn)
{
	for (int i = 0; i < num_pkg_servers; i++) {
		client_connection *conn = &cn->pkg_client_connections[i];
		memcpy(conn->write_buf,
		       cn->client->pkg_auth_requests[i],
		       net_header_BYTES + cli_pkg_single_auth_req_BYTES);
		conn->bytes_written = 0;
		serialize_uint32(conn->write_buf, CLI_AUTH_REQ);
		serialize_uint32(conn->write_buf + sizeof(uint32_t), cn->client->af_round);
		conn->write_remaining = net_header_BYTES + cli_pkg_single_auth_req_BYTES;
		epoll_csend(cn, &cn->pkg_client_connections[i]);
	}
}

void net_client_pkg_read(void *cl_ptr, client_connection *conn, ssize_t count)
{
	client_net_s *client = (client_net_s *) cl_ptr;
	conn->bytes_read += count;

	if (conn->curr_msg_len == 0) {
		if ((count < net_header_BYTES)) {
			return;
		}

		uint32_t msg_type = deserialize_uint32(conn->read_buf->base);
		if (msg_type == PKG_BR_MSG) {
			conn->msg_type = PKG_BR_MSG;
			conn->curr_msg_len = pkg_broadcast_msg_BYTES;

		}

		else if (msg_type == PKG_AUTH_RES_MSG) {
			conn->msg_type = PKG_AUTH_RES_MSG;
			conn->curr_msg_len = pkg_enc_auth_res_BYTES;

		}

		else {
			fprintf(stderr, "Invalid message %ld %ld\n", count, conn->bytes_read);
			printhex("read buf", conn->read_buf->base, conn->bytes_read);
			close(conn->sock_fd);
			return;
		}
	}

	if (conn->bytes_read < conn->curr_msg_len + net_header_BYTES) {
		printf("Mix last read: %ld (%ld)of %ld | Buf capacity: %d\n",
		       count,
		       conn->bytes_read,
		       conn->curr_msg_len,
		       conn->read_buf->capacity_bytes);
		return;
	}

	if (conn->msg_type == PKG_BR_MSG) {
		memcpy(client->client->pkg_broadcast_msgs[conn->id],
		       conn->read_buf->base + net_header_BYTES,
		       pkg_broadcast_msg_BYTES);
		client->num_broadcast_responses++;
		if (client->num_broadcast_responses == num_pkg_servers) {
			af_create_pkg_auth_request(client->client);
			net_client_pkg_auth(client);
			client->num_broadcast_responses = 0;
		}
	}

	else if (conn->msg_type == PKG_AUTH_RES_MSG) {
		memcpy(client->client->pkg_auth_responses[conn->id],
		       conn->read_buf->base + net_header_BYTES,
		       pkg_enc_auth_res_BYTES);
		//printhex("auth response", conn->read_buf->base + net_header_BYTES, pkg_enc_auth_res_BYTES);
		client->num_auth_responses++;

		if (client->client->last_mailbox_read == client->client->af_round - 1) {
			printf("All auth responses received, MB processed already so replace IBE keys\n");
			af_process_auth_responses(client->client);
			client->num_auth_responses = 0;
			client->num_broadcast_responses = 0;
		}

	}

	size_t remaining = (size_t) conn->bytes_read - (conn->curr_msg_len + net_header_BYTES);
	if (remaining > 0) {
		printf("Remaining after processing msg length %ld: %lu\n", conn->curr_msg_len, remaining);
		memcpy(conn->read_buf->base, conn->read_buf->base + conn->bytes_read, remaining);
		conn->read_buf->pos = conn->read_buf->base + remaining;

	}
	conn->msg_type = 0;
	conn->curr_msg_len = 0;
	conn->bytes_read = remaining;
	conn->read_buf->pos = conn->read_buf->base + remaining;

}

int epoll_read(client_net_s *c, client_connection *conn)
{
	int close_client_connection = 0;
	for (;;) {
		ssize_t count;
		byte_buffer_s *read_buf = conn->read_buf;
		size_t buf_space = read_buf->capacity_bytes - conn->bytes_read;
		if (buf_space <= 0) {
			fprintf(stderr, "NO BUFFER SPACE REMAINING BEEP BOOP LALALALA\n------------------\n");
			abort();
		}
		/*printf("Buf stats:\n-----------\n");
		printf("Capacity: %d\n", read_buf->capacity_bytes);
		printf("Bytes read: %ld\n", conn->bytes_read);
		printf("Point difference betwen base and pos: %ld\n", (size_t)&conn->read_buf->pos - (size_t)&conn->read_buf->base);*/
		count = read(conn->sock_fd, read_buf->pos, buf_space);

		if (count == -1) {
			if (errno != EAGAIN) {
				perror("read");
				close_client_connection = 1;
			}
			break;
		}
		else if (count == 0) {
			printf("(%c) Sock read 0 in epoll read, sock %d\n", conn->conn_type, conn->sock_fd);
			close_client_connection = 1;
			break;
		}
		if (conn->on_read) {
			conn->on_read(c, conn, count);
		}
	}

	if (close_client_connection) {
		fprintf(stderr, "Epoll read: closing client_connection on sock %d..\n", conn->sock_fd);
		//close(conn->sock_fd);
	}
	return 0;
}

int net_client_startup(client_net_s *cn)
{

	int mix_last_sfd = net_connect("127.0.0.1", mix_listen_ports[num_mix_servers - 1], 1);
	if (mix_last_sfd == -1) {
		fprintf(stderr, "could not connect to mix distribution server\n");
		return -1;
	}
	cn->mix_last.conn_type = 'L';
	cn->mix_last.sock_fd = mix_last_sfd;
	cn->mix_last.on_read = net_client_lastmix_read;
	cn->mix_last.event.events = EPOLLIN | EPOLLET;
	cn->mix_last.event.data.ptr = &cn->mix_last;
	epoll_ctl(cn->epoll_inst, EPOLL_CTL_ADD, cn->mix_last.sock_fd, &cn->mix_last.event);
	int mix_sfd = net_connect("127.0.0.1", mix_client_listen, 0);
	if (mix_sfd == -1) {
		fprintf(stderr, "could not connect to mix entry server\n");
		return -1;
	}
	cn->mix_entry.sock_fd = mix_sfd;
	cn->mix_entry.on_read = net_client_mixentry_read;
	cn->mix_entry.conn_type = 'E';
	int res;
	res = net_read_nb(mix_sfd, cn->mix_entry.read_buf->base, 12 + net_client_connect_BYTES);
	if (res == -1) {
		perror("client read");
	}
	cn->client->af_round = deserialize_uint32(cn->mix_entry.read_buf->base + 4);
	cn->client->dialling_round = deserialize_uint32(cn->mix_entry.read_buf->base + 8);
	cn->client->last_mailbox_read = cn->client->af_round - 1;

	uint8_t *dh_ptr = cn->mix_entry.read_buf->base + 12;
	for (uint32_t i = 0; i < num_mix_servers; i++) {
		memcpy(cn->client->mix_eph_pub_keys[i], dh_ptr, crypto_box_PUBLICKEYBYTES);
		printhex("mix pk", cn->client->mix_eph_pub_keys[i], crypto_box_PUBLICKEYBYTES);
		dh_ptr += crypto_box_PUBLICKEYBYTES + 12;
	}

	af_fake_request(cn->client);
	dial_fake_request(cn->client);
	socket_set_nb(cn->mix_entry.sock_fd);
	cn->mix_entry.event.data.ptr = &cn->mix_entry;
	cn->mix_entry.event.events = EPOLLIN | EPOLLET;
	epoll_ctl(cn->epoll_inst, EPOLL_CTL_ADD, cn->mix_entry.sock_fd, &cn->mix_entry.event);

	for (uint32_t i = 0; i < num_pkg_servers; i++) {
		client_connection *pkg_conn = &cn->pkg_client_connections[i];
		pkg_conn->sock_fd = net_connect("127.0.0.1", pkg_cl_listen_ports[i], 1);
		if (cn->pkg_client_connections[i].sock_fd == -1) {
			return -1;
		}

		pkg_conn->id = i;
		pkg_conn->bytes_read = 0;
		pkg_conn->conn_type = 'P';
		pkg_conn->write_remaining = 0;
		pkg_conn->bytes_written = 0;
		pkg_conn->on_read = net_client_pkg_read;
		pkg_conn->event.data.ptr = &cn->pkg_client_connections[i];
		pkg_conn->event.events = EPOLLIN | EPOLLET;
		epoll_ctl(cn->epoll_inst, EPOLL_CTL_ADD, cn->pkg_client_connections[i].sock_fd, &pkg_conn->event);
	}

	struct epoll_event *events = cn->events;

	while (!cn->client->authed) {
		int n = epoll_wait(cn->epoll_inst, cn->events, 100, 5000);
		client_connection *conn = NULL;
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
				epoll_read(cn, conn);
			}
			else if (events[i].events & EPOLLOUT) {
				epoll_csend(cn, conn);
			}
		}
	}
	//af_process_auth_responses(cn->client);
	cn->num_auth_responses = 0;
	cn->num_broadcast_responses = 0;
	return 0;
}

void *net_client_loop(void *cns)
{
	client_net_s *c = (client_net_s *) cns;
	struct epoll_event *events = c->events;
	c->running = true;
	while (c->running) {
		int n = epoll_wait(c->epoll_inst, c->events, 100, 100);
		action *curr_action = action_stack_pop(c);
		while (curr_action) {
			do_action(c, curr_action);
			curr_action = action_stack_pop(c);
		}
		client_connection *conn = NULL;
		// Error of some sort on the socket
		for (int i = 0; i < n; i++) {
			if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
				conn = events[i].data.ptr;
				fprintf(stderr, "Mix loop: Closing client_connection on sock %d\n", conn->sock_fd);
				close(conn->sock_fd);
				free(events[i].data.ptr);
				continue;
			}
				// Read from a socket
			else if (events[i].events & EPOLLIN) {
				conn = events[i].data.ptr;
				epoll_read(c, conn);
			}
			else if (events[i].events & EPOLLOUT) {
				conn = events[i].data.ptr;
				epoll_send(c, conn);
			}
		}
	}

}

int main(int argc, char **argv)
{
	client_s c;
	int uid;
	if (argc < 2) {
		uid = 0;
	}
	else {
		uid = atoi(argv[1]);
	}
	client_init(&c, user_ids[uid], user_lt_pub_sig_keys[uid], user_lt_secret_sig_keys[uid]);
	client_net_s s;
	net_client_init(&s, &c);
	net_client_startup(&s);
	pthread_t net_thread;
	pthread_create(&net_thread, NULL, net_client_loop, &s);
	int running = 1;
	while (running) {
		action *act = calloc(1, sizeof *act);
		memset(act->user_id, 0, user_id_BYTES);
		int a = getc(stdin);
		switch (a) {
		case ADD_FRIEND:
			printf("Enter friend's user ID: ");
			fflush(stdout);
			fflush(stdin);
			fscanf(stdin, "%s\n", act->user_id);
			act->type = ADD_FRIEND;
			action_stack_push(&s, act);
			fflush(stdin);
			break;
		case CONFIRM_FRIEND:
			printf("Enter friend's user ID: ");
			fflush(stdout);
			fflush(stdin);
			fscanf(stdin, "%s\n", act->user_id);
			act->type = CONFIRM_FRIEND;
			action_stack_push(&s, act);
			fflush(stdin);
			break;
		default:
			if (a == 123456789) {
				running = 0;
			}
			fflush(stdin);
			break;
		}
	}

}