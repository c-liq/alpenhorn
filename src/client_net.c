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
	void (*process)(void *owner, client_connection *conn);
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

void action_stack_push(client_net_s *c, action *new_action)
{
	pthread_mutex_lock(&c->aq_lock);
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
	conn->process = NULL;
	conn->event.events = 0;
	conn->read_buf = calloc(1, sizeof *conn->read_buf);
	byte_buffer_init(conn->read_buf, 16384, 0);
	memset(conn->write_buf, 0, buf_size);
}

void ep_socket_send(client_net_s *s, client_connection *conn);

void net_send_message(void *s, struct client_connection *conn, uint8_t *msg, uint32_t msg_size_bytes)
{
	memcpy(conn->write_buf + conn->bytes_written + conn->write_remaining, msg, msg_size_bytes);
	conn->write_remaining += msg_size_bytes;
	ep_socket_send(s, conn);
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

void ep_socket_send(client_net_s *c, client_connection *conn)
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

void mix_entry_process_msg(void *s, struct client_connection *conn)
{
	client_net_s *c = (client_net_s *) s;
	switch (conn->msg_type) {
	case NEW_AF_ROUND:
		net_send_message(s, conn, c->client->friend_request_buf, net_header_BYTES + onionenc_friend_request_BYTES);
		c->client->authed = false;
		c->num_broadcast_responses = 0;
		c->num_auth_responses = 0;
		c->client->af_round = deserialize_uint64(conn->read_buf->data + 8);
		c->client->mb_processed = false;
		printf("AF round %ld started\n", c->client->af_round);
		af_fake_request(c->client);
		break;
	case NEW_DIAL_ROUND:
		net_send_message(s, conn, c->client->dial_request_buf, net_header_BYTES + onionenc_dial_token_BYTES);
		c->client->dialling_round = deserialize_uint64(conn->read_buf->data + 8);
		printf("Dial round %ld started\n", c->client->dialling_round);
		dial_fake_request(c->client);
		break;
	case MIX_SYNC:
		c->client->af_round = deserialize_uint64(conn->read_buf->data + 8);
		c->client->dialling_round = deserialize_uint64(conn->read_buf->data + 16);
		memcpy(c->client->mix_eph_pub_keys, conn->read_buf->data + net_header_BYTES, net_client_connect_BYTES);
		break;
	default:
		fprintf(stderr, "Invalid message from Mix Entry\n");
		break;
	}
}

void net_client_pkg_auth(client_net_s *cn)
{
	for (int i = 0; i < num_pkg_servers; i++) {
		client_connection *conn = &cn->pkg_client_connections[i];
		net_send_message(cn, conn, cn->client->pkg_auth_requests[i], net_header_BYTES + cli_pkg_single_auth_req_BYTES);
	}
	cn->num_broadcast_responses = 0;
}

void pkg_process_message(void *s, client_connection *conn)
{
	client_net_s *client = (client_net_s *) s;
	switch (conn->msg_type) {
	case PKG_BR_MSG:
		memcpy(client->client->pkg_broadcast_msgs[conn->id],
		       conn->read_buf->data + net_header_BYTES,
		       pkg_broadcast_msg_BYTES);
		client->num_broadcast_responses++;
		if (client->num_broadcast_responses == num_pkg_servers) {
			af_create_pkg_auth_request(client->client);
			net_client_pkg_auth(client);
			client->num_broadcast_responses = 0;
		}
		break;

	case PKG_AUTH_RES_MSG:
		memcpy(client->client->pkg_auth_responses[conn->id],
		       conn->read_buf->base + net_header_BYTES,
		       pkg_enc_auth_res_BYTES);
		//printhex("auth response", conn->read_buf->base + net_header_BYTES, pkg_enc_auth_res_BYTES);
		client->num_auth_responses++;
		if (client->num_auth_responses == num_pkg_servers && client->client->mb_processed) {
			//printf("All auth responses received, MB processed already so replace IBE keys\n");
			af_process_auth_responses(client->client);
			client->num_auth_responses = 0;
		}
		break;
	default:
		fprintf(stderr, "Invalid message received from PKG server\n");
		printhex("Message", conn->read_buf->data, conn->curr_msg_len);
		break;
	}
}

void mix_last_process_message(void *s, struct client_connection *conn)
{
	client_net_s *c = (client_net_s *) s;
	switch (conn->msg_type) {
	case DIAL_MB:
		dial_process_mb(c->client,
		                conn->read_buf->data + net_header_BYTES,
		                deserialize_uint64(conn->read_buf->data + 8),
		                deserialize_uint32(conn->read_buf->data + 16));
		kw_advance_table(&c->client->keywheel);
		break;
	case AF_MB:
		af_process_mb(c->client,
		              conn->read_buf->data + net_header_BYTES,
		              deserialize_uint32(conn->read_buf->data + 16),
		              deserialize_uint64(conn->read_buf->data + 8));
		c->client->mb_processed = true;
		if (c->num_auth_responses == num_pkg_servers && !c->client->authed) {
			//printf("Processed mailbox -> Replace IBE keys by processing auth responses\n");
			af_process_auth_responses(c->client);
			c->num_auth_responses = 0;
		};
		break;
	case NEW_AFMB_AVAIL:
		serialize_uint32(conn->write_buf + conn->bytes_written + conn->write_remaining, CLIENT_AF_MB_REQUEST);
		serialize_uint32(conn->write_buf + conn->bytes_written + conn->write_remaining + 4, user_id_BYTES);
		memcpy(conn->write_buf + conn->bytes_written + conn->write_remaining + 8,
		       conn->read_buf->data + 8,
		       round_BYTES);
		memcpy(conn->write_buf + conn->bytes_written + conn->write_remaining + net_header_BYTES,
		       c->client->user_id,
		       user_id_BYTES);
		conn->write_remaining += net_header_BYTES + user_id_BYTES;
		ep_socket_send(c, conn);
		break;
	case NEW_DMB_AVAIL:
		serialize_uint32(conn->write_buf + conn->bytes_written + conn->write_remaining, CLIENT_DIAL_MB_REQUEST);
		serialize_uint32(conn->write_buf + conn->bytes_written + conn->write_remaining + 4, user_id_BYTES);
		memcpy(conn->write_buf + conn->bytes_written + conn->write_remaining + 8,
		       conn->read_buf->base + 8,
		       round_BYTES);
		memcpy(conn->write_buf + conn->bytes_written + conn->write_remaining + net_header_BYTES,
		       c->client->user_id,
		       user_id_BYTES);
		conn->write_remaining += net_header_BYTES + user_id_BYTES;
		ep_socket_send(c, conn);
		break;
	default:
		fprintf(stderr, "Invalid message from Mix distribution server\n");
		break;
	}
}

void net_process_read(void *s, client_connection *conn, ssize_t count)
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

		uint32_t read_remaining = (uint32_t) (conn->bytes_read - conn->curr_msg_len - net_header_BYTES);

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

int ep_socket_read(client_net_s *c, client_connection *conn)
{
	int close_client_connection = 0;
	for (;;) {
		ssize_t count;
		byte_buffer_s *read_buf = conn->read_buf;
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
			printf("(%c) Sock read 0 in epoll read, sock %d\n", conn->conn_type, conn->sock_fd);
			close_client_connection = 1;
			break;
		}

		net_process_read(c, conn, count);
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
	cn->mix_last.process = mix_last_process_message;
	cn->mix_last.event.events = EPOLLIN | EPOLLET;
	cn->mix_last.event.data.ptr = &cn->mix_last;
	epoll_ctl(cn->epoll_inst, EPOLL_CTL_ADD, cn->mix_last.sock_fd, &cn->mix_last.event);
	int mix_sfd = net_connect("127.0.0.1", mix_client_listen, 0);
	if (mix_sfd == -1) {
		fprintf(stderr, "could not connect to mix entry server\n");
		return -1;
	}

	cn->mix_entry.sock_fd = mix_sfd;
	cn->mix_entry.process = mix_entry_process_msg;
	cn->mix_entry.conn_type = 'E';

	int res = net_read_nb(mix_sfd, cn->mix_entry.read_buf->base, net_header_BYTES + net_client_connect_BYTES);
	if (res == -1) {
		perror("client read");
	}

	cn->client->af_round = deserialize_uint64(cn->mix_entry.read_buf->data + 8);
	cn->client->dialling_round = deserialize_uint64(cn->mix_entry.read_buf->base + 16);
	cn->client->keywheel.table_round = cn->client->dialling_round;
	cn->client->mb_processed = 1;
	printf("[Connected: Dial round: %ld | Add friend round: %ld]\n", cn->client->dialling_round, cn->client->af_round);

	uint8_t *dh_ptr = cn->mix_entry.read_buf->base + net_header_BYTES;
	for (uint32_t i = 0; i < num_mix_servers; i++) {
		memcpy(cn->client->mix_eph_pub_keys[i], dh_ptr, crypto_box_PUBLICKEYBYTES);
		dh_ptr += crypto_box_PUBLICKEYBYTES;
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
		pkg_conn->process = pkg_process_message;
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
				ep_socket_read(cn, conn);
			}
			else if (events[i].events & EPOLLOUT) {
				ep_socket_send(cn, conn);
			}
		}
	}
	cn->num_auth_responses = 0;
	cn->num_broadcast_responses = 0;
	return 0;
}

void *net_client_loop(void *cns)
{

	client_net_s *c = (client_net_s *) cns;
	for (int i = 0; i < num_mix_servers; i++) {
	}
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
		for (int i = 0; i < n; i++) {
			if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
				conn = events[i].data.ptr;
				fprintf(stderr, "Client: Socket error on connection type %c - Exiting\n", conn->conn_type);
				c->running = false;
				break;
			}

			else if (events[i].events & EPOLLIN) {
				conn = events[i].data.ptr;
				ep_socket_read(c, conn);
			}
			else if (events[i].events & EPOLLOUT) {
				conn = events[i].data.ptr;
				ep_socket_send(c, conn);
			}
		}
	}
	return NULL;
}

int main(int argc, char **argv)
{

	int uid;
	if (argc < 2) {
		uid = 0;
	}
	else {
		uid = atoi(argv[1]);
	}
	client_s *c = client_alloc(user_ids[uid], user_lt_pub_sig_keys[uid], user_lt_secret_sig_keys[uid]);
	client_net_s s;
	net_client_init(&s, c);
	net_client_startup(&s);
	pthread_t net_thread;
	pthread_create(&net_thread, NULL, net_client_loop, &s);
	int running = 1;
	char buf[user_id_BYTES + 1];
	while (running) {
		memset(buf, 0, sizeof buf);
		action *act = calloc(1, sizeof *act);
		memset(act->user_id, 0, user_id_BYTES);
		fgets(buf, 3, stdin);
		size_t id_len;
		switch (buf[0]) {
		case ADD_FRIEND:
			printf("Enter friend's user ID: ");
			fflush(stdout);
			fflush(stdin);
			fgets(buf, sizeof buf, stdin);
			id_len = strlen(buf) - 1;
			if (buf[id_len] == '\n') {
				buf[id_len] = '\0';
			}
			memcpy(act->user_id, buf, user_id_BYTES);
			act->type = ADD_FRIEND;
			action_stack_push(&s, act);
			break;
		case CONFIRM_FRIEND:
			printf("Enter friend's user ID: ");
			fflush(stdout);
			fflush(stdin);
			fgets(buf, sizeof buf, stdin);
			id_len = strlen(buf) - 1;
			if (buf[id_len] == '\n') {
				buf[id_len] = '\0';
			}
			memcpy(act->user_id, buf, user_id_BYTES);
			act->type = CONFIRM_FRIEND;
			action_stack_push(&s, act);
			fflush(stdin);
			break;
		case DIAL_FRIEND: {
			printf("Enter friend's user ID: ");
			fflush(stdout);
			fgets(buf, sizeof buf, stdin);
			fflush(stdin);
			id_len = strlen(buf) - 1;
			if (buf[id_len] == '\n') {
				buf[id_len] = '\0';
			}
			memcpy(act->user_id, buf, user_id_BYTES);
			printf("Enter intent: ");
			fflush(stdout);
			char intent_buf[4];
			fgets(intent_buf, sizeof intent_buf, stdin);
			int i = atoi(intent_buf);
			if (i > c->num_intents - 1 || i < 0) {
				fprintf(stderr, "Invalid intent\n");
				free(act);
				break;
			}

			act->type = DIAL_FRIEND;
			act->intent = (uint32_t) i;
			action_stack_push(&s, act);
			fflush(stdin);
			break;
		}
		case PRINT_KW_TABLE:
			act->type = PRINT_KW_TABLE;
			action_stack_push(&s, act);
			fflush(stdin);
		default:
			if (buf[0] == 'Q') {
				running = 0;
			}
			fflush(stdin);
			break;
		}
	}
}