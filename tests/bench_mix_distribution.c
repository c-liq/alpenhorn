#include <time.h>
#include <xxhash.h>
#include <pthread.h>
#include "mixnet.h"

#define test_client_count 3600

static int num_responses_sent;
int num_act_connections;

void net_sim_send_queue(net_server_state *net_state, connection *conn);
int net_sim_queue_write(net_server_state *owner,
                        connection *conn,
                        uint8_t *buffer,
                        uint64_t data_size,
                        bool copy)
{
	if (!owner || !conn || !buffer)
		return -1;

	send_item *new_item = calloc(1, sizeof *new_item);
	if (!new_item) {
		perror("malloc");
		return -1;
	}

	if (copy) {
		uint8_t *msg_buffer = calloc(data_size, sizeof(uint8_t));
		if (!msg_buffer) {
			free(new_item);
			perror("malloc");
			return -1;
		}
		memcpy(msg_buffer, buffer, data_size);
		new_item->buffer = msg_buffer;
	}
	else {
		new_item->buffer = buffer;
	}

	new_item->write_remaining = data_size;
	new_item->bytes_written = 0;
	new_item->next = NULL;
	new_item->copied = copy;

	pthread_mutex_lock(&conn->send_queue_lock);

	if (conn->send_queue_tail) {
		conn->send_queue_tail->next = new_item;
	}

	conn->send_queue_tail = new_item;
	if (!conn->send_queue_head) {
		conn->send_queue_head = new_item;
	}

	pthread_mutex_unlock(&conn->send_queue_lock);
	net_sim_send_queue(owner, conn);
	return 0;
}

void net_sim_send_queue(net_server_state *net_state, connection *conn)
{
	int close_connection = 0;
	send_item *current_item;
	while (conn->send_queue_head) {
		current_item = conn->send_queue_head;
		ssize_t count = send(conn->sock_fd, current_item->buffer + current_item->bytes_written,
		                     current_item->write_remaining, 0);
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
			current_item->bytes_written += count;
			current_item->write_remaining -= count;

			if (current_item->write_remaining == 0) {
				pthread_mutex_lock(&conn->send_queue_lock);
				if (!current_item->next) {
					conn->send_queue_tail = NULL;
				}
				conn->send_queue_head = current_item->next;

				pthread_mutex_unlock(&conn->send_queue_lock);
				num_responses_sent++;
				if (current_item->copied) {
					free(current_item->buffer);
				}
				free(current_item);
			}
		}
	}
	if (close_connection) {
		return;
	}

	if (conn->send_queue_head && !(conn->event.events & EPOLLOUT)) {
		conn->event.events = EPOLLOUT | EPOLLET;
		epoll_ctl(net_state->epoll_fd, EPOLL_CTL_MOD, conn->sock_fd,
		          &conn->event);
	}

	else if (!conn->send_queue_head && conn->event.events & EPOLLOUT) {
		conn->event.events = EPOLLIN | EPOLLET;
		epoll_ctl(net_state->epoll_fd, EPOLL_CTL_MOD, conn->sock_fd,
		          &conn->event);
	}
}

int mix_dist_sim_process_client(void *owner, connection *conn)
{
	mix_s *mix = (mix_s *) owner;
	if (conn->msg_type == CLIENT_DIAL_MB_REQUEST) {
		uint64_t mb_round = deserialize_uint64(conn->read_buf.data + 8);
		/*printf("Received Dial mailbox download request for round %ld from %.60s\n",
		       mb_round, conn->read_buf.data + net_header_BYTES);*/
		dial_mailbox_s *request_mb = mix_dial_get_mailbox_buffer(
			owner, mb_round, conn->read_buf.data + net_header_BYTES);
		if (request_mb) {
			net_sim_queue_write(&mix->net_state, conn, request_mb->bloom.base_ptr,
			                    request_mb->bloom.total_size_bytes, NULL);
		}
	}
	else if (conn->msg_type == CLIENT_AF_MB_REQUEST) {
		uint64_t round_num = deserialize_uint64(conn->read_buf.data + 8);
		/*	printf("Received AF mailbox download request for round %ld from %.60s\n",
					   round_num, conn->read_buf.data + net_header_BYTES);*/
		uint64_t index = XXH64(conn->read_buf.data + net_header_BYTES, user_id_BYTES, 0) % mix->af_data.num_mailboxes;
		af_mailbox_s *mailbox = &mix->af_mb_container.mailboxes[index];
		net_sim_queue_write(&mix->net_state, conn, mailbox->data, mailbox->size_bytes, NULL);

	}

	else {
		fprintf(stderr, "Invalid message\n");
		return -1;
	}
	return 0;
}

void mix_distrib_sim(mix_s *mix,
                     void on_accept(void *, connection *),
                     int on_read(void *, connection *))
{

	net_server_state *net_state = &mix->net_state;
	int listen_socket = net_start_listen_socket(mix_listen_ports[mix->server_id], 1);
	if (listen_socket == -1) {
		fprintf(stderr, "failed to start listen socket\n");
	}
	printf("[Mix distribution: initialised]\n");
	net_state->listen_socket = listen_socket;
	connection *listen_conn = calloc(1, sizeof *listen_conn);
	listen_conn->sock_fd = net_state->listen_socket;
	struct epoll_event event;
	event.data.ptr = listen_conn;
	event.events = EPOLLIN | EPOLLET;
	epoll_ctl(net_state->epoll_fd, EPOLL_CTL_ADD, net_state->listen_socket,
	          &event);


	net_server_state *es = &mix->net_state;
	struct epoll_event *events = es->events;

	es->running = 1;
	int num_connections = 0;
	double start_time = 0;
	double end_time = 0;
	bool conn_failed = false;
	num_act_connections = -1;
	num_responses_sent = 0;
	bool skip = false;
	while (es->running) {
		if (num_responses_sent == num_act_connections) {
			es->running = false;
			break;
		}
		if (num_connections == test_client_count || conn_failed) {
			if (!skip) {
				printf("%d clients connected, sleeping\n", num_connections);
				printf("All clients connected, announcing AF mailbox availanility\n");


				mix_af_distribute(mix);
				start_time = get_time();
				mix_broadcast_new_afmb(mix, mix->af_data.round);
				num_act_connections = num_connections;
				skip = true;
			}
		}

		int num_events = epoll_wait(es->epoll_fd, es->events, 20000, 5000);
		for (int i = 0; i < num_events; i++) {
			connection *conn = events[i].data.ptr;
			if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
				fprintf(stderr, "Error on socket %d\n", conn->sock_fd);
				close(conn->sock_fd);
				mix_remove_client(mix, conn);
				continue;
			}
			else if (es->listen_socket == conn->sock_fd) {

				int res = net_epoll_client_accept(&mix->net_state, on_accept, on_read);
				if (!res) {
					num_connections++;
				}
				else {
					//conn_failed = true;
					break;
				}
			}
			else if (events[i].events & EPOLLIN) {
				net_epoll_read(mix, conn);
			}
			else if (events[i].events & EPOLLOUT) {
				net_epoll_send(mix, conn, mix->net_state.epoll_fd);
			}
		}
	}

	end_time = get_time();
	printf("All mailbox requests responded to (%d)\n", num_responses_sent);
	printf("Time taken: %f\n", end_time - start_time);
	sleep(5);
}

int main()
{

#if !USE_PBC
	bn256_init();
#endif
	mix_s *mix = calloc(1, sizeof *mix);
	mix_init(mix, 1, 0, 0);
	mix_af_add_noise(mix);
	mix_net_init(mix);
	mix_distrib_sim(mix, NULL, mix_dist_sim_process_client);

}

