#ifndef ALPENHORN_NET_COMMON_H
#define ALPENHORN_NET_COMMON_H
#include "config.h"
#include "utils.h"
#include <sys/epoll.h>

typedef struct send_item send_item;
struct send_item
{
	uint8_t *buffer;
	uint64_t msg_size;
	uint64_t bytes_written;
	uint64_t write_remaining;
	send_item *next;
};

typedef struct connection connection;
struct connection
{
	uint64_t id;
	int sock_fd;
	byte_buffer_s read_buf;
	uint32_t curr_msg_len;
	uint32_t bytes_read;
	uint32_t msg_type;
	byte_buffer_s write_buf;
	uint32_t bytes_written;
	uint32_t write_remaining;
	struct epoll_event event;
	int (*process)(void *owner, connection *conn);
	connection *next;
	connection *prev;
	bool connected;
	send_item *send_queue_head;
	send_item *send_queue_tail;
	pthread_mutex_t send_queue_lock;
	unsigned char conn_type;
	void *client_state;
};

int net_epoll_accept(int listen_fd, int set_nb);
int net_read_nonblock(int sock_fd, uint8_t *buf, size_t n);
int net_send_nonblock(int sock_fd, uint8_t *buf, size_t n);
int net_connect(const char *addr, const char *port, int set_nb);
int socket_set_nonblocking(int socket);
int net_start_listen_socket(const char *port, int set_nb);
int connection_init(connection *conn);
void net_process_read(void *owner, connection *conn, ssize_t count);
#endif //ALPENHORN_NET_COMMON_H
