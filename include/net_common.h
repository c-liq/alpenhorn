#ifndef ALPENHORN_NET_COMMON_H
#define ALPENHORN_NET_COMMON_H

#include "alpenhorn/config.h"
#include "utils.h"
#include <sys/epoll.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <pthread.h>

#define epoll_num_events 50000

typedef struct send_item send_item;
struct send_item
{
	uint8_t *buffer;
	u64 bytes_written;
	u64 write_remaining;
	send_item *next;
	bool copied;
};

typedef struct net_header net_header;
struct net_header {
	u64 type;
	u64 len;
	u64 round;
	u64 misc;
};

typedef struct connection connection;
struct connection
{
	int sock_fd;
	int id;
	byte_buffer_s read_buf;
    byte_buffer_s write_buf;
    net_header header;
    struct epoll_event event;
	int (*process)(void *owner, connection *conn, byte_buffer_s *buf);
	connection *next;
	connection *prev;
	bool connected;
	send_item *send_queue_head;
	send_item *send_queue_tail;
	pthread_mutex_t send_queue_lock;
	void *client_state;
	void *srv_state;
};

typedef struct net_server_state net_server_state;

struct net_server_state
{
	int epoll_fd;
	connection listen_conn;
	struct epoll_event events[epoll_num_events];
    connection *clients;
    void *owner;
};

int net_accept(int listen_fd, int set_nb);

int net_epoll_send(connection *conn, int epoll_fd);

int net_epoll_read(void *owner, connection *conn);

int net_read_blocking(int sock_fd, uint8_t *buf, size_t n);

int net_send_blocking(int sock_fd, uint8_t *buf, size_t n);

int net_connect(const char *addr, const char *port, int set_nb);

int socket_set_nonblocking(int socket);

int net_start_listen_socket(const char *port, bool set_nb);

int connection_init(connection *conn,
					u64 read_buf_size,
					u64 write_buf_size,
					int (*process)(void *, connection *, byte_buffer_s *),
					int epoll_fd,
					int socket_fd);

void net_process_read(void *owner, connection *conn);

int net_epoll_client_accept(net_server_state *srv_state, void on_accept(void *, connection *),
							int on_read(void *, connection *, byte_buffer_s *));

int net_serialize_header(uint8_t *header,
                         u64 type,
                         u64 length,
                         u64 round,
                         u64 misc);

void net_epoll_send_queue(net_server_state *net_state, connection *conn);

int net_epoll_queue_write(net_server_state *owner, connection *conn, uint8_t *buffer, u64 data_size, bool copy);
int alp_serialize_header(byte_buffer_s *buf,
                         uint64_t type,
                         uint64_t length,
                         uint64_t round,
                         uint64_t misc);

int alp_deserialize_header(net_header *header, byte_buffer_s *buf);
#endif //ALPENHORN_NET_COMMON_H
