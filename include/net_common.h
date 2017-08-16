#ifndef ALPENHORN_NET_COMMON_H
#define ALPENHORN_NET_COMMON_H
#include "config.h"
#include "utils.h"
#include <sys/epoll.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <pthread.h>

typedef struct send_item send_item;
struct send_item
{
	uint8_t *buffer;
	uint64_t bytes_written;
	uint64_t write_remaining;
	send_item *next;
	bool copied;
};

typedef struct connection connection;
struct connection
{
	int sock_fd;
	int id;
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
	void *client_state;
};

typedef struct net_server_state net_server_state;

struct net_server_state
{
	int epoll_fd;
	int listen_socket;
	struct epoll_event *events;
	int running;
	connection prev_mix;
	connection next_mix;
	time_t next_af_round;
	time_t next_dial_round;
	time_t af_window_close;
	time_t dial_window_close;
	connection pkg_conns[num_pkg_servers];
	byte_buffer_s bc_buf;
	connection *clients;
	struct remove_conn_list *remove_list;
	byte_buffer_s af_client_broadcast;
	byte_buffer_s dial_client_broadcast;
	void *owner;
};

int net_accept(int listen_fd, int set_nb);
int net_epoll_send(void *c, connection *conn, int epoll_fd);
int net_epoll_read(void *owner, connection *conn);
int net_read_blocking(const int sock_fd, uint8_t *buf, const size_t n);
int net_send_blocking(int sock_fd, uint8_t *buf, size_t n);
int net_connect(const char *addr, const char *port, const int set_nb);
int socket_set_nonblocking(int socket);
int net_start_listen_socket(const char *port, const int set_nb);
int connection_init(connection *conn,
                    uint64_t read_buf_size,
                    uint64_t write_buf_size,
                    int (*process)(void *, connection *),
                    int epoll_fd,
                    int socket_fd);
void net_process_read(void *owner, connection *conn, ssize_t count);
int net_epoll_client_accept(net_server_state *srv_state, void on_accept(void *, connection *), int on_read(void *, connection *));
int net_serialize_header(uint8_t *header,
                         uint32_t msg_type,
                         uint32_t msg_length,
                         uint64_t af_round,
                         uint64_t dial_round);
void net_epoll_send_queue(net_server_state *net_state, connection *conn);
int net_epoll_queue_write(net_server_state *owner,
                          connection *conn,
                          uint8_t *buffer,
                          uint64_t data_size,
                          bool copy);
#endif //ALPENHORN_NET_COMMON_H
