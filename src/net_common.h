
#ifndef ALPENHORN_NET_COMMON_H
#define ALPENHORN_NET_COMMON_H

#include <sys/epoll.h>
#include "mix.h"

typedef struct connection connection;

static const char mix_client_listen[] = "7000";

static const char *mix_listen_ports[] = {"5000", "5001", "5002", "5003"};

static const char *pkg_cl_listen_ports[] = {"7500", "7501", "7502"};

#define PKG_CONN 1
#define PKG_BR_MSG 70
#define PKG_AUTH_RES_MSG 80

enum conn_type
{
	MIX, PKG, CLIENT
};

typedef enum conn_type conn_type;

struct connection
{
	conn_type type;
	uint32_t id;
	int sock_fd;
	uint8_t internal_read_buf[buf_size];
	byte_buffer_s *read_buf;
	ssize_t read_remaining;
	ssize_t curr_msg_len;
	ssize_t bytes_read;
	uint32_t msg_type;
	uint8_t internal_write_buf[buf_size];
	byte_buffer_s *write_buf;
	ssize_t bytes_written;
	ssize_t write_remaining;
	struct epoll_event event;
	void (*on_read)(void *owner, connection *conn, ssize_t count);
	void (*on_write)(void *owner, connection *conn, ssize_t count);
	connection *next;
	connection *prev;
	uint32_t bc_bytes_remaining;
};

int net_accept(int listen_fd, int set_nb);
int net_read_nb(int sock_fd, uint8_t *buf, size_t n);
int net_send_nb(int sock_fd, uint8_t *buf, size_t n);
int net_connect(const char *addr, const char *port, int set_nb);
int socket_set_nb(int socket);
int net_start_listen_socket(const char *port, int set_nb);
void connection_init(connection *conn);
#endif //ALPENHORN_NET_COMMON_H
