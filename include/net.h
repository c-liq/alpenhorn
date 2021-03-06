#ifndef ALPENHORN_NET_COMMON_H
#define ALPENHORN_NET_COMMON_H

#include "byte_buffer.h"
#include "list.h"
#include <sys/epoll.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <pthread.h>

#define epoll_num_events 50000

typedef struct send_item send_item;
struct send_item {
  byte_buffer *data;
  bool copied;
};

typedef struct net_header {
  uint64_t type;
  uint64_t len;
  uint64_t round;
  uint64_t misc;
} net_header;

typedef struct connection connection;
struct connection {
  int sock_fd;
  int id;
  byte_buffer read_buf;
  byte_buffer write_buf;
  byte_buffer_t msg_buf;
  net_header header;
  struct epoll_event event;
  int (*process)(void *owner, connection *conn);
  bool connected;
  list *send_queue;
  pthread_mutex_t send_queue_lock;
  void *client;
  void *server;
};

typedef struct connection connection_t[1];

typedef struct net_server {
  int epoll_fd;
  uint64_t num_events;
  struct epoll_event *events;
  connection listen_conn;
  list *clients;
  void *owner;
} net_server;

int net_accept(int listen_fd, int set_nb);

int net_send(connection *conn, int epoll_fd);

int net_read(void *owner, connection *conn);

int net_read_blocking(int sock_fd, uint8_t *buf, size_t n);

int net_send_blocking(int sock_fd, uint8_t *buf, size_t n);

int net_connect(const char *addr, const char *port, int set_nb);

int socket_set_nonblocking(int socket);

int net_listen_socket(const char *port, const bool set_nb);

int connection_init(connection *conn,
                    uint64_t rbuf_size,
                    uint64_t wbuf_size,
                    int (*process)(void *, connection *),
                    int epfd,
                    int sockfd);

void net_process_read(void *owner, connection *conn);

int net_accept_client(net_server *srv_state, void on_accept(void *, connection *),
                      int on_read(void *, connection *));

int net_serialize_header(uint8_t *header,
                         uint64_t type,
                         uint64_t length,
                         uint64_t round,
                         uint64_t misc);

void net_queue_write(net_server *net_state, connection *conn);

int net_queue_send_push(net_server *owner, connection *conn, byte_buffer *buffer, bool copy);

int alp_serialize_header(byte_buffer *buf,
                         uint64_t type,
                         uint64_t length,
                         uint64_t round,
                         uint64_t misc);

int alp_deserialize_header(net_header *header, byte_buffer *buf);

int net_connect_init(connection *conn,
                     const char *addr,
                     const char *port,
                     int epoll_fd,
                     int set_nb,
                     uint64_t buf_size,
                     int (*process)(void *, connection *));
#endif //ALPENHORN_NET_COMMON_H
