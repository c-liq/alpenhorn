
#ifndef ALPENHORN_NET_COMMON_H
#define ALPENHORN_NET_COMMON_H

#define net_client_connect_BYTES 12U
#include <sys/epoll.h>
typedef struct connection connection;
static const char mix_client_listen[] = "7000";
static const char *mix_listen_ports[] = {"5000", "5001", "5002", "5003"};
static const char *pkg_cl_listen_ports[] = {"7500", "7501", "7502"};

#define PKG_CONN 1
#define PKG_BR_MSG 70
#define PKG_AUTH_RES_MSG 80

struct connection {
  int sock_fd;
  byte_t internal_read_buf[buf_size];
  mix_buffer_s *read_buf;
  uint32_t read_remaining;
  uint32_t curr_msg_len;
  uint32_t bytes_read;
  uint32_t msg_type;
  byte_t internal_write_buf[buf_size];
  mix_buffer_s *write_buf;
  uint32_t bytes_written;
  uint32_t write_remaining;
  struct epoll_event event;
};
#include <sys/epoll.h>
#include "mix.h"
int net_accept (int listen_fd, int set_nb);
int net_read_nb (int sock_fd, byte_t *buf, size_t n);
int net_connect (const char *addr, const char *port, int set_nb);
int socket_set_nb (int socket);
int net_start_listen_socket (const char *port, int set_nb);
#endif //ALPENHORN_NET_COMMON_H
