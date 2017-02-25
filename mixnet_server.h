#ifndef ALPENHORN_ENTRY_SERVER_H
#define ALPENHORN_ENTRY_SERVER_H

enum conn_type {
  PKG,
  MIX,
  CLIENT
};

enum msg_type {
  NONE = 'N', AF = 'A', DIAL = 'D', NEW_ROUND = 'R'
};

struct mixnet_server;
typedef struct mixnet_server net_server_s;

static const char *mix_listen_ports[] = {"5000", "5001", "5002", "5003"};

struct connection {
  enum conn_type type;
  int sock_fd;
  byte_t read_buf[buf_size];
  byte_t *curr_buf_ptr;
  uint32_t buf_capacity;
  int32_t read_remaining;
  uint32_t curr_msg_len;
  uint32_t bytes_read;
  byte_t write_buf[buf_size];
  uint32_t write_buf_pos;
  enum msg_type msg_t;
  byte_t *write_buf_ptr;
  uint32_t bytes_written;
  uint32_t write_remaining;
  struct epoll_event event;
};
typedef struct connection connection;

int epoll_accept(net_server_s *es);
int net_accept(int listen_fd, int set_nb);
int net_connect(const char *addr, const char *port, int set_nb);
int epoll_read(net_server_s *es, connection *conn, void(*process)(net_server_s *, connection *, ssize_t));
void entry_process_client_read(net_server_s *s, connection *conn, ssize_t count);
int net_start_listen_socket(const char *port, int set_nb);
void epoll_send(struct epoll_event *event);

#endif //ALPENHORN_ENTRY_SERVER_H
