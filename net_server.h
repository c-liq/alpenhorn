#ifndef ALPENHORN_ENTRY_SERVER_H
#define ALPENHORN_ENTRY_SERVER_H

enum conn_type {
  PKG,
  MIX,
  CLIENT
};

enum msg_type {
  NONE = 'N', AF = 'A', DIAL = 'D'
};

struct net_server;
typedef struct net_server net_server_s;

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
};
typedef struct connection connection;

int es_listen_socket_init(char *port);
int net_accept(net_server_s *es);
int net_read(net_server_s *es, connection *conn, void(*process)(net_server_s *, connection *, ssize_t));
void entry_process_client_read(net_server_s *s, connection *conn, ssize_t count);
#endif //ALPENHORN_ENTRY_SERVER_H
