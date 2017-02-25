#include <string.h>
#include "mix.h"
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <time.h>
#include "config.h"
#include "mixnet_server.h"

#define FRIEND_MSG 'F'
#define DIAL_MSG 'D'

static const connection default_conn = {
    .curr_buf_ptr = NULL,
    .buf_capacity = 1024,
    .bytes_read = 0,
    .curr_msg_len = 0,
    .read_buf = {0},
    .msg_t = NONE,
    .write_buf_pos = 0,
    .sock_fd = -1,
    .write_buf = {0}
};

struct mixnet_server {
  mix_s *mix;
  int epoll_inst;
  int listen_socket;
  struct epoll_event *events;
  uint32_t num_pending_responses;
  int running;
  byte_t *dh_key_buf;
  size_t dh_key_buf_size;
  connection prev_mix;
  connection next_mix;
  time_t next_af_round;
  time_t next_dial_round;
};

struct mix_to_mix_conn {
  connection *next_mix;
  connection *prev_mix;
  mix_s *mix;
  enum msg_type curr_type;
  uint32_t curr_size;
  uint32_t curr_read;
  byte_t read_buf[1024 * 64];
};
typedef struct mix_to_mix_conn mix_to_mix_s;

int socket_set_nb(int socket) {
  int flags, status;

  flags = fcntl(socket, F_GETFL, 0);
  if (flags == -1) {
    perror("fcntl");
    return -1;
  }

  flags |= O_NONBLOCK;
  status = fcntl(socket, F_SETFL, flags);
  if (status == -1) {
    perror("fcntl");
    return -1;
  }
  return 0;
}

void net_mix_mix_read(net_server_s *srv, connection *conn, ssize_t count) {
  printf("Read: %ld | Cur remaining: %d | bytes read: %d | capacity: %d | cur_msg_len: %d\n",
         count, conn->read_remaining,
         conn->bytes_read,
         conn->buf_capacity,
         conn->curr_msg_len);

  ssize_t c_read = count;
  if (conn->curr_msg_len == 0) {
    if ((count < sizeof(byte_t) + mailbox_BYTES)) {
      return;
    }
    uint32_t msg_len;
    char msg_type = conn->read_buf[0];
    if (msg_type == 'A') {
      conn->msg_t = AF;
      printhex("incoming msg buffer", conn->read_buf, 10);
      msg_len = 7640;
      conn->curr_msg_len = msg_len;
      conn->read_remaining = msg_len;
      conn->curr_buf_ptr = srv->mix->af_incoming_msgs;
      conn->buf_capacity = srv->mix->af_inc_buf_capacity;
    } else if (msg_type == DIAL) {
      conn->msg_t = DIAL;
      msg_len = deserialize_uint32(conn->read_buf + 1);
      conn->curr_msg_len = msg_len;
      conn->read_remaining = msg_len;
      conn->curr_buf_ptr = srv->mix->dial_incoming_msgs;
      conn->buf_capacity = srv->mix->dial_inc_buf_capacity;
    } else if (msg_type == NEW_ROUND) {
      conn->write_buf_ptr = conn->write_buf;
      conn->write_buf[0] = NEW_ROUND;
      conn->write_remaining = 1;
      conn->bytes_written = 0;
      epoll_send(&conn->event);
    } else {
      fprintf(stderr, "Invalid message %c\n", conn->read_buf[0]);
      close(conn->sock_fd);
      return;
    }

    c_read -= 5;
    memcpy(conn->curr_buf_ptr, conn->read_buf + 5, (size_t) c_read);
    conn->curr_buf_ptr += c_read;
  }

  conn->read_remaining -= c_read;
  conn->bytes_read += count;

  if (conn->read_remaining <= 0) {
    printf("Finished reading message\n");
    if (conn->msg_t == AF) {
      srv->mix->af_num_inc_msgs = conn->curr_msg_len / srv->mix->af_incoming_msg_length;
      mix_af_decrypt_messages(srv->mix);
    } else if (conn->msg_t == DIAL) {
      mix_dial_decrypt_messages(srv->mix);
    }
    conn->curr_buf_ptr = conn->read_buf;
    conn->buf_capacity = sizeof conn->read_buf;
    conn->msg_t = NONE;
    conn->curr_msg_len = 0;
    conn->bytes_read = 0;
  }
}

int net_mix_sync_prev(int srv_id) {
  if (srv_id <= 0) {
    fprintf(stderr, "invalid server id %d\n", srv_id);
    return -1;
  }
  const char *port = mix_listen_ports[srv_id - 1];
  int sock_fd = net_connect("127.0.0.1", port, 0);
  if (sock_fd == -1) {
    fprintf(stderr, "could not connect to neighbouring mixnet server\n");
    return -1;
  }
  return sock_fd;
}

int net_send_nb(int sock_fd, byte_t *buf, size_t n) {
  ssize_t bytes_sent = 0;
  while (bytes_sent < n) {
    ssize_t tmp_sent = send(sock_fd, buf + bytes_sent, n - bytes_sent, 0);
    if (tmp_sent <= 0) {
      fprintf(stderr, "socket write error\n");
      return -1;
    }
    bytes_sent += tmp_sent;
  }
  return 0;
}

int net_read_nb(int sock_fd, byte_t *buf, size_t n) {
  int bytes_read = 0;
  while (bytes_read < n) {
    ssize_t tmp_read = read(sock_fd, buf + bytes_read, n - bytes_read);
    if (tmp_read <= 0) {
      fprintf(stderr, "socket error %d %d\n", errno, EAGAIN);
      return -1;
    }
    bytes_read += tmp_read;
  }
  return 0;
}

int net_mix_sync(net_server_s *es) {
  uint32_t srv_id = es->mix->server_id;
  int res;
  // Unless we're the last server in the mixnet chain, setup a temp listening socket to allow the next server
  // to establish a connection
  if (srv_id < num_mix_servers - 1) {
    int listen_socket = net_start_listen_socket(mix_listen_ports[srv_id], 0);
    es->listen_socket = listen_socket;
    int next_mix_sfd = net_accept(listen_socket, 0);

    if (next_mix_sfd == -1) {
      fprintf(stderr, "fatal error on listening socket\n");
      return -1;
    }

    es->next_mix.sock_fd = next_mix_sfd;
    size_t inc_dh_keys_bytes = es->dh_key_buf_size - crypto_box_PUBLICKEYBYTES;
    byte_t *dh_ptr = es->mix->mix_dh_public_keys[srv_id + 1];
    res = net_read_nb(es->next_mix.sock_fd, dh_ptr, inc_dh_keys_bytes);
    close(listen_socket);
    if (res) {
      fprintf(stderr, "fatal socket error during mix startup\n");
      return -1;
    }
    es->next_mix.event.events = EPOLLIN;
    es->next_mix.event.data.ptr = &es->next_mix;
    res = epoll_ctl(es->epoll_inst, EPOLL_CTL_ADD, es->next_mix.sock_fd, &es->next_mix.event);
    if (res) {
      fprintf(stderr, "epoll_ctl error\n");
      return -1;
    }
    res = socket_set_nb(es->next_mix.sock_fd);
    if (res) {
      fprintf(stderr, "error when setting socket to non blocking\n");
    }
  }

  if (es->mix->server_id > 0) {
    es->prev_mix.sock_fd = net_mix_sync_prev(es->mix->server_id);
    res = net_send_nb(es->prev_mix.sock_fd, es->dh_key_buf, es->dh_key_buf_size);
    if (res) {
      fprintf(stderr, "socker error writing to previous server in mixnet chain\n");
      return -1;
    }
    es->prev_mix.event.events = EPOLLIN;
    es->prev_mix.event.data.ptr = &es->prev_mix;
    res = epoll_ctl(es->epoll_inst, EPOLL_CTL_ADD, es->prev_mix.sock_fd, &es->prev_mix.event);
    if (res) {
      fprintf(stderr, "epoll_ctrl error\n");
      return -1;
    }
    res = socket_set_nb(es->prev_mix.sock_fd);
    if (res) {
      fprintf(stderr, "failure setting socket to non blocking mode\n");
      return -1;
    }
  }
  return 0;
}

int net_entry_sync(net_server_s *es) {
  int res;

  res = net_mix_sync(es);
  if (res) {
    fprintf(stderr, "fatal error during mixnet startup\n");
    return -1;
  }

  es->listen_socket = net_start_listen_socket("7000", 1);
  if (es->listen_socket == -1) {
    fprintf(stderr, "entry mix error when starting listensocket\n");
    return -1;
  }

  return 0;
}

int net_start_listen_socket(const char *port, int set_nb) {
  int listen_sfd;
  struct addrinfo hints;
  struct addrinfo *serverinfo;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  int status = getaddrinfo(NULL, port, &hints, &serverinfo);
  if (status != 0) {
    fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
    freeaddrinfo(serverinfo);
    return -1;
  }
  // Iterate through addrinfo structures until a socket is created
  struct addrinfo *p;
  for (p = serverinfo; p != NULL; p = p->ai_next) {
    listen_sfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (listen_sfd != -1)
      break;
  }

  if (listen_sfd == -1) {
    perror("couldn't establish socket");
    freeaddrinfo(serverinfo);
    return -1;
  }

  int y = 1;
  if (setsockopt(listen_sfd, SOL_SOCKET, SO_REUSEADDR, &y, sizeof y) == -1) {
    perror("setoption");
    return -1;
  }

  if (set_nb) {
    status = socket_set_nb(listen_sfd);
    if (status == -1) {
      close(listen_sfd);
      return -1;
    }
  }

  status = bind(listen_sfd, p->ai_addr, p->ai_addrlen);
  if (status == -1) {
    perror("bind failure");
    return -1;
  }

  status = listen(listen_sfd, 5);
  if (status == -1) {
    perror("listen failure");
    return -1;
  }

  freeaddrinfo(serverinfo);
  return listen_sfd;
}

int net_connect(const char *addr, const char *port, int set_nb) {
  struct addrinfo hints, *servinfo, *p;
  int sock_fd;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  int res = getaddrinfo(addr, port, &hints, &servinfo);
  if (res) {
    gai_strerror(res);
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(res));
    return -1;
  }

  for (p = servinfo; p != NULL; p = p->ai_next) {
    if ((sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      continue;
    }
    if (connect(sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sock_fd);
      perror("client: connect");
      return -1;
    }
    break;
  }
  if (set_nb) {
    res = socket_set_nb(sock_fd);
    if (res) {
      fprintf(stderr, "error setting non blocking mode on socket\n");
      return -1;
    }
  }
  return sock_fd;
}
void compact_read_buf(connection *conn) {
  uint32_t remaining = conn->bytes_read - conn->curr_msg_len;
  memcpy(conn->read_buf, conn->read_buf + conn->curr_msg_len, remaining);
  conn->bytes_read = remaining;

}

void entry_process_client_read(net_server_s *s, connection *conn, ssize_t count) {
  conn->bytes_read += count;
  printf("Client read stared - msg len: %d read: %d \n", conn->curr_msg_len, conn->bytes_read);
  if (conn->curr_msg_len == 0) {
    switch (conn->read_buf[0]) {
    case FRIEND_MSG:
      conn->curr_msg_len = onionenc_friend_request_BYTES;
      break;
    case DIAL_MSG:
      conn->curr_msg_len = onionenc_dial_token_BYTES;
      break;
    default:
      fprintf(stderr, "Invalid message format\n");
      conn->bytes_read = 0;
      conn->curr_msg_len = 0;
      return;
    }
  }

  if (conn->bytes_read < conn->curr_msg_len) {
    return;
  }

  switch (conn->curr_msg_len) {
  case onionenc_friend_request_BYTES:
    mix_af_add_inc_msg(s->mix, conn->read_buf);
    break;
  case onionenc_dial_token_BYTES:
    mix_dial_add_inc_msg(s->mix, conn->read_buf);
    break;
  default:
    fprintf(stderr, "Invalid message format %d %d\n", conn->bytes_read, conn->curr_msg_len);
    close(conn->sock_fd);
  }
  conn->bytes_read = 0;
  conn->curr_msg_len = 0;
}

int es_init(net_server_s *server, mix_s *mix) {
  server->mix = mix;
  server->epoll_inst = epoll_create1(0);
  if (server->epoll_inst == -1) {
    fprintf(stderr, "Entry Server: failure when creating epoll instance\n");
    return -1;
  }
  uint32_t buffer_size = crypto_box_PUBLICKEYBYTES * (num_mix_servers - server->mix->server_id);
  server->dh_key_buf = calloc(1, buffer_size);
  server->dh_key_buf_size = buffer_size;
  memcpy(server->dh_key_buf, server->mix->eph_dh_public_key, crypto_box_PUBLICKEYBYTES);
  server->events = calloc(2000, sizeof *server->events);
  server->next_mix = default_conn;
  server->prev_mix = default_conn;
  server->next_mix.curr_buf_ptr = server->next_mix.read_buf;
  server->next_mix.write_buf_ptr = server->next_mix.write_buf;

  server->prev_mix.curr_buf_ptr = server->prev_mix.read_buf;
  server->prev_mix.bytes_read = 0;
  server->prev_mix.buf_capacity = sizeof server->prev_mix.read_buf;
  return 0;
}

int net_accept(int listen_sfd, int set_nb) {
  struct sockaddr_storage client_addr;
  int new_sfd, status;
  socklen_t addr_size;
  addr_size = sizeof client_addr;

  new_sfd = accept(listen_sfd, (struct sockaddr *) &client_addr, &addr_size);
  if (new_sfd == -1) {
    return -1;
  }

  if (set_nb) {
    status = socket_set_nb(new_sfd);
    if (status == -1) {
      perror("setting non blocking option on socket");
      return -1;
    }
  }
  return new_sfd;
}

int epoll_accept(net_server_s *es) {
  for (;;) {

    struct epoll_event event;
    int status;
    int new_sock;
    new_sock = net_accept(es->listen_socket, 1);
    if (new_sock == -1) {
      // All new connections processed
      if ((errno == EAGAIN || errno == EWOULDBLOCK)) {
        break;
      }
      // Something broke
      perror("client accept");
      continue;
    }

    connection *new_conn = calloc(1, sizeof(*new_conn));
    if (!new_conn) {
      perror("malloc");
      return -1;
    }
    new_conn->sock_fd = new_sock;
    event.data.ptr = new_conn;
    event.events = EPOLLIN | EPOLLET;
    status = epoll_ctl(es->epoll_inst, EPOLL_CTL_ADD, new_sock, &event);

    if (status == -1) {
      perror("epoll_ctl");
      return -1;
    }
  }
  return 0;
}

void net_mix_af_forward(net_server_s *s) {
  mix_af_decrypt_messages(s->mix);
  connection *conn = &s->next_mix;
  conn->write_buf_ptr = s->mix->af_out_msgs;
  conn->bytes_written = 0;
  conn->write_remaining = 5 + (s->mix->af_num_out_msgs * s->mix->af_outgoing_msg_length);
  printhex("start of msg send buffer", s->mix->af_out_msgs, 10);
  printf("Num af messages: %d | Size of outgoing message: %d | Message payload size: %d\n",
         s->mix->af_num_out_msgs,
         s->mix->af_outgoing_msg_length,
         s->mix->af_num_out_msgs * s->mix->af_outgoing_msg_length);
  epoll_send(&conn->event);
}

void epoll_send(struct epoll_event *event) {
  connection *conn = (connection *) event->data.ptr;
  int close_connection = 0;
  ssize_t count = send(conn->sock_fd, conn->write_buf_ptr + conn->bytes_written, conn->write_remaining, 0);
  if (count == -1) {
    if (errno != EAGAIN) {
      perror("read");
      close_connection = 1;
    }
  } else if (count == 0) {
    close_connection = 1;
  }
  conn->bytes_written += count;
  conn->write_remaining -= count;

  if (close_connection) {
    //close(conn->sock_fd);
    //free(conn);
  }
  printf("Sent %ld bytes, %d remaining\n", count, conn->write_remaining);
  if (conn->write_remaining == 0) {
    event->events = EPOLLIN;
  } else {
    event->events = EPOLLOUT;
  }
}

int epoll_read(net_server_s *es, connection *conn, void (*process)(net_server_s *, connection *, ssize_t)) {
  int close_connection = 0;
  for (;;) {
    ssize_t count = read(conn->sock_fd, conn->curr_buf_ptr, conn->buf_capacity - conn->bytes_read);
    if (count == -1) {
      if (errno != EAGAIN) {
        perror("read");
        close_connection = 1;
      }
      break;
    } else if (count == 0) {
      close_connection = 1;
      break;
    }
    process(es, conn, count);
  }

  if (close_connection) {
    close(conn->sock_fd);
  }
  return 0;
}

void check_time(net_server_s *s) {
  time_t rem = s->next_dial_round - time(0);
  if (rem <= 0) {
    net_mix_af_forward(s);
    // mix_dial_newround(s->mix);
    s->next_dial_round = time(0) + s->mix->dial_round_duration;
    printf("New dial round started: %u\n", s->mix->dial_round);

  }
}

void net_mix_loop(net_server_s *es) {

  struct epoll_event *events = es->events;
  es->running = 1;
  while (es->running) {
    int n = epoll_wait(es->epoll_inst, es->events, 100, 5000);
    connection *conn = NULL;
    // Error of some sort on the socket
    for (int i = 0; i < n; i++) {
      if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
        conn = (connection *) events[i].data.ptr;
        close(conn->sock_fd);
        free(events[i].data.ptr);
        continue;
      }
        // Read from a socket
      else if (events[i].events & EPOLLIN) {
        conn = events[i].data.ptr;
        epoll_read(es, conn, net_mix_mix_read);
      } else if (events[i].events & EPOLLOUT) {
        epoll_send(&events[i]);
      }
    }
  }

}

void net_srv_loop(net_server_s *es, void(*on_read)(net_server_s *, connection *, ssize_t)) {

  struct epoll_event *events = es->events;
  es->running = 1;
  es->next_af_round = time(0) + es->mix->af_round_duration;
  es->next_dial_round = time(0) + es->mix->dial_round_duration;
  while (es->running) {
    check_time(es);
    int n = epoll_wait(es->epoll_inst, es->events, 100, 5000);
    connection *conn = NULL;
    // Error of some sort on the socket
    for (int i = 0; i < n; i++) {
      if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
        conn = (connection *) events[i].data.ptr;
        close(conn->sock_fd);
        free(events[i].data.ptr);
        continue;
      } else if (es->listen_socket == events[i].data.fd) {
        int res = epoll_accept(es);
        if (res) {
          fprintf(stderr, "fatal server error\n");
          es->running = 0;
          exit(1);
        }
      }
        // Read from a socket
      else if (events[i].events & EPOLLIN) {
        conn = events[i].data.ptr;
        epoll_read(es, conn, on_read);
      } else if (events[i].events & EPOLLOUT) {
        epoll_send(&events[i]);
      }
    }
  }
}

int main(int argc, char **argv) {
  if (*argv[1] == '0') {
    net_server_s es;
    mix_s mix;
    mix_init(&mix, 0, 20000);
    es_init(&es, &mix);
    net_entry_sync(&es);
    mix_af_add_noise(&mix);
    net_srv_loop(&es, entry_process_client_read);
  } else {
    mix_s mix;
    mix_init(&mix, 1, 20000);
    net_server_s es;
    es_init(&es, &mix);
    net_mix_sync(&es);
    net_mix_loop(&es);
  }
}

