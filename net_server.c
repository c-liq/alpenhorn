#include <string.h>
#include "mix.h"
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include "config.h"
#include "net_server.h"

#define FRIEND_MSG 'F'
#define DIAL_MSG 'D'
#define MIX_BROADCAST_MSG 'M'
#define es_mix_broadcast_BYTES (1 + mailbox_BYTES + crypto_box_PUBLICKEYBYTES)

struct net_server {
  mix_s *mix;
  int epoll_inst;
  int listen_socket;
  connection *mix_conns;
  struct epoll_event *events;
  uint32_t num_pending_responses;
};

struct mix_to_mix_conn {
  int sock_fd;
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

void mix_read(net_server_s *srv, connection *conn, ssize_t count) {

  conn->bytes_read += count;
  printf("Client read stared - msg len: %d read: %d \n", conn->curr_msg_len, conn->bytes_read);
  if (conn->curr_msg_len == 0) {
    if (*conn->read_buf == MIX_BROADCAST_MSG) {
      conn->curr_msg_len = es_mix_broadcast_BYTES;
    } else {
      fprintf(stderr, "Invalid message format\n");
      conn->bytes_read = 0;
      conn->curr_msg_len = 0;
      close(conn->sock_fd);
      return;
    }
  }

  if (conn->bytes_read < conn->curr_msg_len) {
    return;
  }
  byte_t *buf_ptr = conn->read_buf;
  uint32_t mix_id = deserialize_uint32(++buf_ptr);
  buf_ptr += mailbox_BYTES;
  if (mix_id >= num_mix_servers) {
    fprintf(stderr, "Invalid mix id");
    close(conn->sock_fd);
    return;
  }
  printf("Mix entry: connection established with mix server %d\n", mix_id);
  memcpy(srv->mix->mix_dh_public_keys[mix_id], buf_ptr, crypto_box_PUBLICKEYBYTES);
  srv->num_pending_responses--;

}

void mix_startup() {

}

void mix_batch_read(net_server_s *srv, connection *conn, uint32_t count) {
  uint32_t c_read = count;
  if (conn->curr_msg_len == 0) {
    if ((count < sizeof(byte_t) + mailbox_BYTES)) {
      return;
    }
    uint32_t msg_len;
    char msg_type = conn->read_buf[0];
    if (msg_type == AF) {
      conn->msg_t = AF;
      msg_len = deserialize_uint32(conn->read_buf + 1);
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
    } else {
      fprintf(stderr, "Invalid message\n");
      close(conn->sock_fd);
      return;
    }

    if (conn->curr_msg_len > conn->buf_capacity) {
      //resize
    }
    c_read -= 5;
    memcpy(conn->curr_buf_ptr, conn->read_buf + 5, c_read);
    conn->curr_buf_ptr += c_read;
  }

  conn->read_remaining -= c_read;

  if (conn->read_remaining <= 0) {
    if (conn->msg_t == AF) {
      mix_af_decrypt_messages(srv->mix);
    } else if (conn->msg_t == DIAL) {
      mix_dial_decrypt_messages(srv->mix);
    }
    conn->curr_buf_ptr = conn->read_buf;
    conn->buf_capacity = sizeof conn->read_buf;
    conn->msg_t = NONE;
    conn->curr_msg_len = 0;
  }
}

int es_mix_startup(net_server_s *es) {
  // start listen socket
  // wait for other mix servers to connect + send first dh key
  // send mix keys back out to each mix server
  // announce first round and start accepting client messages
  es->num_pending_responses = num_mix_servers;
  int listen_s = es_listen_socket_init("5000");
  if (listen_s == -1) {
    fprintf(stderr, "failed to initialise listening socket\n");
    return -1;
  }
  es->listen_socket = listen_s;
  struct epoll_event event;
  event.data.fd = listen_s;
  event.events = EPOLLIN | EPOLLET;

  int status = epoll_ctl(es->epoll_inst, EPOLL_CTL_ADD, listen_s, &event);
  if (status == -1) {
    perror("epoll ctl");
    abort();
  }

  struct epoll_event *events = es->events;

  while (es->num_pending_responses > 0) {
    int n = epoll_wait(es->epoll_inst, events, 100, -1);

    // Error of some sort on the socket
    for (int i = 0; i < n; i++) {
      if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
        close(events[i].data.fd);
        continue;
      }

        // Activity on listening socket, connection to accept
      else if (listen_s == events[i].data.fd) {
        int res = net_accept(es);
        if (res) {
          fprintf(stderr, "fatal error while accepting clients\n");
          abort();
        }
      }
        // Read from a socket
      else if (events[i].events & EPOLLIN) {
        connection *conn = events[i].data.ptr;
        net_read(es, conn, mix_read);
      }
    }
  }

  return 0;
}

int es_listen_socket_init(char *port) {
  int server_socket;
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
    server_socket = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (server_socket != -1)
      break;
  }

  if (server_socket == -1) {
    perror("couldn't establish socket");
    freeaddrinfo(serverinfo);
    return -1;
  }

  int y = 1;
  if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &y, sizeof y) == -1) {
    perror("setoption");
    return -1;
  }

  status = socket_set_nb(server_socket);
  if (status == -1) {
    abort();
  }

  status = bind(server_socket, p->ai_addr, p->ai_addrlen);
  if (status == -1) {
    perror("bind failure");
    return -1;
  }

  status = listen(server_socket, 5);
  if (status == -1) {
    perror("listen failure");
    return -1;
  }

  freeaddrinfo(serverinfo);
  return server_socket;
}

void es_mix_broadcast_reply(net_server_s *s) {
  struct addrinfo hints, *servinfo, *p;
  int mix_sock;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  int res = getaddrinfo("127.0.0.1", "5000", &hints, &servinfo);

  for (p = servinfo; p != NULL; p = p->ai_next) {
    if ((mix_sock = socket(p->ai_family, p->ai_socktype,
                           p->ai_protocol)) == -1) {
      perror("client: socket");
      continue;
    }

    if (connect(mix_sock, p->ai_addr, p->ai_addrlen) == -1) {
      close(mix_sock);
      perror("client: connect");
      continue;
    }

    break;
  }

  socket_set_nb(mix_sock);

  byte_t broadcast[es_mix_broadcast_BYTES];
  broadcast[0] = 'M';
  serialize_uint32(broadcast + 1, 1);
  memcpy(broadcast + 5, s->mix->eph_dh_public_key, crypto_box_PUBLICKEYBYTES);
  send(mix_sock, broadcast, es_mix_broadcast_BYTES, 0);

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
  server->events = calloc(2000, sizeof *server->events);
  return 0;
}

int net_accept(net_server_s *es) {
  for (;;) {
    struct sockaddr_storage client_addr;
    int client_socket, status;
    socklen_t addr_size;
    addr_size = sizeof client_addr;
    struct epoll_event event;

    client_socket = accept(es->listen_socket, (struct sockaddr *) &client_addr, &addr_size);
    if (client_socket == -1) {
      // All new connections processed
      if ((errno == EAGAIN || errno == EWOULDBLOCK)) {
        break;
      }
      // Something broke
      perror("client accept");
      continue;
    }

    status = socket_set_nb(client_socket);
    if (status == -1) {
      perror("setting non blocking option on socket");
      return -1;
    }
    connection *new_conn = calloc(1, sizeof(*new_conn));
    if (!new_conn) {
      perror("malloc");
      return -1;
    }
    new_conn->sock_fd = client_socket;
    event.data.ptr = new_conn;
    event.events = EPOLLIN | EPOLLET;
    status = epoll_ctl(es->epoll_inst, EPOLL_CTL_ADD, client_socket, &event);

    if (status == -1) {
      perror("epoll_ctl");
      return -1;
    }
  }
  return 0;
}

int net_read(net_server_s *es, connection *conn, void (*process)(net_server_s *, connection *, ssize_t)) {
  int close_connection = 0;
  for (;;) {
    ssize_t count = read(conn->sock_fd, conn->read_buf + conn->bytes_read, conn->buf_capacity - conn->bytes_read);
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
    free(conn);
    close(conn->sock_fd);
  }
  return 0;
}

int main_loop(net_server_s *es, void(*process)(net_server_s *, connection *, ssize_t)) {
  struct epoll_event event;
  memset(&event, 0, sizeof event);

  struct epoll_event *events = es->events;

  for (;;) {
    int n = epoll_wait(es->epoll_inst, es->events, 100, -1);

    // Error of some sort on the socket
    for (int i = 0; i < n; i++) {
      if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
        close(events[i].data.fd);
        continue;
      }

        // Activity on listening socket, connection to accept
      else if (es->listen_socket == events[i].data.fd) {
        int res = net_accept(es);
        if (res) {
          fprintf(stderr, "fatal error while accepting clients\n");
          abort();
        }
      }
        // Read from a socket
      else if (events[i].events & EPOLLIN) {
        connection *conn = events[i].data.ptr;
        int res = net_read(es, conn, process);
      }
    }
  }
}

int main(int argc, char **argv) {
  if (*argv[1] == '1') {
    net_server_s es;
    mix_s mix;
    mix_init(&mix, 0, 20000);
    es_init(&es, &mix);
    es_mix_startup(&es);
    main_loop(&es, entry_process_client_read);
  } else {
    mix_s mix;
    mix_init(&mix, 1, 20000);
    net_server_s es;
    es_init(&es, &mix);
    es_mix_broadcast_reply(&es);
  }
}

