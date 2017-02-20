#include <string.h>
#include "mix.h"
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include "config.h"

#define AUTH_MSG 'A'
#define FRIEND_MSG 'F'
#define DIAL_MSG 'D'

struct entry_server {
  uint32_t af_round;
  uint32_t dial_round;
  uint32_t af_round_duration;
  uint32_t dial_round_duration;

  int mix_pkg_listen_socket;
  int client_listen_socket;

  byte_t *auth_req_msg_buffer;
  uint32_t auth_req_buf_capacity;
  uint32_t auth_req_buf_size;

  byte_t *auth_res_msg_buffer;
  uint32_t auth_res_buf_capacity;
  uint32_t auth_res_buf_size;

  byte_t *af_message_buffer;
  uint32_t af_message_buf_capacity;
  uint32_t af_message_buf_size;

  byte_t *dial_message_buffer;
  uint32_t dial_message_buf_capacity;
  uint32_t dial_message_buf_size;
};

typedef struct entry_server entry_server;

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

void compact_read_buf(connection *conn) {
  uint32_t remaining = conn->read_buf_pos - conn->curr_msg_len;
  memcpy(conn->read_buf, conn->read_buf + cli_pkg_combined_auth_req_BYTES, remaining);

}

void client_read(entry_server *server, connection *conn, ssize_t count) {

  conn->read_buf_pos += count;
  printf("Client read stared - msg len: %d read: %d \n", conn->curr_msg_len, conn->read_buf_pos);
  if (conn->curr_msg_len == 0) {
    switch (conn->read_buf[0]) {
    case AUTH_MSG:conn->curr_msg_len = cli_pkg_combined_auth_req_BYTES;
      break;
    case FRIEND_MSG:conn->curr_msg_len = onionenc_friend_request_BYTES;
      break;
    case DIAL_MSG:conn->curr_msg_len = onionenc_dial_token_BYTES;
      break;
    default:fprintf(stderr, "Invalid message format\n");
      conn->read_buf_pos = 0;
      conn->curr_msg_len = 0;
      return;
    }
  }

  if (conn->read_buf_pos < conn->curr_msg_len) {
    fprintf(stderr,
            "Full message not yet transmitted: read buf pos = %d, msg len = %d\n",
            conn->read_buf_pos,
            conn->curr_msg_len);
    return;
  }

  switch (conn->curr_msg_len) {
  case cli_pkg_combined_auth_req_BYTES + 1:
    memcpy(server->auth_req_msg_buffer + (server->auth_req_buf_size * cli_pkg_combined_auth_req_BYTES),
           conn->read_buf,
           cli_pkg_combined_auth_req_BYTES);
    server->auth_req_buf_size++;
    break;
  case onionenc_friend_request_BYTES:
    memcpy(server->af_message_buffer + (server->af_message_buf_size + onionenc_friend_request_BYTES),
           conn->read_buf,
           onionenc_friend_request_BYTES);
    server->af_message_buf_size++;
    break;
  case onionenc_dial_token_BYTES:
    memcpy(server->dial_message_buffer + (server->dial_message_buf_size + onionenc_dial_token_BYTES),
           conn->read_buf,
           onionenc_dial_token_BYTES);
    server->dial_message_buf_size++;
    break;
  default:fprintf(stderr, "Invalid message format %d %d\n", conn->read_buf_pos, conn->curr_msg_len);
  }
  conn->read_buf_pos = 0;
  conn->curr_msg_len = 0;
}

#define buffer_n_elems 10000

int es_init(entry_server *server) {
  server->auth_req_msg_buffer = calloc(buffer_n_elems, cli_pkg_combined_auth_req_BYTES + sizeof(uint32_t));
  server->auth_res_msg_buffer = calloc(buffer_n_elems, (sizeof(uint32_t) + pkg_auth_res_BYTES) * num_pkg_servers);
  server->af_message_buffer = calloc(buffer_n_elems, onionenc_friend_request_BYTES);
  server->dial_message_buffer = calloc(buffer_n_elems, onionenc_dial_token_BYTES);
  server->af_message_buf_capacity = buffer_n_elems;
  server->dial_message_buf_capacity = buffer_n_elems;
  server->auth_req_buf_capacity = buffer_n_elems;
  server->auth_res_buf_capacity = buffer_n_elems;
  server->af_message_buf_size = 0;
  server->dial_message_buf_size = 0;
  server->auth_res_buf_size = 0;
  server->auth_req_buf_size = 0;
  return 0;
}
int run() {

  entry_server es;
  es_init(&es);

  struct epoll_event event;
  struct epoll_event *events;

  memset(&event, 0, sizeof event);
  int server_socket = es_listen_socket_init("5000");
  if (server_socket == -1) {
    perror("server initialisation failed");
    abort();
  }

  int efd = epoll_create1(0);
  if (efd == -1) {
    abort();
  }
  event.data.fd = server_socket;
  event.events = EPOLLIN | EPOLLET;

  int status = epoll_ctl(efd, EPOLL_CTL_ADD, server_socket, &event);
  if (status == -1) {
    perror("epoll ctl");
    abort();
  }

  events = calloc(100, sizeof event);
  for (;;) {
    int n = epoll_wait(efd, events, 100, -1);

    // Error of some sort on the socket
    for (int i = 0; i < n; i++) {
      if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
        close(events[i].data.fd);
        continue;
      }

        // Activity on listening socket, connection to accept
      else if (server_socket == events[i].data.fd) {
        for (;;) {
          struct sockaddr_storage client_addr;
          int client_socket;
          socklen_t addr_size;
          addr_size = sizeof client_addr;

          client_socket = accept(server_socket, (struct sockaddr *) &client_addr, &addr_size);
          if (client_socket == -1) {
            // All new connections processed
            if ((errno == EAGAIN || errno == EWOULDBLOCK)) {
              break;
            }
            perror("client accept");
            abort();
          }

          status = socket_set_nb(client_socket);
          if (status == -1) {
            abort();
          }
          connection *new_conn = calloc(1, sizeof(*new_conn));
          if (!new_conn) {
            perror("malloc");
            abort();
          }
          new_conn->sock_fd = client_socket;
          event.data.ptr = new_conn;
          event.events = EPOLLIN | EPOLLET;
          status = epoll_ctl(efd, EPOLL_CTL_ADD, client_socket, &event);

          if (status == -1) {
            perror("epoll_ctl");
            abort();
          }
        }
      }
        // Read from/write to a client socket
      else if (events[i].events & EPOLLIN) {
        connection *conn = events[i].data.ptr;
        int finished = 0;
        for (;;) {
          ssize_t count = read(conn->sock_fd, conn->read_buf + conn->read_buf_pos, buf_size - conn->read_buf_pos);
          if (count == -1) {
            if (errno != EAGAIN) {
              perror("read");
              finished = 1;
            }
            break;
          } else if (count == 0) {
            finished = 1;
            break;
          }

          client_read(&es, conn, count);

        }

        if (finished) {
          close(events[i].data.fd);
        }
      }

    }
  }
}

int main() {
  run();
}

