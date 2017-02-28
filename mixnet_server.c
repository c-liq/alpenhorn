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
#include "net_common.h"

#define FRIEND_MSG 'F'
#define DIAL_MSG 'D'

struct mixnet_server {
  mix_s *mix;
  int epoll_inst;
  int listen_socket;
  struct epoll_event *events;
  int running;
  byte_t *dh_key_buf;
  size_t dh_key_buf_size;
  connection prev_mix;
  connection next_mix;
  time_t next_af_round;
  time_t next_dial_round;
  connection pkg_conns[num_pkg_servers];
};

struct mix_to_mix_conn {
  connection *next_mix;
  connection *prev_mix;
  mix_s *mix;
  u32 curr_size;
  u32 curr_read;
  byte_t read_buf[1024 * 64];
};
typedef struct mix_to_mix_conn mix_to_mix_s;

void net_mix_new_dr (net_server_s *s)
{
  if (!s->mix->is_last)
    {
      if (s->next_mix.write_buf)
        {
          byte_t *write_buf_end = s->next_mix.write_buf->buf_pos_ptr + s->next_mix.write_remaining;
          serialize_uint32 (write_buf_end, NEW_DIAL_ROUND);
          s->next_mix.write_buf->buf_pos_ptr += sizeof (u32);
          s->next_mix.write_remaining += sizeof (u32);
          epoll_send (s, &s->next_mix);
        }
      else
        {
          serialize_uint32 (s->next_mix.internal_write_buf, NEW_DIAL_ROUND);
          s->next_mix.write_remaining = sizeof (u32);
          epoll_send (s, &s->next_mix);
        }
  }
  mix_dial_newround (s->mix);
}

void net_mix_mix_read(net_server_s *srv, connection *conn, ssize_t count) {
  ssize_t c_read = count;
  if (conn->curr_msg_len == 0) {
      if ((count < net_batch_prefix))
        {
      return;
    }
      byte_t *buf_ptr = conn->internal_read_buf;
      u32 msg_type = deserialize_uint32 (buf_ptr);
      buf_ptr += 4;
      u32 num_msgs = deserialize_uint32 (buf_ptr);
      if (msg_type == AF_BATCH)
        {
          conn->msg_type = AF_BATCH;
          conn->read_buf = &srv->mix->af_data.in_buf;
          u32 message_len = num_msgs * conn->read_buf->msg_len_bytes;
          conn->curr_msg_len = message_len;
          conn->read_remaining = message_len;
        }
      else if (msg_type == DIAL_BATCH)
        {
          conn->msg_type = DIAL_BATCH;
          conn->read_buf = &srv->mix->dial_data.in_buf;
          u32 message_len = num_msgs * conn->read_buf->msg_len_bytes;
          conn->curr_msg_len = message_len;
          conn->read_remaining = message_len;
        }
      else if (msg_type == NEW_DIAL_ROUND)
        {
          net_mix_new_dr (srv);
    } else {
          fprintf (stderr, "Invalid message %c\n", conn->internal_read_buf[0]);
      close(conn->sock_fd);
      return;
    }

      c_read -= net_batch_prefix;
      memcpy (conn->read_buf->buf_base_ptr, conn->internal_read_buf + net_batch_prefix, (size_t) c_read);
      conn->read_buf->buf_pos_ptr += c_read;
  }

  conn->read_remaining -= c_read;
  conn->bytes_read += count;
  printf ("Just read %lu of %u | %d remaining | Message type: %d\n",
          c_read,
          conn->curr_msg_len,
          conn->read_remaining,
          conn->msg_type);
  if (conn->read_remaining <= 0) {
    printf("Finished reading message\n");
      printhex ("payload at forwarding server", conn->read_buf->buf_base_ptr, 256);
      if (conn->msg_type == AF_BATCH)
        {
          conn->read_buf->num_msgs = conn->curr_msg_len / conn->read_buf->msg_len_bytes;
      mix_af_decrypt_messages(srv->mix);
          printf ("Decrypted %d messages for round %d",
                  srv->mix->af_data.out_buf.num_msgs,
                  srv->mix->af_data.round_duration);
          mix_af_newround (srv->mix);
          printf ("Advanced to round %d\n", srv->mix->af_data.round);
        }
      else if (conn->msg_type == DIAL_BATCH)
        {
          conn->read_buf->num_msgs = conn->curr_msg_len / conn->read_buf->msg_len_bytes;
      mix_dial_decrypt_messages(srv->mix);
          printf ("Decrypted %d messages for round %d",
                  srv->mix->dial_data.out_buf.num_msgs,
                  srv->mix->dial_data.round_duration);
          mix_dial_newround (srv->mix);
          printf ("Advanced to round %d\n", srv->mix->dial_data.round);
    }
      conn->read_buf = NULL;
      conn->msg_type = 0;
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

int net_mix_sync(net_server_s *es) {
  u32 srv_id = es->mix->server_id;
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
      es->next_mix.event.events = EPOLLIN | EPOLLET;
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
      es->prev_mix.event.events = EPOLLIN | EPOLLET;
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
  struct epoll_event event;
  event.events = EPOLLIN | EPOLLET;
  int listen_fd = net_start_listen_socket ("3000", 0);
  for (int i = 0; i < num_pkg_servers; i++)
    {
      int fd = net_accept (listen_fd, 1);
      es->pkg_conns[i].sock_fd = fd;
      event.data.ptr = &es->pkg_conns[i];
      epoll_ctl (es->epoll_inst, EPOLL_CTL_ADD, fd, &event);
    }
  close (listen_fd);

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

void compact_read_buf(connection *conn) {
  u32 remaining = conn->bytes_read - conn->curr_msg_len;
  memcpy (conn->internal_read_buf, conn->internal_read_buf + conn->curr_msg_len, remaining);
  conn->bytes_read = remaining;

}

void net_mix_entry_clientread (net_server_s *s, connection *conn, ssize_t count)
{
  conn->bytes_read += count;
  printf("Client read stared - msg len: %d read: %d \n", conn->curr_msg_len, conn->bytes_read);
  if (conn->curr_msg_len == 0) {
      switch (conn->internal_read_buf[0])
        {
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
    mix_af_add_inc_msg (s->mix, conn->internal_read_buf);
    break;
  case onionenc_dial_token_BYTES:
    mix_dial_add_inc_msg (s->mix, conn->internal_read_buf);
    break;
  default:
    fprintf(stderr, "Invalid message format %d %d\n", conn->bytes_read, conn->curr_msg_len);
    close(conn->sock_fd);
  }
  conn->bytes_read = 0;
  conn->curr_msg_len = 0;
}

void connection_init (connection *conn)
{
  conn->read_buf = NULL;
  memset (conn->internal_read_buf, 0, sizeof conn->internal_read_buf);
  conn->read_remaining = 0;
  conn->bytes_read = 0;
  conn->msg_type = 0;
  conn->write_buf = NULL;
  conn->bytes_written = 0;
  conn->write_remaining = 0;
  conn->sock_fd = -1;
  conn->event.data.ptr = conn;
  conn->curr_msg_len = 0;
}

int es_init(net_server_s *server, mix_s *mix) {
  server->mix = mix;
  server->epoll_inst = epoll_create1(0);
  if (server->epoll_inst == -1) {
    fprintf(stderr, "Entry Server: failure when creating epoll instance\n");
    return -1;
  }
  u32 buffer_size = crypto_box_PUBLICKEYBYTES * (num_mix_servers - server->mix->server_id);
  server->dh_key_buf = calloc(1, buffer_size);
  server->dh_key_buf_size = buffer_size;
  memcpy (server->dh_key_buf, server->mix->eph_pk, crypto_box_PUBLICKEYBYTES);
  server->events = calloc(2000, sizeof *server->events);
  connection_init (&server->prev_mix);
  connection_init (&server->next_mix);
  return 0;
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

void net_mix_batch_forward (net_server_s *s, mix_buffer_s *buf)
{
  connection *conn = &s->next_mix;
  conn->write_buf = buf;
  conn->bytes_written = 0;
  conn->write_remaining = net_batch_prefix + (buf->num_msgs * buf->msg_len_bytes);
  buf->buf_pos_ptr = buf->buf_base_ptr;
  epoll_send (s, conn);
}

void net_mix_af_forward (net_server_s *s)
{
  mix_af_decrypt_messages (s->mix);
  mix_buffer_s *buf = &s->mix->af_data.out_buf;
  net_mix_batch_forward (s, buf);
}

void net_mix_dial_forward (net_server_s *s)
{
  mix_dial_decrypt_messages (s->mix);
  mix_af_decrypt_messages (s->mix);
  mix_buffer_s *buf = &s->mix->dial_data.out_buf;
  printhex ("buf at srv", buf->buf_base_ptr, 256);
  printf ("Num msgs: %u | Msg_size: %u | Payload size: %u\n\n",
          buf->num_msgs,
          buf->msg_len_bytes,
          buf->num_msgs * buf->msg_len_bytes);
  net_mix_batch_forward (s, buf);
}

void epoll_send (net_server_s *s, connection *conn)
{
  int close_connection = 0;
  for (;;)
    {
      ssize_t count = send (conn->sock_fd, conn->write_buf->buf_pos_ptr, conn->write_remaining, 0);
      if (count == -1)
        {
          if (errno != EAGAIN)
            {
              perror ("send");
              close_connection = 1;
            }
          break;
        }
      else if (count == 0)
        {
          close_connection = 1;
          break;
        }
      else
        {
          conn->bytes_written += count;
          conn->write_buf->buf_pos_ptr += count;
          conn->write_remaining -= count;
        }
    }
  if (close_connection) {
    //close(conn->sock_fd);
    //free(conn);
  }

  // If we haven't finished writing, make sure EPOLLOUT is set
  if (conn->write_remaining != 0 && !(conn->event.events & EPOLLOUT))
    {
      conn->event.events = EPOLLOUT | EPOLLERR | EPOLLERR;
      epoll_ctl (s->epoll_inst, EPOLL_CTL_MOD, conn->sock_fd, &conn->event);
    }
    // If we have finished writing, make sure to unset EPOLLOUT
  else if (conn->write_remaining == 0 && conn->event.events & EPOLLOUT)
    {
      conn->event.events = EPOLLIN | EPOLLERR | EPOLLHUP;
      epoll_ctl (s->epoll_inst, EPOLL_CTL_MOD, conn->sock_fd, &conn->event);
  }
}

int epoll_read(net_server_s *es, connection *conn, void (*process)(net_server_s *, connection *, ssize_t)) {
  int close_connection = 0;
  for (;;) {
      ssize_t count;
      if (conn->read_buf != NULL)
        {
          mix_buffer_s *read_buf = conn->read_buf;
          count = read (conn->sock_fd, read_buf->buf_pos_ptr, conn->read_remaining);
        }
      else
        {
          count = read (conn->sock_fd, conn->internal_read_buf, sizeof conn->internal_read_buf);
        }
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
      net_mix_dial_forward (s);
      s->next_dial_round = time (0) + s->mix->dial_data.round_duration;
      printf ("New dial round started: %u\n", s->mix->dial_data.round);
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
          conn = (connection *) events[i].data.ptr;
          epoll_send (es, conn);
      }
    }
  }

}

void net_srv_loop(net_server_s *es, void(*on_read)(net_server_s *, connection *, ssize_t)) {

  struct epoll_event *events = es->events;
  es->running = 1;
  es->next_af_round = time (0) + es->mix->af_data.round_duration;
  es->next_dial_round = time (0) + es->mix->dial_data.round_duration;
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
          epoll_send (es, conn);
      }
    }
  }
}

/*int main(int argc, char **argv) {
  if (*argv[1] == '0') {
    net_server_s es;
    mix_s mix;
    mix_init(&mix, 0);
    es_init(&es, &mix);
    net_entry_sync(&es);
    mix_dial_add_noise(&mix);
    mix_af_add_noise(&mix);
    net_srv_loop(&es, net_mix_entry_clientread);
  } else {
    mix_s mix;
    mix_init(&mix, 1);
    net_server_s es;
    es_init(&es, &mix);
    net_mix_sync(&es);
    net_mix_loop(&es);
  }
}*/

