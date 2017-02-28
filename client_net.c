#include <sys/epoll.h>
#include "client_net.h"
#include "client.h"
//#include "mixnet_server.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include "net_common.h"

#define MIX_NEWDROUND_MSG
#define MIX_NEWAFROUND_MSG
struct cli_conn {
  int sock_fd;
  uint32_t type;
  uint32_t id;
  byte_t read_buf[buf_size];
  uint32_t read_remaining;
  uint32_t curr_msg_len;
  uint32_t bytes_read;
  uint32_t msg_type;
  byte_t write_buf[buf_size];
  uint32_t bytes_written;
  uint32_t write_remaining;
  struct epoll_event event;
};

typedef struct cli_conn cli_conn_s;
typedef struct client_net client_net_s;
struct client_net {
  cli_conn_s mix_entry;
  cli_conn_s pkg_connections[num_pkg_servers];
  client_s *client;
  struct epoll_event *events;
  int epoll_inst;
  int num_broadcast_responses;
  int num_auth_responses;
};

int net_client_init (client_net_s *cs, client_s *c)
{
  cs->client = c;
  cs->epoll_inst = epoll_create1 (0);
  cs->events = calloc (100, sizeof *cs->events);
  cs->num_auth_responses = 0;
  cs->num_broadcast_responses = 0;
  return 0;
}

void epoll_csend (client_net_s *c, cli_conn_s *conn)
{
  int close_connection = 0;
  for (;;)
    {
      ssize_t count = send (conn->sock_fd, conn->write_buf + conn->bytes_written, conn->write_remaining, 0);
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
          conn->write_remaining -= count;
        }
    }
  if (close_connection)
    {
      //close(conn->sock_fd);
      //free(conn);
    }

  // If we haven't finished writing, make sure EPOLLOUT is set
  if (conn->write_remaining != 0 && !(conn->event.events & EPOLLOUT))
    {
      conn->event.events = EPOLLOUT | EPOLLERR | EPOLLERR;
      epoll_ctl (c->epoll_inst, EPOLL_CTL_MOD, conn->sock_fd, &conn->event);
    }
    // If we have finished writing, make sure to unset EPOLLOUT
  else if (conn->write_remaining == 0 && conn->event.events & EPOLLOUT)
    {
      conn->event.events = EPOLLIN | EPOLLERR | EPOLLHUP;
      epoll_ctl (c->epoll_inst, EPOLL_CTL_MOD, conn->sock_fd, &conn->event);
    }
}

void net_client_pkg_read (client_net_s *client, cli_conn_s *conn, ssize_t count)
{
  ssize_t c_read = count;
  if (conn->curr_msg_len == 0)
    {
      if ((count < net_batch_prefix))
        {
          return;
        }
      uint32_t msg_type = deserialize_uint32 (conn->read_buf);
      if (msg_type == PKG_BR_MSG)
        {
          conn->msg_type = PKG_BR_MSG;
          conn->curr_msg_len = pkg_broadcast_msg_BYTES;
          conn->read_remaining = pkg_broadcast_msg_BYTES;
        }
      else if (msg_type == PKG_AUTH_RES_MSG)
        {
          conn->msg_type = PKG_AUTH_RES_MSG;
          conn->curr_msg_len = pkg_enc_auth_res_BYTES;
          conn->read_remaining = pkg_enc_auth_res_BYTES;
        }

      else
        {
          fprintf (stderr, "Invalid message %c\n", conn->read_buf[0]);
          close (conn->sock_fd);
          return;
        }
      c_read -= net_batch_prefix;
    }

  conn->read_remaining -= c_read;
  conn->bytes_read += count;
  printf ("Just read %lu of %u | %d remaining | Message type: %d\n", c_read, conn->curr_msg_len, conn->read_remaining, conn->msg_type);
  if (conn->read_remaining <= 0)
    {
      if (conn->msg_type == PKG_BR_MSG)
        {
          memcpy (client->client->pkg_broadcast_msgs[conn->id],
                  conn->read_buf + net_batch_prefix, pkg_broadcast_msg_BYTES);
          client->num_broadcast_responses++;
        }
      else if (conn->msg_type == PKG_AUTH_RES_MSG)
        {
          memcpy (client->client->pkg_auth_responses[conn->id],
                  conn->read_buf + net_batch_prefix, pkg_enc_auth_res_BYTES);
          client->num_auth_responses++;
        }

      conn->msg_type = 0;
      conn->curr_msg_len = 0;
      conn->bytes_read = 0;
    }
}

int net_cli_epread (client_net_s *client, cli_conn_s *conn)
{
  int close_connection = 0;
  for (;;)
    {
      ssize_t count;
      count = read (conn->sock_fd, conn->read_buf + conn->bytes_read, sizeof conn->read_buf - conn->bytes_read);

      if (count == -1)
        {
          if (errno != EAGAIN)
            {
              perror ("read");
              close_connection = 1;
            }
          break;
        }
      else if (count == 0)
        {
          close_connection = 1;
          break;
        }

      net_client_pkg_read (client, conn, count);
    }

  if (close_connection)
    {
      close (conn->sock_fd);
    }
  return 0;
}

int net_client_startup (client_net_s *cn)
{
  struct epoll_event event;
  int mix_sfd = net_connect ("127.0.0.1", mix_client_listen, 0);
  if (mix_sfd == -1)
    {
      fprintf (stderr, "could not connect to mix entry server\n");
      return -1;
    }
  cn->mix_entry.sock_fd = mix_sfd;
  int res;
  /* int res = net_read_nb(mix_sfd, cn->mix_entry.read_buf, net_client_connect_BYTES);
   if (res == -1) {
     perror("client read");
   }
   socket_set_nb(cn->mix_entry.sock_fd);
   event.data.ptr = &cn->mix_entry;
   event.events = EPOLLIN | EPOLLHUP;
   epoll_ctl(cn->epoll_inst, EPOLL_CTL_ADD, cn->mix_entry.sock_fd, &event);

   cn->client->af_round = deserialize_uint32(cn->mix_entry.read_buf);
   cn->client->dialling_round = deserialize_uint32(cn->mix_entry.read_buf + 4);*/
  //TODO copy mix dh keys
  //TODO sync keywheels
  for (uint32_t i = 0; i < num_pkg_servers; i++)
    {
      cli_conn_s *pkg_conn = &cn->pkg_connections[i];
      pkg_conn->sock_fd = net_connect ("127.0.0.1", pkg_cl_listen_ports[i], 1);
      if (cn->pkg_connections[i].sock_fd == -1)
        {
          return -1;
        }
      pkg_conn->type = PKG_CONN;
      pkg_conn->id = i;
      pkg_conn->bytes_read = 0;
      pkg_conn->read_remaining = 0;
      pkg_conn->write_remaining = 0;
      pkg_conn->bytes_written = 0;
      event.data.ptr = &cn->pkg_connections[i];
      event.events = EPOLLIN | EPOLLET;
      epoll_ctl (cn->epoll_inst, EPOLL_CTL_ADD, cn->pkg_connections[i].sock_fd, &event);
    }

  struct epoll_event *events = cn->events;
  while (cn->num_broadcast_responses < num_pkg_servers)
    {
      int n = epoll_wait (cn->epoll_inst, cn->events, 100, 5000);
      printf ("Looping..\n");
      cli_conn_s *conn = NULL;
      // Error of some sort on the socket
      for (int i = 0; i < n; i++)
        {
          conn = events[i].data.ptr;
          if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP)
            {
              close (conn->sock_fd);
              free (events[i].data.ptr);
              continue;
            }
            // Read from a socket
          else if (events[i].events & EPOLLIN)
            {
              net_cli_epread (cn, conn);
            }
          else if (events[i].events & EPOLLOUT)
            {
              epoll_csend (cn, conn);
            }
        }
    }

  res = af_create_pkg_auth_request (cn->client);
  if (res)
    {
      fprintf (stderr, "Error creating authentication request\n");
    }

  for (int i = 0; i < num_pkg_servers; i++)
    {
      cli_conn_s *conn = &cn->pkg_connections[i];
      memcpy (conn->write_buf, cn->client->pkg_auth_requests[i], net_batch_prefix + cli_pkg_single_auth_req_BYTES);
      conn->bytes_written = 0;
      serialize_uint32 (conn->write_buf, CLI_AUTH_REQ);
      serialize_uint32 (conn->write_buf + sizeof (uint32_t), cn->client->af_round);
      conn->write_remaining = net_batch_prefix + cli_pkg_single_auth_req_BYTES;
      epoll_csend (cn, &cn->pkg_connections[i]);
    }

  while (cn->num_auth_responses < num_pkg_servers)
    {
      int n = epoll_wait (cn->epoll_inst, cn->events, 100, 5000);
      cli_conn_s *conn = NULL;
      // Error of some sort on the socket
      for (int i = 0; i < n; i++)
        {
          conn = events[i].data.ptr;
          if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP)
            {
              close (conn->sock_fd);
              free (events[i].data.ptr);
              continue;
            }
            // Read from a socket
          else if (events[i].events & EPOLLIN)
            {
              net_cli_epread (cn, conn);
            }
          else if (events[i].events & EPOLLOUT)
            {
              epoll_csend (cn, conn);
            }
        }
    }
  af_process_auth_responses (cn->client);
  return 0;
}

int main ()
{
  client_s c;
  client_init (&c, user_ids[0], user_lt_pub_sig_keys[0], user_lt_secret_sig_keys[0]);
  client_net_s s;
  net_client_init (&s, &c);
  net_client_startup (&s);

}