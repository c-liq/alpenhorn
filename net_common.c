#include "mix.h"
#include <string.h>
#include "mixnet_server.h"
#include "net_common.h"
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>

int net_accept (int listen_sfd, int set_nb)
{
  struct sockaddr_storage client_addr;
  int new_sfd, status;
  socklen_t addr_size;
  addr_size = sizeof client_addr;

  new_sfd = accept (listen_sfd, (struct sockaddr *) &client_addr, &addr_size);
  if (new_sfd == -1)
    {
      return -1;
    }

  if (set_nb)
    {
      status = socket_set_nb (new_sfd);
      if (status == -1)
        {
          perror ("setting non blocking option on socket");
          return -1;
        }
    }
  return new_sfd;
}

int net_send_nb (int sock_fd, byte_t *buf, size_t n)
{
  ssize_t bytes_sent = 0;
  while (bytes_sent < n)
    {
      ssize_t tmp_sent = send (sock_fd, buf + bytes_sent, n - bytes_sent, 0);
      if (tmp_sent <= 0)
        {
          fprintf (stderr, "socket write error\n");
          return -1;
        }
      bytes_sent += tmp_sent;
    }
  return 0;
}
int net_read_nb (int sock_fd, byte_t *buf, size_t n)
{
  int bytes_read = 0;
  while (bytes_read < n)
    {
      ssize_t tmp_read = read (sock_fd, buf + bytes_read, n - bytes_read);
      if (tmp_read <= 0)
        {
          fprintf (stderr, "socket error %d %d\n", errno, EAGAIN);
          return -1;
        }
      bytes_read += tmp_read;
    }
  return 0;
}
int net_connect (const char *addr, const char *port, int set_nb)
{
  struct addrinfo hints, *servinfo, *p;
  int sock_fd;
  memset (&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  int res = getaddrinfo (addr, port, &hints, &servinfo);
  if (res)
    {
      gai_strerror (res);
      fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (res));
      return -1;
    }

  for (p = servinfo; p != NULL; p = p->ai_next)
    {
      if ((sock_fd = socket (p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
          continue;
        }
      if (connect (sock_fd, p->ai_addr, p->ai_addrlen) == -1)
        {
          close (sock_fd);
          perror ("client: connect");
          return -1;
        }
      break;
    }
  if (set_nb)
    {
      res = socket_set_nb (sock_fd);
      if (res)
        {
          fprintf (stderr, "error setting non blocking mode on socket\n");
          return -1;
        }
    }
  return sock_fd;
}
int socket_set_nb (int socket)
{
  int flags, status;

  flags = fcntl (socket, F_GETFL, 0);
  if (flags == -1)
    {
      perror ("fcntl");
      return -1;
    }

  flags |= O_NONBLOCK;
  status = fcntl (socket, F_SETFL, flags);
  if (status == -1)
    {
      perror ("fcntl");
      return -1;
    }
  return 0;
}
int net_start_listen_socket (const char *port, int set_nb)
{
  int listen_sfd;
  struct addrinfo hints;
  struct addrinfo *serverinfo;
  memset (&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  int status = getaddrinfo (NULL, port, &hints, &serverinfo);
  if (status != 0)
    {
      fprintf (stderr, "getaddrinfo error: %s\n", gai_strerror (status));
      freeaddrinfo (serverinfo);
      return -1;
    }
  // Iterate through addrinfo structures until a socket is created
  struct addrinfo *p;
  for (p = serverinfo; p != NULL; p = p->ai_next)
    {
      listen_sfd = socket (p->ai_family, p->ai_socktype, p->ai_protocol);
      if (listen_sfd != -1)
        break;
    }

  if (listen_sfd == -1)
    {
      perror ("couldn't establish socket");
      freeaddrinfo (serverinfo);
      return -1;
    }

  int y = 1;
  if (setsockopt (listen_sfd, SOL_SOCKET, SO_REUSEADDR, &y, sizeof y) == -1)
    {
      perror ("setoption");
      return -1;
    }

  if (set_nb)
    {
      status = socket_set_nb (listen_sfd);
      if (status == -1)
        {
          close (listen_sfd);
          return -1;
        }
    }

  status = bind (listen_sfd, p->ai_addr, p->ai_addrlen);
  if (status == -1)
    {
      perror ("bind failure");
      return -1;
    }

  status = listen (listen_sfd, 5);
  if (status == -1)
    {
      perror ("listen failure");
      return -1;
    }

  freeaddrinfo (serverinfo);
  return listen_sfd;
}