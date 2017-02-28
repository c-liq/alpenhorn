#ifndef ALPENHORN_ENTRY_SERVER_H
#define ALPENHORN_ENTRY_SERVER_H
#include "mix.h"
#include "net_common.h"
struct mixnet_server;
typedef struct mixnet_server net_server_s;

int epoll_accept(net_server_s *es);
int epoll_read(net_server_s *es, connection *conn, void(*process)(net_server_s *, connection *, ssize_t));
void net_mix_entry_clientread (net_server_s *s, connection *conn, ssize_t count);
void epoll_send (net_server_s *s, connection *conn);

#endif //ALPENHORN_ENTRY_SERVER_H
