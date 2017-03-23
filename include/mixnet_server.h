#ifndef ALPENHORN_ENTRY_SERVER_H
#define ALPENHORN_ENTRY_SERVER_H
#include "mix.h"
#include "net_common.h"
struct mixnet_server;
typedef struct mixnet_server net_server_s;

int epoll_accept(net_server_s *es,
                 void on_accept(net_server_s *, connection *),
                 void on_read(void *, connection *, ssize_t));
int epoll_read(net_server_s *c, connection *conn);
void net_mix_entry_clientread(void *s, connection *conn, ssize_t count);
void epoll_send (net_server_s *s, connection *conn);
void net_mix_af_forward(net_server_s *s);
void net_mix_dial_forward(net_server_s *s);
void net_mix_batch_forward(net_server_s *s, byte_buffer_s *buf);
void net_broadcast_new_dmb(net_server_s *s, uint64_t round);
void net_broadcast_new_afmb(net_server_s *s, uint64_t round);

#endif //ALPENHORN_ENTRY_SERVER_H
