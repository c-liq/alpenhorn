#include "net_common.h"


int net_accept(int listen_sfd, int set_nb)
{
    struct sockaddr_storage client_addr;
    int new_sfd, status;
    socklen_t addr_size = sizeof client_addr;
    //printf("Listen socket: %d\n", listen_sfd);
    new_sfd = accept(listen_sfd, (struct sockaddr *) &client_addr, &addr_size);
    if (new_sfd == -1) {
        return -1;
    }

    if (set_nb) {
        status = socket_set_nonblocking(new_sfd);
        if (status == -1) {
            perror("setting non blocking option on socket");
            close(new_sfd);
            return -1;
        }
    }
    return new_sfd;
}

int net_epoll_client_accept(net_server_state *srv_state,
                            void on_accept(void *, connection *),
                            int on_read(void *, connection *, byte_buffer_s *))
{
    for (;;) {
        int new_sockfd = net_accept(srv_state->listen_conn.sock_fd, 1);
        if (new_sockfd == -1) {
            if ((errno == EAGAIN || errno == EWOULDBLOCK)) {
                return 0;
            }
            return -1;
        }

        connection *new_conn = calloc(1, sizeof *new_conn);
        if (!new_conn) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }

        connection_init(new_conn, read_buf_SIZE, write_buf_SIZE, on_read, srv_state->epoll_fd, new_sockfd);
        new_conn->srv_state = srv_state->owner;

        if (srv_state->clients) {
            srv_state->clients->prev = new_conn;
        }
        new_conn->next = srv_state->clients;
        new_conn->prev = NULL;
        srv_state->clients = new_conn;

        if (on_accept) {
            on_accept(srv_state->owner, new_conn);
        }
    }

}

int net_epoll_queue_write(net_server_state *owner,
                          connection *conn,
                          uint8_t *buffer,
                          u64 data_size,
                          bool copy)
{
    if (!owner || !conn || !buffer)
        return -1;

    send_item *new_item = calloc(1, sizeof *new_item);
    if (!new_item) {
        perror("malloc");
        return -1;
    }

    if (copy) {
        uint8_t *msg_buffer = calloc(data_size, sizeof(uint8_t));
        if (!msg_buffer) {
            free(new_item);
            perror("malloc");
            return -1;
        }
        memcpy(msg_buffer, buffer, data_size);
        new_item->buffer = msg_buffer;
    }
    else {
        new_item->buffer = buffer;
    }

    new_item->write_remaining = data_size;
    new_item->bytes_written = 0;
    new_item->next = NULL;
    new_item->copied = copy;

    pthread_mutex_lock(&conn->send_queue_lock);

    if (conn->send_queue_tail) {
        conn->send_queue_tail->next = new_item;
    }

    conn->send_queue_tail = new_item;
    if (!conn->send_queue_head) {
        conn->send_queue_head = new_item;
    }

    pthread_mutex_unlock(&conn->send_queue_lock);
    net_epoll_send_queue(owner, conn);
    return 0;
}

void net_epoll_send_queue(net_server_state *net_state, connection *conn)
{
    int close_connection = 0;
    send_item *current_item;
    while (conn->send_queue_head) {
        current_item = conn->send_queue_head;
        ssize_t count = send(conn->sock_fd, current_item->buffer + current_item->bytes_written,
                             current_item->write_remaining, 0);
        if (count == -1) {
            if (errno != EAGAIN) {
                fprintf(stderr, "socket send error %d on %d\n", errno, conn->sock_fd);
                close_connection = 1;
            }
            break;
        }
        else if (count == 0) {
            fprintf(stderr, "Socket send 0 bytes on %d\n", conn->sock_fd);
            close_connection = 1;
            break;
        }
        else {
            current_item->bytes_written += count;
            current_item->write_remaining -= count;

            if (current_item->write_remaining == 0) {
                pthread_mutex_lock(&conn->send_queue_lock);
                if (!current_item->next) {
                    conn->send_queue_tail = NULL;
                }
                conn->send_queue_head = current_item->next;

                pthread_mutex_unlock(&conn->send_queue_lock);

                if (current_item->copied) {
                    free(current_item->buffer);
                }
                free(current_item);
            }
        }
    }

    if (close_connection) {
        return;
    }

    if (conn->send_queue_head && !(conn->event.events & EPOLLOUT)) {
        conn->event.events = EPOLLOUT | EPOLLET;
        int res = epoll_ctl(net_state->epoll_fd, EPOLL_CTL_MOD, conn->sock_fd,
                            &conn->event);
        if (res) {
            fprintf(stderr, "epoll_ctl failed: %d\n", res);
        }
    }

    else if (!conn->send_queue_head && conn->event.events & EPOLLOUT) {
        conn->event.events = EPOLLIN | EPOLLET;
        epoll_ctl(net_state->epoll_fd, EPOLL_CTL_MOD, conn->sock_fd,
                  &conn->event);
    }
}

int connection_init(connection *conn,
                    u64 read_buf_size,
                    u64 write_buf_size,
                    int (*process)(void *, connection *, byte_buffer_s *),
                    int epoll_fd,
                    int socket_fd)
{

    if (!conn) return -1;

    int result = bb_init(&conn->read_buf, read_buf_size, true);
    if (result) return -1;

    result = bb_init(&conn->write_buf, write_buf_size, true);
    if (result) return -1;

    pthread_mutex_init(&conn->send_queue_lock, NULL);

    conn->sock_fd = socket_fd;
    conn->event.data.ptr = conn;
    conn->process = process;
    conn->event.events = EPOLLIN | EPOLLET;
    if (epoll_fd > 0 && socket_fd > 0) {
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket_fd, &conn->event))
            return -1;
    }
    conn->connected = 1;
    conn->send_queue_head = NULL;
    conn->send_queue_tail = NULL;
    return 0;
}

int net_serialize_header(uint8_t *header, u64 type, u64 length, u64 round, u64 misc)
{
    serialize_uint64(header, type);
    serialize_uint64(header + 8, length);
    serialize_uint64(header + 16, round);
    serialize_uint64(header + 24, misc);

    return 0;
}

int alp_serialize_header(byte_buffer_s *buf, u64 type, u64 length, u64 round, u64 misc)
{
    bb_write_u64(buf, type);
    bb_write_u64(buf, length);
    bb_write_u64(buf, round);
    bb_write_u64(buf, misc);

    return 0;
}

int alp_deserialize_header(net_header *header, byte_buffer_s *buf)
{
    bb_read_u64(&header->type, buf);
    bb_read_u64(&header->len, buf);
    bb_read_u64(&header->round, buf);
    bb_read_u64(&header->misc, buf);

    return 0;
}

int net_send_blocking(int sock_fd, uint8_t *buf, size_t n)
{
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

int net_read_blocking(const int sock_fd, uint8_t *buf, const size_t n)
{
    int bytes_read = 0;
    while (bytes_read < n) {
        ssize_t tmp_read = read(sock_fd, buf + bytes_read, n - bytes_read);
        if (tmp_read <= 0) {
            fprintf(stderr, "socket read error\n");
            return -1;
        }
        bytes_read += tmp_read;

    }
    return 0;
}

int net_connect(const char *addr, const char *port, const int set_nb)
{
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
        res = socket_set_nonblocking(sock_fd);
        if (res) {
            fprintf(stderr, "error setting non blocking mode on socket\n");
            close(sock_fd);
            return -1;
        }
    }
    return sock_fd;
}

int socket_set_nonblocking(int socket)
{
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

void net_process_read(void *owner, connection *conn)
{
    byte_buffer_s *buf = &conn->read_buf;
    net_header *header = &conn->header;

    while (buf->read_limit > 0) {
        if (header->type == 0) {
            if ((buf->read_limit < header_BYTES)) {
                return;
            }
            alp_deserialize_header(header, buf);
        }

        if (buf->read_limit < header->len + header_BYTES) {
            return;
        }

        byte_buffer_t message_buf;
        bb_init(message_buf, header->len, true);
        bb_to_bb(message_buf, buf, header->len);

        if (conn->process) {
            conn->process(owner, conn, buf);
        }

        bb_clear(message_buf);
        bb_compact(buf);

        header->type = 0;
        header->len = 0;
        header->round = 0;
        header->misc = 0;
    }
}

int net_epoll_read(void *owner, connection *conn)
{
    int close_client_connection = 0;
    ssize_t count;
    for (;;) {
        byte_buffer_s *read_buf = &conn->read_buf;
        count = bb_write_from_fd(read_buf, conn->sock_fd);

        if (count == -1) {
            if (errno != EAGAIN) {
                perror("read");
                close_client_connection = 1;
            }
            break;
        }

        else if (count == 0) {
            close_client_connection = 1;
            break;
        }

        net_process_read(owner, conn);
    }

    if (close_client_connection) {
        fprintf(stderr, "Epoll read: closing client_connection on sock %d | count: %lu\n", conn->sock_fd, count);
        return -1;
    }
    return 0;
}

int net_epoll_send(connection *conn, int epoll_fd)
{
    if (!conn) return -1;

    int close = 0;
    byte_buffer_s *wbuf = &conn->write_buf;

    while (wbuf->write_limit > 0) {
        ssize_t count = bb_read_to_fd(wbuf, conn->sock_fd);
        if (count == -1) {
            if (errno != EAGAIN) {
                fprintf(stderr, "socket send error %d on %d\n", errno, conn->sock_fd);
                close = 1;
            }
            break;
        }
        else if (count == 0) {
            fprintf(stderr, "Socket send 0 bytes on %d\n", conn->sock_fd);
            close = 1;
            break;
        }
    }

    if (close) {
        fprintf(stderr, "Closing socket %d in epoll send\n", conn->sock_fd);
        return -1;
    }

    if (wbuf->write_limit != 0 && !(conn->event.events & EPOLLOUT)) {
        conn->event.events = EPOLLOUT | EPOLLET;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->sock_fd, &conn->event);
    }

    else if (wbuf->write_limit == 0 && conn->event.events & EPOLLOUT) {
        conn->event.events = EPOLLIN | EPOLLET;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->sock_fd, &conn->event);
    }
    return 0;
}

int net_start_listen_socket(const char *port, const bool set_nb)
{
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
        return -1;
    }

    int y = 1;
    if (setsockopt(listen_sfd, SOL_SOCKET, SO_REUSEADDR, &y, sizeof y) == -1) {
        perror("setoption");
        close(listen_sfd);
        return -1;
    }

    if (set_nb) {
        status = socket_set_nonblocking(listen_sfd);
        if (status == -1) {
            close(listen_sfd);
            return -1;
        }
    }

    status = bind(listen_sfd, p->ai_addr, p->ai_addrlen);
    if (status == -1) {
        perror("bind failure");
        close(listen_sfd);
        return -1;
    }

    status = listen(listen_sfd, 5);
    if (status == -1) {
        perror("listen failure");
        close(listen_sfd);
        return -1;
    }
    freeaddrinfo(serverinfo);
    return listen_sfd;
}