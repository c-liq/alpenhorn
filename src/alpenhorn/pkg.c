#include "alpenhorn/pkg.h"
#include "alpenhorn/pkg_config.h"
#include <curl/curl.h>
#include <assert.h>

typedef struct pkg_thread_args {
  pkg *server;
  u64 begin;
  u64 end;
  uint8_t *data;
} pkg_thread_args;

struct upload_status {
  size_t remaining;
  size_t read;
  uint8_t *data;
};

typedef struct pkg_auth_args {
  pkg *pkg_s;
  connection *conn;
  byte_buffer *buf;
} pkg_auth_args;

void *pkg_client_auth_data(void *args);
void *pkg_client_parallel_init(void *args);

static size_t payload_source(void *ptr, size_t size, size_t nmemb, void *userp) {
    struct upload_status *upload_ctx = (struct upload_status *) userp;
    size_t max_read = nmemb * size;

    if ((size == 0) || (nmemb == 0) || ((max_read) < 1)) {
        return 0;
    }

    size_t rem = upload_ctx->remaining;
    size_t to_read = max_read > rem ? rem : max_read;

    if (to_read <= 0) {
        return 0;
    }

    memcpy(ptr, upload_ctx->data + upload_ctx->read, to_read);
    upload_ctx->remaining -= to_read;
    upload_ctx->read += to_read;

    return to_read;
}
/// @param up

void pkg_configure_curl(struct upload_status *up, CURL *curl, struct curl_slist *recipients) {
    /*curl_easy_setopt(curl, CURLOPT_USERNAME, "alpenhorn.test@gmail.com");
    curl_easy_setopt(curl, CURLOPT_PASSWORD, "alpenhorn");
    curl_easy_setopt(curl, CURLOPT_URL, "smtp://smtp.gmail.com:587");
    curl_easy_setopt(curl, CURLOPT_USE_SSL, (long) CURLUSESSL_ALL);
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, "alpenhorn.test@gmail.com");

    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
    curl_easy_setopt(curl, CURLOPT_READDATA, up);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);*/
}

int pkg_registration_request(pkg *server, byte_buffer *buf) {
    u8 *user_id = bb_read_virtual(buf, user_id_BYTES);
    u8 *sig_key = bb_read_virtual(buf, crypto_sign_BYTES);

    pkg_pending_client *pc = calloc(1, sizeof(pkg_pending_client));
    memcpy(pc->user_id, user_id, user_id_BYTES);
    memcpy(pc->sig_key, sig_key, crypto_sign_PUBLICKEYBYTES);
    randombytes_buf(pc->confirmation_key, crypto_ghash_BYTES);

    char *date = "Date: Mon, 29 Nov 2010 21:54:29 +1100\r\n";
    char *from = "From: alpenhorn.test@gmail.com\r\n";
    char *subject = "Subject: Alpenhorn registration request\r\n\r\n";

    byte_buffer *email_buffer = bb_alloc(1024, false);
    bb_write(email_buffer, (uint8_t *) date, strlen(date));
    char to_string[1024];
    char body_string[1024];
    sprintf(to_string, "To: %s\r\n", user_id);
    bb_write(email_buffer, (uint8_t *) to_string, strlen(to_string));
    bb_write(email_buffer, (uint8_t *) from, strlen(from));
    bb_write(email_buffer, (uint8_t *) subject, strlen(subject));

    sodium_bin2hex(body_string, crypto_ghash_BYTES * 2 + 1, pc->confirmation_key, crypto_ghash_BYTES);
    bb_write(email_buffer, (uint8_t *) body_string, strlen(body_string));

    struct upload_status up;
    up.data = email_buffer->data;
    up.read = 0;
    up.remaining = email_buffer->read_limit;

    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "curl error\n");
        return -1;
    }

    struct curl_slist *recipients = NULL;
    recipients = curl_slist_append(recipients, (char *) user_id);

    pkg_configure_curl(&up, curl, recipients);
    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(recipients);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        fprintf(
            stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        free(pc);
        return -1;
    }

    pc->next = server->pending_registration_requests;
    server->pending_registration_requests = pc;
    pc->prev = NULL;

    if (pc->next) {
        pc->next->prev = pc;
    }

    return 0;
}

pkg_pending_client *pkg_lookup_pending_reg(pkg *server, uint8_t *user_id) {
    pkg_pending_client *pc = server->pending_registration_requests;
    while (pc) {
        if (!strncmp((char *) user_id, (char *) pc->user_id, user_id_BYTES)) {
            break;
        }
        pc = pc->next;
    }
    return pc;
}

void pkg_delete_registration_request(pkg *server, pkg_pending_client *pc) {
    if (server->pending_registration_requests == pc) {
        server->pending_registration_requests = pc->next;
    }

    if (pc->next) {
        pc->next->prev = pc->prev;
    }

    if (pc->prev) {
        pc->prev->next = pc->next;
    }

    free(pc);
}

int pkg_confirm_registration(pkg *server, byte_buffer *buf) {
    u8 *user_id = bb_read_virtual(buf, user_id_BYTES);
    u8 *sig = bb_read_virtual(buf, crypto_sign_BYTES);

    pkg_pending_client *pc = pkg_lookup_pending_reg(server, user_id);
    if (!pc) {
        fprintf(stderr, "no pending request matching userid\n");
        return -1;
    }

    if (crypto_sign_verify_detached(sig, pc->confirmation_key, crypto_ghash_BYTES, pc->sig_key)) {
        fprintf(stderr, "sig verification failed when confirming user registration\n");
        return -1;
    }

    pkg_client *new_client = &server->clients[server->num_clients++];
    pkg_client_init(new_client, server, pc->user_id, pc->sig_key);

    pkg_gen_identity_sk(server, new_client);
    pkg_gen_certificate(server, new_client);

    pkg_delete_registration_request(server, pc);
    return 0;
}

void load_user_data(pkg *pkg, u64 num_clients, const char *user_data_path);

int pkg_server_init(pkg *pkg, u64 server_id, u64 num_users, int num_threads, char *user_data_path) {
    twistpoint_fp2_set(pkg->sig_keys.public_key, pkg_lt_pks[server_id]);
    scalar_set_lluarray(pkg->sig_keys.sk, pkg_lt_sks[server_id]);
    pkg->round = 0;
    pkg->num_clients = num_users;
    pkg->client_capacity = num_users * 2 + 10;
    pkg->num_threads = num_threads;
    pkg->id = server_id;
    pkg->clients = calloc(pkg->client_capacity, sizeof(pkg_client));

    if (user_data_path) {
        load_user_data(pkg, num_users, user_data_path);
    }

    pkg->pending_registration_requests = NULL;
    pkg->broadcast = bb_alloc(header_BYTES + pkg_broadcast_msg_BYTES, false);
    pkg_new_ibe_keypair(pkg);
    crypto_box_keypair(pkg->dh_pk, pkg->dh_sk);
    pkg->thread_pool = thpool_init(pkg->num_threads);

    return 0;
}

void load_user_data(struct pkg *pkg, u64 num_clients, const char *user_data_path) {
    u64 client_data_size = user_id_BYTES + crypto_sign_PUBLICKEYBYTES + crypto_sign_SECRETKEYBYTES;
    FILE *user_file = fopen(user_data_path, "r");
    u64 data_size = num_clients * client_data_size;
    uint8_t *client_data_buffer = calloc(1, data_size);
    if (!user_file) {
        fprintf(stderr, "failed to open user data file, terminating\n");

    }

    fread(client_data_buffer, client_data_size, num_clients, user_file);
    fclose(user_file);

    pkg_parallel_operation(pkg, pkg_client_parallel_init, client_data_buffer, client_data_size);
    pkg_parallel_operation(pkg, pkg_client_auth_data, NULL, 0);
}

void thpool_auth_client(void *arg) {
    pkg_auth_args *args = (pkg_auth_args *) arg;
    connection *conn = args->conn;
    pkg_client *client = conn->client_state;
    byte_buffer *buf = args->buf;

    if (!client) {
        pkg *srv = args->pkg_s;
        uint8_t *user_id = buf->read_pos + round_BYTES;
        assert(user_id);
        int index = pkg_client_lookup(srv, user_id);
        if (index == -1) {
            fprintf(stderr, "could not find username %s\n", user_id);
            free(args->buf);
            free(args);
            return;
        }
        conn->client_state = &srv->clients[index];
        client = conn->client_state;
    }

    int authed = pkg_auth_client(client->server, client, conn, buf);
    if (!authed) {
        client->last_auth = time(0);
        net_epoll_send(conn, conn->sock_fd);
    }

    free(args);
    free(buf);

}

void *pkg_client_auth_data(void *args) {
    pkg_thread_args *th_args = (pkg_thread_args *) args;
    pkg *srv = th_args->server;

    for (u64 i = th_args->begin; i < th_args->end; i++) {
        pkg_gen_identity_sk(srv, &srv->clients[i]);
        pkg_gen_certificate(srv, &srv->clients[i]);
    }
    return NULL;
}

void *pkg_client_parallel_init(void *args) {
    pkg_thread_args *th_args = (pkg_thread_args *) args;
    pkg *pkg = th_args->server;
    uint8_t *data = th_args->data;

    for (u64 i = th_args->begin; i < th_args->end; i++) {
        pkg_client_init(&pkg->clients[i], pkg, data, data + user_id_BYTES);
        data += (user_id_BYTES + crypto_sign_PUBLICKEYBYTES + crypto_sign_SECRETKEYBYTES);
    }
    return NULL;
}

int pkg_parallel_operation(pkg *server, void *(*operator)(void *), uint8_t *data_ptr, u64 data_elem_length) {
    long num_threads = server->num_threads;
    pthread_t threads[num_threads];
    pkg_thread_args args[num_threads];
    u64 num_per_thread = server->num_clients / num_threads;
    u64 curindex = 0;
    for (int i = 0; i < num_threads - 1; i++) {
        args[i].server = server;
        args[i].begin = curindex;
        args[i].end = curindex + num_per_thread;
        if (data_ptr) {
            args[i].data = data_ptr + (curindex * data_elem_length);
        }
        curindex += num_per_thread;

    }

    args[num_threads - 1].server = server;
    args[num_threads - 1].begin = curindex;
    args[num_threads - 1].end = server->num_clients;
    if (data_ptr) {
        args[num_threads - 1].data = data_ptr + (curindex * data_elem_length);
    }

    for (int i = 0; i < num_threads; i++) {
        int res = pthread_create(&threads[i], NULL, operator, &args[i]);
        if (res) {
            fprintf(stderr, "fatal pthread creation error\n");
            exit(EXIT_FAILURE);
        }
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}

int pkg_client_lookup(pkg *server, uint8_t *user_id) {
    int index = -1;
    for (int i = 0; i < server->num_clients; i++) {
        if (!(strncmp((char *) user_id, (char *) server->clients[i].user_id, user_id_BYTES))) {
            index = i;
            break;
        }
    }
    return index;
}

void
pkg_client_init(pkg_client *client, pkg *server, const uint8_t *user_id, const uint8_t *lt_sig_key) {
    client->server = server;
    client->auth_response_ibe_key_ptr = client->eph_client_data + bn256_bls_sig_message_bytes;
    serialize_u64(client->eph_client_data, PKG_AUTH_RES_MSG);
    memcpy(client->user_id, user_id, user_id_BYTES);
    memcpy(client->sig_pk, lt_sig_key, crypto_sign_PUBLICKEYBYTES);
    memcpy(client->rnd_sig_msg + round_BYTES, client->user_id, user_id_BYTES);
    memcpy(client->rnd_sig_msg + round_BYTES + user_id_BYTES, client->sig_pk, crypto_sign_PUBLICKEYBYTES);
    bn256_hash_g2(client->hashed_id_elem_g2, user_id, user_id_BYTES);
}

void pkg_server_shutdown(pkg *server) {
    if (!server)
        return;

    free(server->clients);
}

void pkg_broadcast_round(pkg *pkg) {
    connection *conn = pkg->net_state.clients;
    while (conn) {
        bb_write(&conn->write_buf, pkg->broadcast->data, pkg->broadcast->written);
        net_epoll_send(conn, conn->sock_fd);
        conn = conn->next;
    }
    printf("Starting round %ld\n", pkg->round);
}

void pkg_new_round(pkg *server) {
    server->round++;
    bb_reset(server->broadcast);

    alp_serialize_header(server->broadcast, PKG_BR_MSG, pkg_broadcast_msg_BYTES, server->round, 0UL);
    pkg_new_ibe_keypair(server);
    crypto_box_keypair(server->dh_pk, server->dh_sk);
    bb_write(server->broadcast, server->dh_pk, crypto_box_PUBLICKEYBYTES);

    pkg_parallel_operation(server, pkg_client_auth_data, NULL, 0);
    pkg_broadcast_round(server);
}

void build_client_auth_msg(u8 *auth_msg, u64 round, pkg_client *client, u8 *pk) {
    serialize_u64(auth_msg, round);
    memcpy(auth_msg + round_BYTES, client->user_id, user_id_BYTES);
    memcpy(auth_msg + round_BYTES + user_id_BYTES, pk, crypto_box_PUBLICKEYBYTES);
}

int pkg_auth_client(pkg *server, pkg_client *client, connection *conn, byte_buffer *buf) {

    bb_read_virtual(buf, round_BYTES + user_id_BYTES);
    u8 *pk = bb_read_virtual(buf, crypto_box_PUBLICKEYBYTES);
    u8 *sig = bb_read_virtual(buf, crypto_sign_BYTES);
    u8 auth_msg[client_sigmsg_BYTES];
    build_client_auth_msg(auth_msg, server->round, client, pk);
    if (crypto_sign_verify_detached(sig, auth_msg, client_sigmsg_BYTES, client->sig_pk)) {
        fprintf(stderr, "failed to verify signature during client auth\n");
        return -1;
    }

    u8 symmetric_key[crypto_box_SECRETKEYBYTES];
    crypto_shared_secret(symmetric_key, server->dh_sk, pk, pk, server->dh_pk, crypto_secretbox_KEYBYTES);

    alp_serialize_header(&conn->write_buf, PKG_AUTH_RES_MSG, pkg_enc_auth_res_BYTES, server->round, 0);
    u8 *ctext_ptr = bb_write_virtual(&conn->write_buf, pkg_enc_auth_res_BYTES);
    crypto_salsa_encrypt(ctext_ptr, client->eph_client_data, pkg_auth_res_BYTES, symmetric_key);

    sodium_memzero(symmetric_key, sizeof symmetric_key);
    printf("Auth success\n");
    return 0;
}

void pkg_new_ibe_keypair(pkg *server) {
    bn256_scalar_random(server->ibe_master_sk);
    bn256_scalarmult_base_g1(server->ibe_master_pk, server->ibe_master_sk);
    curvepoint_fp_makeaffine(server->ibe_master_pk);
    u8 *serialized_pk_ptr = bb_write_virtual(server->broadcast, g1_bytes);
    bn256_serialize_g1(serialized_pk_ptr, server->ibe_master_pk);
}

void pkg_gen_identity_sk(pkg *server, pkg_client *client) {
    twistpoint_fp2_t client_sk;
    twistpoint_fp2_scalarmult_vartime(client_sk, client->hashed_id_elem_g2, server->ibe_master_sk);
    twistpoint_fp2_makeaffine(client_sk);
    bn256_serialize_g2(client->auth_response_ibe_key_ptr, client_sk);
}

void pkg_gen_certificate(pkg *pkg, pkg_client *client) {
    serialize_u64(client->rnd_sig_msg, pkg->round);
    bn256_bls_sign_message(client->eph_client_data, client->rnd_sig_msg, pkg_sig_message_BYTES, pkg->sig_keys.sk);
}

static const char *pkg_cl_listen_ports[] = {"7500", "7501", "7502"};

void remove_client(pkg *s, connection *conn) {
    nss_s *net_state = &s->net_state;
    epoll_ctl(net_state->epoll_fd, EPOLL_CTL_DEL, conn->sock_fd, &conn->event);
    if (conn == net_state->clients) {
        net_state->clients = conn->next;
    }
    if (conn->next) {
        conn->next->prev = conn->prev;
    }
    if (conn->prev) {
        conn->prev->next = conn->next;
    }
    free(conn);
}

int pkg_mix_read(void *srv, connection *conn, byte_buffer *buf) {
    net_header *header = &conn->header;
    if (header->type == PKG_REFRESH_KEYS) {
        pkg_new_round(srv);
    }

    (void) buf;
    return 0;
}

int pkg_net_process_client_msg(void *srv, connection *conn, byte_buffer *buf) {
    pkg *s = (pkg *) srv;
    net_header *header = &conn->header;

    switch (header->type) {
        case CLIENT_AUTH_REQ: {
            byte_buffer *msg = bb_clone(conn->msg_buf);
            struct pkg_auth_args *args = calloc(1, sizeof *args);
            args->pkg_s = s;
            args->conn = conn;
            args->buf = msg;
            thpool_add_work(s->thread_pool, thpool_auth_client, args);
            break;
        }
        case CLIENT_REG_REQUEST:pkg_registration_request(s, buf);
            break;
        case CLIENT_REG_CONFIRM:pkg_confirm_registration(s, buf);
            break;
        default:fprintf(stderr, "Invalid message type from client\n");
    }
    return 0;
}

int pkg_server_startup(pkg *pkg) {
    nss_s *s = &pkg->net_state;
    s->owner = pkg;
    s->clients = NULL;
    s->epoll_fd = epoll_create1(0);

    net_connect_init(&pkg->mix_conn, mix_server_ip, mix_server_port, s->epoll_fd, 1, read_buf_SIZE, pkg_mix_read);

    s->listen_conn.sock_fd = net_start_listen_socket(pkg_cl_listen_ports[pkg->id], 1);
    if (s->listen_conn.sock_fd == -1) {
        fprintf(stderr, "failed to establish listening socket for pkg server\n");
        return -1;
    }

    struct epoll_event event;
    memset(&event, 0, sizeof event);
    event.data.ptr = &s->listen_conn;
    event.events = EPOLLIN | EPOLLET;
    epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, s->listen_conn.sock_fd, &event);

    return 0;
}

void pkg_server_run(pkg *s) {
    nss_s *net_state = &s->net_state;
    struct epoll_event *events = net_state->events;

    for (;;) {
        int n = epoll_wait(net_state->epoll_fd, net_state->events, epoll_num_events, 5000);
        connection *conn = NULL;
        // Error of some sort on the socket
        for (int i = 0; i < n; i++) {
            conn = (connection *) events[i].data.ptr;
            if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
                close(conn->sock_fd);
                remove_client(s, conn);
                continue;
            } else if (&net_state->listen_conn == events[i].data.ptr) {
                int res = net_epoll_client_accept(net_state, NULL, pkg_net_process_client_msg);
                if (res) {
                    fprintf(stderr, "fatal server error\n");
                    exit(1);
                }
            } else if (events[i].events & EPOLLIN) {
                net_epoll_read(s, conn);
            } else if (events[i].events & EPOLLOUT) {
                net_epoll_send(conn, conn->sock_fd);
            }
        }
    }
}
