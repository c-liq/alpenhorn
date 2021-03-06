#include <assert.h>
#include "alpenhorn/mixnet.h"

static bool running;

void mix_af_init_container(mixer_s *mixer) {
    mailbox_container_s *c = &mixer->mailboxes;

    for (u64 i = 0; i < c->num_boxes; i++) {
        mailbox_s *mb = &c->boxes[i];
        mb->id = i;
        mb->msg_count = mixer->mb_counts[i];
        mb->size_bytes = header_BYTES + (af_ibeenc_request_BYTES * mb->msg_count);
        mb->box_struct = bb_alloc(mb->size_bytes, false);

        if (!mb->box_struct) {
            fprintf(stderr, "fatal calloc error");
            exit(EXIT_FAILURE);
        }
        byte_buffer *buffer = (byte_buffer *) mb->box_struct;
        mb->box_data = buffer->data;
        alp_serialize_header(buffer, AF_MB, mb->size_bytes - header_BYTES, c->round, mb->msg_count);
    }
}

void mix_dial_init_container(mixer_s *mixer) {
    mailbox_container_s *c = &mixer->mailboxes;
    double bloom_p_val = 1e-10;

    for (u64 i = 0; i < c->num_boxes; i++) {
        mailbox_s *mb = &c->boxes[i];
        mb->id = i;
        mb->msg_count = mixer->mb_counts[i];

        if (mb->msg_count < 1) {
            continue;
        }

        mb->box_struct = bloom_alloc(bloom_p_val, mb->msg_count, NULL, header_BYTES);
        if (!mb->box_struct) {
            fprintf(stderr, "fatal calloc error");
            exit(EXIT_FAILURE);
        }

        bloom_s *bf = (bloom_s *) mb->box_struct;
        mb->box_data = bf->base_ptr;
        mb->size_bytes = bf->total_size;
        net_serialize_header(bf->base_ptr, DIAL_MB, mb->size_bytes - header_BYTES, c->round, mb->msg_count);
    }
}

void mix_dial_clear_container(mixer_s *mixer) {
    for (u64 i = 0; i < mixer->mailboxes.num_boxes; i++) {
        bloom_free(mixer->mailboxes.boxes[i].box_struct);
    }
}

void mix_af_clear_container(mixer_s *mixer) {
    for (u64 i = 0; i < mixer->mailboxes.num_boxes; i++) {
        bb_free(mixer->mailboxes.boxes[i].box_struct);
    }
}

void mix_af_distribute(mixer_s *mixer) {
    mailbox_container_s *c = &mixer->mailboxes;
    c->num_boxes = mixer->num_boxes;
    c->round = mixer->round;

    for (u64 i = 0; i < mixer->out_msg_count; i++) {
        u64 box_num;
        bb_read_u64(&box_num, mixer->out_buf);
        bb_to_bb(c->boxes[0].box_struct, mixer->out_buf, af_ibeenc_request_BYTES);
    }
}

void mix_dial_distribute(mixer_s *mixer) {
    mailbox_container_s *c = &mixer->mailboxes;

    byte_buffer *buf = mixer->out_buf;
    u8 *curr_msg_ptr = buf->data;
    for (int i = 0; i < mixer->out_msg_count; i++) {
        u64 mb = deserialize_uint64(curr_msg_ptr);
        bloom_add_elem(c->boxes[mb].box_struct, curr_msg_ptr + mb_BYTES, dialling_token_BYTES);
        curr_msg_ptr += (mb_BYTES + dialling_token_BYTES);
    }
}

mailbox_s *mix_exit_get_mailbox(mixer_s *mixer, u64 mb_num) {
    mailbox_container_s *container = &mixer->mailboxes;
    if (mb_num >= mixer->num_boxes) {
        return NULL;
    }

    return &container->boxes[mb_num];
}

void mix_entry_add_message(byte_buffer_t buf, mixer_s *mixer) {
    if (!bb_to_bb(mixer->in_buf, buf, mixer->inc_msg_length)) {
        mixer->inc_msg_count++;
    } else {
        printf("Failed to add client msg for %s\n", mixer->name);
        bb_print(buf);
    }
}

void mix_af_gen_noise_msg(u8 *msg) {
    scalar_t random;
    curvepoint_fp_t tmp;
    bn256_g1_random(tmp, random);
    bn256_serialize_g1(msg, tmp);
    randombytes_buf(msg + g1_serialized_bytes, af_ibeenc_request_BYTES - g1_serialized_bytes);
}

static const struct mixer_config af_cfg = {
    .msg_length = af_ibeenc_request_BYTES,
    .auth_msg_type = MIX_AF_SETTINGS,
    .round_msg_type = NEW_AF_ROUND,
    .batch_msg_type = MIX_AF_BATCH,
    .round_duration = af_duration,
    .window_duration = af_window,
    .laplace_b = af_b,
    .laplace_mu = af_mu,
    .init_container = mix_af_init_container,
    .clear_container = mix_af_clear_container,
    .distribute = mix_af_distribute,
    .fill_noise_msg = mix_af_gen_noise_msg,
    .name = "AF"
};

void mix_dial_gen_noise_msg(u8 *msg) {
    randombytes_buf(msg, dialling_token_BYTES);
}

static const struct mixer_config dial_cfg =
    {.msg_length = dialling_token_BYTES, .auth_msg_type = MIX_DIAL_SETTINGS, .round_msg_type = NEW_DIAL_ROUND, .batch_msg_type = MIX_DIAL_BATCH, .round_duration = dial_duration, .window_duration = dial_window, .laplace_b = dial_b, .laplace_mu = dial_mu, .init_container = mix_dial_init_container, .clear_container = mix_dial_clear_container, .distribute = mix_dial_distribute, .fill_noise_msg = mix_dial_gen_noise_msg, .name = "Dial"};

int mix_init_mixer(mix_s *mix, mixer_s *mixer, const struct mixer_config *cfg) {
    mixer->name = cfg->name;
    mixer->msg_length = cfg->msg_length;
    mixer->inc_msg_length = mixer->msg_length + mb_BYTES + (mix->num_in_layers * crypto_box_SEALBYTES);
    mixer->out_msg_length = mixer->inc_msg_length - crypto_box_SEALBYTES;
    mixer->round_duration = cfg->round_duration;
    mixer->window_duration = cfg->window_duration;
    mixer->auth_msg_type = cfg->auth_msg_type;
    mixer->batch_msg_type = cfg->batch_msg_type;
    mixer->round_msg_type = cfg->round_msg_type;
    mixer->laplace.mu = cfg->laplace_mu;
    mixer->laplace.b = cfg->laplace_b;
    mixer->num_boxes = 1;
    mixer->init_container = cfg->init_container;
    mixer->clear_container = cfg->clear_container;
    mixer->distribute = cfg->distribute;
    mixer->fill_noise_msg = cfg->fill_noise_msg;

    memset(mixer->pk, 0, sizeof mixer->pk);
    memset(mixer->sk, 0, sizeof mixer->sk);
    memset(mixer->mix_pks, 0, crypto_box_PUBLICKEYBYTES * num_mix_servers);

    mixer->inc_msg_count = 0;
    mixer->out_msg_count = 0;
    mixer->mb_counts = calloc(mixer->num_boxes, sizeof mixer->mb_counts);

    mixer->mailboxes.boxes = calloc(mixer->num_boxes, sizeof *mixer->mailboxes.boxes);
    mixer->mailboxes.num_boxes = mixer->num_boxes;
    mixer->mailboxes.round = mixer->round;
    mixer->init_container(mixer);

    bb_init(mixer->in_buf, 64000, true);
    bb_init(mixer->out_buf, 64000, true);
    bb_init(mixer->broadcast, 2048, true);

    mixer->round = 0;
    pthread_mutex_init(&mixer->mutex, NULL);

    return 0;
}

int mix_init_crypto(mix_s *mix) {
    if (sodium_init() < 0) {
        fprintf(stderr, "failied to initialise libsodium\n");
        exit(EXIT_FAILURE);
    }

#if USE_PBC
    pairing_init_set_str(&mix->pairing, pbc_params);
    element_init_G1(&mix->ibe_gen_elem, &mix->pairing);
    result = element_set_str(&mix->ibe_gen_elem, ibe_generator, 10);
    if (result == 0) {
        fprintf(stderr, "Invalid string for ibe generation element\n");
        return -1;
    }
#else
    (void) mix;
    bn256_init();
#endif
    return 0;
}
/*
struct mix_cfg {
    u64 num_servers;
    u64 id;
    long num_threads;
    char **server_addresses;
    char **server_ports;
    u8 signing_pk[crypto_sign_PUBLICKEYBYTES];
    u8 signing_sk[crypto_sign_SECRETKEYBYTES];
    u8 *mix_signing_pks[crypto_sign_PUBLICKEYBYTES];
    u64 num_mixers;
    struct mixer_config *mixer_configs;
};*/

int mix_init(mix_s *mix, u64 server_id, long num_threads) {
    mix_init_crypto(mix);

    mix->id = server_id;
    mix->is_last = num_mix_servers - mix->id == 1;
    mix->num_in_layers = num_mix_servers - server_id;
    mix->num_out_layers = mix->num_in_layers - 1;
    mix->num_threads = num_threads;

    mix_init_mixer(mix, &mix->af_data, &af_cfg);
    mix_init_mixer(mix, &mix->dial_data, &dial_cfg);
    bb_init(mix->broadcast, header_BYTES, false);

    mix->next_mix = calloc(1, sizeof *mix->next_mix);
    mix->prev_mix = calloc(1, sizeof *mix->prev_mix);

    net_server *net_state = &mix->ns;
    net_state->owner = mix;
    net_state->epoll_fd = epoll_create1(0);

    for (int i = 0; i < num_mix_servers; i++) {
        sodium_hex2bin(mix->mix_sig_pks[i],
                       crypto_sign_PUBLICKEYBYTES,
                       mix_sig_pks[i],
                       crypto_sign_PUBLICKEYBYTES * 2 + 1,
                       NULL,
                       NULL,
                       NULL);
    }

    sodium_hex2bin(mix->sig_sk,
                   crypto_sign_SECRETKEYBYTES,
                   mix_sig_sks[mix->id],
                   crypto_sign_SECRETKEYBYTES * 2 + 1,
                   NULL,
                   NULL,
                   NULL);

    if (net_state->epoll_fd == -1) {
        fprintf(stderr, "Entry Server: failure when creating epoll instance\n");
        return -1;
    }

    signal(SIGPIPE, SIG_IGN);

    return 0;
}

void mix_calc_mb_count(mix_s *mix, mixer_s *mixer) {
    (void) mix;
    mixer->num_boxes = 1;
}

void mix_new_round(mix_s *mix, mixer_s *mixer) {
    bb_reset(mixer->in_buf);
    bb_reset(mixer->out_buf);
    mixer->round++;

    if (mix->is_last) {
        mix_calc_mb_count(mix, mixer);
        free(mixer->mb_counts);
        mixer->mb_counts = calloc(mixer->num_boxes, sizeof *mixer->mb_counts);
    }

    mixer->inc_msg_count = 0;
    mixer->out_msg_count = 0;
    crypto_box_keypair(mixer->pk, mixer->sk);
}

void mix_shuffle_messages(mixer_s *mixer) {
    if (mixer->out_msg_count < 2) {
        return;
    }

    u64 msg_count = mixer->out_msg_count;
    u8 *messages = mixer->out_buf->data;
    u64 msg_length = mixer->out_msg_length;

    u8 tmp_message[msg_length];
    for (u64 i = msg_count - 1; i >= 1; i--) {
        u64 j = randombytes_uniform((uint32_t) i);
        memcpy(tmp_message, messages + (i * msg_length), msg_length);
        memcpy(messages + (i * msg_length), messages + (j * msg_length), msg_length);
        memcpy(messages + (j * msg_length), tmp_message, msg_length);
    }
}

void mix_add_noise(mix_s *mix, mixer_s *mixer) {
    mixer->last_noise_count = 0;
    for (u64 i = 0; i < mixer->num_boxes; i++) {
        u64 noise = laplace_rand(&mixer->laplace);
        for (u64 j = 0; j < noise; j++) {
            u8 *ctext_ptr = bb_write_virtual(mixer->out_buf, mixer->out_msg_length);
            u8 *msg_ptr = ctext_ptr + (mix->num_out_layers * crypto_box_SEALBYTES);
            serialize_u64(msg_ptr, i);
            mixer->fill_noise_msg(msg_ptr + mb_BYTES);
            crypto_salsa_onion_seal(ctext_ptr,
                                    NULL,
                                    msg_ptr,
                                    mixer->msg_length + mb_BYTES,
                                    &mixer->mix_pks[mix->id + 1],
                                    mix->num_out_layers);

        }
        mixer->mb_counts[i] += noise;
        mixer->last_noise_count += noise;
        mixer->out_msg_count += noise;
    }
}

int mix_update_mailbox_counts(u64 n, mixer_s *mixer, u64 *mb_counts) {
    if (n >= mixer->num_boxes) {
        return -1;
    } else {
        mb_counts[n]++;
    }

    return 0;
}

int mix_decrypt_messages(mix_s *mix, mixer_s *mixer, u8 *in, u8 *out, u64 msg_count, u64 *box_counts) {
    int decrypted_msg_count = 0;

    for (int i = 0; i < msg_count; i++) {
        int res = crypto_box_seal_open(out, in, mixer->inc_msg_length, mixer->pk, mixer->sk);
        // If we're at the last server, check the message has a valid mailbox id or discard the message
        if (!res && mix->is_last) {
            u64 n = deserialize_uint64(out);
            res = mix_update_mailbox_counts(n, mixer, box_counts);
        }
        if (!res) {
            out += mixer->out_msg_length;
            decrypted_msg_count++;
        }

        in += mixer->inc_msg_length;
    }
    return decrypted_msg_count;
}

int mix_distribute(mixer_s *mixer) {
    mixer->clear_container(mixer);
    free(mixer->mailboxes.boxes);

    mixer->mailboxes.boxes = calloc(mixer->num_boxes, sizeof *mixer->mailboxes.boxes);
    mixer->mailboxes.num_boxes = mixer->num_boxes;
    mixer->mailboxes.round = mixer->round;

    mixer->init_container(mixer);
    mixer->distribute(mixer);
    return 0;
}

void *mix_decrypt_task(void *args) {
    mix_thread_args *targs = (mix_thread_args *) args;
    mix_s *mix = targs->mix;
    u8 *in_ptr = targs->data;
    mixer_s *mixer = targs->mixer;

    u8 *buf = calloc(targs->num_msgs, mixer->out_msg_length);
    assert(buf);
    assert(in_ptr);
    u64 mb_counts[mixer->num_boxes];
    memset(mb_counts, 0, sizeof mb_counts);

    int n = mix_decrypt_messages(mix, targs->mixer, in_ptr, buf, targs->num_msgs, mb_counts);

    pthread_mutex_lock(&mixer->mutex);
    if (mix->is_last) {
        for (int i = 0; i < mixer->num_boxes; i++) {
            mixer->mb_counts[i] += mb_counts[i];
        }
    }
    mixer->out_msg_count += n;
    bb_write(mixer->out_buf, buf, n * mixer->out_msg_length);
    pthread_mutex_unlock(&mixer->mutex);

    free(buf);
    return NULL;
}

int mix_decrypt_msg_batch(mix_s *mix, mixer_s *mixer, byte_buffer *in_buf) {
    long num_threads = mix->num_threads;
    pthread_t threads[num_threads];
    mix_thread_args args[num_threads];
    u64 msgs_per_thread = mixer->inc_msg_count / num_threads;
    u64 remaining_msgs = mixer->inc_msg_count;
    for (int i = 0; i < num_threads - 1; i++) {
        args[i].mix = mix;
        args[i].data = bb_read_virtual(in_buf, msgs_per_thread * mixer->inc_msg_length);
        assert(args[i].data);
        args[i].num_msgs = msgs_per_thread;
        args[i].mixer = mixer;
        remaining_msgs -= msgs_per_thread;
    }

    args[num_threads - 1].mix = mix;
    args[num_threads - 1].num_msgs = remaining_msgs;
    args[num_threads - 1].data = bb_read_virtual(in_buf, remaining_msgs * mixer->inc_msg_length);
    args[num_threads - 1].mixer = mixer;
    assert(args[num_threads - 1].data);
    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&threads[i], NULL, mix_decrypt_task, &args[i])) {
            fprintf(stderr, "fatal pthread creation error\n");
            exit(EXIT_FAILURE);
        }
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}

void mix_pkg_broadcast(mix_s *mix) {
    u8 buf[header_BYTES];
    net_serialize_header(buf, PKG_REFRESH_KEYS, 0UL, mix->af_data.round, 0UL);
    for (int i = 0; i < num_pkg_servers; i++) {
        send(mix->pkg_conns[i].sock_fd, buf, header_BYTES, 0);
    }
}

int mix_exit_process_client(void *owner, connection *conn) {
    mix_s *mix = (mix_s *) owner;
    net_header *header = &conn->header;

    if (header->type == CLIENT_DIAL_MB_REQUEST) {
        mailbox_s *mb = mix_exit_get_mailbox(&mix->dial_data, header->misc);
        if (mb) {
            bb_write(&conn->write_buf, mb->box_data, mb->size_bytes);
            net_send(conn, mix->ns.epoll_fd);
        }
    } else if (header->type == CLIENT_AF_MB_REQUEST) {
        mailbox_s *request_mb = mix_exit_get_mailbox(&mix->af_data, header->misc);
        if (request_mb) {
            bb_write(&conn->write_buf, request_mb->box_data, request_mb->size_bytes);
            net_send(conn, mix->ns.epoll_fd);
        }
    } else {
        fprintf(stderr, "Invalid message\n");
        return -1;
    }

    return 0;
}

int mix_sign_and_verify_settings(mix_s *mix, mixer_s *mixer, u8 signatures[][crypto_sign_BYTES]) {
    u64 keys_length = num_mix_servers * crypto_box_PUBLICKEYBYTES;
    byte_buffer_t msg;
    bb_init(msg, round_BYTES + sizeof(u64) + keys_length, false);
    bb_write_u64(msg, mixer->round);
    bb_write_u64(msg, mixer->num_boxes);
    bb_write(msg, mixer->mix_pks[0], keys_length);
    for (u64 i = 1; i < mix->num_in_layers; i++) {
        if (crypto_sign_verify_detached(signatures[i], msg->data, msg->read_limit, mix->mix_sig_pks[i])) {
            return -1;
        }
    }

    crypto_sign_detached(signatures[0], NULL, msg->data, msg->read_limit, mix->sig_sk);
    bb_clear(msg);
    return 0;
}

void mix_auth_settings(mix_s *mix, mixer_s *mixer, byte_buffer *buf) {
    u64 keys_length = num_mix_servers * crypto_box_PUBLICKEYBYTES;
    u8 signatures[mix->num_in_layers][crypto_sign_BYTES];
    if (!mix->is_last) {
        bb_read(mixer->mix_pks[0], buf, keys_length);
        bb_read(signatures[1], buf, mix->num_out_layers * crypto_sign_BYTES);
    }
    // Make sure our PK hasn't been altered at some point
    memcpy(mixer->mix_pks[mix->id], mixer->pk, crypto_box_PUBLICKEYBYTES);
    if (mix_sign_and_verify_settings(mix, mixer, signatures)) {
        printf("signature verification failure\n");
        return;
    }

    u64 msg_length = keys_length + (mix->num_in_layers * crypto_sign_BYTES);
    byte_buffer *write_buf = mix->id == 0 ? mixer->broadcast : &mix->prev_mix->write_buf;
    if (mix->id == 0) {
        bb_reset(write_buf);
    }
    alp_serialize_header(write_buf, mixer->auth_msg_type, msg_length, mixer->round, mixer->num_boxes);
    bb_write(write_buf, mixer->mix_pks[0], keys_length);
    bb_write(write_buf, signatures[0], mix->num_in_layers * crypto_sign_BYTES);
    if (mix->id > 0) {
        net_send(mix->prev_mix, mix->ns.epoll_fd);
    }

    mix_add_noise(mix, mixer);
}

void mix_new_keys(mix_s *mix, mixer_s *mixer, byte_buffer *buf) {
    mix_new_round(mix, mixer);

    if (!mix->is_last) {
        byte_buffer *writebuf = &mix->next_mix->write_buf;
        alp_serialize_header(writebuf, mixer->round_msg_type, (mix->id + 1) * sizeof mixer->pk, mixer->round, 0);
        if (mix->id > 0) {
            bb_to_bb(writebuf, buf, mix->id * sizeof mixer->pk);
        }
        bb_write(writebuf, mixer->pk, sizeof mixer->pk);
        net_send(mix->next_mix, mix->ns.epoll_fd);
    } else {
        bb_read(mixer->mix_pks[0], buf, (num_mix_servers - 1) * crypto_box_PUBLICKEYBYTES);
        mix_auth_settings(mix, mixer, buf);
    }
}

void mix_log(const mixer_s *mixer);

void mix_process_batch(mix_s *mix, mixer_s *mixer, byte_buffer *buf) {
    mix_decrypt_msg_batch(mix, mixer, buf);
    mix_shuffle_messages(mixer);
    mix_log(mixer);
    if (!mix->is_last) {
        alp_serialize_header(&mix->next_mix->write_buf,
                             mixer->batch_msg_type,
                             mixer->out_buf->read_limit,
                             mixer->round,
                             mixer->out_msg_count);
        bb_to_bb(&mix->next_mix->write_buf, mixer->out_buf, mixer->out_buf->read_limit);
        net_send(mix->next_mix, mix->ns.epoll_fd);
    } else {
        mix_distribute(mixer);
        mix_exit_broadcast_box(mix, mixer, mixer->batch_msg_type);
    }
}
void mix_log(const mixer_s *mixer) {
    char time_buffer[40];
    get_current_time(time_buffer);
    fprintf(stdout,
            "%s Round %ld: Received %ld msgs, added %lu noise -> Forwarding %ld at %s\n",
            mixer->name,
            mixer->round,
            mixer->inc_msg_count,
            mixer->last_noise_count,
            mixer->out_msg_count,
            time_buffer);
}

int mix_process_mix_msg(void *m, connection *conn) {
    mix_s *mix = (mix_s *) m;
    net_header *header = &conn->header;
    byte_buffer *buf = conn->msg_buf;

    switch (header->type) {
        case MIX_AF_BATCH:
            mix->af_data.inc_msg_count = header->misc;
            assert(mix->af_data.inc_msg_count * mix->af_data.inc_msg_length == header->len);
            mix_process_batch(mix, &mix->af_data, buf);
            break;
        case MIX_DIAL_BATCH:
            mix->dial_data.inc_msg_count = header->misc;
            mix_process_batch(mix, &mix->dial_data, buf);
            break;
        case NEW_AF_ROUND:
            mix_new_keys(mix, &mix->af_data, buf);
            break;
        case NEW_DIAL_ROUND:
            mix_new_keys(mix, &mix->dial_data, buf);
            break;
        case MIX_AF_SETTINGS:
            mix_auth_settings(mix, &mix->af_data, buf);
            break;
        case MIX_DIAL_SETTINGS:
            mix_auth_settings(mix, &mix->dial_data, buf);
            break;
        default:
            break;
    }

    return 0;
}

int mix_listen_conn(net_server *ns, const char *port, const bool set_nb) {
    int listen_socket = net_listen_socket(port, set_nb);
    if (listen_socket == -1) {
        fprintf(stderr, "failed to start listen socket %s\n", port);
        return -1;
    }

    connection_init(&ns->listen_conn, 1024, 1024, NULL, ns->epoll_fd, listen_socket);
    return 0;
}

int mix_net_sync(mix_s *mix) {
    u64 id = mix->id;
    net_server *ns = &mix->ns;

    if (mix->is_last) {
        mix_listen_conn(ns, mix_listen_ports[id], true);
    } else {
        int listen_fd = net_listen_socket(mix_listen_ports[id], false);
        int mix_fd = net_accept(listen_fd, 0);
        if (mix_fd == -1) {
            fprintf(stderr, "fatal error on listening socket %s\n", mix_listen_ports[id]);
            return -1;
        }

        connection_init(mix->next_mix, 50000, 50000, mix_process_mix_msg, mix->ns.epoll_fd, mix_fd);
        socket_set_nonblocking(mix_fd);
        close(listen_fd);
    }

    if (mix->id > 0) {
        int prev_mix_sfd = net_connect(mix_server_ips[mix->id - 1], mix_listen_ports[mix->id - 1], 1);
        if (prev_mix_sfd == -1) {
            fprintf(stderr, "Failed to connect to neighbour in mixchain\n");
            return -1;
        }
        connection_init(mix->next_mix, 50000, 50000, mix_process_mix_msg, mix->ns.epoll_fd, prev_mix_sfd);
    }
    printf("[Mix server %ld: initialised]\n", mix->id);
    return 0;
}

void mix_entry_client_onconnect(void *s, connection *conn) {
    mix_s *mix = (mix_s *) s;
    bb_write(&conn->write_buf, mix->broadcast->data, header_BYTES);
    net_send(conn, mix->ns.epoll_fd);
}

void mix_exit_broadcast_box(mix_s *s, mixer_s *mixer, u64 type) {
    u8 buf[header_BYTES];
    net_serialize_header(buf, type, 0, mixer->round, type);

    for (list_item *hd = s->ns.clients->head; hd != NULL; hd = hd->next) {
        connection *conn = hd->data;
        bb_write(&conn->write_buf, buf, sizeof buf);
        net_send(conn, s->ns.epoll_fd);
    }
}

void mix_entry_broadcast_round(mix_s *mix, mixer_s *mixer) {

    byte_buffer *broadcast_buf = mixer->broadcast;
    // Updating the 'global' broadcast msg which just includes current rounds for clients when they connect
    bb_reset(mix->broadcast);
    alp_serialize_header(mix->broadcast, MIX_SYNC, 0, mix->af_data.round, mix->dial_data.round);

    // The full round broadcast msg that includes the settings
    for (list_item *hd = mix->ns.clients->head; hd != NULL; hd = hd->next) {
        connection *conn = hd->data;
        bb_write(&conn->write_buf, broadcast_buf->data, broadcast_buf->read_limit);
        net_send(conn, mix->ns.epoll_fd);
    }
}

int mix_entry_sync(mix_s *mix) {
    net_server *net_state = &mix->ns;
    int listen_fd = net_listen_socket(mix_entry_pkg_listenport, 0);

    for (int i = 0; i < num_pkg_servers; i++) {
        int fd = net_accept(listen_fd, 1);
        connection_init(&mix->pkg_conns[i], 2048, 2048, NULL, net_state->epoll_fd, fd);
    }

    close(listen_fd);
    if (mix_net_sync(mix)) {
        fprintf(stderr, "fatal error during mixnet startup\n");
        return -1;
    }

    alp_serialize_header(mix->broadcast, MIX_SYNC, 0, mix->af_data.round, mix->dial_data.round);
    mix_listen_conn(&mix->ns, mix_entry_client_listenport, 1);
    mix_new_keys(mix, &mix->af_data, NULL);
    mix_new_keys(mix, &mix->dial_data, NULL);

    return 0;
}

int mix_entry_process_client(void *server, connection *conn) {
    mix_s *mix = (mix_s *) server;
    net_header *header = &conn->header;
    byte_buffer *buf = conn->msg_buf;

    if (header->type == CLIENT_DIAL_MSG) {
        mix_entry_add_message(buf, &mix->dial_data);
    } else if (header->type == CLIENT_AF_MSG) {
        mix_entry_add_message(buf, &mix->af_data);
    } else {
        fprintf(stderr, "Invalid client msg\n");
        conn->connected = false;
    }
    return 0;
}

void mix_entry_check_timers(mix_s *mix) {
    time_t rem;

    if (mix->dial_data.window_remaining > 0) {
        rem = mix->dial_data.window_remaining - time(0);
        if (rem <= 0) {
            mix_process_batch(mix, &mix->dial_data, mix->dial_data.in_buf);
            mix->dial_data.window_remaining = -1;
            mix_new_keys(mix, &mix->dial_data, NULL);
        }
    }

    if (mix->af_data.window_remaining > 0) {
        rem = mix->af_data.window_remaining - time(0);
        if (rem <= 0) {
            mix_process_batch(mix, &mix->af_data, mix->af_data.in_buf);
            mix->af_data.window_remaining = -1;
            mix_new_keys(mix, &mix->af_data, NULL);
        }
    }

    rem = mix->dial_data.next_round - time(0);
    if (rem <= 0) {
        mix_entry_broadcast_round(mix, &mix->dial_data);
        mix->dial_data.next_round = time(0) + mix->dial_data.round_duration;
        mix->dial_data.window_remaining = time(0) + mix->dial_data.window_duration;
        printf("New dial round started: %lu\n", mix->dial_data.round);
    }

    rem = mix->af_data.next_round - time(0);
    double proportion_remaining = (double) rem / mix->af_data.round_duration;
    if (proportion_remaining <= 0.3) {
        if (!mix->pkg_preprocess_check) {
            mix_pkg_broadcast(mix);
            mix->pkg_preprocess_check = true;
        }
    }

    if (rem <= 0) {
        mix_entry_broadcast_round(mix, &mix->af_data);
        mix->pkg_preprocess_check = false;
        mix->af_data.next_round = time(0) + mix->af_data.round_duration;
        mix->af_data.window_remaining = time(0) + mix->af_data.window_duration;
        printf("New add friend round started: %lu\n", mix->af_data.round);
    }
}

void mix_run(mix_s *mix, void on_accept(void *, connection *), int on_read(void *, connection *)) {
    net_server *es = &mix->ns;
    es->events = calloc(epoll_num_events, sizeof *es->events);
    struct epoll_event *events = es->events;

    mix->dial_data.next_round = time(0) + mix->dial_data.round_duration;
    mix->af_data.next_round = time(0) + mix->af_data.round_duration;
    running = true;

    while (running) {
        if (mix->id == 0) {
            mix_entry_check_timers(mix);
        }

        int event_count = epoll_wait(es->epoll_fd, es->events, epoll_num_events, 1000);
        for (int i = 0; i < event_count; i++) {
            connection *conn = events[i].data.ptr;
            if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
                fprintf(stderr, "Error on socket %d\n", conn->sock_fd);
                close(conn->sock_fd);
                continue;
            } else if (&es->listen_conn == conn) {
                net_accept_client(&mix->ns, on_accept, on_read);
            } else if (events[i].events & EPOLLIN) {
                net_read(mix, conn);
            } else if (events[i].events & EPOLLOUT) {
                net_send(conn, es->epoll_fd);
            }
        }
    }
}

int mix_main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "invalid args\n");
        exit(EXIT_FAILURE);
    }

    long id = strtol(argv[1], NULL, 10);
    long num_threads = strtol(argv[2], NULL, 10);
    if (id >= num_mix_servers || id < 0) {
        fprintf(stderr, "invalid server id\n");
        exit(EXIT_FAILURE);
    }

    int (*on_read)(void *, connection *) = NULL;
    void (*on_accept)(void *, connection *) = NULL;

    if (id == 0) {
        on_accept = mix_entry_client_onconnect;
        on_read = mix_entry_process_client;
    } else if (id == num_mix_servers - 1) {
        on_read = mix_exit_process_client;
    } else {
        on_read = mix_process_mix_msg;
    }

    mix_s *mix = calloc(1, sizeof *mix);
    mix_init(mix, (u64) id, num_threads);
    if (mix->id == 0) {
        mix_entry_sync(mix);
    } else {
        mix_net_sync(mix);
    }
    mix_run(mix, on_accept, on_read);
    free(mix);

    return 0;
}
