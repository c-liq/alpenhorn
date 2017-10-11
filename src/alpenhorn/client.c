#include "alpenhorn/client.h"
#include "alpenhorn/client_config.h"

static u64 calc_mailbox_id(const u8 *user_id, u64 num_boxes) {
    u64 hash = XXH64(user_id, user_id_BYTES, 0);
    return hash % num_boxes;
}

int alp_register(char *user_id, u8 *pk, u8 *sk) {
    if (!pk || !sk || !user_id) {
        return -1;
    }

    crypto_sign_keypair(pk, sk);
    byte_buffer *buffer = bb_alloc(header_BYTES + cli_pkg_reg_request_BYTES, false);

    alp_serialize_header(buffer, CLIENT_REG_REQUEST, cli_pkg_reg_request_BYTES, 0, 0);
    bb_write(buffer, (u8 *) user_id, user_id_BYTES);
    bb_write(buffer, pk, crypto_sign_PUBLICKEYBYTES);

    for (u64 i = 0; i < num_pkg_servers; i++) {
        int sock_fd = net_connect(pkg_server_ips[i], pkg_cl_listen_ports[i], 0);
        if (net_send_blocking(sock_fd, buffer->data, buffer->read_limit)) {
            bb_free(buffer);
            return -1;
        }
        u8 response[header_BYTES];
        if (net_read_blocking(sock_fd, response, sizeof response)) {
            bb_free(buffer);
            return -1;
        }
        close(sock_fd);
    }

    bb_free(buffer);
    printf("Registration request made for email %s\n", user_id);
    return 0;
}

int alp_confirm_registration(u8 *user_id, u8 *sig_key, u8 *msgs_buf) {

    u64 net_msg_size_bytes = header_BYTES + cli_pkg_reg_confirm_BYTES;
    u8 reg_confirm_msg[net_msg_size_bytes];
    memset(reg_confirm_msg, 0, net_msg_size_bytes);
    net_serialize_header(reg_confirm_msg, CLIENT_REG_CONFIRM, cli_pkg_reg_confirm_BYTES, 0, 0);

    u8 user_id_verified[user_id_BYTES];
    memset(user_id_verified, 0, user_id_BYTES);

    size_t uid_len = strlen((char *) user_id);
    if (uid_len > user_id_BYTES) {
        fprintf(stderr, "username too long\n");
        return -1;
    }

    memcpy(user_id_verified, user_id, uid_len);
    memcpy(reg_confirm_msg + header_BYTES, user_id_verified, user_id_BYTES);

    const u64 msg_length_hex = crypto_ghash_BYTES * 2;
    u64 sig_offset = header_BYTES + user_id_BYTES;

    for (u64 i = 0; i < num_pkg_servers; i++) {
        crypto_sign(reg_confirm_msg + sig_offset,
                    NULL,
                    msgs_buf + (i * msg_length_hex),
                    crypto_ghash_BYTES * 2,
                    sig_key);

        int socket_fd = net_connect(pkg_server_ips[i], pkg_cl_listen_ports[i], 0);
        if (socket_fd == -1) {
            fprintf(stderr, "pkg server connection failure\n");
            return -1;
        }

        if (net_send_blocking(socket_fd, reg_confirm_msg, net_msg_size_bytes)) {
            fprintf(stderr, "socket send failure\n");
            close(socket_fd);
            return -1;
        }

        u8 response_buf[header_BYTES + pkg_broadcast_msg_BYTES + header_BYTES];
        if (net_read_blocking(socket_fd, response_buf, sizeof response_buf)) {
            fprintf(stderr, "socket read failure\n");
            close(socket_fd);
            return -1;
        }
        close(socket_fd);
    }

    return 0;
}

int alp_call_friend(client *c, u8 *user_id, u64 intent) {
    if (!c || !user_id || intent >= c->num_intents) {
        return -1;
    }

    pthread_mutex_lock(c->mutex);

    if (!kw_lookup(&c->kw_table, user_id)) {
        pthread_mutex_unlock(c->mutex);
        return -1;
    }

    call *call = calloc(1, sizeof *call);
    memcpy(call->user_id, user_id, user_id_BYTES);
    call->intent = intent;
    list_push_tail(c->outgoing_calls, call);

    pthread_mutex_unlock(c->mutex);
    return 0;
}

static int onion_encrypt_msg(client *client, mix_data *mix) {
    connection *mconn = client->mix_entry;
    alp_serialize_header(&mconn->write_buf, mix->msg_type, mix->encrypted_msg_length, mix->round, 0);
    u8 *ctext_p = bb_write_virtual(&mconn->write_buf, mix->encrypted_msg_length);
    crypto_salsa_onion_seal(ctext_p,
                            NULL,
                            mix->msg_buffer->data,
                            mb_BYTES + mix->msg_length,
                            mix->mix_pks,
                            num_mix_servers);
    return 0;
}

static int dial_call_friend(client *c, call *call) {
    if (!call) {
        return -1;
    }

    bb_reset(c->dial_data.msg_buffer);
    bb_write_u64(c->dial_data.msg_buffer, calc_mailbox_id(call->user_id, c->dial_data.num_boxes));
    u8 *token_p = bb_write_virtual(c->dial_data.msg_buffer, dialling_token_BYTES);

    call->round = c->dial_data.round;
    int result = kw_call_keys(call->session_key, token_p, &c->kw_table, call->user_id, call->intent);
    if (!result) {
        c->event_fns->call_sent(call);
    }
    return result;
}

static int dial_fake_request(client *c) {
    byte_buffer *buf = c->dial_data.msg_buffer;
    bb_reset_zero(buf);
    bb_write_u64(buf, c->dial_data.num_boxes);
    bb_write_virtual(buf, dialling_token_BYTES);
    return 0;
}

static int dial_build_call(client *c) {
    pthread_mutex_lock(c->mutex);
    call *call = list_pop_head(c->outgoing_calls);

    if (dial_call_friend(c, call)) {
        dial_fake_request(c);
    }

    free(call);
    pthread_mutex_unlock(c->mutex);

    return 0;
}

int alp_add_friend(client *c, u8 *user_id) {
    if (!c || !user_id)
        return -1;

    pthread_mutex_lock(c->mutex);
    // Either already confirmed as a friend, or there is an outgoing request waiting to be confirmed
    // Should maybe clear unsynced entries after a period once it seems unlikely a reply is coming?
    if (kw_lookup(&c->kw_table, user_id) || kw_unsynced_lookup(&c->kw_table, user_id)) {
        pthread_mutex_unlock(c->mutex);
        return -1;
    }

    friend_request *new_req = calloc(1, sizeof *new_req);
    memcpy(new_req->user_id, user_id, user_id_BYTES);
    list_push_tail(c->outgoing_requests, new_req);

    pthread_mutex_unlock(c->mutex);
    return 0;
}

typedef struct friend_request_msg {
  u64 dial_round;
  u8 *user_id;
  u8 *dh_pk;
  u8 *cert;
  u8 *sig;
  u8 *sig_pk;
} friend_request_msg;

static inline void deserialize_request_msg(friend_request_msg *fr, u8 *request_buffer) {
    fr->dial_round = deserialize_uint64(request_buffer);
    fr->user_id = request_buffer + round_BYTES;
    fr->dh_pk = fr->user_id + user_id_BYTES;
    fr->sig = fr->dh_pk + crypto_box_PKBYTES;
    fr->sig_pk = fr->sig + crypto_sign_BYTES;
    fr->cert = fr->sig + crypto_sign_PUBLICKEYBYTES;
}

static inline void af_build_friend_sig_msg(u8 *out, u64 round, u8 *user_id, u8 *dh_pk) {
    serialize_u64(out, round);
    memcpy(out + round_BYTES, user_id, user_id_BYTES);
    memcpy(out + round_BYTES + user_id_BYTES, dh_pk, crypto_box_PUBLICKEYBYTES);
}

static inline void af_build_pkg_sig_msg(u64 round, friend_request_msg *req_msg, u8 *cert_msg) {
    serialize_u64(cert_msg, round);
    memcpy(cert_msg + round_BYTES, req_msg->user_id, user_id_BYTES);
    memcpy(cert_msg + round_BYTES + user_id_BYTES, req_msg->sig_pk, crypto_sign_PUBLICKEYBYTES);
}

static void process_friend_request(client *c, friend_request_msg *req_msg) {
    friend_request *confirmed_friend = calloc(1, sizeof *confirmed_friend);
    if (!confirmed_friend) {
        perror("malloc");
        return;
    }

    memcpy(confirmed_friend->user_id, req_msg->user_id, user_id_BYTES);
    memcpy(confirmed_friend->sig_pk, req_msg->sig_pk, crypto_sign_PUBLICKEYBYTES);
    memcpy(confirmed_friend->dh_pk, req_msg->dh_pk, crypto_box_PUBLICKEYBYTES);
    confirmed_friend->dialling_round = req_msg->dial_round;

    keywheel_unsynced *entry = kw_unsynced_lookup(&c->kw_table, req_msg->user_id);
    if (entry) {
        kw_complete_keywheel(&c->kw_table, req_msg->user_id, req_msg->dh_pk, req_msg->dial_round);
        c->event_fns->friend_request_confirmed(confirmed_friend);
        free(confirmed_friend);
    } else {
        list_push_tail(c->friend_requests, confirmed_friend);
        c->event_fns->friend_request_received(confirmed_friend);
    }
}

static int af_decrypt_request(client *c, u8 *buf, u64 round) {
    u8 request[af_request_BYTES];
    if (bn256_ibe_decrypt(request, buf, af_ibeenc_request_BYTES, c->pkg_state.hashed_id, c->pkg_state.id_sk)) {
        return -1;
    }

    friend_request_msg req_msg;
    deserialize_request_msg(&req_msg, request);

    u8 certificate_msg[pkg_sig_message_BYTES];
    af_build_pkg_sig_msg(round, &req_msg, certificate_msg);
    if (bn256_bls_verify(c->pkg_state.pkg_sig_pk, req_msg.cert, certificate_msg, pkg_sig_message_BYTES)) {
        fprintf(stderr, "Multisig verification failed\n");
        return -1;
    }

    u8 user_sig_msg[client_sigmsg_BYTES];
    af_build_friend_sig_msg(user_sig_msg, req_msg.dial_round, req_msg.user_id, req_msg.dh_pk);
    if (crypto_sign_verify_detached(req_msg.sig, user_sig_msg, client_sigmsg_BYTES, req_msg.sig_pk)) {
        printf("Personal sig verification failed\n");
        return -1;
    }

    process_friend_request(c, &req_msg);
    return 0;
}

static int af_process_mb(client *c, byte_buffer *mailbox, u64 count, u64 round) {
    for (int i = 0; i < count; i++) {
        u8 *msg_ptr = bb_read_virtual(mailbox, af_ibeenc_request_BYTES);
        af_decrypt_request(c, msg_ptr, round);
    }

    return 0;
}

static int af_fake_request(client *c) {
    byte_buffer *buf = c->af_data.msg_buffer;
    bb_reset_zero(buf);
    bb_write_u64(buf, c->af_data.num_boxes);
    u8 *g1_elem_p = bb_write_virtual(buf, g1_serialized_bytes);

    scalar_t r;
    curvepoint_fp_t rndg1;
    bn256_g1_random(rndg1, r);
    bn256_serialize_g1(g1_elem_p, rndg1);
    return 0;
}

static int dial_process_mb(client *c, byte_buffer *mailbox, u64 round, u64 num_tokens) {
    while (c->kw_table.table_round < round) {
        kw_advance_table(&c->kw_table);
    }
    bloom_s bloom;
    u8 dial_token_buf[dialling_token_BYTES];
    if (bloom_init(&bloom, c->bloom_p_val, num_tokens, mailbox->data, 0)) {
        fprintf(stderr, "failed to initialise bloom filter\n");
        return -1;
    };

    list_item *curr_kw = c->kw_table.keywheels->head;
    while (curr_kw) {
        keywheel *kw = curr_kw->data;
        for (u64 j = 0; j < c->num_intents; j++) {
            kw_dialling_token(dial_token_buf, &c->kw_table, kw->user_id, j);
            int found = bloom_lookup(&bloom, dial_token_buf, dialling_token_BYTES);

            if (!found) {
                call new_call;
                new_call.round = round;
                new_call.intent = j;
                memcpy(new_call.user_id, kw->user_id, user_id_BYTES);
                kw_session_key(new_call.session_key, &c->kw_table, kw->user_id);
                c->event_fns->call_received(&new_call);
            }
        }
        curr_kw = curr_kw->next;
    }
    kw_advance_table(&c->kw_table);
    return 0;
}

static int pkg_create_auth_request(client *c) {
    for (u64 i = 0; i < num_pkg_servers; i++) {
        byte_buffer *auth_msg = bb_alloc(client_sigmsg_BYTES, false);
        bb_write_u64(auth_msg, c->af_data.round + 1);
        bb_write(auth_msg, c->user_id, user_id_BYTES);
        u8 *pk = bb_write_virtual(auth_msg, crypto_box_SECRETKEYBYTES);
        u8 sk[crypto_box_SECRETKEYBYTES];
        crypto_box_keypair(pk, sk);

        crypto_shared_secret(c->pkg_state.symmetric_keys[i],
                             sk,
                             c->pkg_state.bc_dh_pks[i],
                             pk,
                             c->pkg_state.bc_dh_pks[i],
                             crypto_box_SECRETKEYBYTES);

        alp_serialize_header(&c->pkg_state.pkg_conns[i].write_buf,
                             CLIENT_AUTH_REQ,
                             pkg_auth_request_BYTES,
                             c->af_data.round,
                             0);

        bb_to_bb(&c->pkg_state.pkg_conns[i].write_buf, auth_msg, client_sigmsg_BYTES);

        u8 *sig = bb_write_virtual(&c->pkg_state.pkg_conns[i].write_buf, crypto_sign_BYTES);
        crypto_sign_detached(sig, NULL, auth_msg->data, client_sigmsg_BYTES, c->sig_sk);

        net_send(&c->pkg_state.pkg_conns[i], c->epoll_fd);
        bb_free(auth_msg);
    }
    return 0;
}

static int af_create_request(client *c, u8 *pk, friend_request *req) {
    byte_buffer_t request_buf;
    bb_init(request_buf, af_ibeenc_request_BYTES, false);
    bb_write_u64(request_buf, req->dialling_round);
    bb_write(request_buf, c->user_id, user_id_BYTES);
    bb_write(request_buf, pk, crypto_box_PUBLICKEYBYTES);

    u8 *client_sig = bb_write_virtual(request_buf, crypto_sign_BYTES);
    crypto_sign_detached(client_sig, NULL, request_buf->data, client_sigmsg_BYTES, c->sig_sk);
    bb_write(request_buf, c->sig_pk, crypto_sign_PUBLICKEYBYTES);

    u8 *pkg_certificate = bb_write_virtual(request_buf, g1_serialized_bytes);
    bn256_serialize_g1(pkg_certificate, c->pkg_state.pkg_multisig);

    bb_reset_zero(c->af_data.msg_buffer);
    bb_write_u64(c->af_data.msg_buffer, calc_mailbox_id(req->user_id, c->af_data.num_boxes));

    u8 *ibe_ciphertext = bb_write_virtual(c->af_data.msg_buffer, af_ibeenc_request_BYTES);
    bn256_ibe_encrypt(ibe_ciphertext,
                      request_buf->data,
                      af_request_BYTES,
                      c->pkg_state.pkg_master_pk,
                      req->user_id,
                      user_id_BYTES);

    c->event_fns->friend_request_sent(req);
    return 0;
}

static int af_update_pkg_public_keys(client *c) {
    curvepoint_fp_t g1_temp;
    curvepoint_fp_setneutral(c->pkg_state.pkg_master_pk);

    for (int i = 0; i < num_pkg_servers; i++) {
        bn256_deserialize_g1(g1_temp, c->pkg_state.bc_ibe_keys[i]);
        curvepoint_fp_add_vartime(c->pkg_state.pkg_master_pk, c->pkg_state.pkg_master_pk, g1_temp);
    }

    return 0;
}

static int af_process_auth_responses(client *c) {
    curvepoint_fp_setneutral(c->pkg_state.pkg_multisig);
    twistpoint_fp2_setneutral(c->pkg_state.id_sk);

    for (int i = 0; i < num_pkg_servers; i++) {
        u8 *response = c->pkg_state.auth_responses[i];
        u8 decrypted_response[pkg_auth_res_BYTES];
        if (crypto_salsa_decrypt(decrypted_response,
                                 response,
                                 pkg_enc_auth_res_BYTES,
                                 c->pkg_state.symmetric_keys[i])) {
            fprintf(stderr, "%s: decryption failed on auth response from pkg %d\n", c->user_id, i);
            return -1;
        }
        curvepoint_fp_t g1_tmp;
        twistpoint_fp2_t g2_tmp;
        bn256_deserialize_g1(g1_tmp, decrypted_response);
        bn256_deserialize_g2(g2_tmp, decrypted_response + g1_xonly_serialized_bytes);
        curvepoint_fp_add_vartime(c->pkg_state.pkg_multisig, c->pkg_state.pkg_multisig, g1_tmp);
        twistpoint_fp2_add_vartime(c->pkg_state.id_sk, c->pkg_state.id_sk, g2_tmp);
    }

    printf("[Client authed for round %lu]\n", c->af_data.round);
    return 0;
}

static int cmp_friend_request(const void *a, const void *b) {
    friend_request *fr_a = a;
    friend_request *fr_b = b;
    return memcmp(fr_a->user_id, fr_b->user_id, user_id_BYTES);
}

static int af_build_request(client *c) {
    pthread_mutex_lock(c->mutex);
    friend_request *request = list_pop_head(c->outgoing_requests);
    if (!request) {
        af_fake_request(c);
        pthread_mutex_unlock(c->mutex);
        return 0;
    }

    u8 pk[crypto_box_PUBLICKEYBYTES];
    friend_request *received = list_find(c->friend_requests, request, cmp_friend_request);

    if (received) {
        keywheel *new_kw = kw_from_request(&c->kw_table, request->user_id, pk, received->dh_pk);
        request->dialling_round = new_kw->dial_round;
    } else {
        u8 sk[crypto_box_SECRETKEYBYTES];
        crypto_box_keypair(pk, sk);
        kw_new_keywheel(&c->kw_table, request->user_id, pk, sk, c->dial_data.round);
        request->dialling_round = c->dial_data.round;
        sodium_memzero(sk, crypto_box_SECRETKEYBYTES);
    }

    af_create_request(c, pk, request);
    free(request);
    free(received);

    pthread_mutex_unlock(c->mutex);
    return 0;
}

static void client_event_handlers_init(client *c, client_event_fns *event_fns) {
    c->event_fns = calloc(1, sizeof *c->event_fns);
    client_event_fns *fns = c->event_fns;
    fns->friend_request_received = event_fns->friend_request_received;
    fns->call_sent = event_fns->call_sent;
    fns->call_received = event_fns->call_received;
    fns->friend_request_confirmed = event_fns->friend_request_confirmed;
    fns->friend_request_sent = event_fns->friend_request_sent;
}

static const mix_client_config af_cfg = {
    .num_boxes = 1,
    .msg_length = af_ibeenc_request_BYTES,
    .msg_type = CLIENT_AF_MSG,
    .mb_request_type = CLIENT_AF_MB_REQUEST,
    .build_message = af_build_request
};

static const mix_client_config dial_cfg = {
    .num_boxes = 1,
    .msg_length = dialling_token_BYTES,
    .msg_type = CLIENT_DIAL_MSG,
    .mb_request_type = CLIENT_DIAL_MB_REQUEST,
    .build_message = dial_build_call
};

static void client_mix_state_init(mix_data *mix, const mix_client_config *cfg) {
    mix->num_boxes = cfg->num_boxes;
    mix->msg_length = cfg->msg_length;
    u64 crypto_abytes = num_mix_servers * crypto_box_SEALBYTES;
    mix->encrypted_msg_length = mix->msg_length + mb_BYTES + crypto_abytes;
    mix->msg_type = cfg->msg_type;
    mix->mb_request_type = cfg->mb_request_type;
    mix->build_message = cfg->build_message;
    bb_init(mix->msg_buffer, mix->msg_length + mb_BYTES, false);

    mix->round = 0;
    mix->datap = NULL;
}

static void client_pkg_state_init(client *c) {
    c->pkg_state.num_servers = num_pkg_servers;
    c->pkg_state.pkg_conns = calloc(c->pkg_state.num_servers, sizeof(connection));
    c->pkg_state.num_auth_responses = 0;
    c->pkg_state.num_broadcasts = 0;
}

int client_init(client *c, const u8 *user_id, client_event_fns *event_fns, u8 *pk, u8 *sk) {
    if (!c || !user_id || !pk || !sk || !event_fns) {
        return -1;
    }

    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium fatal error\n");
        return -1;
    }

    bn256_init();

    c->epoll_fd = epoll_create1(0);
    c->mutex = calloc(1, sizeof *c->mutex);
    pthread_mutex_init(c->mutex, NULL);

    c->outgoing_calls = list_alloc();
    c->outgoing_requests = list_alloc();
    c->friend_requests = list_alloc();

    client_event_handlers_init(c, event_fns);
    client_mix_state_init(&c->af_data, &af_cfg);
    client_mix_state_init(&c->dial_data, &dial_cfg);
    client_pkg_state_init(c);

    for (int i = 0; i < num_mix_servers; i++) {
        sodium_hex2bin(c->mix_sig_pks[i],
                       crypto_sign_PUBLICKEYBYTES,
                       mix_sig_pks[i],
                       crypto_sign_PUBLICKEYBYTES * 2 + 1,
                       NULL,
                       NULL,
                       NULL);
    }

    memset(c->user_id, 0, user_id_BYTES);
    strncpy((char *) c->user_id, (char *) user_id, user_id_BYTES);
    memcpy(c->sig_pk, pk, crypto_sign_PUBLICKEYBYTES);
    memcpy(c->sig_sk, sk, crypto_sign_SECRETKEYBYTES);

    kw_table_init(&c->kw_table, c->dial_data.round, NULL);
    c->num_intents = num_INTENTS;
    c->bloom_p_val = pow(10.0, -10.0);

    twistpoint_fp2_t userid_hash;
    bn256_hash_g2(userid_hash, user_id_BYTES, c->user_id);
    bn256_serialize_g2(c->pkg_state.hashed_id, userid_hash);

    bn256_sum_g2(c->pkg_state.pkg_sig_pk, pkg_lt_pks, num_pkg_servers);
    twistpoint_fp2_setneutral(c->pkg_state.id_sk);

    return 0;
}

client *client_alloc(const u8 *user_id, client_event_fns *event_fns, u8 *pk, u8 *sk) {
    client *client = calloc(1, sizeof *client);

    if (client_init(client, user_id, event_fns, pk, sk)) {
        free(client);
        client = NULL;
    }

    return client;
}

int client_verify_round_settings(client *client, byte_buffer *buf, mix_data *mix) {
    u64 keys_size = num_mix_servers * crypto_box_PUBLICKEYBYTES;
    byte_buffer *settings = bb_alloc(round_BYTES + sizeof(u64) + keys_size, false);

    bb_write_u64(settings, mix->round);
    bb_write_u64(settings, mix->num_boxes);
    bb_read(mix->mix_pks[0], buf, keys_size);
    bb_write(settings, mix->mix_pks[0], keys_size);

    int result = 0;
    for (int i = 0; i < num_mix_servers; i++) {
        u8 *sig = bb_read_virtual(buf, crypto_sign_BYTES);
        if (crypto_sign_verify_detached(sig, settings->data, settings->written, client->mix_sig_pks[i])) {
            result = -1;
            break;
        }
    }

    bb_free(settings);
    return result;
}

int mix_client_new_round(client *client, mix_data *mix) {
    connection *conn = client->mix_entry;
    mix->round = conn->header.round;
    mix->num_boxes = conn->header.misc;

    if (!client_verify_round_settings(client, conn->msg_buf, mix)) {
        mix->build_message(client);
        onion_encrypt_msg(client, mix);
        net_send(conn, client->epoll_fd);
    } else {
        fprintf(stderr, "failed to verify round settings\n");
        return -1;
    }

    return 0;
}

int mix_entry_process_msg(void *client_ptr, connection *conn) {
    client *client = client_ptr;
    net_header *header = &conn->header;
    byte_buffer *buf = conn->msg_buf;

    switch (header->type) {
        case MIX_AF_SETTINGS:
            mix_client_new_round(client, &client->af_data);
            printf("New AF round: %ld\n", client->af_data.round);
            break;
        case MIX_DIAL_SETTINGS:
            mix_client_new_round(client, &client->dial_data);
            printf("New Dial round: %ld\n", client->dial_data.round);
            break;
        case MIX_SYNC:
            client->af_data.round = header->round;
            client->dial_data.round = header->misc;
            printf("AF round: %lu | Dial round: %lu\n", client->af_data.round, client->dial_data.round);
            break;
        default:
            fprintf(stderr, "Invalid message from Mix Entry\n");
            return -1;
    }

    (void) buf;
    return 0;
}

int client_net_process_pkg(void *client_ptr, connection *conn) {
    client *c = (client *) client_ptr;
    net_header *header = &conn->header;
    pkg_data *pkg = &c->pkg_state;
    byte_buffer *buf = conn->msg_buf;

    switch (header->type) {
        case PKG_BR_MSG:
            bb_read(pkg->bc_ibe_keys[conn->id], buf, bn256_ibe_pkg_pk_BYTES);
            bb_read(pkg->bc_dh_pks[conn->id], buf, crypto_box_PKBYTES);
            c->pkg_state.num_broadcasts++;
            if (c->pkg_state.num_broadcasts == num_pkg_servers) {
                af_update_pkg_public_keys(c);
                pkg_create_auth_request(c);
            }
            break;
        case PKG_AUTH_RES_MSG:
            bb_read(pkg->auth_responses[conn->id], buf, pkg_enc_auth_res_BYTES);
            c->pkg_state.num_auth_responses++;
            if (c->pkg_state.num_auth_responses == num_pkg_servers) {
                af_process_auth_responses(c);
                c->pkg_state.num_auth_responses = 0;
                c->pkg_state.num_broadcasts = 0;
            }
            break;
        default:
            fprintf(stderr, "Invalid message received from PKG server\n");
            return -1;
    }
    return 0;
}

int mix_exit_process_msg(void *client_ptr, connection *conn) {
    client *client = client_ptr;
    net_header *header = &conn->header;
    byte_buffer *buf = conn->msg_buf;
    switch (header->type) {
        case DIAL_MB:
            dial_process_mb(client, buf, header->round, header->misc);
            break;
        case AF_MB:
            af_process_mb(client, buf, header->misc, client->af_data.round);
            break;
        case MIX_AF_BATCH: {
            u64 mb = calc_mailbox_id(client->user_id, client->af_data.num_boxes);
            alp_serialize_header(&conn->write_buf, CLIENT_AF_MB_REQUEST, 0, header->round, mb);
            net_send(conn, conn->sock_fd);
            break;
        }
        case MIX_DIAL_BATCH: {
            u64 mb = calc_mailbox_id(client->user_id, client->dial_data.num_boxes);
            alp_serialize_header(&conn->write_buf, CLIENT_DIAL_MB_REQUEST, 0, header->round, mb);
            net_send(conn, conn->sock_fd);
            break;
        }
        default:
            fprintf(stderr, "Invalid message from Mix distribution server\n");
            return -1;
    }
    return 0;
}

int client_run(client *client) {
    net_connect_init(client->mix_last,
                     mix_server_ips[num_mix_servers - 1],
                     mix_listen_ports[num_mix_servers - 1],
                     client->epoll_fd,
                     1,
                     2048,
                     mix_exit_process_msg);

    net_connect_init(client->mix_entry,
                     mix_server_ips[0],
                     mix_entry_client_listenport,
                     client->epoll_fd,
                     0,
                     read_buf_SIZE,
                     mix_entry_process_msg);

    if (net_read_blocking(client->mix_entry->sock_fd, client->mix_entry->read_buf.data, header_BYTES)) {
        perror("client read");
        return -1;
    }

    client->af_data.round = deserialize_uint64(client->mix_entry->read_buf.data + 16);
    client->dial_data.round = deserialize_uint64(client->mix_entry->read_buf.data + 24);
    client->kw_table.table_round = client->dial_data.round;

    printf("[Connected as %s: Dial round: %ld | Add friend round: %ld]\n",
           client->user_id,
           client->dial_data.round,
           client->af_data.round);

    socket_set_nonblocking(client->mix_entry->sock_fd);

    for (int i = 0; i < num_pkg_servers; i++) {
        net_connect_init(&client->pkg_state.pkg_conns[i],
                         pkg_server_ips[i],
                         pkg_cl_listen_ports[i],
                         client->epoll_fd,
                         1,
                         read_buf_SIZE,
                         client_net_process_pkg);
        client->pkg_state.pkg_conns[i].id = i;
    }

    pthread_t net_thread;
    pthread_create(&net_thread, NULL, client_process_loop, client);
    return 0;
}

void *client_process_loop(void *client_p) {
    client *c = (client *) client_p;

    struct epoll_event *events = calloc(100, sizeof *events);
    c->running = true;

    while (c->running) {
        int n = epoll_wait(c->epoll_fd, events, 100, 100000);

        connection *conn = NULL;
        for (int i = 0; i < n; i++) {
            conn = events[i].data.ptr;
            if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
                fprintf(stderr, "Client: Socket error on socket %d - Exiting\n", conn->sock_fd);
                c->running = false;
                break;
            } else if (events[i].events & EPOLLIN) {
                net_read(c, conn);
            } else if (events[i].events & EPOLLOUT) {
                net_send(conn, c->epoll_fd);
            }
        }
    }
    return NULL;
}
