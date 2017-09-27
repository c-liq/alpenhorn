#ifndef ALPENHORN_MIX_H
#define ALPENHORN_MIX_H

#include <stdbool.h>
#include "config.h"
#include "utils.h"
#include "bloom.h"
#include "net_common.h"
#include "mixnet_config.h"
#include <signal.h>

static const char *mix_server_ips[] = {"127.0.0.1", "127.0.0.1", "127.0.0.1"};

static const char *mix_listen_ports[] = {"5000", "5001", "5002", "5003"};

static const char mix_entry_client_listenport[] = "7000";

static const char mix_entry_pkg_listenport[] = "6666";

struct mix_s;

typedef struct mix_s mix_s;

typedef struct mailbox mailbox_s;

struct mailbox
{
    u64 id;
    u64 size_bytes;
    u64 msg_count;
    u8 *box_data;
    void *box_struct;
};

typedef struct mailbox_container mailbox_container_s;

struct mailbox_container
{
    u64 round;
    u64 num_boxes;
    mailbox_s *boxes;
};

typedef struct mixer mixer_s;

struct mixer
{
    uint64_t num_boxes;
    byte_buffer_t in_buf;
    byte_buffer_t out_buf;
    uint64_t inc_msg_count;
    uint64_t out_msg_count;
    uint64_t inc_msg_length;
    uint64_t out_msg_length;
    laplace_s laplace;
    uint64_t round;
    uint64_t round_duration;
    int32_t window_duration;
    uint64_t *mb_counts;
    mailbox_container_s box_container;
    u8 pk[crypto_box_PUBLICKEYBYTES];
    u8 sk[crypto_box_SECRETKEYBYTES];
    u8 mix_pks[num_mix_servers][crypto_box_PUBLICKEYBYTES];
    pthread_mutex_t mutex;
    byte_buffer_s *broadcast;
    void (*clear_container)(mixer_s *mixer);
    void (*init_container)(mixer_s *mixer);
    void (*distribute)(mixer_s *mixer);
    void (*fill_noise_msg)(u8 *msg);
    time_t next_round;
    time_t window_remaining;
    u64 msg_length;
    u64 batch_msg_type;
    u64 round_msg_type;
    u64 auth_msg_type;
};

struct mixer_config
{
    u64 msg_length;
    u64 laplace_mu;
    u64 laplace_b;
    u64 batch_msg_type;
    u64 round_msg_type;
    u64 auth_msg_type;
    u64 round_duration;
    int32_t window_duration;
    void (*clear_container)(mixer_s *mixer);
    void (*init_container)(mixer_s *mixer);
    void (*distribute)(mixer_s *mixer);
    void (*fill_noise_msg)(u8 *msg);
};

struct mix_s
{
    uint64_t id;
    uint64_t num_inc_onion_layers;
    uint64_t num_out_onion_layers;
    bool is_last;
    mixer_s af_data;
    mixer_s dial_data;
    nss_s ns;
    bool pkg_preprocess_check;
    long num_threads;
    connection *next_mix;
    connection *prev_mix;
    connection pkg_conns[num_pkg_servers];
    u8 sig_sk[crypto_sign_SECRETKEYBYTES];
    u8 mix_sig_pks[num_mix_servers][crypto_sign_PUBLICKEYBYTES];
    byte_buffer_t broadcast;
#if USE_PBC
    struct pairing_s pairing;
    struct element_s ibe_gen_elem;
    struct element_s noise_Zr_elem;
    struct element_s noise_G1_elem;
#endif
};

typedef struct mix_thread_args mix_thread_args;
struct mix_thread_args
{
    mix_s *mix;
    uint8_t *data;
    uint64_t num_msgs;
    mixer_s *mixer;
};

int mix_init(mix_s *mix, u64 server_id, long num_threads);

void mix_entry_add_message(byte_buffer_s *buf, mixer_s *mixer);

void mix_new_round(mix_s *mix, mixer_s *mixer);

void mix_exit_broadcast_box(mix_s *s, mixer_s *mixer, u64 type);

int mix_net_init(mix_s *mix);

int mix_exit_process_client(void *owner, connection *conn, byte_buffer_s *buf);

void mix_run(mix_s *mix,
             void on_accept(void *, connection *),
             int on_read(void *, connection *, byte_buffer_s *));

int mix_entry_sync(mix_s *mix);

int mix_main(int argc, char **argv);



#endif //ALPENHORN_MIX_H


