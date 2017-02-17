//
// Created by chris on 12/02/17.
//

#ifndef ALPENHORN_KEYWHEEL_H
#define ALPENHORN_KEYWHEEL_H

#include "alpenhorn.h"

#define initial_table_size 50

struct keywheel_table;
struct keywheel;
struct keywheel_unconfirmed;
typedef struct keywheel_table keywheel_table;
typedef struct keywheel keywheel;
typedef struct keywheel_unconfirmed keywheel_unconfirmed;

typedef struct keywheel_queue keywheel_queue;

struct keywheel_queue {
  keywheel *entry;
  keywheel_queue *next;
  keywheel_queue *prev;
};

struct keywheel_table {
  keywheel *keywheels;
  size_t keywheel_tbl_capacity;
  size_t num_keywheels;
  keywheel_queue *queue;
  keywheel_unconfirmed *unconfirmed_keywheels;
  size_t unconfirmed_capacity;
  size_t num_unconfirmed;
  uint32_t current_round;
};

struct keywheel {
  byte_t userid[af_email_string_bytes];
  byte_t hash_key[crypto_generichash_BYTES];
  byte_t key_state[intent_length + crypto_generichash_BYTES_MAX];
  uint32_t dialling_round;
};

struct keywheel_unconfirmed {
  byte_t user_id[af_email_string_bytes];
  byte_t public_key[crypto_box_PUBLICKEYBYTES];
  byte_t secret_key[crypto_box_SECRETKEYBYTES];
  uint32_t round_sent;
};
#endif //ALPENHORN_KEYWHEEL_H
