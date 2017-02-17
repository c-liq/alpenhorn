#ifndef ALPENHORN_KEYWHEEL_H
#define ALPENHORN_KEYWHEEL_H

#include "config.h"
#include "utils.h"

struct keywheel_table;
struct keywheel;
struct keywheel_unconfirmed;
typedef struct keywheel_table keywheel_table;
typedef struct keywheel keywheel;
typedef struct keywheel_unconfirmed keywheel_unconfirmed;

struct keywheel_table {
  keywheel *keywheels;
  size_t keywheel_tbl_capacity;
  size_t num_keywheels;
  keywheel_unconfirmed *unconfirmed_keywheels;
  size_t unconfirmed_capacity;
  size_t num_unconfirmed;
  uint32_t current_round;
};

struct keywheel {
  byte_t user_id[user_id_BYTES];
  byte_t hash_key[crypto_generichash_BYTES];
  byte_t key_state[intent_BYTES + crypto_generichash_BYTES_MAX];
  byte_t *intent_ptr;
  byte_t *key_ptr;
  uint32_t dialling_round;
};

struct keywheel_unconfirmed {
  byte_t user_id[user_id_BYTES];
  byte_t public_key[crypto_box_PUBLICKEYBYTES];
  byte_t secret_key[crypto_box_SECRETKEYBYTES];
  uint32_t round_sent;
};

int kw_table_init(keywheel_table *table);
#endif //ALPENHORN_KEYWHEEL_H
