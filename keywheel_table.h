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
int kw_generate_dialling_token(byte_t *out, keywheel_table *table, byte_t *userid, uint32_t intent);
int kw_generate_session_key(byte_t *out, keywheel_table *table, byte_t *user_id);
void kw_advance_table(keywheel_table *table);
size_t kw_new_keywheel(keywheel_table *table, byte_t *user_id, uint32_t round_sentt);
size_t kw_complete_keywheel(keywheel_table *table,
                            byte_t *user_id,
                            byte_t *friend_public_key,
                            uint32_t dial_round_sync);
#endif //ALPENHORN_KEYWHEEL_H
