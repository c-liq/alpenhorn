#ifndef ALPENHORN_KEYWHEEL_H
#define ALPENHORN_KEYWHEEL_H

#include "config.h"
#include "utils.h"
#include "client.h"

struct keywheel;
struct keywheel_table;
struct keywheel_unsynced;
typedef struct keywheel_table keywheel_table_s;
typedef struct keywheel keywheel_s;
typedef struct keywheel_unsynced keywheel_unsynced;

struct keywheel_table
{
	keywheel_s *keywheels;
	size_t keywheel_tbl_capacity;
	size_t num_keywheels;
	keywheel_unsynced *unsynced_keywheels;
	size_t unconfirmed_capacity;
	size_t num_unsynced;
	u32 table_round;
	u32 cli_dial_round;
};

struct keywheel
{
	byte_t user_id[user_id_BYTES];
	byte_t hash_key[crypto_generichash_BYTES];
	byte_t key_state[intent_BYTES + crypto_generichash_BYTES_MAX];
	byte_t *intent_ptr;
	byte_t *key_ptr;
	u32 dialling_round;
};

struct keywheel_unsynced
{
	byte_t user_id[user_id_BYTES];
	byte_t public_key[crypto_box_PUBLICKEYBYTES];
	byte_t secret_key[crypto_box_SECRETKEYBYTES];
	u32 round_sent;
};

int kw_table_init(keywheel_table_s *table, u32 dial_round);
int kw_dialling_token(byte_t *out, keywheel_table_s *table, const byte_t *userid, u32 intent);
int kw_session_key(byte_t *out, keywheel_table_s *table, const byte_t *user_id);
void kw_advance_table(keywheel_table_s *table);
size_t kw_new_keywheel(keywheel_table_s *table, byte_t *user_id, byte_t *pk, byte_t *sk, u32 round_sentt);
size_t kw_complete_keywheel(keywheel_table_s *table, byte_t *user_id, byte_t *friend_pk, u32 round_sync);
keywheel_s *kw_new_keywheel_from_request(keywheel_table_s *table,
                                         byte_t *user_id,
                                         byte_t *dh_pk_out,
                                         byte_t *friend_pk);
void kw_print_table(keywheel_table_s *table);

#endif //ALPENHORN_KEYWHEEL_H
