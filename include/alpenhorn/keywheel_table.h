#ifndef ALPENHORN_KEYWHEEL_H
#define ALPENHORN_KEYWHEEL_H

#include "config.h"
#include "utils.h"


struct keywheel;
struct keywheel_table;
struct keywheel_unsynced;
typedef struct keywheel_table keywheel_table;
typedef struct keywheel keywheel;
typedef struct keywheel_unsynced keywheel_unsynced;

struct keywheel_table
{
  keywheel *keywheels;
	size_t num_keywheels;
	keywheel_unsynced *unsynced_keywheels;
	size_t num_unsynced;
	uint64_t table_round;
	char *table_file;
};

struct keywheel
{
  u8 user_id[user_id_BYTES];
  u8 key_state[intent_BYTES + crypto_generichash_BYTES_MAX];
	uint64_t dialling_round;
  keywheel *next;
  keywheel *prev;
};

struct keywheel_unsynced
{
  u8 user_id[user_id_BYTES];
  u8 public_key[crypto_box_PKBYTES];
  u8 secret_key[crypto_box_SECRETKEYBYTES];
	uint64_t round_sent;
	keywheel_unsynced *next;
	keywheel_unsynced *prev;
};

int kw_table_init(keywheel_table *table, uint64_t dial_round, char *table_file);
int kw_dialling_token(u8 *out, keywheel_table *table, u8 *userid, uint64_t intent);
int kw_session_key(u8 *out, keywheel_table *table, u8 *user_id);
void kw_advance_table(keywheel_table *table);
int kw_new_keywheel(keywheel_table *table, u8 *user_id, u8 *pk, u8 *sk, uint64_t round_sentt);
int kw_complete_keywheel(keywheel_table *table, u8 *user_id, u8 *friend_pk, uint64_t round_sync);
keywheel *kw_from_request(keywheel_table *table, u8 *user_id, u8 *dh_pk_out, u8 *friend_pk);
int kw_save(keywheel_table *table);
int kw_load(keywheel_table *table, uint64_t dial_round, char *file_path);
void kw_print_table(keywheel_table *table);
keywheel_unsynced *kw_unsynced_lookup(keywheel_table *table, const u8 *user_id);
keywheel *kw_lookup(keywheel_table *table, const u8 *user_id);
int kw_call_keys(u8 *session, u8 *token, keywheel_table *table, const u8 *user_id, u64 intent);
#endif //ALPENHORN_KEYWHEEL_H
