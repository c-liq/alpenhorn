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
	uint32_t table_round;
	uint32_t cli_dial_round;
	char *table_file;
};

struct keywheel
{
	uint8_t user_id[user_id_BYTES];
	uint8_t hash_key[crypto_generichash_BYTES];
	uint8_t key_state[intent_BYTES + crypto_generichash_BYTES_MAX];
	uint8_t *intent_ptr;
	uint8_t *key_ptr;
	uint32_t dialling_round;
	keywheel_s *next;
	keywheel_s *prev;
};

struct keywheel_unsynced
{
	uint8_t user_id[user_id_BYTES];
	uint8_t public_key[crypto_box_PUBLICKEYBYTES];
	uint8_t secret_key[crypto_box_SECRETKEYBYTES];
	uint32_t round_sent;
	keywheel_unsynced *next;
	keywheel_unsynced *prev;
};

int kw_table_init(keywheel_table_s *table, uint32_t dial_round, char *table_file);
int kw_dialling_token(uint8_t *out, keywheel_table_s *table, const uint8_t *userid, uint32_t intent);
int kw_session_key(uint8_t *out, keywheel_table_s *table, const uint8_t *user_id);
void kw_advance_table(keywheel_table_s *table);
int kw_new_keywheel(keywheel_table_s *table,
                    const uint8_t *user_id,
                    uint8_t *pk,
                    uint8_t *sk,
                    const uint32_t round_sentt);
int kw_complete_keywheel(keywheel_table_s *table,
                         const uint8_t *user_id,
                         uint8_t *friend_pk,
                         const uint32_t round_sync);
keywheel_s *kw_from_request(keywheel_table_s *table, const uint8_t *user_id, uint8_t *dh_pk_out, uint8_t *friend_pk);
int kw_save(keywheel_table_s *table);
int kw_load(keywheel_table_s *table, uint32_t dial_round, char *file_path);
void kw_print_table(keywheel_table_s *table);

#endif //ALPENHORN_KEYWHEEL_H