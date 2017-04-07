#ifndef ALPENHORN_KEYWHEEL_H
#define ALPENHORN_KEYWHEEL_H

#include "config.h"
#include "utils.h"
#include "client2.h"

struct keywheel;
struct keywheel_table;
struct keywheel_unsynced;

typedef struct keywheel_table keywheel_table_s;

typedef struct keywheel keywheel_s;

typedef struct keywheel_unsynced keywheel_unsynced;

struct keywheel_table
{
	keywheel_s *keywheels;
	size_t num_keywheels;
	keywheel_unsynced *unsynced_keywheels;
	size_t num_unsynced;
	uint64_t table_round;
	char *table_file;
};

struct keywheel
{
	uint8_t user_id[user_id_BYTES];
	uint8_t key_state[2][intent_BYTES + crypto_generichash_BYTES_MAX];
	uint64_t dialling_round;
	keywheel_s *next;
	keywheel_s *prev;
};

struct keywheel_unsynced
{
	uint8_t user_id[user_id_BYTES];
	uint8_t public_key[crypto_box_PUBLICKEYBYTES];
	uint8_t secret_key[crypto_box_SECRETKEYBYTES];
	uint64_t round_sent;
	keywheel_unsynced *next;
	keywheel_unsynced *prev;
};

int kw_table_init(keywheel_table_s *table, uint64_t dial_round, char *table_file);
int kw_dialling_token(uint8_t *out, keywheel_table_s *table, const uint8_t *userid, uint32_t intent, bool is_outgoing);
int kw_session_key(uint8_t *out, keywheel_table_s *table, const uint8_t *user_id, bool is_outgoing);
void kw_advance_table(keywheel_table_s *table);
int kw_new_keywheel(keywheel_table_s *table,
                    const uint8_t *user_id,
                    uint8_t *pk,
                    uint8_t *sk,
                    uint64_t round_sentt);
int kw_complete_keywheel(keywheel_table_s *table,
                         const uint8_t *user_id,
                         uint8_t *friend_pk,
                         const uint64_t round_sync);
keywheel_s *kw_from_request(keywheel_table_s *table, const uint8_t *user_id, uint8_t *dh_pk_out, uint8_t *friend_pk);
int kw_save(keywheel_table_s *table);
int kw_load(keywheel_table_s *table, uint64_t dial_round, char *file_path);
void kw_print_table(keywheel_table_s *table);
keywheel_unsynced *kw_unsynced_lookup(keywheel_table_s *table, const uint8_t *user_id);

#endif //ALPENHORN_KEYWHEEL_H
