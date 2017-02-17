#include <sodium.h>
#include <memory.h>
#include "keywheel_table.h"
#include "client.h"

static const keywheel empty_keywheel;
static const byte_t saltbytes_0[16] = {0};
static const byte_t saltbytes_1[16] = {1};

int keywheel_table_init(keywheel_table *table) {
  table->keywheels = malloc(sizeof(keywheel) * initial_table_size);
  if (!table->keywheels) {
    fprintf(stderr, "malloc failure when initialising keywheel table\n");
    return -1;
  }
  table->unconfirmed_keywheels = malloc(sizeof(keywheel) * initial_table_size);
  if (!table->unconfirmed_keywheels) {
    fprintf(stderr, "malloc failure during keywheel table initialisation\n");
    return -1;
  }
  table->keywheel_tbl_capacity = initial_table_size;
  table->unconfirmed_capacity = initial_table_size;
  table->num_keywheels = 0;
  table->num_unconfirmed = 0;
  return 0;
}

int kw_lookup_user_index(keywheel_table *table, byte_t *userid) {
  int index = -1;
  for (int i = 0; i < table->num_keywheels; i++) {
    if (strncmp((char *) userid, (char *) table->keywheels[i].userid, af_email_string_bytes)) {
      index = i;
      break;
    }
  }
  return index;
}

int kw_generate_session_key(byte_t *out, keywheel_table *table, byte_t *userid, uint32_t intent) {
  int index = kw_lookup_user_index(table, userid);

  if (index == -1) {
    fprintf(stderr, "failed to generate session key, no keywheel entry for %s\n", userid);
  }

  keywheel *entry = &table->keywheels[index];
  crypto_generichash_blake2b_salt_personal(out, crypto_generichash_BYTES, entry->key_state + intent_length,
                                           crypto_generichash_BYTES_MAX, NULL, 0, saltbytes_0, NULL);

}

int kw_generate_dialling_token(byte_t *out, keywheel_table *table, byte_t *userid, uint32_t intent) {

  int index = kw_lookup_user_index(table, userid);

  if (index == -1) {
    fprintf(stderr, "dialling token generation error, no keywheel matching id: %s\n", userid);
    return -1;
  }

  keywheel *entry = &table->keywheels[index];
  serialize_uint32(entry->key_state, intent);
  crypto_generichash_blake2b_salt_personal(out, crypto_generichash_BYTES,
                                           entry->key_state, intent_length + crypto_generichash_BYTES_MAX,
                                           NULL, 0, saltbytes_1, NULL
  );
  return 0;
}

void kw_advance_table(keywheel_table *table) {
  keywheel_queue *queue = table->queue->next;
  while (queue) {
    keywheel *queue_kw = queue->entry;
    if (queue_kw->dialling_round == table->current_round) {
      table->keywheels[table->num_keywheels++] = *queue_kw;
      *queue_kw = empty_keywheel;
      free(queue_kw);
      queue->prev->next = queue->next;
      if (queue->next) {
        queue->next->prev = queue->prev;
      }
      keywheel_queue *tmp = queue->next;
      free(queue);
      queue = tmp;
    } else {
      queue = queue->next;
    }
  }

  for (int i = 0; i < table->keywheel_tbl_capacity; i++) {
    keywheel *cur_kw = &table->keywheels[i];
    crypto_generichash(cur_kw->key_state, crypto_generichash_BYTES_MAX, cur_kw->key_state,
                       crypto_generichash_BYTES_MAX, NULL, 0);
  }
}

size_t kw_new_keywheel(keywheel_table *table, byte_t *user_id, uint32_t round_sent) {
  keywheel_unconfirmed *nu = &table->unconfirmed_keywheels[table->num_unconfirmed];
  memcpy(nu->user_id, user_id, af_email_string_bytes);
  crypto_box_keypair(nu->public_key, nu->secret_key);
  nu->round_sent = round_sent;
  return table->num_unconfirmed++;
}

size_t fw_complete_keywheel(keywheel_table *table,
                            byte_t *user_id,
                            byte_t *friend_public_key,
                            uint32_t dialling_round) {
  int index = -1;

  for (int i = 0; i < table->num_unconfirmed; i++) {
    int cmp = strncmp((char *) user_id, (char *) table->unconfirmed_keywheels[i].user_id, af_email_string_bytes);
    if (cmp == 0) {
      index = i;
      break;
    }
  }

  if (index == -1) {
    fprintf(stderr, "key_state confirmation error, couldn't locate keywheel matching the userid %s", user_id);
  }

  keywheel_unconfirmed *nu = &table->unconfirmed_keywheels[index];
  keywheel *new_keywheel = &table->keywheels[table->num_keywheels];

  byte_t scalar_mult[crypto_scalarmult_BYTES];
  int res = crypto_scalarmult(scalar_mult, nu->secret_key, friend_public_key);
  if (res) {
    fprintf(stderr, "scalar mult error during keywheel confirmation for %s", user_id);
  }
  memcpy(new_keywheel->userid, nu->user_id, af_email_string_bytes);
  crypto_shared_secret(new_keywheel->key_state,
                       scalar_mult,
                       nu->public_key,
                       friend_public_key,
                       crypto_generichash_BYTES_MAX);
  new_keywheel->dialling_round = dialling_round;

  return 0;
}

