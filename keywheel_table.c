#include <sodium.h>
#include <memory.h>
#include "keywheel_table.h"

static const keywheel empty_keywheel;
static const byte_t saltbytes_0[16] = {0};
static const byte_t saltbytes_1[16] = {1};

int kw_table_init(keywheel_table *table) {
  table->keywheels = calloc(initial_table_size, sizeof(*table->keywheels));
  if (!table->keywheels) {
    fprintf(stderr, "malloc failure when initialising keywheel table\n");
    return -1;
  }

  table->unconfirmed_keywheels = calloc(initial_table_size, sizeof(*table->unconfirmed_keywheels));
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

int kw_lookup_user_index(keywheel_table *table, byte_t *user_id) {
  int index = -1;
  for (int i = 0; i < table->num_keywheels; i++) {
    if (!(strncmp((char *) user_id, (char *) table->keywheels[i].user_id, user_id_BYTES))) {
      index = i;
      break;
    }
  }
  return index;
}

void kw_print_table(keywheel_table *table) {
  printf("Keywheel table\n----------\n");
  for (int i = 0; i < table->num_keywheels; i++) {
    keywheel *entry = &table->keywheels[i];
    printf("%60s", entry->user_id);
    printhex(" ", entry->key_ptr, crypto_maxhash_BYTES);
  }
}

int kw_generate_session_key(byte_t *out, keywheel_table *table, byte_t *user_id) {
  int index = kw_lookup_user_index(table, user_id);

  if (index == -1) {
    fprintf(stderr, "failed to generate session key, no keywheel entry for %s\n", user_id);
  }

  keywheel *entry = &table->keywheels[index];
  crypto_generichash_blake2b_salt_personal(out, crypto_ghash_BYTES, entry->key_ptr,
                                           crypto_maxhash_BYTES, NULL, 0, saltbytes_0, NULL);

  return 0;
}

int kw_generate_dialling_token(byte_t *out, keywheel_table *table, byte_t *userid, uint32_t intent) {

  int index = kw_lookup_user_index(table, userid);

  if (index == -1) {
    fprintf(stderr, "dialling token generation error, no keywheel matching id: %s\n", userid);
    return -1;
  }

  keywheel *entry = &table->keywheels[index];
  serialize_uint32(entry->intent_ptr, intent);
  crypto_generichash_blake2b_salt_personal(out, crypto_ghash_BYTES,
                                           entry->intent_ptr, intent_BYTES + crypto_maxhash_BYTES,
                                           NULL, 0, saltbytes_1, NULL
  );
  return 0;
}

void kw_advance_table(keywheel_table *table) {
/*  keywheel_queue *queue = table->queue->next;
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
  }*/

  for (int i = 0; i < table->num_keywheels; i++) {
    keywheel *cur_kw = &table->keywheels[i];
    crypto_generichash(cur_kw->key_ptr, crypto_maxhash_BYTES, cur_kw->key_ptr,
                       crypto_maxhash_BYTES, NULL, 0);
  }
}

size_t kw_new_keywheel(keywheel_table *table, byte_t *user_id, uint32_t round_sent) {
  keywheel_unconfirmed *nu = &table->unconfirmed_keywheels[table->num_unconfirmed];
  memcpy(nu->user_id, user_id, user_id_BYTES);
  crypto_box_keypair(nu->public_key, nu->secret_key);
  nu->round_sent = round_sent;
  return table->num_unconfirmed++;
}

size_t kw_complete_keywheel(keywheel_table *table,
                            byte_t *user_id,
                            byte_t *friend_public_key,
                            uint32_t dial_round_sync) {
  int index = -1;

  for (int i = 0; i < table->num_unconfirmed; i++) {
    int cmp = strncmp((char *) user_id, (char *) table->unconfirmed_keywheels[i].user_id, user_id_BYTES);
    if (cmp == 0) {
      index = i;
      break;
    }
  }

  if (index == -1) {
    fprintf(stderr, "key_state confirmation error, couldn't locate keywheel matching the user_id %s", user_id);
  }

  keywheel_unconfirmed *nu = &table->unconfirmed_keywheels[index];
  keywheel *new_keywheel = &table->keywheels[table->num_keywheels++];
  new_keywheel->intent_ptr = new_keywheel->key_state;
  new_keywheel->key_ptr = new_keywheel->key_state + intent_BYTES;
  serialize_uint32(new_keywheel->intent_ptr, 0);

  byte_t scalar_mult[crypto_scalarmult_BYTES];
  int res = crypto_scalarmult(scalar_mult, nu->secret_key, friend_public_key);
  if (res) {
    fprintf(stderr, "scalar mult error during keywheel confirmation for %s", user_id);
  }
  memcpy(new_keywheel->user_id, nu->user_id, user_id_BYTES);
  crypto_shared_secret(new_keywheel->key_ptr,
                       scalar_mult,
                       nu->public_key,
                       friend_public_key,
                       crypto_maxhash_BYTES);
  while (dial_round_sync != table->current_round) {
    printf("BLEEP BLOOP\n");
    crypto_generichash(new_keywheel->key_ptr,
                       crypto_maxhash_BYTES,
                       new_keywheel->key_ptr,
                       crypto_maxhash_BYTES,
                       NULL,
                       0);
  }
  new_keywheel->dialling_round = dial_round_sync;

  return 0;
}

int main() {
  keywheel_table table;
  kw_table_init(&table);
  byte_t sk[crypto_box_PUBLICKEYBYTES];
  byte_t pk[crypto_box_SECRETKEYBYTES];
  randombytes_buf(sk, crypto_box_SECRETKEYBYTES);
  crypto_scalarmult_base(pk, sk);
  table.current_round = 1;
  byte_t uname[user_id_BYTES] = {'c', 'h', 'r', 'i', 's'};
  kw_new_keywheel(&table, uname, 1);
  kw_complete_keywheel(&table, uname, pk, 1);
  kw_print_table(&table);
  kw_advance_table(&table);
  byte_t dial_token[dialling_token_BYTES];
  byte_t session_key[crypto_ghash_BYTES];
  kw_generate_dialling_token(dial_token, &table, uname, 1);
  kw_generate_session_key(session_key, &table, uname);
  printhex("dial token", dial_token, dialling_token_BYTES);
  printhex("session key", session_key, crypto_ghash_BYTES);
}
