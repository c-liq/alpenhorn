#include "alpenhorn/keywheel_table.h"

static const u8 saltbytes_0[16] = {};

static const u8 saltbytes_1[16] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

int kw_save(keywheel_table *table) {
    FILE *out_file = fopen(table->table_file, "w");
    if (!out_file) {
        fprintf(stderr, "failed to open table file for saving\n");
        return -1;
    }

    fprintf(out_file, "%ld %ld %ld\n", table->table_round, table->num_keywheels, table->num_unsynced);

    char pk_buf[crypto_box_PKBYTES * 2 + 1];
    char sk_buf[crypto_box_SECRETKEYBYTES * 2 + 1];
    keywheel_unsynced *curr_kwu = table->unsynced_keywheels;

    while (curr_kwu) {
        sodium_bin2hex(pk_buf, sizeof pk_buf, curr_kwu->public_key, crypto_box_PKBYTES);
        sodium_bin2hex(sk_buf, sizeof sk_buf, curr_kwu->secret_key, crypto_box_SECRETKEYBYTES);
        fprintf(out_file, "%s %s %s %ld\n", curr_kwu->user_id, pk_buf, sk_buf, curr_kwu->round_sent);
        curr_kwu = curr_kwu->next;
    }

    char secret_buf[crypto_maxhash_BYTES * 2 + 1];
    keywheel *curr_kw = table->keywheels;
    while (curr_kw) {
        sodium_bin2hex(secret_buf,
                       crypto_maxhash_BYTES * 2 + 1,
                       curr_kw->key_state + intent_BYTES,
                       crypto_maxhash_BYTES);
        fprintf(out_file, "%s %s %ld\n", curr_kw->user_id, secret_buf, curr_kw->dialling_round);
        curr_kw = curr_kw->next;
    }

    int status = fclose(out_file);
    if (status) {
        perror("closing table file");
        return -1;
    }

    return 0;
}

int kw_load(keywheel_table *table, u64 dial_round, char *file_path) {
    if (!file_path) {
        fprintf(stderr, "no file path supplied to load table\n");
        return -1;
    }

    FILE *in_file = fopen(file_path, "r");
    if (!in_file) {
        fprintf(stderr, "failed to load specified table file\n");
        return -1;
    }

    kw_table_init(table, dial_round, file_path);

    fscanf(in_file, "%lu %lu %lu\n", &table->table_round, &table->num_keywheels, &table->num_unsynced);

    char pk_hex_buf[crypto_box_PKBYTES * 2 + 1];
    char sk_hex_buf[crypto_box_SECRETKEYBYTES * 2 + 1];
    keywheel_unsynced *prev = NULL;
    for (int i = 0; i < table->num_unsynced; i++) {
        keywheel_unsynced *curr = calloc(1, sizeof *curr);
        if (!curr) {
            return -1;
        }

        if (!prev) {
            table->unsynced_keywheels = curr;
        } else {
            prev->next = curr;
        }
        curr->next = NULL;
        curr->prev = prev;
        prev = curr;

        fscanf(in_file, "%s %s %s %lu\n", curr->user_id, pk_hex_buf, sk_hex_buf, &curr->round_sent);
        sodium_hex2bin(curr->public_key, crypto_box_PKBYTES, pk_hex_buf, sizeof pk_hex_buf, NULL, NULL, NULL);
        sodium_hex2bin(curr->secret_key, crypto_box_SECRETKEYBYTES, sk_hex_buf, sizeof sk_hex_buf, NULL, NULL, NULL);
    }

    char secret_hex_buf[crypto_maxhash_BYTES * 2 + 1];
    keywheel *prev_kw = NULL;
    for (int i = 0; i < table->num_keywheels; i++) {
        keywheel *curr = calloc(1, sizeof *curr);

        if (!curr) {
            return -1;
        }
        if (!prev_kw) {
            table->keywheels = curr;
        } else {
            prev_kw->next = curr;
        }
        curr->next = NULL;
        curr->prev = prev_kw;
        prev_kw = curr;

        fscanf(in_file, "%s %s %lu\n", curr->user_id, secret_hex_buf, &curr->dialling_round);
        sodium_hex2bin(curr->key_state + intent_BYTES,
                       crypto_maxhash_BYTES,
                       secret_hex_buf,
                       sizeof secret_hex_buf,
                       NULL,
                       NULL,
                       NULL);
    }

    int status = fclose(in_file);
    if (status) {
        fprintf(stderr, "error when closing keywheel table file\n");
        return -1;
    }

    return 0;
}

int kw_table_init(keywheel_table *table, u64 dial_round, char *file_path) {
    table->keywheels = NULL;
    table->unsynced_keywheels = NULL;
    table->num_keywheels = 0;
    table->num_unsynced = 0;
    table->table_round = dial_round;
    table->table_file = file_path ? file_path : "keywheel.table";
    return 0;
}

keywheel *kw_lookup(keywheel_table *table, const u8 *user_id) {
    keywheel *current = table->keywheels;
    keywheel *entry = NULL;
    while (current) {
        if (!(strncmp((char *) user_id, (char *) current->user_id, user_id_BYTES))) {
            entry = current;
            break;
        }
        current = current->next;
    }
    return entry;
}

keywheel_unsynced *kw_unsynced_lookup(keywheel_table *table, const u8 *user_id) {
    keywheel_unsynced *current = table->unsynced_keywheels;
    keywheel_unsynced *entry = NULL;
    while (current) {
        if (!(strncmp((char *) user_id, (char *) current->user_id, user_id_BYTES))) {
            entry = current;
            break;
        }
        current = current->next;
    }
    return entry;
}

void kw_print_table(keywheel_table *table) {
    keywheel *entry = table->keywheels;
    printf("Keywheel table | #%lu [Round %ld]\n-------------------------\n", table->num_keywheels, table->table_round);
    while (entry) {
        printf("%s", entry->user_id);
        printhex(" ", entry->key_state + intent_BYTES, crypto_ghash_BYTES);
        entry = entry->next;
    }
    printf("-------------------------\n");
}

int kw_call_keys(u8 *session, u8 *token, keywheel_table *table, const u8 *user_id, u64 intent) {
    keywheel *kw = kw_lookup(table, user_id);
    if (!kw) {
        return -1;
    }
    crypto_generichash_blake2b_salt_personal(session, crypto_ghash_BYTES, kw->key_state + intent_BYTES,
                                             crypto_maxhash_BYTES, NULL, 0, saltbytes_0, NULL);

    serialize_u64(kw->key_state, intent);
    crypto_generichash_blake2b_salt_personal(token, crypto_ghash_BYTES,
                                             kw->key_state, intent_BYTES + crypto_maxhash_BYTES,
                                             NULL, 0, saltbytes_1, NULL);

    return 0;
}

int kw_session_key(u8 *out, keywheel_table *table, u8 *user_id) {
    keywheel *kw = kw_lookup(table, user_id);

    if (!kw) {
        fprintf(stderr, "failed to generate session key, no keywheel entry for %s\n", user_id);
        return -1;
    }
    crypto_generichash_blake2b_salt_personal(out, crypto_ghash_BYTES, kw->key_state + intent_BYTES,
                                             crypto_maxhash_BYTES, NULL, 0, saltbytes_0, NULL);

    return 0;
}

int kw_dialling_token(u8 *out, keywheel_table *table, u8 *userid, u64 intent) {
    keywheel *entry = kw_lookup(table, userid);

    if (!entry) {
        return -1;
    }

    serialize_u64(entry->key_state, intent);
    crypto_generichash_blake2b_salt_personal(out, crypto_ghash_BYTES,
                                             entry->key_state, intent_BYTES + crypto_maxhash_BYTES,
                                             NULL, 0, saltbytes_1, NULL
    );

    return 0;
}

void kw_advance_table(keywheel_table *table) {
    keywheel *curr = table->keywheels;
    while (curr) {
        crypto_generichash(curr->key_state + intent_BYTES,
                           crypto_maxhash_BYTES,
                           curr->key_state + intent_BYTES,
                           crypto_maxhash_BYTES,
                           NULL,
                           0);
        curr = curr->next;
    }
    table->table_round++;
}

int kw_new_keywheel(keywheel_table *table, u8 *user_id, u8 *pk, u8 *sk, u64 round_sent) {
    keywheel_unsynced *nu = calloc(1, sizeof *nu);
    if (!nu) {
        fprintf(stderr, "calloc failure when creating new keywheel\n");
        return -1;
    }
    memcpy(nu->user_id, user_id, user_id_BYTES);
    memcpy(nu->public_key, pk, crypto_box_PKBYTES);
    memcpy(nu->secret_key, sk, crypto_box_SECRETKEYBYTES);
    nu->round_sent = round_sent;

    nu->next = table->unsynced_keywheels;
    nu->prev = NULL;
    table->unsynced_keywheels = nu;
    table->num_unsynced++;

    return 0;
}

keywheel *kw_from_request(keywheel_table *table, u8 *user_id, u8 *dh_pk_out, u8 *friend_pk) {
    u8 our_sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(dh_pk_out, our_sk);

    keywheel *kw = calloc(1, sizeof *kw);
    if (!kw) {
        fprintf(stderr, "malloc failure when creating new keywheel\n");
        return NULL;
    }

    memcpy(kw->user_id, user_id, user_id_BYTES);
    kw->dialling_round = table->table_round;
    crypto_shared_secret(kw->key_state + intent_BYTES, our_sk, friend_pk, dh_pk_out, friend_pk, crypto_maxhash_BYTES);

    kw->next = table->keywheels;
    kw->prev = NULL;
    table->keywheels = kw;
    table->num_keywheels++;

    return kw;
}

int kw_remove(keywheel_table *table, const u8 *user_id) {
    keywheel *entry = kw_lookup(table, user_id);
    if (!entry) {
        return -1;
    }

    if (table->keywheels == entry) {
        table->keywheels = entry->next;
    }

    if (entry->prev) {
        entry->prev->next = entry->next;
    }

    if (entry->next) {
        entry->next->prev = entry->prev;
    }
    table->num_keywheels--;
    free(entry);
    return 0;
}

int kw_unsynced_remove(keywheel_table *table, const u8 *user_id) {
    keywheel_unsynced *entry = kw_unsynced_lookup(table, user_id);
    if (!entry) {
        return -1;
    }

    if (table->unsynced_keywheels == entry) {
        table->unsynced_keywheels = entry->next;
    }

    if (entry->prev) {
        entry->prev->next = entry->next;
    }

    if (entry->next) {
        entry->next->prev = entry->prev;
    }
    table->num_unsynced--;
    free(entry);
    return 0;
}

int kw_complete_keywheel(keywheel_table *table, u8 *user_id, u8 *friend_pk, u64 round_sync) {
    keywheel_unsynced *entry = kw_unsynced_lookup(table, user_id);
    if (!entry) {
        return -1;
    }

    keywheel *kw = calloc(1, sizeof *kw);
    if (!kw) {
        fprintf(stderr, "memory allocation failure during kw completion\n");
        return -1;
    }

    memcpy(kw->user_id, entry->user_id, user_id_BYTES);
    crypto_shared_secret(kw->key_state + intent_BYTES,
                         entry->secret_key,
                         friend_pk,
                         friend_pk,
                         entry->public_key,
                         crypto_maxhash_BYTES);
    kw->dialling_round = round_sync;
    while (kw->dialling_round < table->table_round) {
        crypto_generichash(kw->key_state + intent_BYTES, crypto_maxhash_BYTES, kw->key_state + intent_BYTES,
                           crypto_maxhash_BYTES, NULL, 0);
        kw->dialling_round++;
    }
    kw->next = table->keywheels;
    kw->prev = NULL;
    table->keywheels = kw;
    table->num_keywheels++;
    kw_unsynced_remove(table, user_id);
    return 0;
}
