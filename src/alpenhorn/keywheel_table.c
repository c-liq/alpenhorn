#include "alpenhorn/keywheel_table.h"

static const u8 saltbytes_0[16] = {};

static const u8 saltbytes_1[16] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

int kw_save(keywheel_table *table) {
    FILE *out_file = fopen(table->table_file, "w");
    if (!out_file) {
        fprintf(stderr, "failed to open table file for saving\n");
        return -1;
    }

    fprintf(out_file, "%ld %ld %ld\n", table->table_round, table->keywheels->size, table->unsynced_keywheels->size);

    char pk_buf[crypto_box_PKBYTES * 2 + 1];
    char sk_buf[crypto_box_SECRETKEYBYTES * 2 + 1];
    list_item *curr_kwu = table->unsynced_keywheels->head;

    while (curr_kwu)
        while (curr_kwu) {
            keywheel_unsynced *unsynced = curr_kwu->data;
            sodium_bin2hex(pk_buf, sizeof pk_buf, unsynced->public_key, crypto_box_PKBYTES);
            sodium_bin2hex(sk_buf, sizeof sk_buf, unsynced->secret_key, crypto_box_SECRETKEYBYTES);
            fprintf(out_file, "%s %s %s %ld\n", unsynced->user_id, pk_buf, sk_buf, unsynced->round_sent);
            curr_kwu = curr_kwu->next;
        }

    char secret_buf[crypto_maxhash_BYTES * 2 + 1];

    list_item *curr_kw = table->keywheels->head;
    while (curr_kw) {
        keywheel *kw = curr_kw->data;
        sodium_bin2hex(secret_buf,
                       crypto_maxhash_BYTES * 2 + 1,
                       kw->key_state + intent_BYTES,
                       crypto_maxhash_BYTES);
        fprintf(out_file, "%s %s %ld\n", kw->user_id, secret_buf, kw->dial_round);
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

    u64 num_keywheels;
    u64 num_unsynced;
    fscanf(in_file, "%lu %lu %lu\n", &table->table_round, &num_keywheels, &num_unsynced);

    char pk_hex_buf[crypto_box_PKBYTES * 2 + 1];
    char sk_hex_buf[crypto_box_SECRETKEYBYTES * 2 + 1];

    for (int i = 0; i < table->unsynced_keywheels->size; i++) {
        keywheel_unsynced *curr = calloc(1, sizeof *curr);
        if (!curr) {
            return -1;
        }
        list_push_head(table->unsynced_keywheels, curr);
        fscanf(in_file, "%s %s %s %lu\n", curr->user_id, pk_hex_buf, sk_hex_buf, &curr->round_sent);

        sodium_hex2bin(curr->public_key, crypto_box_PKBYTES, pk_hex_buf, sizeof pk_hex_buf, NULL, NULL, NULL);
        sodium_hex2bin(curr->secret_key, crypto_box_SECRETKEYBYTES, sk_hex_buf, sizeof sk_hex_buf, NULL, NULL, NULL);
    }

    char secret_hex_buf[crypto_maxhash_BYTES * 2 + 1];

    for (int i = 0; i < table->keywheels->size; i++) {
        keywheel *curr = calloc(1, sizeof *curr);

        if (!curr) {
            return -1;
        }
        list_push_head(table->keywheels, curr);

        fscanf(in_file, "%s %s %lu\n", curr->user_id, secret_hex_buf, &curr->dial_round);
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
    table->keywheels = list_alloc();
    table->unsynced_keywheels = list_alloc();
    if (!table->keywheels || !table->unsynced_keywheels) {
        free(table->keywheels);
        free(table->unsynced_keywheels);
        return -1;
    }

    table->table_round = dial_round;
    table->table_file = file_path ? file_path : "keywheel.table";
    return 0;
}

static int kw_cmp_userids(const void *a, const void *b) {
    keywheel *ka = a;
    keywheel *kb = b;
    return memcmp(ka->user_id, kb->user_id, user_id_BYTES);
}

static int kwu_cmp_userids(const void *a, const void *b) {
    keywheel_unsynced *ka = a;
    keywheel_unsynced *kb = b;
    return memcmp(ka->user_id, kb->user_id, user_id_BYTES);
}

keywheel *kw_lookup(keywheel_table *table, const u8 *user_id) {
    return list_find(table->keywheels, user_id, kw_cmp_userids);
}

keywheel_unsynced *kw_unsynced_lookup(keywheel_table *table, const u8 *user_id) {
    return list_find(table->unsynced_keywheels, user_id, kwu_cmp_userids);
}

void kw_print_table(keywheel_table *table) {
    list_item *entry = table->keywheels->head;
    printf("Keywheel table | #%lu [Round %ld]\n-------------------------\n",
           table->keywheels->size,
           table->table_round);
    while (entry) {
        keywheel *kw = entry->data;
        printf("%s", kw->user_id);
        printhex(" ", kw->key_state + intent_BYTES, crypto_ghash_BYTES);
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
    list_item *curr = table->keywheels->head;
    while (curr) {
        keywheel *kw = curr->data;
        crypto_generichash(kw->key_state + intent_BYTES,
                           crypto_maxhash_BYTES,
                           kw->key_state + intent_BYTES,
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
        return -1;
    }

    memcpy(nu->user_id, user_id, user_id_BYTES);
    memcpy(nu->public_key, pk, crypto_box_PKBYTES);
    memcpy(nu->secret_key, sk, crypto_box_SECRETKEYBYTES);
    nu->round_sent = round_sent;

    list_push_head(table->unsynced_keywheels, nu);
    return 0;
}

keywheel *kw_from_request(keywheel_table *table, u8 *user_id, u8 *dh_pk_out, u8 *friend_pk) {
    keywheel *kw = calloc(1, sizeof *kw);
    if (!kw) {
        fprintf(stderr, "malloc failure when creating new keywheel\n");
        return NULL;
    }

    u8 sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(dh_pk_out, sk);
    memcpy(kw->user_id, user_id, user_id_BYTES);
    kw->dial_round = table->table_round;
    crypto_shared_secret(kw->key_state + intent_BYTES, sk, friend_pk, dh_pk_out, friend_pk, crypto_maxhash_BYTES);

    list_push_head(table->keywheels, kw);
    return kw;
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
    kw->dial_round = round_sync;
    while (kw->dial_round < table->table_round) {
        crypto_generichash(kw->key_state + intent_BYTES, crypto_maxhash_BYTES, kw->key_state + intent_BYTES,
                           crypto_maxhash_BYTES, NULL, 0);
        kw->dial_round++;
    }

    list_push_head(table->keywheels, kw);
    list_remove(table->unsynced_keywheels, user_id, kwu_cmp_userids);
    return 0;
}
