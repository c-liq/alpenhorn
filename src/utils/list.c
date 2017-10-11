#include <stdio.h>
#include <malloc.h>
#include "list.h"

struct x {
  size_t x:56;

};

int list_push_head(list *list, void *data) {
    list_item *item = calloc(1, sizeof *item);
    if (!item) {
        return -1;
    }

    item->next = NULL;
    item->prev = NULL;
    item->data = data;

    if (list->size == 0) {
        list->head = item;
        list->tail = item;
    } else {
        item->next = list->head;
        list->head->prev = item;
        list->head = item;
    }

    list->size++;
    return 0;
}

list *list_alloc(void) {
    list *new_list = calloc(1, sizeof *new_list);
    if (!new_list) {
        return NULL;
    }
    new_list->size = 0;
    new_list->head = NULL;
    new_list->tail = NULL;

    return new_list;
}

int list_push_tail(list *list, void *data) {
    list_item *item = calloc(1, sizeof *item);
    if (!item) {
        return -1;
    }

    item->next = NULL;
    item->prev = NULL;
    item->data = data;

    if (list->size == 0) {
        list->head = item;
        list->tail = item;
    } else {
        item->prev = list->tail;
        list->tail->next = item;
        list->tail = item;
    }

    list->size++;
    return 0;
}

void *list_pop_head(list *list) {
    if (!list || list->size == 0) {
        return NULL;
    }

    list_item *popped = NULL;
    if (list->size == 1) {
        popped = list->head;
        list->head = NULL;
        list->tail = NULL;
    } else {
        popped = list->head;
        list->head = popped->next;
        list->head->prev = NULL;
    }

    void *data = popped->data;
    free(popped);
    list->size--;

    return data;
}

void *list_find(list *list, const void *item, int cmp(const void *, const void *)) {
    if (!list || !item || !cmp) {
        return NULL;
    }

    list_item *current_item = list->head;
    while (current_item) {
        if (!cmp(current_item->data, item)) {
            return current_item->data;
        }
        current_item = current_item->next;
    }

    return NULL;
}

void *list_remove(list *list, void *item, int cmp(const void *, const void *)) {
    if (!list || !item || !cmp) {
        return NULL;
    }

    list_item *current_item = list->head;
    while (current_item) {
        if (!cmp(current_item->data, item)) {
            break;
        }
        current_item = current_item->next;
    }

    if (!current_item) {
        return NULL;
    }

    void *return_data = current_item->data;

    if (list->size == 1) {
        list->head = NULL;
        list->tail = NULL;
    } else {
        if (current_item->next) {
            current_item->next->prev = current_item->prev;
        }
        if (current_item->prev) {
            current_item->prev->next = current_item->next;
        }
        if (current_item == list->head) {
            list->head = current_item->next;
        } else if (current_item == list->tail) {
            list->tail = current_item->prev;
        }
    }

    list->size--;
    free(current_item);
    return return_data;
}

void *list_pop_tail(list *list) {
    if (!list || list->size == 0) {
        return NULL;
    }

    list_item *popped = NULL;
    if (list->size == 1) {
        popped = list->head;
        list->head = NULL;
        list->tail = NULL;
    } else {
        popped = list->tail;
        list->tail = popped->prev;
        list->tail->next = NULL;
    }

    void *data = popped->data;
    free(popped);
    list->size--;

    return data;
}

