#ifndef list_H
#define list_H

typedef struct list_item list_item;
struct list_item {
  void *data;
  list_item *next;
  list_item *prev;
};

typedef struct list {
  list_item *head;
  list_item *tail;
  ssize_t size;
} list;

int list_push_head(list *list, void *data);
int list_push_tail(list *list, void *data);
void *list_pop_head(list *list);
void *list_pop_tail(list *list);
void *list_find(list *list, void *item, int cmp(void *, void *));
list *list_alloc(void);

#endif //ALPENHORN_list_H
