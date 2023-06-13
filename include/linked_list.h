#ifndef _LINKED_LIST_H_
#define _LINKED_LIST_H_

#include <stdint.h>

typedef uint32_t cmp_func(void *a, void *b);

struct ListEntry {
    void *data;
    struct ListEntry *next;
};

void insert_list(struct ListEntry **head, void *data);
void append_list(struct ListEntry **head, void *data);
void remove_list(struct ListEntry **head, struct ListEntry *node);
struct ListEntry *check_list(struct ListEntry **head, void *data, cmp_func *cmp);
void free_list(struct ListEntry *node);
void dump_list(struct ListEntry *head);

#endif