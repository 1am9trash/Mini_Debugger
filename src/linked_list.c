#include "linked_list.h"

#include <stdlib.h>
#include <stdio.h>

void insert_list(struct ListEntry **head, void *data) {
    struct ListEntry **indirect = head;

    struct ListEntry *node = malloc(1 * sizeof(struct ListEntry));
    node->data = data;
    node->next = *indirect;

    *indirect = node;
}

void append_list(struct ListEntry **head, void *data) {
    struct ListEntry **indirect = head;

    struct ListEntry *node = malloc(1 * sizeof(struct ListEntry));
    node->data = data;
    node->next = NULL;

    while (*indirect) {
        indirect = &((*indirect)->next);
    }

    *indirect = node;
}

void remove_list(struct ListEntry **head, struct ListEntry *node) {
    struct ListEntry **indirect = head;

    while (*indirect && *indirect != node) {
        indirect = &(*indirect)->next;
    }

    if (*indirect) {
        *indirect = node->next;
    }

    free_list(node);
}

struct ListEntry *check_list(struct ListEntry **head, void *data, cmp_func *cmp) {
    struct ListEntry **indirect = head;

    while (*indirect) {
        if (cmp((*indirect)->data, data)) {
            return *indirect;
        }
        indirect = &(*indirect)->next;
    }

    return NULL;
}

void free_list(struct ListEntry *node) {
    if (node) {
        if (node->data) {
            free(node->data);
        }
        free(node);
    }
}

void dump_list(struct ListEntry *head) {
    uint32_t index = 0;
    fprintf(stdout, "List:\n");
    while (head) {
        fprintf(stdout, "%4d: %p\n", index, head->data);
        index++;
        head = head->next;
    }
}