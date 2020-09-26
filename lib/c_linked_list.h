#ifndef C_LINKED_LIST_H
#define C_LINKED_LIST_H

struct c_linked_list;
typedef struct c_linked_list CLinkedList;

typedef void (*c_linked_list_free_cb)(void *);

CLinkedList *c_linked_list_new();

#define CLinkedList_new() c_linked_list_new()

int c_linked_list_set_free_cb(CLinkedList *list, c_linked_list_free_cb cb);

int c_linked_list_free(CLinkedList *list);

#define CLinkedList_free(list, cb) c_linked_list_set_free_cb(list, cb); c_linked_list_free(list)

size_t c_linked_list_length(CLinkedList *list);

int c_linked_list_add(CLinkedList *list, void *v);

void *c_linked_list_get_header(CLinkedList *list);

void *c_linked_list_get_footer(CLinkedList *list);

void *c_linked_list_remove_header(CLinkedList *list);

void *c_linked_list_remove_footer(CLinkedList *list);

void *c_linked_list_remove(CLinkedList *list, void *v);

void c_linked_list_clear(CLinkedList *list);

void *c_linked_list_iterator(CLinkedList *list);

void *c_linked_list_iterator_get_value(void *it);

void *c_linked_list_iterator_next(void *it);

int c_linked_list_merge(CLinkedList *dest, CLinkedList *src);

int c_linked_list_reset_with_no_free(CLinkedList *list);

int c_linked_list_move(CLinkedList **dest, CLinkedList *src);

#endif