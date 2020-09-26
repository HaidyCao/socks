#include <stdio.h>
#include <stdlib.h>

#include "c_linked_list.h"

struct c_linked_list_node;
typedef struct c_linked_list_node Node;

struct c_linked_list_node {
    void *value;
    Node *next;
};

struct c_linked_list {
    Node *header;
    Node *footer;
    size_t len;
    c_linked_list_free_cb cb;

};

CLinkedList *c_linked_list_new() {
    CLinkedList *list = (CLinkedList *) calloc(1, sizeof(CLinkedList));

    return list;
}

int c_linked_list_set_free_cb(CLinkedList *list, c_linked_list_free_cb cb) {
    if (list == NULL) {
        return -1;
    }

    list->cb = cb;
    return 0;
}

int c_linked_list_free(CLinkedList *list) {
    if (list == NULL) {
        return -1;
    }
    Node *node = list->header;
    while (node) {
        Node *next = node->next;
        if (list->cb) {
            list->cb(node->value);
        }
        free(node);
        node = next;
    }
    free(list);

    return 0;
}

size_t c_linked_list_length(CLinkedList *list) {
    if (list == NULL) return 0;
    return list->len;
}

int c_linked_list_add(CLinkedList *list, void *v) {
    if (list == NULL) {
        return -1;
    }

    Node *node = (Node *) malloc(sizeof(Node));
    node->value = v;
    node->next = NULL;

    if (list->footer == NULL) {
        list->header = node;
        list->footer = node;
    } else {
        list->footer->next = node;
        list->footer = node;
    }
    list->len++;

    return 0;
}

void *c_linked_list_get_header(CLinkedList *list) {
    if (list == NULL)
        return NULL;

    void *v = NULL;
    if (list->header != NULL)
        v = list->header->value;

    return v;
}

void *c_linked_list_get_footer(CLinkedList *list) {
    if (list == NULL)
        return NULL;

    void *v = NULL;
    if (list->footer != NULL)
        v = list->footer->value;
    return v;
}

void *c_linked_list_remove_header(CLinkedList *list) {
    if (list == NULL) {
        return NULL;
    }

    if (list->header == NULL) {
        return NULL;
    }

    void *v = list->header->value;
    if (list->cb && v) {
        list->cb(v);
        v = NULL;
    }
    if (list->header == list->footer) {
        list->header = list->footer = NULL;
    } else {
        Node *h = list->header;
        list->header = list->header->next;
        free(h);
    }
    list->len--;

    return v;
}

void *c_linked_list_remove_footer(CLinkedList *list) {
    if (list == NULL)
        return NULL;

    if (list->footer == NULL) {
        return NULL;
    }

    void *v = list->footer->value;
    if (list->cb) {
        list->cb(v);
        v = NULL;
    }

    if (list->header->next == NULL) {
        list->header = list->footer = NULL;
    } else {
        Node *f = list->footer;

        Node *node = list->header;
        while (node) {
            Node *next = node->next;
            if (f == next) {
                free(f);
                node->next = NULL;
                list->footer = node;
                break;
            }
        }
    }
    list->len--;

    return v;
}

void *c_linked_list_remove(CLinkedList *list, void *v) {
    if (list == NULL || v == NULL || list->len == 0)
        return NULL;

    Node *node = list->header;
    if (node == v) {
        list->header = node->next;
        if (list->header == NULL)
            list->footer = NULL;
        void *ret = node->value;
        free(node);
        list->len--;
        return ret;
    }
    while (node->next) {
        if (node->next == v) {
            Node *next = node->next;
            Node *nn = next->next;
            node->next = nn;
            if (node->next == NULL)
                list->footer = node;
            void *ret = next->value;
            free(next);
            list->len--;
            return ret;
        }
        node = node->next;
    }

    return NULL;
}

void c_linked_list_clear(CLinkedList *list) {
    if (list == NULL)
        return;

    while (list->len > 0) {
        c_linked_list_remove_header(list);
    }
}

void *c_linked_list_iterator(CLinkedList *list) {
    if (list == NULL)
        return NULL;

    return list->header;
}

void *c_linked_list_iterator_get_value(void *it) {
    if (it == NULL)
        return NULL;
    Node *node = it;
    return node->value;
}

void *c_linked_list_iterator_next(void *it) {
    if (it == NULL)
        return NULL;
    Node *node = it;
    return node->next;
}

int c_linked_list_merge(CLinkedList *dest, CLinkedList *src) {
    if (dest == NULL || src == NULL) {
        return -1;
    }

    if (src->header == NULL) {
        return 0;
    }

    if (dest->footer == NULL) {
        dest->header = src->header;
        dest->footer = src->footer;
    } else {
        dest->footer->next = src->header;
        dest->footer = src->footer;
    }
    dest->len += src->len;

    c_linked_list_reset_with_no_free(src);
    return 0;
}

int c_linked_list_reset_with_no_free(CLinkedList *list) {
    if (list == NULL) return -1;

    list->header = list->footer = NULL;
    list->len = 0;
    return 0;
}

int c_linked_list_move(CLinkedList **dest, CLinkedList *src) {
    if (src == NULL) return -1;
    *dest = c_linked_list_new();
    (*dest)->header = src->header;
    (*dest)->footer = src->footer;
    (*dest)->len = src->len;

    src->header = src->footer = NULL;
    src->len = 0;

    return 0;
}