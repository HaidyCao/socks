//
// Created by Haidy on 2020/8/1.
//
#include <stddef.h>
#include <string.h>
#include <stdint.h>

#include "c_hash_set.h"

#define C_HASH_SET_DEFAULT_SIZE 8

typedef struct node Node;

struct node {
    char *key;
    Node *next;
    size_t index;

    size_t cap;
};

static inline Node *Node_new(char *data) {
    Node *n = malloc(sizeof(Node));
    n->key = strdup(data);
    n->next = NULL;
    n->cap = 0;

    return n;
}

struct c_hash_set {
    size_t cap;
    size_t len;
    float resize_ratio;

    Node **data;
    c_hash_func hash;
};

CHashSet *CHashSet_new_with_size(size_t cap) {
    if (cap > C_HASH_SET_DEFAULT_SIZE) {
        cap = c_hash_cap(cap);
    } else if (cap < C_HASH_SET_DEFAULT_SIZE) {
        cap = C_HASH_SET_DEFAULT_SIZE;
    }

    CHashSet *set = calloc(1, sizeof(CHashSet));
    set->cap = cap;
    set->data = calloc(set->cap, sizeof(Node *));
    set->resize_ratio = 0.75f;
    return set;
}

CHashSet *CHashSet_new() {
    return CHashSet_new_with_size(C_HASH_SET_DEFAULT_SIZE);
}

void CHashSet_free(CHashSet *set) {
    if (set == NULL || set->len == 0) return;

    size_t free_len = 0;
    for (int i = 0; i < set->cap; ++i) {
        Node *v = set->data[i];
        while (v) {
            Node *next = v->next;
            free(v->key);

            free_len++;
            v = next;
        }
    }
    free(set->data);
    free(set);
}

size_t CHashSet_length(CHashSet *set) {
    if (set == NULL) return 0;
    return set->len;
}

static int hash(CHashSet *set, char *data) {
    if (set->hash) {
        return set->hash(data);
    }

    return c_hash(data);
}

static size_t data_index(CHashSet *set, char *data) {
    return (size_t) hash(set, data) & (set->cap - 1);
}

static bool data_equals(char *v1, char *v2) {
    if (v1 == NULL && v2 == NULL) return true;

    if (v1 != NULL && v2 != NULL) {
        return strcmp(v1, v2) == 0;
    }

    return false;
}

static bool CHashSet_add_internal(Node **nodes, int index, Node *n);

static bool resize(CHashSet *set, size_t len) {
    if (len < set->len) return true;
    if (len < set->cap * set->resize_ratio) return true;

    size_t old_cap = set->cap;
    size_t new_cap = old_cap << (uint8_t) 1;
    Node **new_data = realloc(set->data, new_cap * sizeof(Node *));
    if (new_data == NULL) {
        new_data = calloc(new_cap, sizeof(Node *));
        if (new_data == NULL) {
            return false;
        }
        memcpy(new_data, set->data, old_cap * sizeof(Node *));
        free(set->data);
    } else {
        for (size_t i = old_cap; i < new_cap; ++i) {
            new_data[i] = NULL;
        }
    }
    set->data = new_data;
    set->cap = new_cap;

    for (size_t i = 0; i < old_cap; ++i) {
        Node *head = set->data[i];
        Node *pre_node = NULL;
        Node *node = head;

        while (node) {
            Node *next = node->next;
            if (node->cap != set->cap) {
                size_t new_index = data_index(set, node->key);
                if (i != new_index) {
                    // remove from nodes
                    Node *m_node = node;
                    if (node == head) {
                        head = set->data[i] = next;
                    } else {
                        pre_node->next = next;
                    }

                    // add to new_index
                    m_node->next = NULL;
                    m_node->cap = new_cap;
                    if (!CHashSet_add_internal(set->data, new_index, m_node)) {
                        free(m_node->key);
                        free(m_node);
                    }

                    continue;
                } else {
                    node->cap = new_cap;
                }
            }
            pre_node = node;
            node = next;
        }
    }

    return true;
}

static bool CHashSet_add_internal(Node **nodes, int index, Node *n) {
    Node *node = nodes[index];

    while (node) {
        if (node->next == NULL) {
            node->next = n;
            return true;
        }

        if (data_equals(node->key, n->key)) {
            return false;
        }

        node = node->next;
    }

    nodes[index] = n;
    return true;
}

int CHashSet_add(CHashSet *set, char *data) {
    if (set == NULL) return -1;

    if (!resize(set, set->len + 1)) {
        return -1;
    }

    size_t index = data_index(set, data);
    Node *n = Node_new(data);
    if (CHashSet_add_internal(set->data, index, Node_new(data))) {
        set->len++;
    } else {
        free(n->key);
        free(n);
    }
    return 0;
}

bool CHashSet_contains(CHashSet *set, char *data) {
    if (set == NULL) return false;

    size_t index = data_index(set, data);
    Node *node = set->data[index];

    while (node) {
        if (data_equals(node->key, data)) {
            return true;
        }
        node = node->next;
    }

    return false;
}

int CHashSet_remove(CHashSet *set, char *data) {
    if (set == NULL) return -1;

    size_t index = data_index(set, data);
    Node *node = set->data[index];

    if (node == NULL) return -1;

    if (data_equals(node->key, data)) {
        set->data[index] = node->next;
        free(node->key);
        free(node);
        set->len--;
        return 0;
    }

    while (node->next) {
        if (data_equals(node->next->key, data)) {
            Node *new_next = node->next->next;

            Node *r_node = node->next;
            free(r_node->key);
            free(r_node);

            node->next = new_next;
            set->len--;
            return 0;
        }

        node = node->next;
    }

    return -1;
}

int CHashSet_clear(CHashSet *set) {
    if (set == NULL) return -1;

    size_t free_len = 0;
    for (int i = 0; i < set->cap; ++i) {
        Node *v = set->data[i];
        while (v) {
            Node *next = v->next;
            free(v->key);

            free_len++;
            v = next;
        }
        set->data[i] = NULL;
    }
    set->len = 0;

    return 0;
}

void *CHashSet_iterator(CHashSet *set) {
    if (set == NULL || set->len == 0) return NULL;

    for (size_t i = 0; i < set->cap; ++i) {
        Node *node = set->data[i];
        if (node) {
            node->index = i;
            return node;
        }
    }
    return NULL;
}

void *CHashSet_iterator_next(CHashSet *set, void *it) {
    if (set == NULL || set->len == 0 || it == NULL) return NULL;

    Node *from = it;

    if (from->next) {
        Node *node = from->next;
        node->index = from->index;
        return node;
    }

    for (size_t i = from->index + 1; i < set->cap; ++i) {
        Node *node = set->data[i];
        if (node) {
            node->index = i;
            return node;
        }
    }
    return NULL;
}

char *CHashSet_iterator_get(void *it) {
    Node *node = it;
    return node->key;
}