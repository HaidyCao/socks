//
// Created by haidy on 2020/7/19.
//
#include <stdlib.h>
#include <sys/types.h>
#include <strings.h>
#include <string.h>

#include "c_sparse_array.h"

#define C_SPARSE_ARRAY_DEFAULT_CAP 8

typedef struct c_sparse_array_node {
    int64_t key;
    void *value;
} Node;

struct c_sparse_array {
    uint64_t cap;
    uint64_t len;
    Node *nodes;
};

CSparseArray *CSparseArray_new() {
    CSparseArray *array = malloc(sizeof(CSparseArray));
    array->cap = C_SPARSE_ARRAY_DEFAULT_CAP;
    array->len = 0;
    array->nodes = malloc(array->cap * sizeof(Node));

    return array;
}

void CSparseArray_free(CSparseArray *array, c_sparse_array_value_free_cb cb) {
    if (array == NULL) return;
    CSparseArray_clear(array, cb);
    free(array->nodes);
    free(array);
}

uint64_t CSparseArray_length(CSparseArray *array) {
    if (array == NULL) return 0;
    return array->len;
}

int CSparseArray_clear(CSparseArray *array, c_sparse_array_value_free_cb cb) {
    if (array == NULL) return -1;

    if (cb) {
        for (int i = 0; i < array->len; ++i) {
            if (array->nodes[i].value) {
                cb(array->nodes[i].value);
            }
        }
    }
    array->len = 0;
    return 0;
}

static int resize(CSparseArray *array, uint64_t len) {
    if (array->cap >= len) {
        return 0;
    }

    uint64_t new_cap = array->cap;
    while (new_cap < len) {
        new_cap = new_cap + (new_cap >> (uint) 1);
    }
    Node *new_nodes = realloc(array->nodes, new_cap * sizeof(Node));
    if (new_nodes == NULL) {
        new_nodes = malloc(new_cap * sizeof(Node));
        if (new_nodes == NULL) {
            return -1;
        }
        memcpy(new_nodes, array->nodes, array->cap * sizeof(Node));
        free(array->nodes);
    }
    array->nodes = new_nodes;
    array->cap = new_cap;
    return 0;
}

static int64_t find_index(CSparseArray *array, int64_t key) {
    uint64_t len = array->len;
    if (len == 0) {
        return ~(uint64_t) 0;
    }

    int64_t start = 0;
    int64_t end = len - 1;
    int64_t mid = end / 2;

    int64_t mid_key;
    while (start <= end) {
        mid_key = array->nodes[mid].key;
        if (mid_key == key) {
            return mid;
        }

        if (mid_key < key) {
            start = mid + 1;
        } else {
            end = mid - 1;
        }

        mid = (start + end) / 2;
    }

    return ~(uint64_t) start;
}

void *CSparseArray_put(CSparseArray *array, int64_t key, void *v) {
    if (array == NULL) return NULL;

    if (resize(array, array->len + 1) == -1) {
        return NULL;
    }

    int64_t index = find_index(array, key);
    if (index >= 0) {
        void *old = array->nodes[index].value;
        array->nodes[index].value = v;
        return old;
    }

    // insert
    index = ~(uint64_t) index;
    int64_t i;
    for (i = array->len - 1; i >= index; i--) {
        array->nodes[i + 1] = array->nodes[i];
    }

    array->len++;
    array->nodes[index].key = key;
    array->nodes[index].value = v;

    return NULL;
}

void *CSparseArray_get(CSparseArray *array, int64_t key) {
    if (array == NULL || array->len == 0) return NULL;
    int64_t index = find_index(array, key);
    if (index < 0) {
        return NULL;
    }

    return array->nodes[index].value;
}

int CSparseArray_get_by_index(CSparseArray *array, uint64_t index, int64_t *key, void **value) {
    if (array == NULL || index >= array->len) return -1;
    if (key) *key = array->nodes[index].key;
    if (value) *value = array->nodes[index].value;
    return 0;
}

void *CSparseArray_remove(CSparseArray *array, int64_t key) {
    if (array == NULL || array->len == 0) return NULL;
    int64_t index = find_index(array, key);
    if (index < 0) {
        return NULL;
    }

    void *v = array->nodes[index].value;
    for (int i = index; i < array->len - 1; ++i) {
        array->nodes[i] = array->nodes[i + 1];
    }
    array->len--;
    return v;
}

void *CSparseArray_remove_last(CSparseArray *array, int64_t *key) {
    if (array == NULL) return NULL;
    if (array->len == 0) return NULL;

    if (key != NULL) *key = array->nodes[array->len - 1].key;
    void *value = array->nodes[array->len - 1].value;
    array->len--;
    return value;
}

uint64_t
CSparseArray_remove_before_key(CSparseArray *array, int64_t key, c_sparse_array_remove_before_cb cb, void *arg) {
    if (array == NULL || array->len == 0) return 0;

    uint64_t i;
    for (i = 0; i < array->len; ++i) {
        if (array->nodes[i].key > key) {
            break;
        }

        if (cb) cb(array->nodes[i].key, array->nodes[i].value, arg);
    }

    for (int j = i; j < array->len; ++j) {
        array->nodes[j - i] = array->nodes[j];
    }
    array->len -= i;
    return i;
}
