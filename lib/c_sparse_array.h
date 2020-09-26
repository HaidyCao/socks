//
// Created by haidy on 2020/7/19.
//

#ifndef SOCKS_C_SPARSE_ARRAY_H
#define SOCKS_C_SPARSE_ARRAY_H

#include <stdint.h>

typedef struct c_sparse_array CSparseArray;

typedef void (*c_sparse_array_value_free_cb)(void *);

typedef void (*c_sparse_array_remove_before_cb)(int64_t key, void *v, void *arg);

CSparseArray *CSparseArray_new();

void CSparseArray_free(CSparseArray *array, c_sparse_array_value_free_cb cb);

void *CSparseArray_put(CSparseArray *array, int64_t key, void *v);

void *CSparseArray_get(CSparseArray *array, int64_t key);

void *CSparseArray_remove(CSparseArray *array, int64_t key);

void *CSparseArray_remove_last(CSparseArray *array, int64_t *key);

uint64_t
CSparseArray_remove_before_key(CSparseArray *array, int64_t key, c_sparse_array_remove_before_cb cb, void *arg);

int CSparseArray_get_by_index(CSparseArray *array, uint64_t index, int64_t *key, void **value);

uint64_t CSparseArray_length(CSparseArray *array);

int CSparseArray_clear(CSparseArray *array, c_sparse_array_value_free_cb cb);

#define CSparseArray_FOR(array, key, value, block)                                      \
for (uint64_t i___LINE__ = 0; i___LINE__ < CSparseArray_length(array); i___LINE__++) {  \
    int64_t key;                                                                        \
    void *value = NULL;                                                                 \
    if (CSparseArray_get_by_index(array, i___LINE__, &key, &value) != -1) {             \
        block                                                                           \
    }                                                                                   \
}

#endif //SOCKS_C_SPARSE_ARRAY_H
