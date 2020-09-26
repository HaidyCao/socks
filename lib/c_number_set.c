//
// Created by Haidy on 2020/8/9.
//
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

#include "c_number_set.h"

#define C_NUM_DEFAULT_CAP 8

struct c_number_set {
    size_t len;
    size_t cap;

    long *data;
};

CNumSet *CNumSet_new() {
    CNumSet *set = calloc(1, sizeof(CNumSet));
    set->cap = C_NUM_DEFAULT_CAP;
    set->data = malloc(set->cap * sizeof(long));
    return set;
}

void CNumSet_free(CNumSet *set) {
    if (set == NULL) return;

    free(set->data);
    free(set);
}

size_t CNumSet_length(CNumSet *set) {
    if (set == NULL) return 0;
    return set->len;
}

static bool resize(CNumSet *set, size_t len) {
    if (set->cap > len) return true;

    size_t new_cap = set->cap + (set->cap >> (uint8_t) 1);
    long *new_data = realloc(set->data, new_cap * sizeof(long));
    if (new_data == NULL) return false;

    set->data = new_data;
    set->cap = new_cap;
    return set;
}

static ssize_t number_index(CNumSet *set, long num) {
    uint64_t len = set->len;
    if (len == 0) {
        return ~(size_t) 0;
    }

    int64_t start = 0;
    int64_t end = len - 1;
    int64_t mid = end / 2;

    int64_t mid_key;
    while (start <= end) {
        mid_key = set->data[mid];
        if (mid_key == num) {
            return mid;
        }

        if (mid_key < num) {
            start = mid + 1;
        } else {
            end = mid - 1;
        }

        mid = (start + end) / 2;
    }

    return ~(uint64_t) start;
}

int CNumSet_put(CNumSet *set, long num) {
    if (set == NULL) return -1;
    resize(set, set->len + 1);

    ssize_t index = number_index(set, num);
    if (index >= 0) {
        return 0;
    }
    index = ~(size_t) index;

    for (ssize_t i = index; i < set->cap; ++i) {
        set->data[i + 1] = set->data[i];
    }
    set->data[index] = num;
    set->len++;

    return 0;
}

int CNumSet_get(CNumSet *set, size_t index, long *num) {
    if (set == 0 || index >= set->len) return -1;
    if (num != NULL) *num = set->data[index];
    return 0;
}

bool CNumSet_contains(CNumSet *set, long num) {
    if (set == NULL || set->len == 0) return false;

    ssize_t index = number_index(set, num);
    return index >= 0;
}

int CNumSet_remove(CNumSet *set, long num) {
    if (set == NULL || set->len == 0) return -1;

    ssize_t index = number_index(set, num);
    if (index < 0) return -1;

    index = ~(size_t) index;
    for (ssize_t i = index; i < set->cap; ++i) {
        set->data[i] = set->data[i + 1];
    }
    set->len--;

    return 0;
}

int CNumSet_clear(CNumSet *set) {
    if (set == NULL) return -1;
    set->len = 0;
    return 0;
}