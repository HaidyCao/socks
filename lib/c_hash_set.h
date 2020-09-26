//
// Created by Haidy on 2020/8/1.
//

#ifndef SOCKS_C_HASH_SET_H
#define SOCKS_C_HASH_SET_H

#include <stdbool.h>
#include <stdlib.h>

#include "c_hash.h"
#include "c_free.h"

typedef struct c_hash_set CHashSet;

CHashSet *CHashSet_new();

CHashSet *CHashSet_new_with_size(size_t cap);

void CHashSet_free(CHashSet *set);

size_t CHashSet_length(CHashSet *set);

int CHashSet_add(CHashSet *set, char *data);

bool CHashSet_contains(CHashSet *set, char *data);

int CHashSet_remove(CHashSet *set, char *data);

int CHashSet_clear(CHashSet *set);

void *CHashSet_iterator(CHashSet *set);

void *CHashSet_iterator_next(CHashSet *set, void *it);

char *CHashSet_iterator_get(void *it);

#define CHashSet_FOR(set, v, block)                         \
void *it__LINE__ = CHashSet_iterator(set);                  \
while (it__LINE__) {                                        \
    char *v = CHashSet_iterator_get(it__LINE__);            \
    block                                                   \
    it__LINE__ = CHashSet_iterator_next(set, it__LINE__);   \
}

#endif //SOCKS_C_HASH_SET_H
