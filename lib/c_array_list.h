//
// Created by haidy on 2020/7/11.
//

#ifndef SOCKS_C_ARRAY_LIST_H
#define SOCKS_C_ARRAY_LIST_H

#include <stdio.h>

typedef struct c_array_list CArrayList;

typedef void (*c_array_list_free_cb)(void *);

CArrayList *CArrayList_new();

void CArrayList_free(CArrayList *list, c_array_list_free_cb cb);

/**
 * free CArrayList width out data
 * @param list
 */
void CArrayList_free_without_data(CArrayList *list);

/**
 * get data as array
 * @param list
 * @return array or NULL
 */
void **CArrayList_get_array(CArrayList *list);

size_t c_array_list_length(CArrayList *list);

#define CArrayList_length(list) c_array_list_length(list)

int c_array_list_add(CArrayList *list, void *data);

#define CArrayList_add(list, data) c_array_list_add(list, data)

void *CArrayList_remove_last(CArrayList *list);

void *CArrayList_remove(CArrayList *list, size_t index);

int CArrayList_clear(CArrayList *list, c_array_list_free_cb cb);

void *c_array_list_get(CArrayList *list, size_t index);

void *CArrayList_last(CArrayList *list);

#define CArrayList_get(list, index) c_array_list_get(list, index)

/**
 * merge ArrayList
 * @param dest
 * @param src
 * @return 0 success
 */
int CArrayList_merge(CArrayList *dest, CArrayList *src);

#define CArrayList_FOR(list, block)             \
{                                               \
    size_t len = c_array_list_length(list);     \
    for (int i = 0; i < len; i++) {             \
        void *data = c_array_list_get(list, i); \
        block                                   \
    }                                           \
}

#define CArrayList_FOR1(list, i, item, block)           \
for (int i = 0; i < c_array_list_length(list); i++) {   \
    void *item = c_array_list_get(list, i);             \
    block                                               \
}

#endif //SOCKS_C_ARRAY_LIST_H
