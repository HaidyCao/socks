//
// Created by Haidy on 2020/8/2.
//

#ifndef SOCKS_C_ARRAY_MAP_H
#define SOCKS_C_ARRAY_MAP_H

#include <stdbool.h>
#include <stdlib.h>

#include "c_hash.h"
#include "c_free.h"

typedef struct c_array_map CArrayMap;

/**
 * new CArrayMap
 * @return
 */
CArrayMap *CArrayMap_new();

/**
 * free CArrayMap
 * @param map
 * @param func
 */
void CArrayMap_free(CArrayMap *map, c_free_func func);

/**
 * map length
 * @param map
 * @return
 */
size_t CArrayMap_length(CArrayMap *map);

/**
 * put data to map
 * @param map
 * @param key
 * @param value
 * @return old value
 */
void *CArrayMap_put(CArrayMap *map, char *key, void *value);

/**
 * remove data by key
 * @param map
 * @param key
 * @return
 */
void *CArrayMap_remove(CArrayMap *map, char *key);

/**
 * get data by key
 * @param map
 * @param key
 * @return
 */
void *CArrayMap_get(CArrayMap *map, char *key);

/**
 * get key and data by index
 * @param map
 * @param index
 * @param key
 * @param value
 * @return
 */
int CArrayMap_get_by_index(CArrayMap *map, size_t index, char **key, void **value);

/**
 * is map contains key
 * @param map
 * @param key
 * @return
 */
bool CArrayMap_contains(CArrayMap *map, char *key);

/**
 * clear map data
 * @param map
 * @param func
 * @return
 */
int CArrayMap_clear(CArrayMap *map, c_free_func func);

#define CArrayMap_FOR(map, key, value, block)                                   \
for (ssize_t i__LINE__ = 0; i__LINE__ < CArrayMap_length(map); i__LINE__++) {   \
    char *key = NULL;                                                           \
    void *value = NULL;                                                         \
    if (CArrayMap_get_by_index(map, i__LINE__, &key, &value) == 0) {            \
        block                                                                   \
    }                                                                           \
}

#endif //SOCKS_C_ARRAY_MAP_H
