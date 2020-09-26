//
// Created by Haidy on 2020/8/2.
//
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "c_array_map.h"

#define C_ARRAY_MAP_DEFAULT_CAP 8

typedef struct {
    char *key;
    void *value;
} Node;

struct c_array_map {
    size_t cap;
    size_t len;

    Node *nodes;
    int *hash_array;
    c_hash_func hash;
};

CArrayMap *CArrayMap_new() {
    CArrayMap *map = calloc(1, sizeof(CArrayMap));
    map->cap = C_ARRAY_MAP_DEFAULT_CAP;
    map->nodes = malloc(map->cap * sizeof(Node));
    map->hash_array = malloc(map->cap * sizeof(int));
    return map;
}

void CArrayMap_free(CArrayMap *map, c_free_func func) {
    if (map == NULL) return;
    CArrayMap_clear(map, func);

    free(map->nodes);
    free(map->hash_array);
    free(map);
}

size_t CArrayMap_length(CArrayMap *map) {
    if (map == NULL) return 0;
    return map->len;
}

static bool resize(CArrayMap *map, size_t len) {
    if (len < map->cap) return true;

    size_t new_cap = map->cap;
    do {
        new_cap = new_cap + (new_cap >> (uint8_t) 1);
    } while (new_cap < len);

    Node *new_nodes = realloc(map->nodes, new_cap * sizeof(Node));
    if (new_nodes == NULL) {
        return false;
    }

    int *new_hash_array = realloc(map->hash_array, new_cap * sizeof(int));
    if (new_hash_array == NULL) {
        return false;
    }

    map->cap = new_cap;
    map->nodes = new_nodes;
    map->hash_array = new_hash_array;

    return true;
}

static int CArrayMap_hash(CArrayMap *map, char *key) {
    if (map->hash) return map->hash(key);
    return c_hash(key);
}

static ssize_t key_index(CArrayMap *map, char *key, int hash) {
    ssize_t index = 0;
    if (key == NULL || map->len == 0) return ~(size_t) index;

    ssize_t start = 0;
    ssize_t end = map->len - 1;
    ssize_t mid = end / 2;

    int mid_key;
    while (start <= end) {
        mid_key = map->hash_array[mid];
        if (mid_key == hash) {
            if (strcmp(map->nodes[mid].key, key) == 0) {
                return mid;
            }

            ssize_t i = mid - 1;
            while (i >= 0 && map->hash_array[i] == hash) {
                if (strcmp(map->nodes[i].key, key) == 0) {
                    return i;
                }

                i--;
            }

            i = mid + 1;
            while (i < map->len && map->hash_array[i] == hash) {
                if (strcmp(map->nodes[i].key, key) == 0) {
                    return i;
                }

                i++;
            }
            return ~(size_t) i;
        }

        if (mid_key < hash) {
            start = mid + 1;
        } else {
            end = mid - 1;
        }

        mid = (start + end) / 2;
    }

    return ~(size_t) start;
}

void *CArrayMap_put(CArrayMap *map, char *key, void *value) {
    if (map == NULL) return NULL;

    // index
    int hash = CArrayMap_hash(map, key);
    ssize_t index = key_index(map, key, hash);
    if (index >= 0) {
        void *old = map->nodes[index].value;
        map->nodes[index].value = value;
        return old;
    }
    resize(map, map->len + 1);

    index = ~(size_t) index;

    // move data to next from index
    for (ssize_t i = index; i < map->len; ++i) {
        map->nodes[i + 1] = map->nodes[i];
        map->hash_array[i + 1] = map->hash_array[i];
    }

    map->nodes[index].key = strdup(key);
    map->nodes[index].value = value;
    map->hash_array[index] = hash;
    map->len++;

    return NULL;
}

void *CArrayMap_remove(CArrayMap *map, char *key) {
    if (map == NULL) return NULL;

    int hash = CArrayMap_hash(map, key);
    ssize_t index = key_index(map, key, hash);
    if (index < 0) {
        return NULL;
    }

    void *value = map->nodes[index].value;
    for (ssize_t i = index; i < map->len; ++i) {
        map->nodes[i] = map->nodes[i + 1];
    }
    map->len--;
    return value;
}

void *CArrayMap_get(CArrayMap *map, char *key) {
    if (map == NULL) return NULL;

    int hash = CArrayMap_hash(map, key);
    ssize_t index = key_index(map, key, hash);
    if (index >= 0)
        return map->nodes[index].value;
    else
        return NULL;
}

int CArrayMap_get_by_index(CArrayMap *map, size_t index, char **key, void **value) {
    if (map == NULL || map->len == 0) return -1;
    if (index >= map->len) return -1;

    Node *node = &map->nodes[index];
    *key = node->key;
    *value = node->value;
    return 0;
}

bool CArrayMap_contains(CArrayMap *map, char *key) {
    if (map == NULL) return NULL;

    int hash = CArrayMap_hash(map, key);
    ssize_t index = key_index(map, key, hash);
    return index >= 0;
}

int CArrayMap_clear(CArrayMap *map, c_free_func func) {
    if (map == NULL) return -1;
    for (size_t i = 0; i < map->len; ++i) {
        Node *node = &map->nodes[i];
        free(node->key);
        if (func) func(node->value);
    }
    map->len = 0;
    return 0;
}