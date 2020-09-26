#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "c_hash.h"
#include "c_hash_map.h"

#define C_HASH_MAP_DEFAULT_CAP 8

struct c_node {
    char *key;
    void *value;
#ifdef C_HASH_MAP_SAVE_HASH_CODE
    int hash_code;
#endif

    struct c_node *next;
};

struct c_hash_map {
    size_t cap;
    size_t count;
    float resize_ratio;
    c_hash_map_free_cb free_cb;
    CNode **nodes;
};

int c_node_free(CNode *node) {
    if (node == NULL)
        return -1;

    free(node->key);
    free(node);
    return 0;
}

int c_node_get(CNode *node, char **key, void **value) {
    if (node == NULL)
        return -1;

    *key = strdup(node->key);
    *value = node->value;
    return 0;
}

static int c_hash_map_hash_code(CHashMap *map, char *key) {
    return c_hash(key);
}

CHashMap *c_hash_map_new_cap(size_t cap) {
    if (cap > C_HASH_MAP_DEFAULT_CAP) {
        cap = c_hash_cap(cap);
    } else if (cap < C_HASH_MAP_DEFAULT_CAP) {
        cap = C_HASH_MAP_DEFAULT_CAP;
    }

    CHashMap *map = (CHashMap *) calloc(1, sizeof(CHashMap));
    map->cap = cap;
    map->count = 0;

    map->nodes = (CNode **) calloc(map->cap, sizeof(CNode));
    map->free_cb = NULL;
    map->resize_ratio = 0.75f;

    return map;
}

CHashMap *c_hash_map_new() {
    return c_hash_map_new_cap(C_HASH_MAP_DEFAULT_CAP);
}

void c_hash_map_set_free_cb(CHashMap *map, c_hash_map_free_cb cb) {
    if (map == NULL)
        return;
    map->free_cb = cb;
}

static int c_hash_map_init(CHashMap *map) {
    if (map == NULL)
        return -1;
    bzero(map, sizeof(CHashMap));
    map->cap = 8;
    map->count = 0;

    size_t nodes_size = map->cap * sizeof(CNode);
    map->nodes = (CNode **) malloc(nodes_size);
    bzero(map->nodes, nodes_size);
    map->resize_ratio = 0.75f;
    return 0;
}

int c_hash_map_free(CHashMap *map) {
    if (map == NULL)
        return -1;

    int i;
    for (i = 0; i < map->cap; i++) {
        CNode *node = map->nodes[i];
        while (node != NULL) {
            CNode *next = node->next;
            if (map->free_cb != NULL)
                map->free_cb(node->value);

            c_node_free(node);
            node = next;
        }
    }
    free(map->nodes);
    return 0;
}

static void c_node_put_node_to_end(CHashMap *map, CNode *node, CNode *new_node, int replace) {
    CNode *p_node = NULL;
    while (node != NULL) {
        if (replace && p_node != NULL && strcmp(node->key, new_node->key) == 0) {
            p_node->next = new_node;
            new_node->next = node->next;
            if (map->free_cb != NULL)
                map->free_cb(node->value);
            c_node_free(node);
            return;
        }
        if (node->next == NULL) {
            node->next = new_node;
            break;
        }

        p_node = node;
        node = node->next;
    }
}

void c_hash_map_resize(CHashMap *map, size_t target_count) {
    if (map->cap * map->resize_ratio > target_count) {
        return;
    }

    if (map->count == 0) {
        return;
    }

    // relocation nodes
    int new_cap = map->cap << (uint8_t) 1;
    CNode **new_nodes = (CNode **) malloc(new_cap * sizeof(CNode));
    bzero(new_nodes, new_cap * sizeof(CNode));

    int i;
    for (i = 0; i < map->cap; i++) {
        CNode *node = map->nodes[i];
        while (node != NULL) {
            CNode *next = node->next;

#ifdef C_HASH_MAP_SAVE_HASH_CODE
            int hash_code = node->hash_code;
#else
            int hash_code = c_hash_map_hash_code(map, node->key);
#endif
            size_t index;
            index = ((uint32_t) hash_code & (uint32_t) new_cap) ? (uint32_t) hash_code & (uint32_t) (new_cap - 1) : i;

            if (new_nodes[index])
                c_node_put_node_to_end(map, new_nodes[index], node, 0);
            else
                new_nodes[index] = node;

            node->next = NULL;
            node = next;
        }
    }
    free(map->nodes);
    map->nodes = new_nodes;
    map->cap = new_cap;
}

int c_hash_map_put(CHashMap *map, char *key, void *value) {
    if (map == NULL || key == NULL)
        return -1;

    c_hash_map_resize(map, map->count + 1);

    char *key_cpy = strdup(key);
    size_t index = (size_t) c_hash_map_hash_code(map, key_cpy) & (map->cap - 1);
    CNode *node = (CNode *) malloc(sizeof(CNode));
    bzero(node, sizeof(CNode));

    node->key = key_cpy;
    node->value = value;
    node->next = NULL;

    if (map->nodes[index] != NULL) {
        CNode *header = map->nodes[index];
        if (strcmp(header->key, key_cpy) == 0) {
            map->nodes[index] = node;
            node->next = header->next;
            if (map->free_cb)
                map->free_cb(header->value);
            c_node_free(header);
        } else
            c_node_put_node_to_end(map, map->nodes[index], node, 1);
    } else {
        map->nodes[index] = node;
    }
    map->count++;
    return 0;
}

int c_hash_map_has(CHashMap *map, char *key) {
    return c_hash_map_get(map, key) != NULL;
}

CNode *c_hash_map_get_node(CHashMap *map, char *key) {
    if (map == NULL || key == NULL)
        return NULL;

    size_t index = (size_t) c_hash_map_hash_code(map, key) & (map->cap - 1);
    CNode *node = map->nodes[index];
    while (node != NULL) {
        if (strcmp(node->key, key) == 0) {
            return node;
        }
        node = node->next;
    }

    return NULL;
}

void *c_hash_map_get(CHashMap *map, char *key) {
    CNode *n = c_hash_map_get_node(map, key);
    if (n)
        return n->value;

    return NULL;
}

CNode *c_hash_map_get_first(CHashMap *map) {
    if (map == NULL || map->count == 0)
        return NULL;

    size_t i;
    for (i = 0; i < map->cap; i++) {
        CNode *node = map->nodes[i];
        if (node)
            return node;
    }

    return NULL;
}

CNode *c_hash_map_get_next(CHashMap *map, CNode *node) {
    if (map == NULL || map->count == 0 || node == NULL)
        return NULL;

    if (node->next != NULL)
        return node->next;
    size_t index = (size_t) c_hash_map_hash_code(map, node->key) & (map->cap - 1);
    size_t i;
    for (i = index + 1; i < map->cap; i++) {
        CNode *n = map->nodes[i];
        if (n)
            return n;
    }

    return NULL;
}

int c_hash_map_get_count(CHashMap *map) {
    if (map == NULL)
        return -1;

    return map->count;
}

void *c_hash_map_remove(CHashMap *map, char *key, int free_value) {
    if (map == NULL || key == NULL)
        return NULL;

    size_t index = (size_t) c_hash_map_hash_code(map, key) & (map->cap - 1);
    CNode *node = map->nodes[index];
    CNode *p_node = NULL;
    while (node != NULL) {
        if (strcmp(node->key, key) == 0) {
            if (p_node != NULL)
                p_node->next = node->next;
            else
                map->nodes[index] = node->next;

            void *v = node->value;
            map->count--;
            c_node_free(node);
            if (free_value && map->free_cb != NULL) {
                map->free_cb(v);
                return NULL;
            }
            return v;
        }
        p_node = node;
        node = node->next;
    }

    return NULL;
}

void c_hash_map_clear(CHashMap *map) {
    c_hash_map_free(map);
    c_hash_map_init(map);
}