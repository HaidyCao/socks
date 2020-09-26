#ifndef C_HASH_MAP_H
#define C_HASH_MAP_H

struct c_node;
typedef struct c_node CNode;

int c_node_get(CNode *node, char **key, void **value);

int c_node_free(CNode *node);

typedef void (*c_hash_map_free_cb)(void *);

#define C_HASH_MAP_FOR(map, task)                     \
    {                                                 \
        if (map)                                      \
        {                                             \
            CNode *node = c_hash_map_get_first(map);  \
            while (node)                              \
            {                                         \
                char *k = NULL;                       \
                void *v = NULL;                       \
                if (c_node_get(node, &k, &v) == -1)   \
                    continue;                         \
                task;                                 \
                free(k);                              \
                node = c_hash_map_get_next(map, node);\
            }                                         \
        }                                             \
    }

struct c_hash_map;
typedef struct c_hash_map CHashMap;

CHashMap *c_hash_map_new();

CHashMap *c_hash_map_new_cap(size_t cap);

int c_hash_map_free(CHashMap *map);

void c_hash_map_set_free_cb(CHashMap *map, c_hash_map_free_cb cb);

int c_hash_map_put(CHashMap *map, char *key, void *value);

int c_hash_map_has(CHashMap *map, char *key);

void *c_hash_map_get(CHashMap *map, char *key);

CNode *c_hash_map_get_first(CHashMap *map);

CNode *c_hash_map_get_next(CHashMap *map, CNode *node);

int c_hash_map_get_count(CHashMap *map);

CNode *c_hash_map_get_node(CHashMap *map, char *key);

void *c_hash_map_remove(CHashMap *map, char *key, int free_value);

void c_hash_map_clear(CHashMap *map);

#endif