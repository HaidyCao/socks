//
// Created by Haidy on 2020/4/28.
//

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <string.h>
#include "lib_test.h"
#include "clib.h"
#include "c_hex_utils.h"
#include "c_array_list.h"
#include "c_sparse_array.h"
#include "../log.h"
#include "c_hash_set.h"
#include "c_array_map.h"
#include "c_number_set.h"

void test_c_array_list() {
    char *a = "123";
    char *b = "456";
    CArrayList *list = CArrayList_new();
    c_array_list_add(list, a);
    c_array_list_add(list, b);

    for (int i = 0; i < 15; ++i) {
        c_array_list_add(list, i);
    }

    printf("%zu\n", CArrayList_length(list));

    CArrayList_FOR(list, {
        printf("%p\n", data);
    })

    char *aa = CArrayList_remove_last(list);

    CArrayList_free(list, NULL);
}

static void c_sparse_array_remove(int64_t key, void *v, void *arg) {
    printf("remove key = %jd v = %d\n", key, (int) v);
}

static
void test_c_sparse_array() {
    printf("\n%s\n", __FUNCTION__);

    CSparseArray *array = CSparseArray_new();
    CSparseArray_put(array, 1, "1");
    CSparseArray_put(array, 2, "2");
    CSparseArray_put(array, -1, "-1");

    printf("length %ju\n", CSparseArray_length(array));

    printf("get %s\n", CSparseArray_get(array, 1));
    printf("get %s\n", CSparseArray_get(array, 2));
    printf("get %s\n", CSparseArray_get(array, -1));

    for (int i = 0; i < 100; ++i) {
        CSparseArray_put(array, i, i);
    }

    printf("remove %d\n", CSparseArray_remove(array, 1));
    printf("remove %d\n", CSparseArray_remove(array, 2));
    printf("remove %s\n", CSparseArray_remove(array, -1));
    printf("length %llu\n", CSparseArray_length(array));

    printf("%zu\n", (size_t) 1);

    printf("remove length = %llu\n", CSparseArray_remove_before_key(array, 50, c_sparse_array_remove, NULL));

    CSparseArray_FOR(array, key, value, {
        printf("key = %jd, value = %d\n", key, value);
    })

    CSparseArray_free(array, NULL);
}

static void test_c_hash_set() {
    CHashSet *set = CHashSet_new();

    CHashSet_add(set, strdup("Hello"));
    CHashSet_add(set, strdup("World"));

    LOGD("set len = %zu", CHashSet_length(set));
    LOGD("set contains \"Hello\" = %d", CHashSet_contains(set, "Hello"));
    LOGD("set contains \"World\" = %d", CHashSet_contains(set, "World"));
    LOGD("set contains \"Hello1\" = %d", CHashSet_contains(set, "Hello1"));
    CHashSet_remove(set, "Hello");
    LOGD("set contains \"Hello\" = %d", CHashSet_contains(set, "Hello"));

    char buffer[] = {'H', 'e', 'l', 'l', 'o', '\0', '\0'};
    for (int i = 0; i < 10; ++i) {
        buffer[5] = '0' + i;
        CHashSet_add(set, strdup(buffer));
    }

    LOGD("set len = %zu", CHashSet_length(set));
    LOGD("set contains \"Hello1\" = %d", CHashSet_contains(set, "Hello1"));

    CHashSet_FOR(set, v, {
        LOGD("%s", v);
    })

    CHashSet_free(set);
}

static void test_array_map() {
    CArrayMap *map = CArrayMap_new();
    CArrayMap_put(map, "1", strdup("Hello"));

    char key[] = {'\0', '\0'};
    char buffer[] = {'H', 'e', 'l', 'l', 'o', '\0', '\0'};
    for (int i = 0; i < 10; ++i) {
        buffer[5] = '0' + i;
        key[0] = '0' + i;
        CArrayMap_put(map, key, strdup(buffer));
    }

    CArrayMap_FOR(map, k, v, {
        LOGD("key = %s, value = %s", k, v);
    })

    for (int i = 0; i < 10; ++i) {
        key[0] = '0' + i * 2;
        CArrayMap_remove(map, key);
    }

    CArrayMap_FOR(map, k, v, {
        LOGD("---- key = %s, value = %s", k, v);
    })

    LOGD("contains 1 = %d", CArrayMap_contains(map, "1"));

    CArrayMap_clear(map, free);

    CArrayMap_free(map, free);
}

static void test_number_set() {
    CNumSet *set = CNumSet_new();

    CNumSet_put(set, 1);
    CNumSet_put(set, 2);

    LOGD("len = %zu", CNumSet_length(set));

    LOGD("contains 1 = %d", CNumSet_contains(set, 1));

    CNumSet_clear(set);

    LOGD("len = %zu", CNumSet_length(set));

    CNumSet_free(set);
}

int main() {
//    test_c_array_list();
//    test_c_sparse_array();

//    test_c_hash_set();
//    test_array_map();
    test_number_set();

    return 0;
}