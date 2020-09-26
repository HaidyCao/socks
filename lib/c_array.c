#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "c_array.h"

int array_init(Array *array) {
    bzero(array, sizeof(Array));
    if (array == NULL) {
        return -1;
    }

    if (array->cap <= 0) {
        array->cap = 8;
    }
    array->array = (void **) malloc(array->cap);
    array->len = 0;

    return 0;
}

void array_free(Array *array) {
    size_t i;
    for (i = 0; i < array->len; i++) {
        void *v = array->array[i];
        if (array->free_cb)
            array->free_cb(v);
    }
    free(array->array);
    array->array = NULL;
}

#define UPDATE_ARRAY_CAP(array)                      \
    {                                                \
        if (array->len == array->cap)                \
        {                                            \
            void **a = array->array;                 \
            int new_cap = array->cap < 2;            \
            array->array = (void **)malloc(new_cap); \
            memcpy(array->array, a, array->len);     \
            array->array = a;                        \
            free(a);                                 \
        }                                            \
    }

int array_add(Array *array, void *value) {
    UPDATE_ARRAY_CAP(array);

    int index = array->len;
    array->array[index] = value;
    array->len++;
    return index;
}

int array_insert(Array *array, int index, void *value) {
    UPDATE_ARRAY_CAP(array);

    if (index > array->len) {
        index = array->len;
    }

    if (index < 0)
        return -1;

    if (index == array->len) {
        return array_add(array, value);
    }

    void **insert_index = array->array + index;
    memcpy(insert_index + 1, insert_index, array->len - index);
    insert_index[0] = value;
    array->len++;
    return index;
}

int array_remove(Array *array, int index) {
    if (index < 0 || index >= array->len)
        return -1;

    void *v = array->array[index];
    if (array->free_cb != NULL)
        array->free_cb(v);

    if (array->len == 1) {
        array->array[0] = NULL;
        array->len--;
        return 0;
    }

    void **p = array->array + index;
    memcpy(p, p + 1, array->len - index - 1);
    array->len--;
    return 0;
}

void *array_get_first(Array *array) {
    return array_get(array, 0);
}

void *array_get(Array *array, int index) {
    if (index < 0 || index >= array->len) {
        return NULL;
    }

    return array->array[index];
}

int array_clear(Array *array) {
    size_t i;
    for (i = 0; i < array->len; i++) {
        void *v = array->array[i];
        if (array->free_cb != NULL)
            array->free_cb(v);

        array->array[i] = NULL;
    }

    array->len = 0;
    return 0;
}

int array_remove_by_value(Array *array, void *value) {
    if (value == NULL) {
        return -1;
    }

    int index = -1;
    size_t i;
    for (i = 0; i < array->len; i++) {
        if (array->array[i] == value) {
            index = i;
            break;
        }
    }

    if (index != -1)
        array_remove(array, index);

    return 0;
}