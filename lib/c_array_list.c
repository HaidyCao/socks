//
// Created by haidy on 2020/7/11.
//
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "c_array_list.h"

#define C_ARRAY_LIST_DEFAULT_CAP 8

struct c_array_list {
    size_t cap;
    size_t length;
    void **data;
};

CArrayList *CArrayList_new() {
    CArrayList *list = malloc(sizeof(CArrayList));
    list->cap = C_ARRAY_LIST_DEFAULT_CAP;
    list->length = 0;
    list->data = calloc(list->cap, sizeof(void *));
    return list;
}

void CArrayList_free(CArrayList *list, c_array_list_free_cb cb) {
    if (cb) {
        for (int i = 0; i < list->length; ++i) {
            cb(list->data[i]);
        }
    }

    free(list->data);
    free(list);
}

void CArrayList_free_without_data(CArrayList *list) {
    if (list == NULL) return;
    free(list);
}

void **CArrayList_get_array(CArrayList *list) {
    if (list == NULL) return NULL;
    return list->data;
}

size_t c_array_list_length(CArrayList *list) {
    if (list == NULL)
        return 0;

    return list->length;
}

static int resize(CArrayList *list, size_t length) {
    if (list->cap > length) {
        return 0;
    }


    size_t new_cap = list->cap;

    while (new_cap < length) {
        new_cap = new_cap + (new_cap >> (uint) 1);
    }

    void **data = realloc(list->data, new_cap * sizeof(void *));
    if (data == NULL) {
        data = calloc(new_cap, sizeof(void *));
        if (data == NULL) {
            return -1;
        }
        memcpy(data, list->data, list->length * sizeof(void *));
    }
    list->data = data;
    list->cap = new_cap;

    return 0;
}

int c_array_list_add(CArrayList *list, void *data) {
    if (list == NULL) {
        return -1;
    }
    if (resize(list, list->length + 1)) {
        return -1;
    }

    list->data[list->length] = data;
    list->length++;
    return 0;
}

void *CArrayList_remove_last(CArrayList *list) {
    if (list == NULL || list->length == 0) {
        return NULL;
    }

    size_t last_index = list->length - 1;
    void *data = list->data[last_index];
    list->data[last_index] = NULL;
    list->length--;
    return data;
}

void *CArrayList_remove(CArrayList *list, size_t index) {
    if (list == NULL || list->length == 0 || index >= list->length) {
        return NULL;
    }

    if (index == list->length - 1) {
        return CArrayList_remove_last(list);
    }

    void *data = list->data[index];

    // move data to front from index+1
    for (size_t i = index; i < list->length - 1; ++i) {
        list->data[i] = list->data[i + 1];
    }
    list->length--;
    return data;
}

int CArrayList_clear(CArrayList *list, c_array_list_free_cb cb) {
    if (list == NULL) return -1;
    if (list->length == 0) return 0;

    if (cb) {
        for (int i = 0; i < list->length; ++i) {
            cb(list->data[i]);
        }
    }
    list->length = 0;
    return 0;
}

void *c_array_list_get(CArrayList *list, size_t index) {
    if (list == NULL || index > list->length) {
        return NULL;
    }

    return list->data[index];
}

void *CArrayList_last(CArrayList *list) {
    if (list == NULL || list->length == 0) return NULL;
    return list->data[list->length - 1];
}

int CArrayList_merge(CArrayList *dest, CArrayList *src) {
    if (dest == NULL) return -1;
    if (src == NULL || src->length == 0) return 0;

    for (int i = 0; i < src->length; ++i) {
        c_array_list_add(dest, src->data[i]);
    }
    src->length = 0;
    return 0;
}