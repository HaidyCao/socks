//
// Created by Haidy on 2020/8/1.
//

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "c_hash.h"

#define C_HASH_MAGIC_CODE 1103515245
#define MAX_HASH_CAP 4294967295

int c_hash(char *str) {
    if (str == NULL) return 0;

    size_t hash, i;
    size_t len;
    if (str == NULL)
        return -1;

    len = strlen(str);
    hash = (int) str[0];
    for (i = 1; i < len; ++i) {
        hash *= C_HASH_MAGIC_CODE + (int) str[i];
    }
    hash >>= (unsigned int) 27;
    return hash;
}

unsigned int c_hash_cap(unsigned int old) {
    unsigned int n = old - 1;
    n |= n >> (uint8_t) 1;
    n |= n >> (uint8_t) 2;
    n |= n >> (uint8_t) 4;
    n |= n >> (uint8_t) 8;
    n |= n >> (uint8_t) 16;
    return n > MAX_HASH_CAP ? MAX_HASH_CAP : (n + 1);
}