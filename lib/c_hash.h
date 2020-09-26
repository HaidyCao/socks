//
// Created by Haidy on 2020/8/1.
//

#ifndef SOCKS_C_HASH_H
#define SOCKS_C_HASH_H

typedef int (*c_hash_func)(char *);

int c_hash(char *str);

unsigned int c_hash_cap(unsigned int old);

#endif //SOCKS_C_HASH_H
