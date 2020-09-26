//
// Created by Haidy on 2020/8/9.
//

#ifndef SOCKS_C_NUMBER_SET_H
#define SOCKS_C_NUMBER_SET_H

#include <stdbool.h>
#include <stdlib.h>

typedef struct c_number_set CNumSet;

CNumSet *CNumSet_new();

void CNumSet_free(CNumSet *set);

size_t CNumSet_length(CNumSet *set);

int CNumSet_put(CNumSet *set, long num);

int CNumSet_get(CNumSet *set, size_t index, long *num);

bool CNumSet_contains(CNumSet *set, long num);

int CNumSet_remove(CNumSet *set, long num);

int CNumSet_clear(CNumSet *set);

#endif //SOCKS_C_NUMBER_SET_H
