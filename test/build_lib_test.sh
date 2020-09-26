#! /bin/bash

gcc lib_test.c ../lib/c_array.c ../lib/c_hash_map.c ../multi_socks.c -o test -I../lib -I..
