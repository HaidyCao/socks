#! /bin/bash
OS=$(uname | tr 'A-Z' 'a-z')
gcc cares_test.c -o test -I../lib -I.. -L../dependencies/${OS}/lib -I../dependencies/${OS}/include -lcares
