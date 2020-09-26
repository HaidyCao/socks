#! /bin/sh

OS=`uname | tr 'A-Z' 'a-z'`

gcc ${1} -o ${1%%.*} -I`pwd`/../dependencies/${OS}/include -L`pwd`/../dependencies/${OS}/lib -levent -O0 -DCLIB_LOG

