#! /bin/bash

OS=`uname | tr 'A-Z' 'a-z'`

if [[ ! -d kcp-1.7 ]]; then
    tar -zxf kcp-1.7.tar.gz
fi

cd kcp-1.7

if [ ! -d build ]; then
    mkdir build
fi

cd build

cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=`pwd`/../../${OS}/ ..

make
make install