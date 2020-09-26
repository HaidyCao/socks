#! /bin/bash

OS=$(uname | tr 'A-Z' 'a-z')

if [[ -d openssl ]]; then
    cd openssl || exit
else
    git clone --branch OpenSSL_1_1_1g https://gitee.com/mirrors/openssl.git
    cd openssl || exit
fi

make distclean

./config no-ui --prefix="$(pwd)"/../"${OS}" --openssldir="$(pwd)"/../"${OS}"

make -j8
make install