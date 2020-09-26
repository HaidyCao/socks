#! /bin/bash

OS=$(uname | tr 'A-Z' 'a-z')

export LD_LIBRARY_PATH=$(pwd)/dependencies/${OS}/lib
# ./server 0.0.0.0 1080 -s key.key cert.pem
# ./server 0.0.0.0 1080 -u caohaidi -p adg931010
./mss 0.0.0.0 995 -u caohaidi -p mn931010
