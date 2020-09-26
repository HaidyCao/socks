#! /bin/bash

OS=`uname | tr 'A-Z' 'a-z'`

export LD_LIBRARY_PATH=`pwd`/../../dependencies/${OS}/lib
# ./server 0.0.0.0 1080 -s key.key cert.pem
# ./server 0.0.0.0 1080 -u caohaidi -p adg931010
lldb --  ./socks 0.0.0.0 1080 -u caohaidi -p mn931010 -mh 47.240.65.204 -mp 995 -m