#! /bin/bash

_CMAKE_PATH=${1}
_NDK_PATH=${2}
_PREFIX_DIR=${3}
BUILD_DIR=android_build

for abi in "armeabi-v7a" "arm64-v8a" "x86" "x86_64"; do
  if [ ! -d ${BUILD_DIR} ]; then
    mkdir ${BUILD_DIR}
  fi
  cd ${BUILD_DIR}
  rm -rf ./*

  ${_CMAKE_PATH} -DCMAKE_TOOLCHAIN_FILE=${_NDK_PATH}/build/cmake/android.toolchain.cmake \
    -DANDROID_ABI=${abi} \
    -DANDROID_NATIVE_API_LEVEL=21 \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_INSTALL_PREFIX=${BUILD_DIR} \
    ..
  make

  if [ ! -d ${_PREFIX_DIR}/${abi} ]; then
    mkdir ${_PREFIX_DIR}/${abi}
  fi

  cp -v lib/*.so ${_PREFIX_DIR}/${abi}/
  cp -v event/*.so ${_PREFIX_DIR}/${abi}/
  cp -v socks5/*.so ${_PREFIX_DIR}/${abi}/

  cd ..
done

# ./cmake_android.sh /Users/haidy/Library/Android/sdk/cmake/3.10.2.4988404/bin/cmake /Users/haidy/Library/Android/sdk/ndk-bundle
# /home/haidy/Android/Sdk/cmake/3.10.2.4988404/bin/cmake -DCMAKE_TOOLCHAIN_FILE=/home/haidy/Android/Sdk/ndk-bundle/build/cmake/android.toolchain.cmake -DANDROID_ABI=armeabi-v7a -DANDROID_NATIVE_API_LEVEL=21 -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=build ..

# ./cmake_android.sh /home/haidy/Android/Sdk/cmake/3.10.2.4988404/bin/cmake /home/haidy/Android/Sdk/ndk/21.3.6528147