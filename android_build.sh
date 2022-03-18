#!/bin/bash

set -ex

ANDROID_NDK_HOME=${ANDROID_NDK_HOME:=/opt/android-ndk-r19c}

TARGET_ARCH="x86 x86_64 arm64-v8a armeabi-v7a"

CURDIR=$PWD

cd build

for r in $TARGET_ARCH ; do
  if [ x"$1" == x"clean" ] ; then
    if [ -d $r ] ; then
      rm -rf $r
    fi
  else
    if [ ! -d $r ] ; then
      mkdir $r
    fi

    cd $r && cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local/ -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
      -DANDROID_ABI=$r \
      -DANDROID_PLATFORM=android-30 \
      -DANDROID_STL=c++_static \
      -DANDROID_CPP_FEATURES="rtti exceptions" \
      -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
      ../../ && make && cd ..
  fi
done

cd $CURDIR
