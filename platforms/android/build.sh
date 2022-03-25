#!/bin/bash

set -ex

THIS_DIR="$(cd -P "$(dirname "${BASH_SOURCES[0]}")" && pwd)"
SOURCE_DIR=$(cd $THIS_DIR/../.. && pwd)
BUILD_TOP=$SOURCE_DIR/build

NDK_ROOT=${NDK_ROOT:-/opt/android-ndk-r21e}
ANDROID_PLATFORM=${ANDROID_PLATFORM:-android-30}
ANDROID_ABIS="x86 x86_64 arm64-v8a armeabi-v7a"
NR_CPU=$(grep -c ^processor /proc/cpuinfo)

for target in $ANDROID_ABIS; do
  BUILD_DIR=$BUILD_TOP/$target

  if [ x"$1" == x"clean" ] ; then
    if [ -d $BUILD_DIR ] ; then
      rm -rf $BUILD_DIR
    fi
  else
    if [ ! -d $BUILD_DIR ] ; then
      mkdir -p $BILD_DIR
    fi

    cd $BUILD_DIR && cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$THIS_DIR/install/$target -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
      -DANDROID_ABI=$target \
      -DANDROID_PLATFORM=$ANDROID_PLATFORM \
      -DANDROID_STL=c++_shared \
      -DANDROID_CPP_FEATURES="rtti exceptions" \
      -DCMAKE_TOOLCHAIN_FILE=$NDK_ROOT/build/cmake/android.toolchain.cmake \
      $SOURCE_DIR && make -j$NR_CPU
  fi
done
