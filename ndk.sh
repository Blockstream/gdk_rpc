#!/bin/bash
set -eo pipefail

if [ -f /.dockerenv ]; then
    source /root/.cargo/env
    export ANDROID_NDK=/android-ndk-r20
    export JAVA_HOME=/usr/lib/jvm/adoptopenjdk-8-hotspot-amd64
fi

have_cmd()
{
    command -v "$1" >/dev/null 2>&1
}
if [ -z "$ANDROID_NDK" ]; then
    if have_cmd ndk-build; then
        export ANDROID_NDK=$(dirname $(command -v ndk-build))
    fi
fi
export PATH=${PATH}:${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin

export CC_i686_linux_android=i686-linux-android19-clang
export CC_x86_64_linux_android=x86_64-linux-android21-clang
export CC_armv7_linux_androideabi=armv7a-linux-androideabi19-clang
export CC_aarch64_linux_android=aarch64-linux-android21-clang

ARCH_LIST="armeabi-v7a x86 x86_64 arm64-v8a"
if [ -n "$1" ]; then
    ARCH_LIST="$1"
fi

if [ ! -f ${GDK_LOCATION}/build-clang-android-x86/android_x86_ndk.txt ]; then
    oldpath=$(pwd)
    cd ${GDK_LOCATION}
    if [[ $ARCH_LIST == *"armeabi-v7a"* ]]; then
        ./tools/build.sh --ndk armeabi-v7a
    fi
    if [[ $ARCH_LIST == *"arm64-v8a"* ]]; then
        ./tools/build.sh --ndk arm64-v8a
    fi
    ./tools/build.sh --ndk arm64-v8a
    if [[ $ARCH_LIST == *"x86_64"* ]]; then
        ./tools/build.sh --ndk x86_64
    fi
    if [[ "${ARCH_LIST/x86_64/}" == *"x86"* ]]; then
        ./tools/build.sh --ndk x86
    fi
    cd $oldpath
fi


# FIXME: we shouldn't need to change the crate-type with sed ...
FEAT="--features android_logger"
if [[ "${ARCH_LIST/x86_64/}" == *"x86"* ]]; then
    export GDK_TARGET=build-clang-android-x86
    cargo build $FEAT --target i686-linux-android --release
fi
if [[ $ARCH_LIST == *"x86_64"* ]]; then
    export GDK_TARGET=build-clang-android-x86_64
    cargo build $FEAT --target x86_64-linux-android --release
fi
if [[ $ARCH_LIST == *"armeabi-v7a"* ]]; then
    export GDK_TARGET=build-clang-android-armeabi-v7a
    cargo build $FEAT --target armv7-linux-androideabi --release
fi
if [[ $ARCH_LIST == *"arm64-v8a"* ]]; then
    export GDK_TARGET=build-clang-android-arm64-v8a
    cargo build $FEAT --target aarch64-linux-android --release
fi
