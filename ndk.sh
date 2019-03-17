#!/bin/bash
set -eo pipefail
if [ -f /.dockerenv ]; then
    source /root/.cargo/env
    export ANDROID_NDK=/android-ndk-r19b
    export GDK_LOCATION=/gdk
    export JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk-amd64
fi
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

# FIXME: we don't need to build everything but just libswig_java.a, libwallycore.a, libsecp256k1.a

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
sed -i 's/dylib/staticlib/g' Cargo.toml
if [[ "${ARCH_LIST/x86_64/}" == *"x86"* ]]; then
    cargo build $FEAT --target i686-linux-android --release
fi
if [[ $ARCH_LIST == *"x86_64"* ]]; then
    cargo build $FEAT --target x86_64-linux-android --release
fi
if [[ $ARCH_LIST == *"armeabi-v7a"* ]]; then
    cargo build $FEAT --target armv7-linux-androideabi --release
fi
if [[ $ARCH_LIST == *"arm64-v8a"* ]]; then
    cargo build $FEAT --target aarch64-linux-android --release
fi
sed -i 's/staticlib/dylib/g' Cargo.toml


jni_lib_path=gdk-android-jni/lib

mkdir -p gdk-android-jni/include/gdk $jni_lib_path/{x86,x86_64,armeabi-v7a,arm64-v8a} gdk-android-jni/java/com/blockstream/{libwally,libgreenaddress}

cp ${GDK_LOCATION}/include/gdk.h gdk-android-jni/include/gdk
cp -nrf ${GDK_LOCATION}/build-clang-android-*/libwally-core/src/swig_java/src/com/blockstream/libwally/Wally.java gdk-android-jni/java/com/blockstream/libwally
cp -nrf ${GDK_LOCATION}/build-clang-android-*/src/swig_java/com/blockstream/libgreenaddress/GDK.java gdk-android-jni/java/com/blockstream/libgreenaddress

if [[ "${ARCH_LIST/x86_64/}" == *"x86"* ]]; then
    ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android19-clang -flto -fPIC -shared -o $jni_lib_path/x86/libgreenaddress.so -Wl,--whole-archive target/i686-linux-android/release/libgdk_rpc.a ${GDK_LOCATION}/build-clang-android-x86/src/swig_java/libswig_java.a ${GDK_LOCATION}/build-clang-android-x86/libwally-core/build/lib/libwallycore.a ${GDK_LOCATION}/build-clang-android-x86/libwally-core/build/lib/libsecp256k1.a ${ANDROID_NDK}/platforms/android-19/arch-x86/usr/lib/liblog.so -Wl,--no-whole-archive  -lm
    ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android-strip $jni_lib_path/x86/libgreenaddress.so

fi
if [[ $ARCH_LIST == *"x86_64"* ]]; then
    ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android21-clang -flto -fPIC -shared -o $jni_lib_path/x86_64/libgreenaddress.so -Wl,--whole-archive target/x86_64-linux-android/release/libgdk_rpc.a ${GDK_LOCATION}/build-clang-android-x86_64/src/swig_java/libswig_java.a ${GDK_LOCATION}/build-clang-android-x86_64/libwally-core/build/lib/libwallycore.a ${GDK_LOCATION}/build-clang-android-x86_64/libwally-core/build/lib/libsecp256k1.a ${ANDROID_NDK}/platforms/android-21/arch-x86_64/usr/lib64/liblog.so -Wl,--no-whole-archive  -lm
    ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android-strip $jni_lib_path/x86_64/libgreenaddress.so
fi

if [[ $ARCH_LIST == *"armeabi-v7a"* ]]; then
    ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi19-clang -flto -fPIC -shared -o $jni_lib_path/armeabi-v7a/libgreenaddress.so -Wl,--whole-archive target/armv7-linux-androideabi/release/libgdk_rpc.a ${GDK_LOCATION}/build-clang-android-armeabi-v7a/src/swig_java/libswig_java.a ${GDK_LOCATION}/build-clang-android-armeabi-v7a/libwally-core/build/lib/libwallycore.a ${GDK_LOCATION}/build-clang-android-armeabi-v7a/libwally-core/build/lib/libsecp256k1.a ${ANDROID_NDK}/platforms/android-19/arch-arm/usr/lib/liblog.so -Wl,--no-whole-archive  -lm
    ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/arm-linux-androideabi-strip $jni_lib_path/armeabi-v7a/libgreenaddress.so
fi

if [[ $ARCH_LIST == *"arm64-v8a"* ]]; then
    ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang -flto -fPIC -shared -o $jni_lib_path/arm64-v8a/libgreenaddress.so -Wl,--whole-archive target/aarch64-linux-android/release/libgdk_rpc.a ${GDK_LOCATION}/build-clang-android-arm64-v8a/src/swig_java/libswig_java.a ${GDK_LOCATION}/build-clang-android-arm64-v8a/libwally-core/build/lib/libwallycore.a ${GDK_LOCATION}/build-clang-android-arm64-v8a/libwally-core/build/lib/libsecp256k1.a ${ANDROID_NDK}/platforms/android-21/arch-arm64/usr/lib/liblog.so -Wl,--no-whole-archive  -lm
    ${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android-strip $jni_lib_path/arm64-v8a/libgreenaddress.so
fi

tar -czf gdk-android-jni.tar.gz gdk-android-jni
