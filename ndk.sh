#!/bin/bash
set -eo pipefail
if [ -f /.dockerenv ]; then
    source /root/.cargo/env
    export ANDROID_NDK=/android-ndk-r19b
fi
export PATH=${PATH}:${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin

export CC_i686_linux_android=i686-linux-android19-clang
export CC_x86_64_linux_android=x86_64-linux-android21-clang
export CC_armv7_linux_androideabi=armv7a-linux-androideabi19-clang
export CC_aarch64_linux_android=aarch64-linux-android21-clang

cp cargo-config.toml ~/.cargo/config

FEAT="--features android_logger"
cargo build $FEAT --target i686-linux-android --release
cargo build $FEAT --target x86_64-linux-android --release
cargo build $FEAT --target armv7-linux-androideabi --release
cargo build $FEAT --target aarch64-linux-android --release
