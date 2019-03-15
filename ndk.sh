#!/bin/bash
set -eo pipefail

export PATH=${PATH}:/android-ndk-r19b/toolchains/llvm/prebuilt/linux-x86_64/bin

export CC_i686_linux_android=i686-linux-android19-clang
export CC_x86_64_linux_android=x86_64-linux-android21-clang
export CC_armv7_linux_androideabi=armv7a-linux-androideabi19-clang
export CC_aarch64_linux_android=aarch64-linux-android21-clang

if [ -f /.dockerenv ]; then
    source /root/.cargo/env
fi

cp cargo-config.toml ~/.cargo/config

cargo build --target i686-linux-android --release
cargo build --target x86_64-linux-android --release
cargo build --target armv7-linux-androideabi --release
cargo build --target aarch64-linux-android --release
