#!/bin/bash
set -eo pipefail

export AR_i686_linux_android=/android-ndk-r19b/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android-ar
export CC_i686_linux_android=/android-ndk-r19b/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android19-clang
export AR_x86_64_linux_android=/android-ndk-r19b/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android-ar
export CC_x86_64_linux_android=/android-ndk-r19b/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android21-clang
export AR_armv7_linux_androideabi=/android-ndk-r19b/toolchains/llvm/prebuilt/linux-x86_64/bin/arm-linux-androideabi-ar
export CC_armv7_linux_androideabi=/android-ndk-r19b/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi19-clang
export AR_aarch64_linux_android=/android-ndk-r19b/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android-ar
export CC_aarch64_linux_android=/android-ndk-r19b/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang

source /root/.cargo/env

cp cargo-config.toml ~/.cargo/config

cargo build --target i686-linux-android --release
cargo build --target x86_64-linux-android --release
cargo build --target armv7-linux-androideabi --release
cargo build --target aarch64-linux-android --release
