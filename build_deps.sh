#!/bin/bash
set -eo pipefail
if [ -f /.dockerenv ]; then
    source /root/.cargo/env
    export GDK_LOCATION=/gdk
fi
have_cmd()
{
    command -v "$1" >/dev/null 2>&1
}
# FIXME: we don't need to build everything but just libwallycore.a, libsecp256k1.a libevent*.a libssl*.a libzlib*.a libtor*.a

if [ ! -d ${GDK_LOCATION}/build-clang ]; then
    oldpath=$(pwd)
    cd ${GDK_LOCATION}
    ./tools/build.sh --clang
    cd $oldpath
fi

# FIXME: we shouldn't need to change the crate-type with sed ...
sed -i 's/dylib/staticlib/g' Cargo.toml
cargo build --release
sed -i 's/staticlib/dylib/g' Cargo.toml

lib_path=release_lib

mkdir -p $lib_path

cp ${GDK_LOCATION}/include/gdk.h $lib_path
clang -flto -fPIC -shared -o $lib_path/libgreenaddress.so -Wl,--whole-archive target/release/libgdk_rpc.a ${GDK_LOCATION}/build-clang/libwally-core/build/lib/libwallycore.a -Wl,--no-whole-archive -lm

strip $lib_path/libgreenaddress.so


