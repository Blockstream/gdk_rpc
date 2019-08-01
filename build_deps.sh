#!/bin/bash
set -eo pipefail

: ${WALLY_LOCATION?"Need to set WALLY_LOCATION"}

if [ -f /.dockerenv ]; then
    source /root/.cargo/env
fi

CONFIGURE_ARGS="--enable-static --disable-shared --enable-elements --enable-ecmult-static-precomputation"
CONFIGURE_ARGS="$CONFIGURE_ARGS --disable-swig-java --disable-swig-python"
CONFIGURE_ARGS="$CONFIGURE_ARGS --disable-dependency-tracking"
CONFIGURE_ARGS="$CONFIGURE_ARGS --prefix=$PWD/bld"

if [ ! -d $PWD/bld ]; then
    mkdir $PWD/bld
    oldpath=$(pwd)
    cd ${WALLY_LOCATION}
    ./tools/cleanup.sh
    ./tools/autogen.sh
    export CFLAGS="$CFLAGS -DPIC -fPIC -flto"
    export LDFLAGS="$LDFLAGS -flto"
    ./configure $CONFIGURE_ARGS
    make -j$(cat /proc/cpuinfo | grep ^processor | wc -l) install
    cd $oldpath
fi
