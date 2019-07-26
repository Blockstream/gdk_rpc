#!/bin/bash
set -eo pipefail

if [ -f /.dockerenv ]; then
    source /root/.cargo/env
fi

if [ ! -d ${GDK_LOCATION}/build-clang ]; then
    oldpath=$(pwd)
    cd ${GDK_LOCATION}
    ./tools/build.sh --clang
    cd $oldpath
fi
