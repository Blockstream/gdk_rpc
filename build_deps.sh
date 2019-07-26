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

if [ ! -d ${GDK_LOCATION}/build-clang ]; then
    oldpath=$(pwd)
    cd ${GDK_LOCATION}
    ./tools/build.sh --clang
    cd $oldpath
fi
