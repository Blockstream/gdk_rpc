#!/bin/bash
set -eo pipefail

if [ -f /.dockerenv ]; then
    export PATH=${PATH}:/bitcoin/bin:/liquid/bin
fi

bitcoind -server=1 -regtest -daemon

bitcoin-cli -regtest -rpcwait generate 102

cargo test --all  -- --test-threads=1

gcc -o test test.c -Isrc  -L. -l:target/release/libgdk_rpc.so && ./test

bitcoin-cli -regtest stop
