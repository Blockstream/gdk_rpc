#!/bin/bash
set -eo pipefail

/bitcoin/bin/bitcoind -server=1 -regtest -daemon

cargo test --all

gcc -o test test.c -Isrc  -L. -l:target/debug/libgdk_rpc.so && ./test

/bitcoin/bin/bitcoin-cli -regtest stop
