#!/bin/bash
set -eo pipefail

/bitcoin/bin/bitcoind -server=1 -regtest -daemon

/bitcoin/bin/bitcoin-cli -regtest -rpcwait generate 102

cargo test --all

gcc -o test test.c -Isrc  -L. -l:target/release/libgdk_rpc.so && ./test

/bitcoin/bin/bitcoin-cli -regtest stop
