#!/bin/bash
set -eo pipefail

if [ -f /.dockerenv ]; then
    export PATH=${PATH}:/bitcoin/bin:/liquid/bin
fi

bitcoind -server=1 -regtest -daemon

bitcoin-cli -regtest -rpcwait generate 200

BITCOIND_DIR=~/.bitcoin/regtest \
cargo test --features stderr_logger --all  -- --test-threads=1

bitcoin-cli -regtest stop
