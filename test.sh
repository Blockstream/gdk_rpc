#!/bin/bash
set -eo pipefail

if [ -f /.dockerenv ]; then
    export PATH=${PATH}:/bitcoin/bin:/liquid/bin
    source /root/.cargo/env
fi

bitcoind -server=1 -regtest -daemon

bitcoin-cli -regtest -rpcwait generatetoaddress 200 $(bitcoin-cli -regtest -rpcwait getnewaddress)

BITCOIND_DIR=~/.bitcoin/regtest \
cargo test --features stderr_logger --all  -- --test-threads=1

bitcoin-cli -regtest stop
