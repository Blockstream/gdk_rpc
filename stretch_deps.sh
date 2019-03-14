#!/bin/bash
set -eo pipefail

apt update -qq
apt upgrade --no-install-recommends -yqq

apt install --no-install-recommends -yqq build-essential clang curl ca-certificates

curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.33.0

source /root/.cargo/env
rustup component add rustfmt clippy

SHA256SUM_BITCOINCORE=53ffca45809127c9ba33ce0080558634101ec49de5224b2998c489b6d0fc2b17
curl -sL -o bitcoin.tar.gz https://bitcoincore.org/bin/bitcoin-core-0.17.1/bitcoin-0.17.1-x86_64-linux-gnu.tar.gz \
 && echo "${SHA256SUM_BITCOINCORE}  bitcoin.tar.gz" | sha256sum --check \
 && tar xzf bitcoin.tar.gz -C . \
 && ln -s bitcoin-0.17.1 bitcoin \
 && rm bitcoin.tar.gz

SHA256SUM_LIQUID=cb135d60407fd4fcd04d1f021cd314e9f8f50a8f0a660551f5ea251b0fea3ffc
curl -sL -o liquid.tar.gz https://github.com/Blockstream/liquid/releases/download/liquid.3.14.1.23/liquid-3.14.1.23-x86_64-linux-gnu.tar.gz \
 && echo "${SHA256SUM_LIQUID}  liquid.tar.gz" | sha256sum --check \
 && tar xzf liquid.tar.gz -C . \
 && ln -s liquid-3.14.1.23 liquid \
 && rm liquid.tar.gz

if [ -f /.dockerenv ]; then
    apt -yqq autoremove
    apt -yqq clean
    rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6* /root/.cache
fi
