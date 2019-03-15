#!/bin/bash
set -eo pipefail

apt update -qq
apt upgrade --no-install-recommends -yqq

apt install --no-install-recommends -yqq build-essential clang curl ca-certificates unzip

SHA256SUM_NDK=0fbb1645d0f1de4dde90a4ff79ca5ec4899c835e729d692f433fda501623257a
curl -sL -o ndk.zip https://dl.google.com/android/repository/android-ndk-r19b-linux-x86_64.zip
echo "${SHA256SUM_NDK}  ndk.zip" | sha256sum --check
unzip ndk.zip
rm ndk.zip

curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.33.0

source /root/.cargo/env
rustup component add rustfmt clippy
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

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
    apt remove --purge unzip -yqq
    apt -yqq autoremove
    apt -yqq clean
    rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6* /root/.cache
fi
