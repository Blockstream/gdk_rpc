#! /usr/bin/env bash
set -e

apt update -qq
apt upgrade --no-install-recommends -yqq

apt install --no-install-recommends -yqq build-essential clang curl ca-certificates

curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.33.0

source /root/.cargo/env
rustup component add rustfmt clippy

if [ -f /.dockerenv ]; then
    apt -yqq autoremove
    apt -yqq clean
    rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6* /root/.cache
fi
