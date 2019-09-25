#!/bin/bash
set -eo pipefail

apt update -qq
apt upgrade --no-install-recommends -yqq
apt install --no-install-recommends -yqq curl ca-certificates build-essential

curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.37.0

source /root/.cargo/env
rustup component add rustfmt clippy

if [ -f /.dockerenv ]; then
    apt -yqq autoremove
    apt -yqq clean
    rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6* /root/.cache
fi
