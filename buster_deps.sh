#!/bin/bash
set -eo pipefail

apt update -qq
apt upgrade --no-install-recommends -yqq

apt install --no-install-recommends -yqq build-essential clang curl ca-certificates unzip git automake autoconf pkg-config libtool virtualenv ninja-build llvm-dev swig python3-{pip,setuptools,wheel} software-properties-common gnupg

ln -s /usr/bin/python3 /usr/bin/python

SHA256SUM_KEY=428ce45ffbc74e350d707d95c661de959a2e43129a869bd82d78d1556a936440
curl -sL -o public.key https://adoptopenjdk.jfrog.io/adoptopenjdk/api/gpg/key/public
echo "${SHA256SUM_KEY}  public.key" | sha256sum --check
apt-key add public.key
add-apt-repository --yes https://adoptopenjdk.jfrog.io/adoptopenjdk/deb/

apt update -qq
apt install --no-install-recommends -yqq adoptopenjdk-8-hotspot
update-java-alternatives -s adoptopenjdk-8-hotspot-amd64

SHA256SUM_NDK=57435158f109162f41f2f43d5563d2164e4d5d0364783a9a6fab3ef12cb06ce0
curl -sL -o ndk.zip https://dl.google.com/android/repository/android-ndk-r20-linux-x86_64.zip
echo "${SHA256SUM_NDK}  ndk.zip" | sha256sum --check
unzip ndk.zip
rm ndk.zip

curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.36.0

source /root/.cargo/env
rustup component add rustfmt clippy
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

SHA256SUM_BITCOINCORE=5146ac5310133fbb01439666131588006543ab5364435b748ddfc95a8cb8d63f
curl -sL -o bitcoin.tar.gz https://bitcoincore.org/bin/bitcoin-core-0.18.0/bitcoin-0.18.0-x86_64-linux-gnu.tar.gz
echo "${SHA256SUM_BITCOINCORE}  bitcoin.tar.gz" | sha256sum --check
tar zxf bitcoin.tar.gz -C .
ln -s bitcoin-0.18.0 bitcoin
rm bitcoin.tar.gz

SHA256SUM_LIQUID=de1c4f7306b0b3f467e743c886a9b469f506acbfb91e19c617dd6a54c7cc9c41
curl -sL -o liquid.tar.gz https://github.com/ElementsProject/elements/releases/download/elements-0.17.0/liquid-0.17.0-x86_64-linux-gnu.tar.gz
echo "${SHA256SUM_LIQUID}  liquid.tar.gz" | sha256sum --check
tar -zxf liquid.tar.gz -C .
ln -s liquid-0.17.0 liquid
rm liquid.tar.gz


git clone --quiet --depth 1 --single-branch --branch release_0.0.17 https://github.com/Blockstream/gdk.git
pip3 install --require-hashes -r /gdk/tools/requirements.txt


if [ -f /.dockerenv ]; then
    apt remove --purge unzip -yqq
    apt -yqq autoremove
    apt -yqq clean
    rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6* /root/.cache /gdk/.git
fi
