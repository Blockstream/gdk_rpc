# GDK Rust RPC Bitcoin/Liquid bridge

[![build status](https://api.travis-ci.org/Blockstream/gdk_rpc.svg)](https://travis-ci.org/Blockstream/gdk_rpc)
[![MIT license](https://img.shields.io/github/license/blockstream/gdk_rpc.svg)](https://github.com/blockstream/gdk_rpc/blob/master/LICENSE)
[![Pull Requests Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

GDK is a cross-platform, cross-language library for Blockstream Green wallets.

For an overview of the api see [gdk.readthedocs.io](https://gdk.readthedocs.io).

GDK-RPC library is compatible with [gdk](https://github.com/blockstream/gdk) and allows
users to use the Green mobile/cli/desktop apps with a Bitcoin or Liquid
full node including pruned.


## Building

Get [rust](https://rustup.rs)

cd in the repo

cargo build

## Building for Android

Download ndk r19b

export ANDROID_NDK=location_of_unzipped_ndk_r19b

You will also need to run (one off)

rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

then to build for the various target run

./ndk.sh
