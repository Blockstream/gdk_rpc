#!/bin/bash

gcc -o test test.c -Isrc  -L. -l:target/debug/libgdk_rpc.so && ./test
