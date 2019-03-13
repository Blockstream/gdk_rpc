#!/bin/bash

gcc -o test test.c -Isrc  -L. -l:target/debug/librust_gdk_core.so && ./test
