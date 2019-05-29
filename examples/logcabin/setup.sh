#!/usr/bin/env sh

rm -rf /tmp/storage1 /tmp/storage2 /tmp/storage3
./logcabin-src/build/LogCabin --config logcabin-1.conf --bootstrap
