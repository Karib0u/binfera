#!/bin/sh
# Development only: rebuilds register_abi.exe (Go 1.17+ register ABI, Windows x86-64). The tests
# read the checked-in file and never run it. Built with go1.27.3; another release lays it out
# differently, so update the addresses in binova/tests/decompiler.rs after a rebuild.
set -eu
cd "$(dirname "$0")"
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 GOFLAGS=-buildvcs=false \
  go build -trimpath -ldflags="-s -w -buildid=" -o register_abi.exe .
