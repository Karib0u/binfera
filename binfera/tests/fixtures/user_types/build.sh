#!/bin/sh
# A freestanding fixture, never executed. Requires LLVM clang, lld and llvm-objcopy.
# LLVM_BIN and LLD_BIN can override the Homebrew paths.
set -eu
cd "$(dirname "$0")"
LLVM_BIN="${LLVM_BIN:-$(brew --prefix llvm)/bin}"
LLD_BIN="${LLD_BIN:-$(brew --prefix lld)/bin}"
export PATH="$LLVM_BIN:$LLD_BIN:$PATH"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
clang --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -O1 -fno-pic -no-pie \
    -fno-stack-protector -Wl,-e,_start -Wl,--build-id=none packet.c -o "$work/packet.elf"
# The test hard-codes these addresses.
llvm-nm --defined-only "$work/packet.elf" | grep ' T '
# No symbols and no debug information; .eh_frame still lists every function.
llvm-objcopy --strip-all "$work/packet.elf" packet.elf
