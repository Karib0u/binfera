#!/bin/sh
# Rebuilds the ELF fixtures. Needs clang and ld.lld; no Linux sysroot, since the programs
# are freestanding and `dynamic.elf` links against a stub that stands in for libc.
set -e
cd "$(dirname "$0")"
C="clang --target=x86_64-linux-gnu -ffreestanding -fno-stack-protector -O1"
$C -fno-pic -c freestanding.c -o freestanding.o
ld.lld -static -nostdlib -e _start freestanding.o -o freestanding.elf
$C -fPIC -c libstub.c -o libstub.o
ld.lld -shared -nostdlib -soname libstub.so libstub.o -o libstub.so
$C -fno-pic -c dynamic.c -o dynamic.o
ld.lld -nostdlib -e _start -dynamic-linker /lib64/ld-linux-x86-64.so.2 dynamic.o ./libstub.so -o dynamic.elf
rm -f ./*.o libstub.so
