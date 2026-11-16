#!/bin/sh
# Rebuilds the i386 ELF fixtures. Needs clang and ld.lld; no Linux sysroot, since the programs
# are freestanding and the dynamic ones link against a stub that stands in for libc.
# `dynamic.elf` calls through absolute GOT slots; `pic.elf` is position independent, so its PLT
# stubs jump through `ebx`. `thunk.elf` finds its GOT through gcc's `__x86.get_pc_thunk.bx`, and
# `thunk-stripped.elf` is the same program without its symbol table.
set -e
cd "$(dirname "$0")"
C="clang --target=i386-linux-gnu -ffreestanding -fno-stack-protector -O1"
$C -fno-pic -c freestanding.c -o freestanding.o
ld.lld -static -nostdlib -e _start freestanding.o -o freestanding.elf
$C -fPIC -c libstub.c -o libstub.o
ld.lld -shared -nostdlib -soname libstub.so libstub.o -o libstub.so
$C -fno-pic -c dynamic.c -o dynamic.o
ld.lld -nostdlib -e _start -dynamic-linker /lib/ld-linux.so.2 dynamic.o ./libstub.so -o dynamic.elf
$C -fPIC -c dynamic.c -o pic.o
ld.lld -pie -nostdlib -e _start -dynamic-linker /lib/ld-linux.so.2 pic.o ./libstub.so -o pic.elf
clang --target=i386-linux-gnu -c thunk.s -o thunk.o
ld.lld -pie -nostdlib -e _start thunk.o -o thunk.elf
llvm-strip --strip-all thunk.elf -o thunk-stripped.elf
rm -f ./*.o libstub.so
