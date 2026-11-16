#!/bin/sh
# Requires clang, llvm-lib, ld.lld and lld-link in PATH. No target SDK is needed.
set -eu
cd "$(dirname "$0")"
clang --target=aarch64-linux-gnu -ffreestanding -fno-stack-protector -O1 -fPIC -c fixture.c -o fixture.o
clang --target=aarch64-linux-gnu -ffreestanding -O1 -fPIC -c ../elf64_sysv/libstub.c -o libstub.o
ld.lld -shared -nostdlib -soname libstub.so libstub.o -o libstub.so
ld.lld -nostdlib -e _start fixture.o libstub.o -o executable.elf
ld.lld -pie -nostdlib -e _start fixture.o libstub.so -o pie.elf
ld.lld -shared -nostdlib fixture.o libstub.so -o shared.elf
llvm-lib /def:kernel32.def /machine:arm64 /out:kernel32.lib
clang --target=aarch64-pc-windows-msvc -ffreestanding -fno-stack-protector -O1 -c fixture.c -o fixture.obj
lld-link /entry:entry_point /subsystem:console /nodefaultlib /out:windows.exe fixture.obj kernel32.lib
rm -f fixture.o libstub.o libstub.so fixture.obj kernel32.lib windows.lib windows.exp
