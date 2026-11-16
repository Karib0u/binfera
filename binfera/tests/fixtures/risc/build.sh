#!/bin/sh
# Requires LLVM clang and LLD. All fixtures are freestanding and need no target SDK.
set -eu
cd "$(dirname "$0")"
clang=${CLANG:-clang}
linker=${LLD:-ld.lld}
pe_linker=${LLD_LINK:-lld-link}
for mode in arm thumb; do
    "$clang" --target=armv7-linux-gnueabi -m"$mode" -mfloat-abi=soft -O1 -ffreestanding -fno-stack-protector -fno-pic -c fixture.c -o fixture.o
    "$linker" -nostdlib -e _start fixture.o -o "$mode.elf"
done
for endian in mips mipsel; do
    "$clang" --target="$endian-linux-gnu" -march=mips32r2 -mabi=32 -mno-abicalls -fno-pic -G0 -O1 -ffreestanding -fno-stack-protector -c fixture.c -o fixture.o
    "$linker" -nostdlib -e _start fixture.o -o "$endian.elf"
done
"$clang" --target=armv7-linux-gnueabi -marm -mfloat-abi=soft -O1 -ffreestanding -fno-pic -c arm.c -o arm.o
"$clang" --target=armv7-linux-gnueabi -mthumb -mfloat-abi=soft -O1 -ffreestanding -fno-pic -c thumb.c -o thumb.o
"$linker" -nostdlib -e _start arm.o thumb.o -o interwork.elf
for abi in softfp hard; do
    "$clang" --target=armv7-linux-gnueabi -mthumb -mfpu=vfpv3-d16 -mfloat-abi="$abi" -O1 -ffreestanding -fno-pic -c floating.c -o fixture.o
    "$linker" -nostdlib -e floating fixture.o -o "arm-$abi.elf"
done
"$clang" --target=thumbv7-pc-windows-msvc -O1 -ffreestanding -fno-stack-protector -c fixture.c -o windows.obj
"$pe_linker" /entry:_start /subsystem:console /nodefaultlib /export:mix /export:invoke /out:windows.exe windows.obj
for mode in arm thumb; do
    "$clang" --target=armv7-linux-gnueabi -m"$mode" -mfloat-abi=soft -O1 -ffreestanding -fPIC -c imports.c -o fixture.o
    "$linker" -shared fixture.o -o "$mode-dynamic.elf"
done
for endian in mips mipsel; do
    "$clang" --target="$endian-linux-gnu" -march=mips32r2 -mabi=32 -fPIC -O1 -ffreestanding -c imports.c -o fixture.o
    "$linker" -shared fixture.o -o "$endian-dynamic.elf"
done
rm -f fixture.o arm.o thumb.o windows.obj windows.lib windows.exp
