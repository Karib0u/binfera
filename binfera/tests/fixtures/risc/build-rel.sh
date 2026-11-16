#!/bin/sh
# Trusted freestanding objects, including kernel-module style external calls.
set -eu
cd "$(dirname "$0")"
clang=${CLANG:-clang}
for mode in arm thumb; do
    "$clang" --target=armv7-linux-gnueabi -m"$mode" -mfloat-abi=soft -O1 -fno-builtin -ffreestanding -fno-pic -fno-stack-protector -c ../elf_rel/module.c -o "$mode-rel.elf"
done
"$clang" --target=aarch64-linux-gnu -O1 -fno-builtin -ffreestanding -fno-pic -fno-stack-protector -c ../elf_rel/module.c -o aarch64-rel.elf
for endian in mips mipsel; do
    "$clang" --target="$endian-linux-gnu" -march=mips32r2 -mabi=32 -mno-abicalls -fno-pic -G0 -O1 -fno-builtin -ffreestanding -fno-stack-protector -c ../elf_rel/module.c -o "$endian-rel.elf"
done
linker=${LLD:-ld.lld}
"$clang" --target=aarch64-linux-gnu -O1 -ffreestanding -fno-stack-protector -fno-pic -c fixture.c -o fixture.o
"$linker" -nostdlib -e _start fixture.o -o aarch64.elf
for mode in arm thumb; do
    "$clang" --target=armv7-linux-gnueabi -m"$mode" -mfloat-abi=soft -O1 -ffreestanding -funwind-tables -fno-stack-protector -c unwind.c -o fixture.o
    "$linker" -nostdlib -e _start fixture.o -o "$mode-unwind.elf"
done
rm -f fixture.o

"$clang" --target=armv7-linux-gnueabi -marm -mfloat-abi=soft -fcommon -O1 -fno-builtin -ffreestanding -fno-pic -c ../elf_rel/module.c -o arm-common-rel.elf
"$clang" --target=mipsel-linux-gnu -march=mips32r2 -mabi=32 -mno-abicalls -fno-pic -G0 -fcommon -O1 -fno-builtin -ffreestanding -c ../elf_rel/module.c -o mipsel-common-rel.elf

"$clang" --target=mipsel-linux-gnu -march=mips32r2 -mabi=32 -fPIC -O1 -fno-builtin -ffreestanding -c ../elf_rel/module.c -o mipsel-pic-rel.elf
