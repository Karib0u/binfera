#!/bin/sh
# RUSTC_BOOTSTRAP enables the legacy mangling flag on current compilers.
# Requires rustup's x86_64 Linux and Windows targets, clang, ld.lld and lld-link.
set -eu
cd "$(dirname "$0")"
for mangling in legacy v0; do
    RUSTC_BOOTSTRAP=1 rustc -Z unstable-options strings.rs --crate-type=lib --crate-name rust_fixture --edition 2021 --target x86_64-unknown-linux-gnu \
        -C opt-level=1 -C panic=abort -C relocation-model=static -C symbol-mangling-version="$mangling" --emit=obj -o strings.o
    clang --target=x86_64-linux-gnu -O1 -ffreestanding -c consume.c -o consume.o
    ld.lld -static -nostdlib -e _start strings.o consume.o -o "strings-$mangling.elf"
    RUSTC_BOOTSTRAP=1 rustc -Z unstable-options strings.rs --crate-type=lib --crate-name rust_fixture --edition 2021 --target x86_64-pc-windows-msvc \
        -C opt-level=1 -C panic=abort -C symbol-mangling-version="$mangling" --emit=obj -o strings.obj
    clang --target=x86_64-pc-windows-msvc -O1 -ffreestanding -c consume.c -o consume.obj
    lld-link /entry:_start /subsystem:console /nodefaultlib /export:_start /export:MESSAGES /export:consume /timestamp:0 \
        /opt:noref strings.obj consume.obj "/out:strings-$mangling.exe" "/map:strings-$mangling.map"
    python3 - "$mangling" <<'PY'
import sys
from pathlib import Path
rows = Path(f"strings-{sys.argv[1]}.map").read_text().splitlines()
names = [row.split()[1] for row in rows if len(row.split()) >= 3 and row.split()[1].startswith(("_ZN", "_R"))]
Path("exports.def").write_text("EXPORTS\n" + "\n".join(names) + "\n")
PY
    lld-link /entry:_start /subsystem:console /nodefaultlib /export:_start /export:MESSAGES /export:consume /timestamp:0 \
        /def:exports.def strings.obj consume.obj "/out:strings-$mangling.exe"
done
rm -f strings.o consume.o strings.obj consume.obj exports.def ./*.lib ./*.map
