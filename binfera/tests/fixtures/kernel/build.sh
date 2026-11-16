#!/bin/sh
# Requires MinGW-w64 14.0.0 cross compilers. These files are never executed.
set -eu
cd "$(dirname "$0")"
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT
for bits in 32 64; do
    if [ "$bits" = 32 ]; then
        target=i686-w64-mingw32
        symbol='FltStartFiltering@4'
        native_symbol='NtCreateFile@44'
    else
        target=x86_64-w64-mingw32
        symbol=FltStartFiltering
        native_symbol=NtCreateFile
    fi
    printf 'LIBRARY fltmgr.sys\nEXPORTS\n%s\n' "$symbol" > "$build_dir/fltmgr.def"
    "$target-dlltool" -k -d "$build_dir/fltmgr.def" -l "$build_dir/libfltmgr.a"
    printf 'LIBRARY ntdll.dll\nEXPORTS\n%s\n' "$native_symbol" > "$build_dir/native.def"
    "$target-dlltool" -k -d "$build_dir/native.def" -l "$build_dir/libnative.a"
    include_dir=$(dirname "$("$target-gcc" -print-file-name=libntoskrnl.a)")/../include
    "$target-gcc" -O1 -fno-inline -fno-builtin -shared -nostdlib \
        -I"$include_dir/ddk" -Wl,--entry,0,--subsystem,native,--no-insert-timestamp \
        imports.c -L"$build_dir" -lnative -lntoskrnl -lhal -lndis -lfltmgr \
        -o "imports$bits.sys"
done
