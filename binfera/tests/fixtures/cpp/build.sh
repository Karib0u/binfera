#!/bin/sh
# Rebuilds the C++ fixtures from rtti.cpp: rtti32.dll and rtti64.dll, Visual C++ ABI with RTTI,
# and rtti64.elf, the Itanium ABI with its symbol table. No C runtime and no Windows SDK: the
# imports come from stub import libraries (msvcp32.def, msvcp64.def, kernel32). Needs Homebrew's LLVM and lld.
set -eu
cd "$(dirname "$0")"
LLVM_BIN="$(brew --prefix llvm)/bin"
LLD_BIN="$(brew --prefix lld)/bin"
export PATH="$LLD_BIN:$PATH"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

for arch in 32 64; do
    if [ "$arch" = 32 ]; then
        target=i686-pc-windows-msvc machine=x86 dlltool=i386 vftable=_fixture_type_info_vftable tick=GetTickCount@0
    else
        target=x86_64-pc-windows-msvc machine=x64 dlltool=i386:x86-64 vftable=fixture_type_info_vftable tick=GetTickCount
    fi
    printf 'LIBRARY kernel32.dll\nEXPORTS\n    %s\n' "$tick" > "$work/kernel32.def"
    "$LLVM_BIN/llvm-dlltool" -k -m "$dlltool" -d "$work/kernel32.def" -l "$work/kernel32.lib"
    "$LLVM_BIN/llvm-lib" "/def:msvcp$arch.def" "/machine:$machine" "/out:$work/msvcp.lib"
    "$LLVM_BIN/clang" --target=$target -O2 -fno-exceptions -fuse-ld=lld -nostdlib -shared \
        -Wl,/entry:_DllMainCRTStartup -Wl,/Brepro \
        "-Wl,/alternatename:??_7type_info@@6B@=$vftable" \
        -o "rtti$arch.dll" rtti.cpp "$work/kernel32.lib" "$work/msvcp.lib"
    rm -f "rtti$arch.lib"
done

# The Itanium ABI keeps its RTTI in the symbol table here; the stubs stand in for the runtime.
"$LLVM_BIN/clang" --target=x86_64-linux-gnu -O2 -fPIC -fno-exceptions -fuse-ld=lld -nostdlib -shared \
    -Wl,--build-id=none -Wl,--unresolved-symbols=ignore-all \
    -o rtti64.elf rtti.cpp
