#!/bin/sh
# LLVM emits the MSVC FH3 ABI; no SDK or runtime execution is required.
set -eu
cd "$(dirname "$0")"
LLVM_BIN="$(brew --prefix llvm)/bin"
LLD_BIN="$(brew --prefix lld)/bin"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
for arch in 32 64; do
    if [ "$arch" = 32 ]; then
        target=i686-pc-windows-msvc machine=x86 vftable=_fixture_type_info_vftable
    else
        target=x86_64-pc-windows-msvc machine=x64 vftable=fixture_type_info_vftable
    fi
    cat > "$work/runtime.def" <<'DEFS'
LIBRARY fixture_runtime.dll
EXPORTS
    may_throw
    cleanup
    __CxxFrameHandler3
    __std_terminate
DEFS
    "$LLVM_BIN/llvm-lib" "/def:$work/runtime.def" "/machine:$machine" "/out:$work/runtime.lib"
    "$LLVM_BIN/clang++" --target="$target" -O1 -fexceptions -fcxx-exceptions -fno-stack-protector \
        -c exceptions.cpp -o "$work/exceptions.obj"
    "$LLD_BIN/lld-link" /dll /noentry /nodefaultlib /Brepro /safeseh:no \
        "/alternatename:??_7type_info@@6B@=$vftable" \
        "/out:exceptions$arch.dll" "$work/exceptions.obj" "$work/runtime.lib"
    rm -f "exceptions$arch.lib"
done
