#!/bin/sh
# Freestanding fixtures, never executed. Requires LLVM tools, Go and Rust with the
# x86_64-unknown-linux-gnu target. LLVM_BIN and LLD_BIN can override Homebrew paths.
set -eu
cd "$(dirname "$0")"
LLVM_BIN="${LLVM_BIN:-$(brew --prefix llvm)/bin}"
LLD_BIN="${LLD_BIN:-$(brew --prefix lld)/bin}"
export PATH="$LLVM_BIN:$LLD_BIN:$PATH"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
for version in 4 5; do
    clang --target=x86_64-linux-gnu -fuse-ld=lld -nostdlib -g -gdwarf-$version -O0 \
        -fdebug-prefix-map="$PWD"=. -fno-stack-protector -Wl,-e,_start -Wl,--build-id=none \
        context.c -o "$work/context.elf"
    # Keep debug info while removing ordinary function symbols.
    llvm-objcopy --strip-all '--keep-section=.debug_*' "$work/context.elf" "dwarf$version.elf"
done
llvm-objcopy --compress-debug-sections=zlib dwarf5.elf compressed.elf
cp dwarf4.elf gnu-compressed.elf
for section in info abbrev str line; do
    llvm-objcopy --dump-section ".debug_$section=$work/raw" dwarf4.elf
    python3 - "$work/raw" "$work/compressed" <<'COMPRESS'
import pathlib, sys, zlib
raw = pathlib.Path(sys.argv[1]).read_bytes()
pathlib.Path(sys.argv[2]).write_bytes(b"ZLIB" + len(raw).to_bytes(8, "big") + zlib.compress(raw))
COMPRESS
    llvm-objcopy --update-section ".debug_$section=$work/compressed" \
        --rename-section ".debug_$section=.zdebug_$section" gnu-compressed.elf
done
for arch in x86_64 i686; do
    entry=_start
    if [ "$arch" = i686 ]; then entry=__start; fi
    clang --target=$arch-w64-windows-gnu -fuse-ld=lld -nostdlib -g -gdwarf-4 -O0 \
        -fdebug-prefix-map="$PWD"=. -fno-stack-protector -Wl,--entry,$entry -Wl,--no-insert-timestamp \
        context.c -o "$arch.exe"
done

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-buildid=' -o go.elf context.go
rustc --crate-type lib --emit=obj --target x86_64-unknown-linux-gnu -C opt-level=1 -C debuginfo=2 \
    -C panic=abort --remap-path-prefix "$PWD"=. context.rs -o "$work/rust.o"
ld.lld -shared --build-id=none "$work/rust.o" -o rust.elf
