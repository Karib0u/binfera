#!/bin/sh
# Rebuilds web/public/demo-v1.exe and demo-v2.exe (the compare page's example) from demo.rs. Both
# come from here, with one toolchain, so what differs between them is the source. Same needs as
# build.sh; never run either file.
set -eu
cd "$(dirname "$0")"
build() {
  rustc demo.rs --edition 2021 --target x86_64-pc-windows-msvc --crate-type bin \
    --check-cfg 'cfg(variant)' "$@" \
    -C opt-level=2 -C panic=abort -C debuginfo=0 -C strip=symbols \
    -C linker=rust-lld -C linker-flavor=lld-link \
    -C link-arg=/entry:entry -C link-arg=/subsystem:console -C link-arg=/nodefaultlib \
    -C link-arg=/brepro -C link-arg=/opt:ref
}
build -o ../public/demo-v1.exe
build --cfg variant -o ../public/demo-v2.exe
rm -f ../public/demo-v1.pdb ../public/demo-v2.pdb
ls -l ../public/demo-v1.exe ../public/demo-v2.exe
