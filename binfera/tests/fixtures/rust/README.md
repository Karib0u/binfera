# Rust fixtures

Small, freestanding x86-64 ELF and PE files, built with rustc 1.96.0. They are decompiled only. `strings.rs` carries real Rust legacy/v0 names, static string descriptors and an immediate UTF-8 pointer/length call. `consume.c` is a link stub whose signature is supplied by the tests.

Run `sh build.sh` here to rebuild. Requires the `x86_64-unknown-linux-gnu` and `x86_64-pc-windows-msvc` rustup targets, clang, ld.lld and lld-link. The script enables the legacy mangling option with RUSTC_BOOTSTRAP and exports Rust function names from the Windows map file.
