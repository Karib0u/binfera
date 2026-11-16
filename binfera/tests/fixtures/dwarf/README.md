# DWARF fixtures

These small programs are compiled for inspection, never executed by the tests. Run `sh build.sh` to rebuild them with LLVM clang/lld/llvm-objcopy, Python 3, Go, and Rust with the `x86_64-unknown-linux-gnu` target installed. `LLVM_BIN` and `LLD_BIN` override the script's Homebrew defaults.

- `dwarf4.elf` and `dwarf5.elf`: PIE C executables with the ordinary symbol table removed while retaining debug sections. Function addresses must be rebased.
- `compressed.elf` and `gnu-compressed.elf`: standard ELF and GNU legacy zlib debug section encodings of those executables.
- `x86_64.exe` and `i686.exe`: MinGW C executables, including COFF long debug section names. The i386 caller dynamically realigns ESP, so its local location is intentionally not treated as a fixed frame offset.
- `go.elf`: Go register arguments, a recursive type graph from the runtime, application structure fields and multiple return values, with compressed DWARF.
- `rust.elf`: a scalar/pointer prototype and a private tuple-return prototype. Only the former is locked; the latter keeps inferred storage.

`decompiler_dwarf.rs` checks names, signatures, fields, fixed stack locals, request reuse, explicit API overrides, compressed-size rejection and byte-wise mutations of a debug information section. No proprietary or malware inputs are needed to reproduce these tests.
