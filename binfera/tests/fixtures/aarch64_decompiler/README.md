# AArch64 decompiler fixtures

`build.sh` builds freestanding little-endian ELF64 executable, PIE, shared-library and ARM64 PE32+ fixtures from `fixture.c`. It needs LLVM clang/llvm-lib and LLD in PATH; no Linux sysroot or Windows SDK is needed. ELF imports use the existing ELF fixture stub library; PE imports use `kernel32.def`. The binaries are only parsed and decompiled.

The tests check x0-x7 and stack arguments, v0-v7 scalar FP arguments with an explicit return signature, named local calls, typed imports and tail calls. PIE and shared-library data exercise RELATIVE, ABS64 and GLOB_DAT relocations. Tests mutate relocation records in memory to check invalid addresses, symbol indices, unsupported types and signed addends.
