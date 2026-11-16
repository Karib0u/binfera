# ARM32/Thumb and MIPS32 fixtures

These small freestanding binaries are built from the C sources in this directory. They do not contain malware and need no target SDK. Rebuild with LLVM clang and LLD:

```sh
CLANG=clang LLD=ld.lld LLD_LINK=lld-link sh build.sh
```

The checked-in outputs were generated with LLVM 23.1.4. Fixtures cover ARM/Thumb, mixed-mode calls, MIPS32r2 o32 in both byte orders, Windows ARMNT PE32, AAPCS soft/hard-float and six integer parameters, and shared-library GOT/PLT imports. The dynamic fixtures deliberately leave `imported` unresolved. Tests analyze these files statically; only the separately emitted trusted floating-point C fixture is compiled and executed on the host for a semantic comparison.

`build-rel.sh` adds ARM/Thumb, AArch64 and both MIPS32 byte orders as ET_REL objects compiled from `../elf_rel/module.c`, plus aligned COMMON storage cases. It also builds ARM/Thumb exception-index fixtures from `unwind.c`, and an AArch64 copy of `fixture.c` for scoped signature checks. LLVM clang and LLD are required; use `CLANG` and `LLD` to select their paths. These fixtures need no kernel, target SDK or target-code execution.
