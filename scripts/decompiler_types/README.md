# Prototype pack generation (development only)

Regenerates `binfera-ghidra/data/winapi64.pack` and `winapi32.pack` from Ghidra's bundled data type archives and Microsoft's Win32 metadata. Java runs only here, never in the build or at runtime. Use the same Ghidra release as `PINNED.md`.

```sh
export GHIDRA_HOME=$HOME/tools/ghidra_12.1.4_PUBLIC
T=$GHIDRA_HOME/Ghidra/Features/Base/data/typeinfo
mkdir -p scripts/decompiler_types/out
"$GHIDRA_HOME/support/analyzeHeadless" "$(mktemp -d)" p -import tests/decompiler/fixtures.dll -noanalysis \
  -scriptPath scripts/decompiler_types -postScript ExportPrototypes.java \
  "$PWD/scripts/decompiler_types/out/proto.tsv" "$T/win32/windows_vs12_64.gdt" "$T/generic/generic_clib_64.gdt" -deleteProject
python3 -I scripts/decompiler_types/pack_prototypes.py scripts/decompiler_types/out/proto.tsv binfera-ghidra/data/winapi64.pack
python3 scripts/decompiler_types/supplement_prototypes.py windows 8 binfera-ghidra/data/winapi64.pack
cargo test --release -p binfera-ghidra --features native packed_archive
```

`ProbeArchive.java` prints a summary of any `.gdt` archive. The export skips intrinsics headers (`*intrin.h`) and keeps the first definition of each function name, in the order the archives are listed.

x86-32: import any PE32 (for example a sample from `tests/testfiles`) instead of `fixtures.dll`, so the script reads the x86-32 compiler specification, and list the 32-bit archives:

```sh
"$GHIDRA_HOME/support/analyzeHeadless" "$(mktemp -d)" p -import PE32_SAMPLE -noanalysis \
  -scriptPath scripts/decompiler_types -postScript ExportPrototypes.java \
  "$PWD/scripts/decompiler_types/out/proto32.tsv" "$T/win32/windows_vs12_32.gdt" "$T/generic/generic_clib.gdt" -deleteProject
python3 -I scripts/decompiler_types/pack_prototypes.py scripts/decompiler_types/out/proto32.tsv binfera-ghidra/data/winapi32.pack
```

System V x86-64 (`sysv64.pack`): import an ELF x86-64 file, so the script reads `x86-64-gcc.cspec`, and list only the C library archive:

```sh
"$GHIDRA_HOME/support/analyzeHeadless" "$(mktemp -d)" p -import binfera/tests/fixtures/elf64_sysv/freestanding.elf -noanalysis \
  -scriptPath scripts/decompiler_types -postScript ExportPrototypes.java \
  "$PWD/scripts/decompiler_types/out/protolinux.tsv" "$T/generic/generic_clib_64.gdt" -deleteProject
python3 -I scripts/decompiler_types/pack_prototypes.py scripts/decompiler_types/out/protolinux.tsv binfera-ghidra/data/sysv64.pack
```

System V i386 (`sysv32.pack`): the same with an i386 ELF file, so the script reads `x86gcc.cspec`, and the 32-bit C library archive:

```sh
"$GHIDRA_HOME/support/analyzeHeadless" "$(mktemp -d)" p -import binfera/tests/fixtures/elf32_sysv/freestanding.elf -noanalysis \
  -scriptPath scripts/decompiler_types -postScript ExportPrototypes.java \
  "$PWD/scripts/decompiler_types/out/protolinux32.tsv" "$T/generic/generic_clib.gdt" -deleteProject
python3 -I scripts/decompiler_types/pack_prototypes.py scripts/decompiler_types/out/protolinux32.tsv binfera-ghidra/data/sysv32.pack
```

## Go standard library signatures (`golang64.pack`, `golang32.pack`)

Ghidra's Go API snapshots are JSON, so the Go packs are built by Python alone:

```sh
T=$HOME/tools/ghidra_12.1.4_PUBLIC/Ghidra/Features/Base/data/typeinfo/golang
python3 -I scripts/decompiler_types/pack_go_snapshots.py "$T" 8 binfera-ghidra/data/golang64.pack
python3 -I scripts/decompiler_types/pack_go_snapshots.py "$T" 4 binfera-ghidra/data/golang32.pack
cargo test --release -p binfera-ghidra --features native --test native go_pack
```

The script's header documents the record format: per function, which operating systems and Go releases have which signature; per named type, which definition each release has. Functions with type parameters and interface methods are left out, and so is any function whose types do not all resolve. The test decodes every record for four platform and release pairs through the engine.

## Kernel and native Windows APIs

The shipped Windows packs also include MinGW-w64 14.0.0's public-domain DDK (`ntifs.h`, `ntddk.h`, `wdm.h`, `ndis.h` and their dependencies), plus ReactOS 0.4.15's public-domain [`fltkernel.h`](https://github.com/reactos/reactos/blob/0.4.15-release/sdk/include/ddk/fltkernel.h). This adds 2,431 x64 and 2,440 x86 prototypes, including `IoCreateDevice`, `ExAllocatePoolWithTag`, `ZwCreateFile`, `NtCreateFile`, `RtlInitUnicodeString`, HAL, NDIS and filter-manager functions. Unlisted APIs remain unknown. This is a header snapshot, not the complete current WDK.

Regenerate with Ghidra 12.1.4 and MinGW-w64 14.0.0 (the checked-in packs used Homebrew `mingw-w64 14.0.0_3`, GCC 16.2.0). Set `MINGW_INCLUDE` to the target compiler's include directory. Run from the repository root. Use a temporary project directory outside a dot-prefixed directory:

```sh
work_dir=$(mktemp -d)
T="$GHIDRA_HOME/Ghidra/Features/Base/data/typeinfo"
curl -fsSL https://raw.githubusercontent.com/reactos/reactos/0.4.15-release/sdk/include/ddk/fltkernel.h \
  -o "$work_dir/fltkernel.h"
# x64; for x86 use i686-w64-mingw32-gcc, its include directory, imports32.sys,
# windows_vs12_32.gdt, generic_clib.gdt and winapi32.pack below.
python3 -I scripts/decompiler_types/prepare_kernel_headers.py \
  x86_64-w64-mingw32-gcc "$MINGW_INCLUDE" "$work_dir/fltkernel.h" "$work_dir/kernel.h"
"$GHIDRA_HOME/support/analyzeHeadless" "$work_dir" kernel \
  -import binfera/tests/fixtures/kernel/imports64.sys -noanalysis \
  -scriptPath scripts/decompiler_types \
  -postScript ParseKernelHeaders.java "$work_dir/kernel.h" "$work_dir/kernel.gdt" \
  -postScript ExportPrototypes.java "$work_dir/proto.tsv" \
  "$T/win32/windows_vs12_64.gdt" "$T/generic/generic_clib_64.gdt" "$work_dir/kernel.gdt" \
  -deleteProject
python3 -I scripts/decompiler_types/pack_prototypes.py "$work_dir/proto.tsv" binfera-ghidra/data/winapi64.pack
python3 scripts/decompiler_types/supplement_prototypes.py windows 8 binfera-ghidra/data/winapi64.pack
cargo test --release -p binfera-ghidra --features native packed_archive
cargo test --release -p binfera --features decompiler --test decompiler_kernel
```

The preprocessor verifies the ReactOS header's SHA-256, omits compiler intrinsics and the unused GCC `max_align_t`, enables both legacy and NDIS 6 declarations, and supplies the opaque transaction pointer missing from MinGW. It fixes a missing comma in MinGW's `NdisMWanIndicateReceiveComplete` declaration. Calling-convention attributes become Ghidra's `__stdcall`, `__fastcall` and `__cdecl` keywords; alignment attributes and packing directives are retained. The exporter follows bitfield base types and records only root type references, so a callback's return type cannot be replaced by the callback definition. Existing Win32 and C library functions retain priority on name clashes. No compiler, Java, headers or download is needed at build time or runtime.

## Win32 metadata (`winapi64.pack`, `winapi32.pack`)

After the Ghidra export, the kernel supplement and `supplement_prototypes.py`, `pack_win32_metadata.py` adds what Microsoft's Win32 metadata describes and the archives lack: prototypes (WinINet, WinHTTP, Toolhelp, BCrypt, netapi, GDI+, LDAP, and the APIs added after Windows 8), and every struct, union, enum, handle typedef and callback typedef of the metadata, whether or not a prototype refers to it (PE headers, loader records, flag sets). Existing entries keep priority: a function or type name the pack already has is referenced as it is and never replaced, so only calls that had no prototype change.

Sources, pinned. Download once, outside the repository; nothing is downloaded at build time or analysis time:

| Input | Pin | SHA-256 |
|---|---|---|
| `Windows.Win32.winmd`, from [microsoft/windows-rs](https://github.com/microsoft/windows-rs) at commit `2670070e0a7d31ff6309d61890fcbc9a5799e456` (release 71, 2025-10-06), path `crates/libs/bindgen/default/Windows.Win32.winmd`, 24 MB | `https://raw.githubusercontent.com/microsoft/windows-rs/2670070e0a7d31ff6309d61890fcbc9a5799e456/crates/libs/bindgen/default/Windows.Win32.winmd` | `97d24cf1a9dc3e50782bbf1dba0952bf6a025fa583d8b3ae6c5ef713b463c869` |
| `windows-metadata` crate 0.100.0 (reads the file) | `Cargo.toml` pins `=0.100.0`; `Cargo.lock` in `win32_metadata/` has the checksums | |

windows-rs publishes the file under MIT OR Apache-2.0. The Microsoft NuGet package `Microsoft.Windows.SDK.Win32Metadata` carries the same data (more functions in some namespaces) under the Windows SDK license terms, which require acceptance, so it is not used. The data describes the Windows SDK headers: confirm the licensing before a pack with this data ships.

```sh
curl -fsSL -o "$work_dir/Windows.Win32.winmd" https://raw.githubusercontent.com/microsoft/windows-rs/2670070e0a7d31ff6309d61890fcbc9a5799e456/crates/libs/bindgen/default/Windows.Win32.winmd
echo "97d24cf1a9dc3e50782bbf1dba0952bf6a025fa583d8b3ae6c5ef713b463c869  $work_dir/Windows.Win32.winmd" | shasum -a 256 -c
# The dumper is a standalone crate outside the workspace, so no shipped binary depends on it.
cargo run --release --manifest-path scripts/decompiler_types/win32_metadata/Cargo.toml -- \
  "$work_dir/Windows.Win32.winmd" "$work_dir/win32.tsv"
python3 scripts/decompiler_types/pack_win32_metadata.py x64 "$work_dir/win32.tsv" binfera-ghidra/data/winapi64.pack
python3 scripts/decompiler_types/pack_win32_metadata.py x86 "$work_dir/win32.tsv" binfera-ghidra/data/winapi32.pack
python3 scripts/test_win32_metadata_pack.py
cargo test --release -p binfera-ghidra --features native --test native -- packed_archive win32_metadata
```

Run the two commands on packs freshly produced by the earlier steps; running them again on their own output changes nothing. What the generator does:

* Calling conventions and sizes follow the Ghidra-derived entries of the same pack: `__stdcall` (x86 with the callee's stack cleanup computed by the engine, as for the archive prototypes) or `__cdecl` for variadic and cdecl exports, 8-byte pointers on x64 and 4-byte on x86, builtin type ids shared with the archive types.
* Types use the names of the metadata; where the pack already has a type of that name (`HANDLE`, `DWORD`, `LPCWSTR`, `_GUID`'s typedef) the existing type is referenced. Layouts (alignment, packing, unions, anonymous members) are computed per architecture; an existing struct's size is used where an array of it is laid out, so the sizes agree. Bitfield members appear as their storage integer. Interfaces appear as a pointer-sized record with a `lpVtbl` pointer: vtable layouts are the COM pack's job.
* A parameter whose type is an enum or flag set in the metadata keeps its integer type in the prototype, so printing does not change. The association is recorded in a `P:<function>` entry, `<parameter index>=<enum name>`, with a `+` after the name of a flag set (`P:VirtualAlloc` is `2=VIRTUAL_ALLOCATION_TYPE+;3=PAGE_PROTECTION_FLAGS+`). `P:` entries exist for functions that already had a Ghidra-derived prototype too. The decompiler and the pack validation ignore them; a symbolic-constants pass reads them.
* A function exported by several DLLs under one name takes the first DLL alphabetically. Data constants (`#define` values that belong to no enum) are not included.
* The `windows-metadata` reader panics on an inline function-pointer type in a struct field. The dumper catches that and records `void *` for the field; this pinned file has no function it cannot read.

`binfera/src/decompiler.rs` (`system_import_function`) applies prototypes only to imports of a listed system DLL. The DLLs the metadata adds (`gdiplus`, `wldap32`, `winspool`, `uxtheme`, `hid`, ...) are listed there.

## Coverage

`coverage.py` measures how many named PE imports reach the decompiler without a prototype, over `tests/testfiles` (or `--corpus DIR`), per DLL and per API. It separates a missing pack entry from a DLL missing in the allow-list above. It needs a built `binfera` (`--binfera PATH`).

## Darwin (`macos64.pack`)

Export from Ghidra 12.1.4 with a linked x86-64 Mach-O as the program. The macOS 10.9 archive takes precedence over the generic 64-bit C archive:

```sh
work_dir=$(mktemp -d)
T="$GHIDRA_HOME/Ghidra/Features/Base/data/typeinfo"
"$GHIDRA_HOME/support/analyzeHeadless" "$work_dir" macos \
  -import binfera/tests/fixtures/macho/thin-x86_64-exe -noanalysis \
  -scriptPath scripts/decompiler_types -postScript ExportPrototypes.java \
  "$work_dir/macos.tsv" "$T/mac_10.9/mac_osx.gdt" "$T/generic/generic_clib_64.gdt" -deleteProject
python3 -I scripts/decompiler_types/pack_prototypes.py "$work_dir/macos.tsv" binfera-ghidra/data/macos64.pack
python3 scripts/decompiler_types/supplement_prototypes.py darwin 8 binfera-ghidra/data/macos64.pack
cargo test -p binfera-ghidra --features native --test native darwin_archive
```

The pack contains 14,256 prototypes including the fixed-signature supplement and 3,250 types. Native loading converts array parameters to pointers and refuses unsupported storage. One x86-64 aggregate and six Go-import signatures remain untyped, as enumerated by the archive test. AArch64 decodes the entire archive. `binfera/data/MachOFunctionsThatDoNotReturn` is copied unchanged from the same release's `Ghidra/Features/Base/data` directory. This data is covered by Ghidra's Apache-2.0 license.


## Fixed C ABI declarations missing from the archives

After the ordinary archive export (and kernel supplement on Windows), run the matching command below. Use `python3` without `-I` so the script can import its sibling pack writer. No downloaded headers or Ghidra installation are needed for this final step.

```sh
python3 scripts/decompiler_types/supplement_prototypes.py linux 4 binfera-ghidra/data/sysv32.pack
python3 scripts/decompiler_types/supplement_prototypes.py linux 8 binfera-ghidra/data/sysv64.pack
python3 scripts/decompiler_types/supplement_prototypes.py windows 4 binfera-ghidra/data/winapi32.pack
python3 scripts/decompiler_types/supplement_prototypes.py windows 8 binfera-ghidra/data/winapi64.pack
python3 scripts/decompiler_types/supplement_prototypes.py darwin 8 binfera-ghidra/data/macos64.pack
```

The supplement adds 28 distinct function names across the five packs (45 entries). Existing archive entries always take precedence. Repeating this step produces identical bytes. Only fixed scalar/pointer ABI descriptions are supplied, with opaque pointer types where full structure or callback definitions are unnecessary for call storage. These are not complete SDK headers or models of Objective-C message dispatch.

- Linux and Darwin: `dlopen`, `dlsym`, `dlclose`, `dlerror`, `__stack_chk_fail`. Linux also gets `__stack_chk_fail_local`. Loader declarations follow the platform `dlfcn.h`; the stack protector is a zero-argument, nonreturning function, as in [glibc's implementation](https://github.com/bminor/glibc/blob/master/debug/stack_chk_fail.c).
- Darwin: 13 fixed Objective-C ownership/runtime helpers plus `CFRunLoopStop`, `CFRunLoopWakeUp` and `CFRunLoopPerformBlock`. Declarations follow [Clang's ARC runtime specification](https://clang.llvm.org/docs/AutomaticReferenceCounting.html), [Apple's runtime header](https://github.com/apple-oss-distributions/objc4/blob/main/runtime/objc-internal.h) and the macOS SDK's `CoreFoundation/CFRunLoop.h`. `objc_msgSend` remains untyped: its actual arguments and return ABI depend on the selected method.
- Windows: `NtReadVirtualMemory`, `NtWriteVirtualMemory` and their `Zw` counterparts, plus `_initterm` and `_initterm_e`. Native declarations follow [ReactOS 0.4.15's NDK header](https://github.com/reactos/reactos/blob/0.4.15-release/sdk/include/ndk/mmfuncs.h) and Microsoft's [Nt/Zw parameter equivalence](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-nt-and-zw-versions-of-the-native-system-services-routines). CRT declarations follow [Microsoft's documentation](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/initterm-initterm-e). The x86 native calls use `__stdcall` with five arguments; CRT calls use `__cdecl`.

Native archive tests decode the supplements on every supported model. Call reconstruction fixtures verify loader argument/return storage on x86, x64 and AArch64, plus consecutive x86 `ZwReadVirtualMemory` calls to check stack cleanup. The Python harness checks archive precedence and deterministic regeneration.

The Windows supplement also includes `DeleteUrlCacheEntryA/W`, a one-pointer Win32 stdcall API with a BOOL result. Source: [Microsoft wininet.h documentation](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-deleteurlcacheentrya). Bare A/W export aliases use the ANSI signature only when both variants exist.
