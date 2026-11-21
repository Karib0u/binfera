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

windows-rs publishes the file under MIT OR Apache-2.0. The Microsoft NuGet package `Microsoft.Windows.SDK.Win32Metadata` carries the same data (more functions in some namespaces) under the Windows SDK license terms, which require acceptance, so it is not used. The data describes the Windows SDK headers; Microsoft redistributes this file under MIT OR Apache-2.0, which binfera relies on (see `NOTICE`).

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
* A parameter whose type is an enum or flag set in the metadata keeps its integer type in the prototype. The association is recorded in a `P:<function>` entry, `<parameter index>=<enum name>`, with a `+` after the name of a flag set (`P:VirtualAlloc` is `2=VIRTUAL_ALLOCATION_TYPE+;3=PAGE_PROTECTION_FLAGS+`). `P:` entries exist for functions that already had a Ghidra-derived prototype too. A few parameters the metadata leaves as a bare integer take the union of metadata sets that the SDK documents for them (`ASSOCIATIONS` in the generator: CreateFile's access mask is `1=FILE_ACCESS_RIGHTS+|GENERIC_ACCESS_RIGHTS+`, CreateRemoteThread's flags are CreateThread's).
* Every set a `P:` entry names has an `E:<name>` entry, `<kind><TAB><member>=<value>;...` in the metadata's declaration order, kind `f` for a flag set and `e` for an enumeration. The dumper also writes `CN` records for constants whose type is a named type; the constants of the handle types in `HANDLE_CONSTANTS` (only `HKEY`: `HANDLE`'s -1 and `HWND`'s 0 have several meanings) become an `E:` entry of kind `h`. The bridge reads `P:` and `E:` to print constant arguments by name (the symbolic-constants pass, `docs/decompiler-design.md`), and the pack validation checks that every `P:` association has its `E:` entries. `P:` and `E:` entries are rewritten on every run; the rest keeps priority.
* A function exported by several DLLs under one name takes the first DLL alphabetically. Data constants (`#define` values that belong to no enum) are not included.
* The `windows-metadata` reader panics on an inline function-pointer type in a struct field. The dumper catches that and records `void *` for the field; this pinned file has no function it cannot read.

`binfera/src/decompiler.rs` (`system_import_function`) applies prototypes only to imports of a listed system DLL. The DLLs the metadata adds (`gdiplus`, `wldap32`, `winspool`, `uxtheme`, `hid`, ...) are listed there.

## Native API (`Nt*`, `Zw*`, `Rtl*`, `Ldr*`) and the loader structures

`winapi64.pack` and `winapi32.pack` also hold the user-mode native API of the [phnt](https://github.com/winsiderss/systeminformer/tree/bfef6c7e7d419bb3dea195eb8149b80f3574d324/phnt) headers of System Informer (MIT licence, "Copyright (c) 2022 Winsider Seminars & Solutions, Inc."; the `LICENSE.txt` of that commit has SHA-256 `e2a4557d2c4e70276b0ddaa31f35e2ce075281dac7e60ac07ca32c7cf58c1820`), pinned to commit `bfef6c7e7d419bb3dea195eb8149b80f3574d324` (2026-11-20), directory `phnt/include`. 1,613 x64 and 1,608 x86 prototypes (`NtQuerySystemInformation`, `NtCreateThreadEx`, `LdrLoadDll`, `LdrGetProcedureAddress`, `RtlAdjustPrivilege`, ...) and about 800 types are added, among them `_PEB`, `_TEB`, `_PEB_LDR_DATA`, `_LDR_DATA_TABLE_ENTRY` and `_RTL_USER_PROCESS_PARAMETERS` with the field offsets Windows uses (`_PEB.Ldr` at 0x18 on x64 and 0xc on x86, `_TEB.ProcessEnvironmentBlock` at 0x60 and 0x30, `_LDR_DATA_TABLE_ENTRY.DllBase` at 0x30 and 0x18). They are parsed by Ghidra's C parser as the kernel supplement is. The headers are for the Windows 11 24H2 build (`PHNT_WINDOWS_11_24H2`).

Existing entries keep priority; an existing `_TEB` (the kernel headers declare it empty) does not block the phnt one, which is added under its own id. The Win32 metadata pack's `PEB`, `TEB`, `PEB_LDR_DATA` and `LDR_DATA_TABLE_ENTRY` typedefs (the public declarations with `Reserved` members) stay as they are.

```sh
export GHIDRA_HOME=$HOME/tools/ghidra_12.1.4_PUBLIC
work_dir=$(mktemp -d)
git clone https://github.com/winsiderss/systeminformer "$work_dir/si" && git -C "$work_dir/si" checkout bfef6c7e7d419bb3dea195eb8149b80f3574d324
# x64; for x86 use i686-w64-mingw32-gcc, its include directory, imports32.sys and winapi32.pack.
python3 -I scripts/decompiler_types/prepare_phnt_headers.py x86_64-w64-mingw32-gcc "$MINGW_INCLUDE" \
  "$work_dir/si/phnt/include" "$work_dir/phnt.h"
"$GHIDRA_HOME/support/analyzeHeadless" "$work_dir" phnt -import binfera/tests/fixtures/kernel/imports64.sys -noanalysis \
  -scriptPath scripts/decompiler_types \
  -postScript ParseKernelHeaders.java "$work_dir/phnt.h" "$work_dir/phnt.gdt" \
  -postScript ExportPrototypes.java "$work_dir/phnt.tsv" \
  roots=_PEB,_TEB,_PEB_LDR_DATA,_LDR_DATA_TABLE_ENTRY,_RTL_USER_PROCESS_PARAMETERS,_CLIENT_ID,_TEB_ACTIVE_FRAME,_ACTIVATION_CONTEXT_STACK \
  "$work_dir/phnt.gdt" -deleteProject
python3 -I scripts/decompiler_types/merge_phnt_export.py "$work_dir/phnt.tsv" "$work_dir/si/phnt/include" binfera-ghidra/data/winapi64.pack
cargo test --release -p binfera-ghidra --features native --test native -- packed_archive native_api
```

(Use a temporary project directory outside a dot-prefixed directory, as for the kernel supplement; `-deleteProject` removes it.) Run it on a pack that already has the Win32 metadata. What the preparation does: it preprocesses a copy of `phnt.h` with MinGW-w64 14.0.0 after dropping the includes that need Windows SDK files MinGW lacks (`ntnsi.h`, `ntuser.h`, `ntwmi.h`, `nthv.h`, `ntsam.h`, `ntlsa.h`, `ntpoapi.h`, ... : see `DROPPED`), replaces the bodies of MinGW's inline functions (assembly that Ghidra's parser cannot read) with semicolons, and defines the SAL and `DECLSPEC` macros MinGW lacks as empty. `merge_phnt_export.py` adds only the functions that the phnt headers declare with `NTAPI` (the archive also holds every function of `windows.h`), the types they and the roots reach, and renumbers the type ids. A structure of bitfields inside a union cannot be decoded by the engine, so each run of bitfields at one offset is exported as one field of the base type, named after its first bit (`ImageUsesLargePages_bits`); the layout is unchanged. One prototype, `RtlLocateExtendedFeature2`, takes a structure by value that x86 cannot place and is left out.

Not covered: the phnt headers that need NDIS or window-system types (`ntnsi.h`, `ntuser.h`, ...), Hyper-V (`nthv.h`), and the kernel-only `Ke*`/`Ex*`/`Mm*` functions, which the kernel supplement covers.

## C runtime startup and helper exports

`supplement_prototypes.py` (the Windows list) declares MSVCRT and UCRT startup and helper exports that neither the Ghidra archives nor the Win32 metadata describe: `__p__fmode`, `__p___argc`, `__p___argv`, `__getmainargs`, `__set_app_type`, `_set_app_type`, `_crt_atexit`, `_configure_narrow_argv`, `_initialize_narrow_environment`, `_initialize_onexit_table`, `_register_onexit_function`, `_seh_filter_exe`, `__acrt_iob_func`, `__stdio_common_vfprintf` and its siblings, `__current_exception`, `terminate`, `_except_handler3`, `__CxxFrameHandler` and others (44 in all that were missing). The declarations follow the UCRT's documented signatures (`corecrt_startup.h`, `corecrt_stdio_config.h`, Microsoft's [C runtime reference](https://learn.microsoft.com/en-us/cpp/c-runtime-library/c-run-time-library-reference)) and use only fixed scalar and pointer types.

The pack is looked up by function name, never by DLL: the API-set DLLs of the UCRT (`api-ms-win-crt-*-l1-1-0.dll`, which arrive from the importer as `api_ms_win_crt_*`) are accepted by their prefix in `system_import_function`, and the CRT DLLs `msvcr70` to `msvcr120`, `msvcr100d` to `msvcr120d`, `ucrtbased`, `vcruntime140`, `vcruntime140d` and `crtdll` are listed there with the rest. Data exports (`_acmdln`, `_iob`, `_fmode`, `_adjust_fdiv`) are not functions and stay untyped.

## Decorated C++ imports

No pack holds the decorated names that `msvcrt.dll` and the other CRT DLLs export (`??2@YAPAXI@Z`, `operator new`; `?terminate@@YAXXZ`). When the pack has no entry for an import, `binfera/src/decompiler.rs` takes the prototype from the decoration, through the Microsoft demangler (`demangle::Prototype`): calling convention, `this` for a method, and the result and parameter types, only when every type is a scalar or a pointer. Imports of a DLL outside the allow-list already took this path; the fallback now also applies to the listed DLLs. Decorated names whose types are classes, references to classes or by-value structures stay untyped: they need the class's declaration, which no pack has. Itanium names carry no result type and are not used for a result.

## Coverage

`coverage.py` measures how many named PE imports reach the decompiler without a prototype, over `tests/testfiles` (or `--corpus DIR`), per DLL and per API. It separates a missing pack entry from a DLL missing in the allow-list above. It needs a built `binfera` (`--binfera PATH`). `--json FILE` also lists the untyped imports of each file (`per_file`). `scripts/bench/quality.py` imports its lookup to report untyped imports next to unresolved indirect calls and numeric API arguments, base against head; the CI subset is `scripts/corpus-quality.txt`.

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
