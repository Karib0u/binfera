# Decompiler

Binfera embeds Ghidra's C++ decompiler and its SLEIGH processor specs, pinned to **Ghidra 12.1.4**. There is no JVM, no Python, no network access and no commercial engine. Binfera's own Rust code loads the file, finds the functions and supplies names and types; Ghidra turns each function into C.

Input code is never executed.

## At a glance

| Format | Architectures | Calling conventions | Library names | API types |
|---|---|---|---|---|
| **PE** | x86-64, x86, AArch64, ARM32/Thumb | Windows, Delphi, Borland | FLIRT, Function ID | Win32, C library, kernel |
| **ELF** | x86-64, x86, AArch64, ARM32/Thumb, MIPS32 | System V, AAPCS, MIPS o32 | Symbols, DWARF | C library |
| **Mach-O** | x86-64, arm64, arm64e | Darwin, Apple AArch64 | Symbols, Objective-C, Swift | macOS 10.9 SDK |
| **Shellcode** | x86, x86-64 | Windows or System V | — | — |
| **Objects** (`.o`, `.ko`) | x86, x86-64, AArch64, ARM32/Thumb, MIPS32 | as ELF | Symbols | C library |

Go, Rust and C++ binaries get language-specific handling on top of this; see [Languages](#languages). .NET assemblies get capability analysis and IL listings, not decompilation.

## Use it

Released builds of the CLI, the desktop app and [binfera.io](https://binfera.io) include the decompiler. Building from source, it is an optional feature that needs a C++14 compiler and zlib on macOS and Linux, or the Visual Studio Build Tools on Windows.

```sh
cargo build --release -p binfera-cli --features decompiler
```

=== "One function"

    ```sh
    binfera sample.exe --decompile-function 0x140001000
    binfera sample.exe --decompile-function 0x140001000 --json --timing
    ```

    Addresses are virtual addresses, image base included, not file offsets or RVAs.

=== "Every function"

    ```sh
    binfera sample.exe --decompile-all --jobs 4
    binfera sample.exe --decompile-all --shard 0/4
    ```

    Streams one JSON record per line. The first record lists every function, the architecture and any sign of packing. `--jobs` sets the number of native workers (up to 16).

=== "Shellcode"

    ```sh
    binfera payload.bin -f sc64 --decompile-all
    binfera payload.bin -f sc32 --os linux --decompile-function 0x0 --json
    ```

    Bytes are mapped at zero, so addresses are offsets. Windows conventions by default; `--os linux` selects System V.

=== "Mach-O slice"

    ```sh
    binfera universal-app --arch arm64 --decompile-all
    ```

    `--arch` takes `x86_64`, `arm64` or `arm64e` (`amd64` and `aarch64` are aliases). Without it, the first slice in the fat header is used.

=== "Recompilable C"

    ```sh
    binfera sample.exe --decompile-function 0x140001000 --unit > f.c
    clang --target=x86_64-pc-windows-msvc -std=gnu11 -fms-extensions -fsyntax-only f.c
    ```

    `--unit` wraps one or more functions in a C file a compiler accepts. See [Self-contained units](#self-contained-units).

!!! tip "Packed files"
    The first `--decompile-all` record flags packing: known packer sections (UPX, ASPack, MPRESS, Themida, VMProtect…), a UPX header, an executable section above 7.2 bits of entropy per byte, or an executable section with no bytes on disk. A packed file's decompiled code is mostly its unpacking stub.

## Reading the output

Every result says how much to trust it.

| Field | Meaning | Action |
|---|---|---|
| `incomplete` | At least one gap below. | Check the warnings before relying on the code. |
| `warnings` | A real gap: a callee without a known prototype, unresolved flow, a guessed return type, a native error. | Read them. |
| `notes` | Informational only: a modeled runtime call (`replaced with injection: security_check_cookie`), an inferred callee prototype. | None needed. |
| `file_warnings` | Diagnostics about the whole image (bad import table, unsupported relocation). | Shown once per file. |

The most common warning by far is an **unknown callee**: a call whose prototype Binfera does not know, so its arguments or return value may be missing. The warning lists up to eight such call sites.

## Platforms

### Windows PE

- **x86-64** uses the Windows x64 convention. Exception tables (`.pdata`) give exact function bounds.
- **x86** infers `__stdcall`, `__cdecl`, `__fastcall` or `__thiscall` per function and names the convention in the output (`__fastcall FUN_00414a70(...)`).
- **Delphi and Borland C++** are detected the way Ghidra does (Rich header, DOS stub, `CODE` section) and use their register conventions, so arguments in `EAX`/`EDX`/`ECX` are not lost.
- **Imports** from Windows system DLLs are typed from Ghidra's Win32 and C library archives, about 30,700 prototypes, plus kernel and native APIs (`ntoskrnl`, `hal`, `fltmgr`, `ndis`, `ntdll`).
- **Library code** is named by FLIRT signatures and Ghidra's Visual Studio Function ID databases, so `memset` and `strlen` come out named and typed.
- **Runtime helpers** such as `__security_check_cookie`, `__chkstk` and `__SEH_prolog4` are replaced by their modeled effect, as in Ghidra.

!!! note "Not yet"
    PDB files, MinGW-specific runtime names, AVX instructions in Function ID hashes.

### Linux ELF

- **x86-64 and x86** use System V; i386 also gets the `__regparm` variants.
- **Imports and PLT stubs** are named and typed from Ghidra's C library archive. So is a function the image defines under a libc name (a rootkit's `access` hook).
- **Position-independent i386 code**: `__x86.get_pc_thunk.*` and the retpoline thunks are modeled, so global reads don't print as `*(unaff_EBX + n)`.
- **System calls** print as `linux_write`, `linux_mmap`… when the number resolves to a constant, using Linux 6.12's tables.
- **`.eh_frame`** entries seed function discovery, even without section headers.

!!! note "Not yet"
    Library recognition for stripped ELF, `sysenter`. Unbranded System V ELF is assumed to be Linux.

### macOS Mach-O

- **x86-64, arm64 and arm64e**, thin or universal.
- **Imports** through classic dyld bindings, stubs and chained fixups (formats 1–3, arm64e authenticated pointers included).
- **Function starts** from `LC_FUNCTION_STARTS`, exports, symbols, DWARF, Go tables and Objective-C/Swift metadata.
- **Objective-C** class and category methods get their runtime names and scalar signatures; selector references and `objc_msgSend` stubs are labeled.
- **Swift** type descriptors supply qualified type names.
- **Apple APIs** are typed from Ghidra's macOS 10.9 archive, a historical snapshot.

!!! note "Not yet"
    32-bit Mach-O, object files, dSYM bundles, kernel caches, Swift demangling and calling convention, Objective-C class layouts, Go on arm64.

### AArch64

- **PE, ELF and Mach-O**, each with its platform convention (Windows, AAPCS64, Apple).
- PLT entries and import thunks are recognized only after their full `ADRP/LDR/BR` sequence validates.
- ELF relocations: `RELATIVE`, `ABS*`, `PREL*`, `GLOB_DAT`, `JUMP_SLOT`.

!!! note "Not yet"
    COFF objects, ARM64EC, big-endian or ILP32 ELF, TLS/COPY/IRELATIVE relocations, the Go AArch64 ABI, named Linux syscalls. Without a signature, a floating-point return can show as a vector.

### ARM32, Thumb and MIPS32

- **ARM32 and Thumb-2** in little-endian ELF32 and Windows PE32. Thumb mode follows ELF mapping symbols, pointer low bits, entry points and `BLX`. Hard-float ELF is detected from its header.
- **ARM `.ARM.exidx`** entries seed functions, including leaves whose symbols were stripped.
- **MIPS32** (MIPS I/II, o32) in either byte order. Delay slots are handled; `_gp`, `t9` and GOT entries resolve imports.
- Custom FLIRT packs can name library code (`--signatures pack.json`, see below).

!!! note "Not yet"
    Big-endian ARM, MIPS64, n32, EABI, microMIPS, MIPS16, MIPS Release 6. A stripped ARM image with no mode metadata can miss Thumb regions nothing branches to. The bundled x86 signatures and type archives don't apply, so library prototypes may need an explicit signature.

??? info "Custom FLIRT packs for ARM, AArch64 and MIPS"
    ```json
    {"architecture":"arm","signatures":["library.pat","other.sig"]}
    ```

    Architectures are `arm`, `aarch64`, `mips` (big endian), `mipsel`, `x86` and `x64`. Paths are relative to the manifest and cannot leave it; an architecture or byte-order mismatch is an error. Recognized calls become capa `api` features. The web app has no pack chooser yet.

### Relocatable objects

`.o` and `.ko` ELF files are laid out in memory at analysis time, without running module initialization. Supported fixups:

| ISA | Fixups |
|---|---|
| ARM/Thumb | ABS32, REL32, PREL31, MOVW/MOVT pairs, calls and long jumps, direct interworking |
| AArch64 | ABS/PREL 16/32/64, CALL26/JUMP26, ADR/ADRP, ADD and scaled LD/ST low-12 |
| MIPS32 | 32/REL32, 26-bit jumps, HI16/LO16 pairs |

!!! note "Not yet"
    Veneers, GOT/TLS object linking, linker relaxations, MIPS compound relocations, compressed modules. This is not a linker: unsupported fixups produce a diagnostic.

### Raw shellcode

`-f sc32` or `-f sc64`. Recovery follows direct control flow and function starts after padding. With no import table or relocations, dynamically resolved APIs and code reached only indirectly may stay unknown.

## Languages

### Go

Go 1.2 to 1.27, x86 and x86-64, PE and ELF, stripped or not, including memory dumps.

- **Every function is named** from the binary's own table (`os.(*File).Write`).
- **Go's calling conventions**: the register ABI from Go 1.17 on amd64, the stack ABI before and on 386.
- **Standard library signatures** from Ghidra's Go 1.15–1.25 snapshots, with multiple results shown as a structure (`oVar5 = os.OpenFile(name,0,0)`).
- **The goroutine register** reads as `CURRENT_G.stackguard0`, not `unaff_R14`.
- `duffzero`, `duffcopy`, write barriers and bounds-check panics are modeled.

!!! note "Not yet"
    Signatures of the program's own methods, string constants (print as integers), the closure context register, the goroutine on x86 or before Go 1.17, Go on AArch64.

### Rust

- Legacy and v0 symbols are demangled, hashes dropped.
- Allocator shims, `exit`/`abort` and panic helpers get signatures; panics don't return.
- String literals print at their exact length, even without a terminating zero.

!!! note "Not yet"
    Signatures for stripped functions, generic aggregates, `String`/`Vec` layouts.

### C++

- **Names**: Microsoft and Itanium decorations become Ghidra's labels (`Counter::add`, `std::_Lockit::~_Lockit`), wherever the name comes from.
- **Prototypes**: a Microsoft name also gives the method's convention and `this`, so the `ECX` argument appears on x86.
- **MSVC RTTI**: virtual tables are labeled and typed, functions are assigned to their class (`Class::FUN_10001160`), and a virtual call through `this` names its target.
- **MSVC exceptions**: `FuncInfo` v1–v3 tables label catch and unwind funclets and annotate try states in comments.

!!! note "Not yet"
    Class layouts, constructors and destructors, virtual bases, Itanium RTTI, `try`/`catch` syntax, `__CxxFrameHandler4` metadata.

### Debug information (DWARF)

Embedded DWARF 4 and 5, in ELF, PE and Mach-O, compressed or not. It supplies function starts, names, parameter names and types, enums, structures and stack locals with fixed offsets.

!!! note "Not yet"
    Split DWARF, separate type units, debug links, unions and bit fields, register locals and location lists.

## Self-contained units

`--unit` produces C that a compiler accepts, so an extracted function can be rebuilt or studied in isolation. It contains Ghidra's helper macros (`CONCAT44`, `SUB84`…), the types and prototypes the code names, and the functions.

**Every guess is marked.** A declaration that is not backed by the type archives carries a `GUESS` comment and is listed in the JSON `guesses`. A unit with no guesses compiles on the archives alone.

!!! note "Not yet"
    Data and strings have no bytes, enumerators are not declared, indirect calls stay as printed. A unit compiles; it is never run, and a dropped argument still compiles. Units are refused for ELF, Go, Delphi/Borland, C++ or Rust names, DWARF types and functions with MSVC exception handlers.

## Limits

| Limit | Default | Maximum |
|---|---:|---:|
| Time per phase | 10 s | 60 s |
| Instructions per function | 10,000 | 100,000 |
| Work units | 20,000,000 | 200,000,000 |

A request has up to three phases (the function, its data symbols, callee inference), each with the full time limit. A function past the instruction limit is retried with its flow truncated and marked incomplete. `--decompile-all` retries a function that hit a limit once at the maximums (see [the decompilation stream](cli.md#decompilation-stream)).

!!! warning "Not a sandbox"
    Limits are cooperative: a single native operation can overshoot the deadline. The decompiler runs in-process and is not an isolation boundary against an exploit of the native engine.

## Learn more

- [Decompiler design](decompiler-design.md): ownership, discovery, naming, types, inference and tests.
- [Benchmarks](benchmarks.md): speed against Ghidra.
- Provenance: [PINNED.md](https://github.com/Karib0u/binfera/blob/main/PINNED.md), [vendoring notes](https://github.com/Karib0u/binfera/blob/main/third_party/ghidra/README.md), [runtime signatures](https://github.com/Karib0u/binfera/blob/main/binfera/sigs/DECOMPILER.md), [Function ID](https://github.com/Karib0u/binfera/blob/main/binfera/sigs/FID.md).
