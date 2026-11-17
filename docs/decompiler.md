# Native function decompilation

Build the optional backend with a C++14 compiler and zlib headers/library on macOS and Linux, or Visual Studio Build Tools (MSVC, which builds its own zlib) on Windows:

```sh
cargo build --release -p binfera-cli --features decompiler
./target/release/binfera sample.exe --decompile-function 0x140001000
./target/release/binfera sample.exe --decompile-function 0x140001000 --json --timing
```

For the browser, the same code builds for `wasm32-unknown-emscripten` (C++ exceptions and zlib come from Emscripten); see [`web/README.md`](https://github.com/Karib0u/binfera/blob/main/web/README.md). The build-time SLEIGH compiler still runs on the build host. `--decompile-all --shard INDEX/COUNT` splits the work so the browser can run several workers in parallel; see the web README for the one caveat on byte-for-byte equality with an unsharded run. Its first record names the architecture (`x86`, `x64`, `aarch64`, `arm`, `mips` or `mipsel`) and, under `packed`, any sign that the file is packed: packer section names (UPX, ASPack, MPRESS, Themida, VMProtect and others), UPX's own header, an executable section above 7.2 bits of entropy per byte, or an executable section with no bytes on disk next to other code. A packed file's decompiled code is mostly its unpacking stub.

The scope is native x86-64, x86-32 and little-endian AArch64 PE and ELF files, ARM32/Thumb PE32 and little-endian ELF32, classic MIPS32 o32 ELF in either byte order, plus x86-64 and AArch64 Mach-O images and explicitly selected x86 shellcode. Managed images support capability extraction, but do not use this native decompiler. The x86-64 PE path uses the Windows x64 calling convention; the x86-32 PE path is described under [x86-32](#x86-32), PE32 programs built by Delphi or Borland C++ under [Delphi and Borland C++](#delphi-and-borland-c), ELF under [ELF](#elf-system-v), Go programs on either format under [Go](#go), and C++ names and classes under [C++](#c). `DecompilerSession::from_bytes` (and the CLI) picks the format by the file's magic. Addresses are hexadecimal virtual addresses, including the image base, not file offsets or RVAs. One function is requested per call, or several with `--unit` (below). The CLI emits C-like text, or a dedicated JSON result with address, optional name, convention, text, warnings, notes and incomplete status. `--timing` adds measured initialization and function timing to JSON. Without it, JSON is deterministic across job counts. Rule files are unnecessary. Normal capability analysis never initializes this backend. A binary built without the feature gives an actionable error for the flag. `--jobs` sets the thread count for capability analysis; with `--decompile-all` it sets the number of native worker processes (up to 16, default 1).

The native library embeds compiled SLEIGH, processor and compiler specs. There is no runtime JVM, Python, network access, external disassembler or commercial engine. The build-time native SLEIGH compiler is built from the same pinned source. See [PINNED.md](https://github.com/Karib0u/binfera/blob/main/PINNED.md) and the [vendoring notes](https://github.com/Karib0u/binfera/blob/main/third_party/ghidra/README.md).

## Raw shellcode

Use `-f sc32` or `-f sc64` with either decompilation flag. Raw bytes are mapped at zero, so addresses are offsets in the input and the initial entry is `0x0`. Windows calling conventions are the default; `--os linux` selects System V. The input is decoded statically and is never executed.

```sh
binfera payload.bin -f sc64 --decompile-all
binfera payload.bin -f sc32 --os linux --decompile-function 0x0 --json
```

The Rust API is `DecompilerSession::from_shellcode_with_analysis(bytes, convention)`. Recovery follows direct control flow and validated starts after padding. Raw inputs have no import table or relocation metadata, so dynamic API resolution, embedded data and indirect-only entries can remain uncertain or undiscovered.

## ARM32, Thumb and MIPS32

The native and browser engines use the existing pinned Ghidra 12.1.4 processor and compiler specifications. ARM/Thumb share `ARM7_le.slaspec`; MIPS uses `mips32le.slaspec` or `mips32be.slaspec`. The build compiles and embeds these unchanged upstream sources, with no Ghidra version change. Capstone provides structured instruction decoding for recovery and capability extraction, including builds without the optional decompiler. Input code is never executed.

- ARM32 little-endian ELF32 executables, PIEs and shared libraries use AAPCS. `EF_ARM_ABI_FLOAT_HARD` selects the hard-float model; other images use the soft-float argument convention. Explicit floating-point signatures are supported.
- Thumb and Thumb-2 mode follows ELF mapping symbols, function-pointer low bits, entry points and direct BLX interworking. Internally code addresses are even. IT-predicated transfers retain their fallthrough paths.
- Windows ARM PE32 uses the pinned Windows ARM compiler model. ARMNT/THUMB images default to Thumb, while legacy ARM images default to ARM mode.
- Classic MIPS32, MIPS I and MIPS II ELF32 use the o32 model in either byte order. Normal delay slots execute on both branch paths; branch-likely slots execute on the taken path. Dynamic GOT entries, `_gp` and PIC entry register `t9` inform import resolution and decompilation.

Rules accept `arch: arm` for ARM/Thumb and `arch: mips` for both MIPS byte orders. Browser image metadata distinguishes `mips` (big endian) and `mipsel` (little endian). Code features include mnemonics, immediates, memory offsets, referenced strings, resolved imported APIs and call characteristics. Pointer relocations are handled according to the pinned Ghidra ARM/MIPS ELF relocation handlers; unsupported kinds produce diagnostics. Linked-image fixups do not execute dynamic resolvers; supported object linking is described below. The x86 FLIRT/FID packs and x86 C type archives are not applied to these architectures. Library prototypes may therefore need an explicit signature.

Not covered: big-endian ARM, 32-bit Mach-O, MIPS64, n32, EABI, microMIPS, MIPS16, MIPS Release 6. Unsupported MIPS ISA/ABI profiles retain file metadata and receive an explicit code-analysis diagnostic. Stripped ARM images without mode metadata depend on reachable interworking transfers; there is no general heuristic for every embedded Thumb region.

`binfera/tests/risc.rs` uses source-built fixtures for both byte orders, mixed ARM/Thumb calls, Windows PE, shared-library imports, IT returns, MIPS delay slots, soft/hard-float signatures and stack parameters. The floating-point check compiles and executes only emitted C from the trusted fixture. Static corpus entry probes also produced output for ARM/Thumb Mirai/Vo1d and MIPS Mirai/AcidRain; they retained incomplete-analysis warnings and do not establish whole-corpus correctness.

```sh
cargo test -p binfera --features decompiler --test risc
cd web
npm run build:wasm
npm run test:risc
```

## Relocatable objects and per-ISA recovery

Uncompressed ELF `ET_REL` inputs, including `.o` and `.ko`, use a bounded synthetic section layout. ARM/Thumb, little-endian AArch64 and classic MIPS32 in both byte orders now share the existing x86 section and external-symbol allocator. BSS and aligned `SHN_COMMON` storage are mapped without executing module initialization. The file extension does not select the loader.

The initial non-x86 relocation coverage is:

| ISA | Implemented object fixups |
| --- | --- |
| ARM/Thumb | ABS32, REL32, PREL31, MOVW/MOVT absolute and relative pairs, ARM/Thumb calls and long jumps, supported direct interworking calls |
| AArch64 | ABS/PREL 16/32/64, CALL26/JUMP26, ADR/ADRP, ADD and scaled LD/ST low-12 fixups |
| MIPS32 | 32/REL32, 26-bit jumps, paired HI16/LO16 with signed low-half carry in either byte order |

The formulas follow the pinned Ghidra relocation handlers and the Arm ELF ABI specifications. Fixups cannot escape their target section. Invalid alignment, branch range and relevant instruction classes are checked. Unpaired MIPS high halves and unsupported fixups produce bounded diagnostics. MIPS `_gp_disp` and `__gnu_local_gp` are diagnosed instead of being assigned fabricated GP values. Out-of-range veneers, GOT/TLS object linking, architecture-specific linker relaxations, MIPS compound/micro relocations and compressed modules remain outside this initial implementation. This is analysis-time layout, not a replacement system linker or kernel loader.

ARM EHABI `.ARM.exidx` entries now seed functions and preserve boundaries, including unreferenced leaves whose symbol table was removed. PREL31 values are read from the relocated image. Invalid sizes, unordered/out-of-code addresses and entry limits are diagnosed without trusting a partial table. Thumb mode still needs a valid mode source, such as mapping symbols, an entry point or interworking. Relocated `.eh_frame` bytes likewise supply object-file unwind entries. MIPS capability reference tracking keeps arguments alive through a call's delay slot and discards caller-saved values after the slot executes.

For additional library names, pass an explicit FLIRT manifest to capability analysis with `--signatures pack.json`:

```json
{"architecture":"arm","signatures":["library.pat","other.sig"]}
```

Architectures are `arm` (ARM/Thumb), `aarch64`, `mips` (big endian), `mipsel` (little endian), `x86` and `x64`. Files are relative to the manifest directory; paths cannot escape the pack. A CPU or byte-order mismatch is an error. The existing FLIRT matcher validates patterns, CRCs, reference names and conflicts. Recognized library calls become capa `api` features for ARM/Thumb, AArch64 and MIPS. Untagged packs retain x86 PE-only behavior; no x86 FID hashes are reused for another ISA. Large bundled per-ISA library collections and native Ghidra FID instruction-mask parity remain ongoing work. The web UI does not yet provide a custom-pack chooser.

Source-built fixtures and tests are in `binfera/tests/risc_rel.rs`, `binfera/tests/arm_unwind.rs` and `binfera/tests/risc_signatures.rs`. The checked objects are trusted test artifacts and are analyzed statically.

## AArch64

AArch64 PE32+ uses Ghidra's `AARCH64_win.cspec`; ELF64 executables, PIEs, shared libraries and supported objects use `AARCH64.cspec` (AAPCS64). Both translate instructions with the pinned `AARCH64.slaspec`. Integer arguments use x0-x7, floating-point arguments use v0-v7, and further arguments use the stack. Mach-O uses `AARCH64_apple.cspec`, including Apple's stack and variadic argument rules.

ELF PLT and Windows import thunks are recognized only after validating their complete `ADRP/LDR/[ADD]/BR` sequence, including the branch register and optional BTI. Their names, platform import prototypes and call-return flow reach the decompiler. Tail-only PLT entries are included even when recovery originally included them in a caller. AArch64 skips x86 FLIRT/Function ID packs, x86 register heuristics and x86 syscall overrides.

The ELF loader applies RELATIVE, ABS16/32/64, PREL16/32/64, GLOB_DAT and JUMP_SLOT relocations with explicit RELA addends or stored REL addends. Defined symbols resolve inside the image; undefined pointer slots retain external bindings. Invalid addresses, invalid symbol indices, narrow overflow and unsupported relocations produce errors or diagnostics. PE images load at their preferred base, so their linked ARM64 instruction operands and DIR64 pointers require no rebasing. Standalone COFF objects and Mach-O object relocations remain unsupported, as do TLS/COPY/IRELATIVE relocation execution, big-endian/ILP32 ELF, ARM64EC and the AArch64 Go ABI. Mach-O loading is described below. No code from the input is executed.

Source-built fixtures in `binfera/tests/fixtures/aarch64_decompiler` exercise integer, floating-point and stack arguments, local and imported calls, PIE/shared relocations, malformed records and ordinary supervisor calls. Scalar and vector returns share v0; without debug information or a supplied signature an FP result can remain a vector. AArch64-specific Rust runtime fixups and named Linux syscalls are not implemented.

The compiled SLA is 495,185 bytes (483.6 KiB); the build enforces a 2 MiB limit for this embedded spec. Linux and Windows reuse the existing 64-bit type packs. No additional signature download is needed in the browser. The Emscripten release build and Node smoke checks pass for ELF/PE fixtures and all three pinned AArch64 corpus entry points; the corpus check only establishes that those entries decompile, not whole-program correctness.

## Mach-O

Automatic detection reaches capability extraction in the CLI, Python API and browser, and native decompilation in the Rust API, CLI and browser. Linked little-endian x86-64, arm64 and arm64e images are supported. Universal files use fat-header order by default; `--arch x86_64`, `arm64` or `arm64e` selects a slice. `amd64` and `aarch64` are aliases. Standard, swapped and 64-bit fat directories are checked against the selected thin header. Recovery, symbols and embedded DWARF all use the same slice; sample hashes still describe the complete input.

```sh
binfera universal-app --arch arm64 --decompile-all
binfera app --decompile-function 0x100000510 --json
```

`DecompilerSession::from_macho(bytes, arch)` opens a selected slice; `from_bytes_with_arch_and_analysis` returns its recovery alongside the session. x86-64 uses the Darwin System V convention and AArch64 uses Apple's compiler specification. Go amd64 retains its Go ABI, Darwin standard-library signatures and embedded DWARF. Linux syscall annotations are disabled for Darwin. Existing Rust and C++ name demanglers apply to Mach-O symbols.

The loader reads classic dyld bindings, indirect symbols, stubs and chained-fixup import formats 1, 2 and 3. It resolves 64/64-offset and arm64e userland pointer formats 1, 2, 6, 9 and 12, including authenticated rebases. Rebases are applied to mapped bytes before metadata and code analysis. Chains are bounded by payload, import table, page and total-step limits. Unsupported pointer formats and compressed fixup symbol pools produce diagnostics. Kernel caches are not supported. Headers, constants and metadata in executable segments are excluded from code recovery.

Function starts come from LC_FUNCTION_STARTS, exports, symbols, Go tables, embedded DWARF and Objective-C/Swift metadata. Objective-C 2 class and category methods, including relative method lists, get their runtime names; scalar method encodings provide signatures. Selector references are labeled, and ARM64 selector-specific objc_msgSend stubs are named for their selector. Common Objective-C allocation and reference-counting helpers are typed. A dynamic receiver or an unknown method signature still produces unknown-callee warnings; selector names alone do not prove the receiver type or the argument ABI. Aggregates, protocols and full Objective-C class layouts are not reconstructed. Swift 5 type descriptors supply qualified type names and metadata-accessor starts. Swift symbol demangling, generic layouts and the Swift calling convention are not implemented.

Apple system imports use the bundled `macos64.pack`, exported from Ghidra 12.1.4's macOS 10.9 archive with generic C-library fallback. This is a historical API snapshot. Full archive decoding covers 14,256 prototypes: one x86-64 aggregate (`hsearch`) and six under the Go C-import model cannot be placed and remain untyped; AArch64 decodes all records. Array parameters decay to C pointers, and missing storage is rejected before native registration. Ghidra's `MachOFunctionsThatDoNotReturn` supplies termination names.

Tests in `decompiler_macho.rs`, `macho_features.rs` and the CLI cover both architectures, universal selection, stripped Objective-C classes/categories/selectors, classic and chained bindings, Swift metadata and Go DWARF. Loader tests cover authenticated pointers, addend import formats, rebases and malformed chains. Rebuild sources in `binfera/tests/fixtures/macho_metadata` with `sh build.sh` on macOS. These are fixture results, not a new malware-corpus coverage count. 32-bit Mach-O, relocatable objects, external dSYMs and AArch64 Go remain unsupported.

## Reusable API

```rust,ignore
use binfera::decompiler::{DecompilerSession, ResourceLimits, ValueType};

let mut session = DecompilerSession::from_pe(&sample_bytes)?;
session.set_limits(ResourceLimits::default())?;
// Optional when the caller knows a fixed-argument prototype.
session.set_signature(0x140001000, ValueType::I32, &[ValueType::I32])?;
let first = session.decompile_function(0x140001000)?;
let second = session.decompile_function(0x140002000)?;
println!("{}", first.text);
```

A session owns one loaded image. `from_analysis(&analysis, &names, CallingConvention::WindowsX64)` (`WindowsX86` for a 32-bit image) reuses existing recovery metadata and accepts additional symbols. Specifications are initialized once per session; function analysis is released after each request, including temporary inferred callee prototypes. The Rust result always includes timings, even when the CLI omits them for deterministic JSON.

Sessions are neither Send nor Sync. Native calls are serialized process-wide because Ghidra has shared registries. An unexpected native failure poisons the session; create another session to continue. A work-limit or deadline error aborts only its request and leaves the session usable. Rust-rejected invalid requests leave it usable. Every function entry in `warnings` is a gap and sets `incomplete`; consumers should display them. Image-wide diagnostics are available through `DecompilerSession::warnings()` and do not mark every function incomplete. The CLI includes them in `file_warnings` for selected-function and unit JSON, and in the `start` and `done` records for streaming output. Consumers merge and deduplicate these two lists, since some archive diagnostics appear only after the first function is printed. `notes` holds what is informational and leaves the result complete: a call replaced by its modeled effect (`replaced with injection: security_check_cookie`), inferred callee prototypes and the inferred-types caveat. The CLI prints them as `note:` lines after the `warning:` lines. `unknown_callees` says whether the cause is a callee without a known prototype (arguments or return values may be missing), which is by far the commonest one. Its warning lists the total uncertain call count and up to eight call sites, with a name or target and whether arguments, return storage, or both remain unknown. Any additional calls are counted rather than printed. Other function warnings include native errors, unresolved flow, and evidence that the inferred return type may be wrong. Repeated optimization comments are collapsed; removing an unreachable block is informational. When a recovered direct caller reads the return register before overwriting it, the adapter can retry an inferred `void` result with unknown integer return storage of the observed width. On x64, disagreeing or byte-only observations and direct jump thunks do not select a width. On x86, this retry is limited to closed leaf functions that write EAX and do not touch EDX or forward calls or jumps. A straight-line wrapper that returns an imported call unchanged can instead use the import's locked four-byte return prototype. The inferred return type and width remain uncertain and set `incomplete`. For x86 recursive calls, matching pushes and immediate caller stack cleanup, with returns that do not purge the stack, can select `__cdecl` for that request. This is also reported as an inference. Both hints are temporary and never override an explicit or archive-backed signature. An inferred boolean return gets a warning when the output casts a constant greater than one to `bool`. In a self-contained unit, unknown integer types use unsigned C types and are listed as `unknown_signedness` guesses because this can change signed comparisons and loops. The adapter applies the prototype of every import from a Windows system DLL that Ghidra's bundled Windows and C library data type archives describe (see [Prototype pack](#prototype-pack)), and `from_pe` applies a compact subset of the bundled FLIRT signatures for runtime names. Validated MSVC runtime matches and the PE DLL entry point get known calling signatures. Runtime helpers with a modeled effect then get their compiler-spec call fixup (see [Effect models](#effect-models)). An export name or an arbitrary caller-supplied name does not enable one, and `from_analysis` applies none. Functions that no other source names are then matched against Ghidra's Function ID databases (see [Function ID names](#function-id-names)); a recognized name also applies the packed prototype of that name, so `memset`, `strlen` and the other libc functions are typed. See the [runtime-signature provenance](https://github.com/Karib0u/binfera/blob/main/binfera/sigs/DECOMPILER.md). `from_pe` loads a PE whose import or delay import directory is malformed without imports and with an "import directory ignored" warning. `from_analysis` uses the caller's symbol map and avoids the library-matching cost. PDB types are not loaded.

PE COFF symbol tables supply function starts and names for defined external and static functions in file-backed code. Both inline and string-table names are supported, including C++ demangling. COFF names override signature-based names; Go's function table and exports take precedence over COFF. Auxiliary records and non-function symbols are excluded. A malformed table leaves the image usable and adds a recovery diagnostic. This applies to native recovery and `from_pe`; the Vivisect-compatible capability path is unchanged.

`set_signature` accepts explicit scalar/pointer prototypes for function entries or IAT slots. For unknown direct callees, native analysis can infer prototypes from at most 16 supporting functions and four call levels per request. These share the request's time/work budget and instruction limit per analyzed function. Only completed analysis without analysis gaps or unresolved call prototypes supplies an inferred signature. Informational modeled-call and duplicate-enum-name notes do not block it. Recursive or unresolved callees remain unknown. Inference has its own budget, separate from the selected function's, and each phase gets the full limits. If enrichment hits a limit, the function is decompiled without it and the result carries an "inference skipped" warning. Inferred signatures are cached per session as a pure function of the image and explicit signatures, and a cache hit charges the work of the original computation, so output and limits do not depend on request order. Locks last only while a function is analyzed, and `set_signature` and the other mutators drop the cache. Limits: 16 direct callees per request, 16 analyzed functions below each, four call levels. Already typed and external calls do not consume those inference slots. An explicitly requested unrecovered wrapper keeps the tail-call override it received.

Win64 entry stores into all four register home slots corroborate four recovered inputs in those integer registers even when the function calls unknown callees. In that case only inputs are locked, and the unknown-return warning remains. A stub that homes those registers but does not use them cannot supply a zero-parameter prototype that would erase its callers' arguments.

ELF unwind ranges also constrain speculative jump tables: a target inside a different declared function stops enumeration, while its entry remains a valid tail/cold-fragment target. Ambiguous overlapping ranges are ignored. A shortened table remains explicitly incomplete. For a wrapped byte selector, enumeration can begin in the neighbouring table before reaching valid low cases. If the high segment starts at a foreign interior, the engine validates every low-case target and recovers that finite segment. Final normalization must reproduce exactly the saved target addresses. The truncation warning remains; this does not prove the enum's legal domain.

A validated GCC SysV register-save prologue and complete `va_list` layout can establish the fixed integer argument count of a variadic forwarder. A balanced call/return tail permits separate, bounded callee analysis to recover its return storage. Saved variadic registers remain visible and semantic types stay uncertain. Explicit signatures take precedence.

On x86-64, a caller's AL use can corroborate a Boolean return when all native return paths have Boolean low bytes and at least one contains a partial AL result. This removes unrelated upper-register bits from the displayed result. An arbitrary byte-valued result is not narrowed by this rule; applied hints remain request-local and carry a warning.

Batch CLI enumeration rejects compatibility-only literals, relative-offset tables and internal labels only with corroborating native data/flow evidence. Uncertain candidates remain listed. ELF entries declared by unwind metadata are included even if compatibility recovery missed them. It retries a resource-limit failure once with 60 seconds per phase, 100,000 instructions and 200,000,000 work units, up to 16 retries per image. Each retry is recorded in JSON as `resource_retry`; successful output also carries a note. Single-function limits are unchanged.

Results using inferred callee prototypes carry an informational note; that note alone does not mark them incomplete. Calls still lacking prototypes retain the explicit unknown callee warning. Recovery-provided direct tail calls and IAT jump thunks use Ghidra's CALL_RETURN flow override; native SLEIGH still supplies the p-code. For a requested entry absent from recovery, a bounded SLEIGH scan of at most 64 straight-line instructions also recognizes a direct tail jump to a supplied executable function entry. It stops on any other control flow. This is the fallback for an analysis that lacks the wrapper; native recovery now finds them (see Function discovery).

## Self-contained unit

`--unit` (with one or more `--decompile-function`) wraps the text in a C translation unit that a C compiler accepts, so an extracted function can be recompiled:

```sh
./target/release/binfera sample.exe --decompile-function 0x140001000 --unit > f.c
./target/release/binfera sample.exe --decompile-function 0x140001000 --decompile-function 0x140001200 --unit --json
clang --target=x86_64-pc-windows-msvc -std=gnu11 -fms-extensions -fsyntax-only f.c
```

API: `DecompilerSession::decompile_unit(&[u64])` returns a `Unit` (text, the functions in it, the guesses, the sub-piece rewrites). Duplicate addresses are decompiled once; between 1 and 256 functions; one function that fails to decompile fails the unit. The unit is, in order: Ghidra's pseudo-types and pseudo-operations (`CONCAT44`, `SUB84`, `ZEXT48`, `SEXT48`, `CARRY4`, `SCARRY4`, `SBORROW4`, `POPCOUNT`, `LZCOUNT`, and the float operations `ROUND`, `NAN`, `ABS`, `SQRT`, `CEIL`, `FLOOR`); the types the text names and the archive's prototype for every callee it knows, read from the prototype pack at request time (no Python, no compiler); a declaration for everything else; a forward declaration of each function in the unit; the bodies.

**Every declaration that is a guess carries a `GUESS` comment and is listed in `guesses`.** A unit whose list is empty compiles on the strength of the archive alone. The kinds: `callee_without_prototype` (`extern long long f();`, parameters unspecified), `data_symbol` (an `extern` without a definition, shaped by how the text uses the name: called through, a structure, indexed, dereferenced, only its address as `byte`; otherwise the scalar type the decompiler's analysis gave it, such as `float4` or `int4`), `undeclared_global` (the same, from the text alone), `register_read` (`unaff_*`, `in_*`, `extraout_*`), `stack_address` (`stack0x...`), `unrecovered_jump` (`UNRECOVERED_JUMPTABLE`). The rule for each construct that cannot compile as printed is in the header of `binfera/src/decompiler/unit.rs`. Sub-piece accesses such as `x._0_4_` are not a guess: they are rewritten to a read or write of that byte range, and the count is in `rewrites`.

What it does not do yet: data symbols get no definition and strings no bytes (`s_` and `u_` names are `extern char[]` and `extern unsigned short[]`), enumerators are not declared (enumerations are integer typedefs), an indirect call through a computed table stays as printed, and a compile is well-formed C only: a dropped argument still compiles. The unit is never run.

## Function discovery

PE and ELF decompilation use the native recovery backend, which adds sources the Vivisect-compatible capability path does not use. Capa results are unchanged: all of it is gated on `RecoveryBackend::Native`.

- **`.pdata`.** Every non-chained `RUNTIME_FUNCTION` begin is a start. Vivisect stops reading the table at the first entry it cannot read; native recovery keeps going. Entries bound a function exactly, so an address strictly inside one (a catch continuation, a switch arm or a chained fragment) is never a start.
- **Code named by data.** Image-relative (`u32`) and absolute (`u64`) values in initialized non-code sections (`.rdata`, `.xdata`, ...) that name undecoded code. MSVC leaf funclets (unwind cleanups, catch thunks) have no unwind entry and are reachable only this way. A value is accepted only if the target decodes, is not `int3`/`nop`, lies outside every unwind extent and follows a function-ending instruction (`ret`, unconditional or indirect `jmp`, `int3`, or a call to a no-return function) with only padding between them. Entries that sit back to back are admitted over successive rounds, once the one before them is decoded.
- **Code addresses in instructions.** On x64, RIP-relative `lea` references can name callbacks without storing a pointer in a data section. The same function boundary and unwind-extent checks apply before admitting one as a start.
- **Tail jumps.** A direct unconditional `jmp` whose target is decoded code starting right after a function end and `int3` padding, outside unwind extents, makes the target a function. This generalizes the wrapper case to any target, and the existing tail-call override then keeps the jump a call. A `jmp [import]` stub that other code branches to is a function too. An unreferenced stub is not.
- **ELF exception frames.** `.eh_frame` FDE starts seed native x86, x64 and AArch64 recovery, including a `PT_GNU_EH_FRAME` fallback without section headers. Addresses are rebased once; ranges must be nonempty, executable and file backed. Malformed metadata adds diagnostics. This discovers starts and separates fallthrough scopes; it does not reconstruct LSDA handlers.
- **Compiler prologues.** A bounded subset of GCC, Windows and Delphi x86/x64 patterns adds candidates after padding, returns or mapping boundaries. Complete instructions must decode; CET prefixes stay at the function entry, and matches inside existing instructions are ignored. The older prologue signatures and raw call sweeps remain available.

The Vivisect `/GS` cookie-tail split is skipped for native recovery: Ghidra keeps the check in its caller.

Not done: a stack-balance check for the tail-jump rule (the padding and function-end test stands in for it), full Ghidra function-start pattern coverage, and `jmp [import]` stubs that nothing references (Ghidra creates some, for example 176 in `kernel32` and 32 in a MinGW DLL).

Read-only image sections retain constant/string semantics except for individual eight-byte IAT slots. Typed string pointers allow Ghidra to render narrow and UTF-16 literals. The adapter keeps small hand-built layouts of `LUID`, `LUID_AND_ATTRIBUTES`, and `TOKEN_PRIVILEGES` for explicit `set_signature` calls (sizes 8, 12 and 16, alignment 4, `ANYSIZE_ARRAY = 1`, following [the SDK](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges)). Imports get their full types from the prototype pack instead.

## Function ID names

`from_pe` hashes every recovered function the way Ghidra's Function ID analyzer does and looks it up in a pack built from Ghidra's Visual Studio databases (`binfera/sigs/fid-x64.pack`, about 9.9 MB, and `fid-x86.pack`, about 12.6 MB, embedded only with the `decompiler` feature; provenance and validation in [`FID.md`](https://github.com/Karib0u/binfera/blob/main/binfera/sigs/FID.md)). Lookup is hash-bucketed and nothing is decoded until a hash matches. Matches are scored with the callee and caller relations like Ghidra's `FidProgramSeeker`, and a name is applied only when it is unambiguous. Exports, FLIRT names and the DLL entry keep their names. Naming depends only on the image, never on request order.

An ambiguous match is left unnamed, but Ghidra labels each of its candidates `FID_conflict:` and its call fixups list those labels. So when every candidate selects the same fixup (`__SEH_prolog4` and `__SEH_prolog4_GS`), the fixup is applied anyway.

A function that is only `jmp [import slot]` is named after the import and typed like it (as Ghidra does for thunks), and an export takes the archive prototype of its own name when the archives know it (a proxy DLL's `GetFileVersionInfoA`). Decorated C++ export names never match.

## Effect models

Some runtime helpers break ordinary calling-convention rules: `__security_check_cookie` preserves RAX and has no visible effect, and `__chkstk` moves the stack pointer. Ghidra replaces calls to them with the p-code snippets of the `<callfixup>` entries in `x86-64-win.cspec` (3 entries, 7 target names). `from_pe` does the same. The table in `binfera/src/decompiler/effects.rs` maps a recognized name, without leading underscores, to a fixup: `security_check_cookie`; `alloca_probe` for `_alloca_probe`, `_alloca_probe2`, `__chkstk`, `__chkstk2` and `___chkstk_ms`; `guard_dispatch_icall`. Only names from FLIRT or Function ID select a model: an export is a claim by the image itself, and `from_analysis` leaves effects to its caller.

Native `Session::set_call_fixup` applies a fixup by name and rejects unknown names. The call disappears from the pseudocode, which gains Ghidra's `replaced with injection` comment. That comment is informational: it does not set `incomplete`, because it records a modeled effect, not a gap. Effects: callers keep RAX across a cookie check, the dead cookie computation no longer shapes parameters (`__GSHandlerCheckCommon` loses a spurious parameter and a void return), and a function with a probed frame keeps a correct stack pointer instead of printing every local as an `&stack0x...` address. `__GSHandlerCheck` itself needs no entry: it is ordinary code that calls the cookie check. The older `set_preserves_rax` stays in the native API for a helper that has a RAX effect but no fixup.

## Data and string symbols

Ghidra labels the data a function touches from its program database. The embedded engine has none, so it printed globals as the engine's own placeholders (`uRam0000000140004098`) and string pointers as bare constants. `Session::decompile` now derives labels from the image bytes, per request, and uses Ghidra's conventions:

| Data | Name | Rule |
|---|---|---|
| Global read or written at a constant address | `DAT_<addr>` | size is the largest access seen |
| Address taken, not a string | `&DAT_<addr>` | |
| NUL-terminated printable ASCII, at least 4 characters | `s_<text>_<addr>` | typed `char[n]`, so the printer can show the literal |
| NUL-terminated UTF-16LE, ASCII range, at least 4 characters | `u_<text>_<addr>` | typed as a wide `char[n]` |
| 8-byte aligned cell holding an image address | `PTR_FUN_`, `PTR_DAT_`, `PTR_s_`/`PTR_u_<text>_<addr>` | by the pointee: code, data or a string |

The text is the first 32 characters after dropping trailing line breaks; every character other than a letter, digit, `_`, `<` or `>` becomes `_` (so `usage: T1181-EWMI <payload>\n` is `usage__T1181_EWMI_<payload>`); the address is lowercase hex padded to 8 digits. The constants (32 characters, the kept set, the padding) were read from Ghidra 12.1.4's output on the baseline and held-out selections (about 15 string labels, all consistent with the rule). The minimum of 4 characters is this adapter's choice, not Ghidra's. Character/byte pointer evidence also permits shorter ASCII strings and UTF-16 strings of at least two characters. Typed structures are not reinterpreted as strings, and zero remains a null pointer even in an image mapped at zero. Writable literals describe the initial bytes without changing load/store semantics; directly modified data is not given a string type.

Go and Rust keep strings as (pointer, length) pairs packed without terminators, so the NUL-terminated scan would print a string and its neighbours as one literal. Sessions for those images (`Session::set_counted_strings`) keep the `s_`/`u_` name but leave the bytes untyped. Rust strings whose length is read from the binary are still typed at that length and print as literals; Go strings print as symbols until their lengths are read.

How it runs: the first analysis finds which data addresses the function uses (persistent varnodes in mapped data, plus constant operands and validated string references in executable segments). The symbols are added to the global scope, the function is analyzed again, and they are removed when the request ends. The symbols are not part of the supplied facts, carry no locked type except the string arrays, and only skip an address that already has a real symbol (an import, a function). The cost is a second analysis of each function that touches data: median request time rose about 26% to 33% (8.1 to 10.3 ms and 4.7 to 6.3 ms on the two measurement sets).

This also fixes a leak. The engine stores its `uRam...` placeholders in the global scope, so the name of a global depended on which earlier request had typed it first (the same address printed `uRam...` in one request and `xRam...` in another). The request's end now removes every placeholder global, and a test requests the same functions in different orders and sessions.

Limits: only addresses inside mapped sections are named, so memory the image does not carry (the unpacked sections of a packed file, zero-filled tails beyond the raw data) keeps placeholders; and a global that the analysis only discovers during callee-prototype inference is named by the engine, not by this pass.

## x86-32

A PE32 image gets the x86-32 language: `x86.slaspec` (compiled at build time next to the x64 one), `x86.pspec` and `x86win.cspec`. Everything that differs lives in one `Spec` in `native/bridge.cc`: the specifications, the prototype pack, the pointer width (4 bytes: import slots, `ValueType::Pointer`, data symbols for pointer cells), and the unmapped range used for import targets (`0xf0000000` upward). Sessions of both languages coexist in one process.

- **Conventions.** `x86win.cspec` defaults to `__stdcall` with the stack purge unknown, so the engine infers it per function; `__cdecl`, `__fastcall` and `__thiscall` are defined too. Imports take the convention recorded in the pack. Fixed-argument `__stdcall` prototypes with assigned storage get their stack cleanup resolved from those arguments, so subsequent stack references stay aligned. Output names the convention as Ghidra does (`__fastcall FUN_00414a70(...)`). The result's `calling_convention` is `windows_x86`.
- **Types.** `binfera-ghidra/data/winapi32.pack` (1.3 MB; 28,186 functions, 8,006 types) comes from `windows_vs12_32.gdt` and `generic_clib.gdt` through the same export as the x64 pack (`scripts/decompiler_types/README.md`).
- **Library names.** `binfera/sigs/fid-x86.pack` (12.6 MB) from the x86 Visual Studio databases; the matcher hashes 32-bit code (`fid::x86::describe_in`). See [`FID.md`](https://github.com/Karib0u/binfera/blob/main/binfera/sigs/FID.md) for how closely it reproduces Ghidra's hashes.
- **Effect models.** `x86win.cspec` declares 10 call fixups with 27 target names (`__EH_prolog3`, `__SEH_prolog4`, `__alloca_probe`, `__RTC_CheckEsp`, `__security_check_cookie`, ...). A table in `binfera/src/decompiler/effects.rs` maps recognized names to them, and a test compares both tables with the vendored specs.
- **Names.** Default function names are padded to the address width, as Ghidra prints them (`FUN_00404dd0`); data symbols use the same width (`DAT_0041b028`).
- **Discovery.** There is no `.pdata`, so function discovery relies on the capability path's sources plus the native additions that do not need it. See the x86-32 results.

Two robustness changes came with it and apply to both languages. A flow that leaves executable memory is now Ghidra's own "bad instruction" warning (the rest of the function stays) instead of a failed request, and a callee whose analysis cannot be translated costs only its own inferred prototype.

Not done for x86-32: MinGW-specific runtime names (no FLIRT or Function ID data), `fwait` plus x87 forms beyond the merge in the hasher, and AVX/VEX instructions in the Function ID masks.

## Delphi and Borland C++

Delphi's own functions take their first three arguments in `EAX`, `EDX` and `ECX` (`register`), and Borland C++ defaults to a register `__fastcall`. Read with `x86win.cspec` they come out with missing parameters and stray register reads (`in_EAX`), and their callers pass the wrong arguments. `from_pe` asks `target::pe_compiler`, a port of Ghidra 12.1.4's `PeLoader.CompilerOpinion`, which compiler built a PE32: it reads the PE header offset, Visual C's Rich header, the DOS stub's code and message ("This program must be run under Win32"), and Borland's `CODE` section. Ghidra's answer `borland:pascal` selects `x86delphi.cspec` (`calling_convention` `delphi_x86`) and `borland:c++` or `borland:unknown` select `x86borland.cspec` (`borland_x86`), as `x86.opinion` does. Every other answer keeps `x86win.cspec`; a Go program is recognized by its function table instead (see [Go](#go)).

Imports keep the Win32 archive and the convention it records for each, since a Delphi program calls Win32 like any other. Function ID and FLIRT still run, with the Visual C databases. Self-contained units are refused: their prelude spells the Visual C conventions only.

One engine detail matters here. A callee prototype inferred as `void` is locked, and a locked void result tells the engine the call leaves the return register alone unless the model kills it. The Windows and System V models kill it; Delphi's and Borland's leave its effect unknown, so a caller that uses the result would print the value from before the call. Such an inferred void result stays unlocked (`apply` in `native/bridge.cc`), so the callers' uses decide, as in Ghidra.

## ELF (System V)

`from_elf` decompiles x86-64 (`x86-64-gcc.cspec`, `calling_convention` `system_v_x64`) and i386 (`x86gcc.cspec`, `system_v_x86`: `__cdecl` by default, with the `__regparm` variants defined) ELF images. Function names come from `.symtab` and `.dynsym`, so a stripped file has none; there is no library recognition for ELF yet.

- **Types.** `sysv64.pack` and `sysv32.pack` (about 200 KB each; 6,633 functions, 1,229 types) come from Ghidra's C library archive (`generic_clib_64.gdt`, `generic_clib.gdt`), exported against the gcc compiler specifications. Dynamic imports and their PLT stubs are typed by name, and so is a function the image defines under a C library name (a wrapper, or a rootkit's `access` hook), as Ghidra's archive analyzer does.
- **PLT.** A stub that jumps through an absolute or RIP-relative GOT slot is named after the import in that slot. i386 position-independent stubs jump through `[ebx + disp]`; the psABI has `ebx` hold the GOT's address (`DT_PLTGOT`) whenever PLT code runs, so the slot is `DT_PLTGOT + disp`.
- **Position-independent i386 code.** gcc's code reads its own address through `__x86.get_pc_thunk.<reg>`, which returns in a register no convention describes. `x86gcc.cspec` models each thunk (and `__x86_return_thunk`, `__fentry__`, `mcount` and the retpoline thunks) as a call fixup; `effects.rs` maps the names, checked against the vendored spec. A stripped image keeps the thunk's body, `mov <reg>, [esp]; ret`, which names it. Without the model the code's global reads print as `*(unaff_EBX + n)`.
- **Linux system calls.** Native x64 `syscall` and i386 `int 0x80` are printed as `linux_write`, `linux_mmap`, etc., when Ghidra's SSA analysis resolves the accumulator to one constant. A temporary p-code probe exposes the number and models register and memory effects; the final pass replaces resolved instructions with calls using the compiler specification's `syscall` model (including x64 `R10` and i386 `EBX` through `EBP`). The call does not pop the stack. Compatible C archive parameters and explicit raw kernel signatures type common calls; return values are signed machine words, including negative kernel error codes. `exit` and `exit_group` do not return. Names use Linux v6.12's tables (452 i386 and 375 native x64 entries), since Ghidra's i386 table stops at 190. Unknown numbers, conflicting branch values, `sysenter`, and long-mode `int 0x80` keep their original SLEIGH translation. A named call without a known signature stays marked as an unknown prototype. This also applies to Linux Go binaries. Windows and explicitly identified non-Linux ELF images are excluded; unbranded System V ELF is assumed to be Linux. Native recovery follows i386 kernel traps through returning wrappers instead of falsely marking those wrappers as non-returning; capability compatibility recovery keeps its reference behavior.
- **Memory.** A segment whose memory size exceeds its file bytes (`.bss`) is zero-filled, capped at 16 MiB.

Units are refused for ELF.

## Go

A Go binary carries its own function table (`pclntab`), stripped or not. `binfera::golang` reads it (the four layouts of Go 1.2 to 1.27, x86 and x86-64, PE and ELF, including a memory dump of a DLL loaded at another base) and the toolchain version from the build information. A dump without build information takes the first `go1.N.M` string in its data that fits the table layout (the runtime's own `runtime.buildVersion`), else the oldest release of that layout. When the table is found, `from_pe` and `from_elf` decompile the program as Go, porting what Ghidra 12.1.4's `GolangSymbolAnalyzer` gives its decompiler:

- **Functions and names.** Every table entry is a function, named as the table names it (`os.(*File).Write`, kept with its punctuation as Ghidra prints it). Native recovery seeds the entries and drops any start strictly inside one (a switch arm, a block after a call that does not return), as it does for `.pdata` extents; `--decompile-all` does the same with the table. A Go name beats a FLIRT match at the same address.
- **Conventions.** `x86-64-golang.cspec` and `x86-32-golang.cspec`, vendored with Ghidra's list of Go functions that do not return. `calling_convention` is `go_windows_x64`, `go_system_v_x64`, `go_windows_x86` or `go_system_v_x86`. Functions without a known signature use the register ABI (`abi-internal`) from Go 1.17 on amd64 and the stack ABI (`abi0`) before it and on 386. Ghidra uses `abi-internal` for every amd64 release; for Go 1.16 and earlier that invents register parameters, so this is a deliberate difference. A `.abi0` function uses the stack ABI.
- **Standard library signatures.** `golang64.pack` and `golang32.pack` (see the [prototype pack](#prototype-pack)) hold Ghidra's Go API snapshots for 1.15 to 1.25, by operating system. A function is looked up under the snapshot's name for it (`os.(*os.File).Write`); a release newer than 1.25 uses the 1.25 records, and one older than 1.15 has none. Storage is assigned as Go does, by a port of Ghidra's `GoParamStorageAllocator` in `native/bridge.cc`: each value takes the next integer or float registers if all its pieces fit, otherwise it goes on the stack and later values may still use registers. Several results come back as a structure laid out the way the registers (or stack slots) hold them, so `oVar5 = os.OpenFile(name,0,0); if (oVar5.~r1.tab == 0)`. Assembly functions (`funcFlag_ASM`), closures, method values and generic functions get no signature, as in Ghidra. About 1.3% of the amd64 signatures stay unapplied: results split between registers and the stack, and structures whose registers skip padding (Ghidra applies these with a storage warning).
- **The goroutine register.** From Go 1.17 on amd64, R14 holds the current goroutine: it is a constant pointing at `CURRENT_G`, typed `runtime.g` from the snapshot, so the stack check prints `&stack0x00000000 <= CURRENT_G.stackguard0` instead of reading `unaff_R14`. XMM15 is zero.
- **Runtime helpers.** `runtime.duffzero` and `runtime.duffcopy` (and every entry into their middle that the code calls), and the write barriers (`runtime.gcWriteBarrier1`-`8` from Go 1.21, `runtime.gcWriteBarrier` and its per-register variants before), use their own models in the compiler specification. Go 1.13 through 1.25 x86/amd64 bounds-panic assembly helpers also receive their explicit register-pair arguments and nonreturning void result: AX/CX for index and slice-B/3C checks, CX/DX for slice-A/3B checks, DX/BX for slice-3A and conversion checks. The first argument is unsigned only for the `U` variant. These helpers use registers even before Go 1.17 and on 386; ordinary stack-ABI signatures would lose their arguments. This follows Go's [amd64 assembly](https://github.com/golang/go/blob/go1.23.0/src/runtime/asm_amd64.s) and [386 assembly](https://github.com/golang/go/blob/go1.23.0/src/runtime/asm_386.s). `.abi0` wrappers and unverified newer releases do not receive this special signature.
- **Types.** Go programs print Go's names for the core types (`int64`, `uint8`, `float64`) and Ghidra's `undefinedN`, so an eight-byte integer never reads as Go's one-byte `int8`.
- **Imports** keep the platform's C convention (`MSABI` or System V) and archive.

Not done: signatures of the program's own methods from its runtime type information (Ghidra's `GoRttiMapper` method tables), Go string constants (they print as packed integers), the closure context register (`unaff_RDX` in closures), the goroutine on x86-32 and before Go 1.17 (read through thread-local storage), and results returned on the stack by 386 callees, which callers read as stack memory. Units are refused for Go.

## DWARF debug information

Native decompiler builds use `gimli` to read embedded DWARF before recovery. Subprogram entries seed native function discovery even without an ordinary symbol table. Debug names override inferred library names; names explicitly supplied to `from_analysis` and later `set_signature` requests remain caller-controlled. Debug prototypes are applied after archive and Go snapshot signatures. The compatibility capability backend does not import DWARF.

The reader handles ELF, PE long section names and thin Mach-O sections, DWARF 4/5 indexed strings and addresses, standard and GNU zlib compression, range lists and cross-unit `abstract_origin`/`specification` references. ELF function addresses use the loader's bias. Mach-O debug information follows the selected universal slice. No external file, debug link or dSYM is opened.

Imported context includes parameter names, scalar types, pointers and references, qualifier and typedef targets, enum underlying types, fixed arrays and recursive structure fields. Function-scope locals with fixed frame offsets are named and typed when the CFA or a recognized x86 stack/frame-pointer prologue establishes their storage. The engine may eliminate a local when it simplifies its value. Dynamic/realigned storage, location lists and register locals are not bound to guessed addresses. Unions and bit fields remain opaque; unsupported by-value layouts leave prototypes inferred. Standalone C units currently refuse sessions with imported DWARF types because their declaration exporter only knows the bundled archives.

Go's `DW_AT_variable_parameter` output parameters become single or multiple return values, with storage assigned by the existing Go allocator. Duplicate output names are removed and assembly helpers are excluded, following `GolangDWARFFunctionFixup`. Rust name-only stubs keep inferred parameters, following `RustDWARFFunctionFixup`; scalar/pointer signatures use the platform model, while private aggregate layouts remain inferred. This is not a full port of Ghidra's DWARF analyzer.

Malformed metadata produces diagnostics without rejecting executable code. Each compilation unit is transactional. Local policy limits the total decompressed sections to 64 MiB, DIEs to 250,000, nesting/type traversal to 64 levels, names to 1,024 bytes and individual types to 1 MiB. External/split DWARF and separate type units are not resolved. Fixtures and their build script are in `binfera/tests/fixtures/dwarf`; run `cargo test -p binfera --features decompiler --test decompiler_dwarf`.

## Rust

Legacy (`_ZN...17h...E`) and v0 (`_R...`) symbols from exports, symbol tables and imports are demangled with `rustc-demangle`. Display names omit hashes and crate disambiguators. Input and rendered output are bounded; plain Itanium C++ names still use the C++ demangler. A Rust name does not encode a function signature, so generic functions keep inferred parameters.

Named Rust functions use the platform's scalar convention, with caller stack cleanup on x86. The allocator shims (`__rust_alloc`, `__rust_alloc_zeroed`, `__rust_dealloc`, `__rust_realloc`), `std::process::{exit,abort}` and selected scalar panic helpers receive explicit signatures. Ghidra 12.1.4's `RustFunctionsThatDoNotReturn` supplies panic/abort names, normalized for v0 too. Its backtrace trampoline and panic-cleanup entries are excluded because they can return. Ghidra's `__rust_probestack` and platform-specific `__rust_try` call fixups are loaded on demand.

Rust evidence is a valid mangled symbol, a runtime helper, or Ghidra's Rust markers (`RUST_BACKTRACE`, `RUST_MIN_STACK`, `/rustc/`, also Windows source paths). Only these images get slice detection. Static pointer/length pairs and constant adjacent x64 call arguments identify exact byte lengths in read-only, file-backed printable UTF-8 data. The printer receives those lengths, so adjacent strings do not run together and no terminating zero is required. Static descriptors use `RustStr { data_ptr, length }`, transcribed from `rust-common.gdt`'s `Str` for either pointer width. Conflicting lengths are omitted. Detection limits strings to 4096 bytes each, 4096 distinct strings/descriptors, 4 MiB of accepted text and 64 MiB of candidate UTF-8 validation per image.

Limits: stripped functions still need library signatures (audit item 18). Generic aggregate signatures, `String`/`Vec` field ordering, slices assembled through general data flow, and immediate stack-passed x86 slices are not inferred. The shared Rust structures have no stable C ABI, so the archive's `String` layout and Unix aggregate convention are not applied blindly. As with C++, self-contained C units reject names containing Rust namespaces.

`binfera/tests/fixtures/rust/build.sh` rebuilds small PE/ELF fixtures in both mangling formats. `cargo test --release -p binfera --features decompiler --test decompiler_rust` checks names, exact UTF-8 literals and request order; module tests cover signatures, no-return paths and malformed input.

## C++

**Names.** `binfera::demangle` turns Microsoft (`?add@Counter@@QAEHH@Z`) and Itanium (`_ZN7Counter3addEi`) decorations into the labels Ghidra shows (`Counter::add`), wherever a name comes from: exports, imports, ELF symbols and Function ID. Ghidra demangles Microsoft names with its own `MDMang` and Itanium names by running GNU binutils; here the `msvc-demangler` crate (LLVM's Microsoft demangler in Rust) and the `cpp_demangle` crate parse them. A label is the qualified name without parameters, spelled as Ghidra spells it: `operator_new`, `std::_Lockit::~_Lockit`, `std::basic_string<char,std::char_traits<char>,std::allocator<char>>::append`, `Class::vftable`. A C++ import is shown by its label alone (`std::_Lockit::_Lockit`, not `msvcp140_...`), since its namespaces say where it comes from. Function ID names that were dropped before (constructors, operators, templates) are now kept, and an ambiguous match reads `FID_conflict:<label>`. Rust's legacy symbols use the Itanium form but are left for a Rust demangler, and a Microsoft name longer than 1,024 characters is not parsed (the parser recurses without a limit).

**Prototypes.** A Microsoft name also encodes its calling convention, `this`, and return and parameter types. When every type is a scalar or a pointer, the function or import gets that prototype, locked, as Ghidra's demangler analysis applies it: a method is `__thiscall` with `this` typed as a pointer to its class, so on x86 the `ECX` argument appears (`std::_Lockit::_Lockit((std::_Lockit *)local,2)`) where it was dropped before. A structure passed or returned by value leaves the prototype out. Itanium names give names only: they encode neither the return type nor whether a method is static.

**RTTI.** `binfera::rtti` reads the run-time type information Visual C++ emits for `typeid` and `dynamic_cast` in a PE file, following the structures Ghidra 12.1.4's `RttiAnalyzer` reads: type descriptors (`.?AV<name>@@`, each pointing at `type_info`'s table, which selects them), complete object locators, class hierarchy descriptors and the virtual function tables that follow a locator's pointer. From them:

- Each table is labeled `Class::vftable`, or `Class::vftable_for_Base` for a base subobject, and typed as a structure with one method pointer per slot, named after the slot's function. Type descriptors are labeled `Class::RTTI_Type_Descriptor`.
- Each class is a structure holding its table pointers (`vftable`, `vftable_for_Logger`). Its size is unknown, so it is open-ended: an access past the table pointers prints as an offset into the object, never as an index into an array of objects.
- A function in a class's tables belongs to that class (`Class::FUN_10001160`, the name Ghidra's `RecoverClassesFromRTTIScript` gives); one in several tables belongs to the class that is a base of the others, and one shared by unrelated classes (identical code folding, `_purecall`) to none. A name from another source wins.
- A function found in its class's primary table is a method: `__thiscall`, with `this` named and typed as the class, its other parameters still inferred. A virtual call through `this` then goes through the typed table and names its target, with `this` passed: `(*this->vftable->FUN_10001180)(this,param_2,param_3)`. On x86 this needs evidence, a function that reads ECX before writing it (past `push ecx`, which only reserves stack, and `__EH_prolog3`): the methods of a COM interface are `__stdcall` with `this` on the stack, so they and a table of them keep that convention.

Not done: class layouts (fields, sizes, inheritance as structures) and constructors and destructors, which Ghidra's prototype class recovery derives from the code; virtual calls outside a method, where the object's class is unknown; `this` for a method found only in a table for a base subobject (it points into the object, and is left untyped); virtual bases; Itanium RTTI (stripped ELF; in a position-independent file the tables are filled by relocations); prototypes for Function ID's C++ names. A self-contained unit is refused for a function that names a C++ symbol, since C cannot declare `::` names.

### MSVC exception metadata

`binfera::msvc_eh::ExceptionInfo` reads classic `FuncInfo` versions 1, 2 and 3 from PE32 and PE32+ images. The layouts follow Ghidra 12.1.4's [PEExceptionAnalyzer](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/Features/MicrosoftCodeAnalyzer/src/main/java/ghidra/app/plugin/prototype/MicrosoftCodeAnalyzerPlugin/PEExceptionAnalyzer.java) and its `EHFunctionInfoModel`, `EHTryBlockModel`, `EHHandlerTypeModel`, `EHUnwindModel` and `EHIPToStateModel` data types. x86 frame-handler stubs supply absolute pointers; x64 exception directory entries supply image-relative pointers, independent of section names. Chained x64 unwind records are followed with a depth bound.

Native recovery seeds validated catch, unwind and registration handlers, and excludes their metadata tables from code discovery. Capability compatibility recovery retains its existing behavior. The decompiler preserves supplied symbol names and gives unnamed funclets labels such as `catch_180001000_180001060` and `unwind_180001000_180001040`. Pseudocode comments show the parent function addresses, try/catch states, catch types and cleanup transitions. The `exception_handling` JSON field carries the same tables, signed stack displacements, flags and IP states. `FunctionInfo::protected_ranges` returns half-open x64 address ranges from the IP map and runtime-function extents. x86 tables usually lack an IP map, so their state intervals are shown without invented address bounds. Shared funclets retain their parent links.

These annotations describe compiler metadata. The native engine does not reconstruct C++ exceptional control-flow edges or turn the result into source-level `try`/`catch` syntax. Standalone C units refuse protected parent functions; individual funclets can still be exported. Compressed `__CxxFrameHandler4` metadata and nonempty dynamic exception-specification lists remain unsupported. FH4 is reported when its imported handler (including a jump thunk) is recognizable; stripped, statically linked FH4 cannot yet be identified reliably. Malformed recognized tables are rejected with diagnostics. Reads require file-backed data, counts and total parsing work are bounded, and bad state transitions, code pointers and unterminated type names are rejected.

The fixtures in `binfera/tests/fixtures/msvc_eh` are built from C++ using clang's MSVC ABI and stub import libraries; they are parsed, never executed. Rebuild with `sh build.sh` there and run `cargo test -p binfera --features decompiler --test msvc_eh`.

## Prototype pack

`binfera-ghidra/data/winapi64.pack` (1.5 MB) holds 30,749 function prototypes and 9,704 named types exported from Ghidra 12.1.4's `windows_vs12_64.gdt` (Win32 headers, earlier archives win name clashes), `generic_clib_64.gdt`, and a kernel archive parsed from MinGW-w64 14.0.0 DDK headers and ReactOS 0.4.15's `fltkernel.h`. They are encoded with Ghidra's own decompiler marshalling, so the embedded engine decodes what Ghidra's decompiler would receive. Entries are zlib blocks sorted by key. A lookup inflates one bounded block, and types are resolved on demand by a `TypeFactory` subclass, the way Ghidra's decompiler asks its host. Nothing is decoded at startup.

An import is typed when its module is a known Windows system DLL (`kernel32`, `user32`, `ntdll`, `ws2_32`, `msvcrt`, `api-ms-win-*` and others, listed in `system_import_function`) and its function name is in the pack. A same-named export of an unrelated DLL stays untyped, as do names the archives lack, which keep the unknown-callee warning. Ghidra itself matches by name only. The module check is a deliberate stricter policy. Archive convention names such as `__stdcall` map to the single Windows x64 model. The x86-32 pack keeps each prototype's own model, since `x86win.cspec` defines `__stdcall`, `__cdecl`, `__fastcall` and `__thiscall`.

Kernel imports from `ntoskrnl` (including its multiprocessor and PAE names), `hal`, `fltmgr` and `ndis` use the same packs. The supplement also types native API calls through `ntdll`, such as `NtCreateFile` and `RtlInitUnicodeString`. Both architectures carry actual pointer widths, NTSTATUS results, Unicode strings, object attributes and I/O structures. On x86, fastcall exports such as `IofCompleteRequest` retain their register arguments; ordinary kernel calls use stdcall and variadic debug output uses cdecl. This covers the bundled header snapshot; newer or undocumented APIs absent from it retain the unknown-callee warning. The x86 pack contains 30,632 prototypes and 9,650 named types. Regeneration is development-only, described in [the type-pack README](https://github.com/Karib0u/binfera/blob/main/scripts/decompiler_types/README.md#kernel-and-native-windows-apis).

The C prototype packs also include a small generated supplement for fixed loader, stack-protector, Objective-C ownership, CoreFoundation and native Windows calls missing from the source archives. Existing archive declarations retain priority. See the [generator and declaration sources](https://github.com/Karib0u/binfera/blob/main/scripts/decompiler_types/README.md#fixed-c-abi-declarations-missing-from-the-archives).

The Go packs (`golang64.pack`, 1.7 MB, and `golang32.pack`, 1.6 MB) use the same block format with their own keys: per function, which operating systems and Go releases have which signature, and per named Go type, which definition each release has (`scripts/decompiler_types/pack_go_snapshots.py`). Go types are referenced by name and resolved for the binary's release on demand, through the same `TypeFactory` hook. `binfera-ghidra`'s `go_pack_decodes_for_each_platform_and_abi` test decodes every record for four platform and release pairs.

The x64 pack decodes completely. One original x86 RAS callback signature (`PMPRADMINCONNECTIONHANGUPNOTIFICATION3`) has an unsupported by-value aggregate; it keeps an unknown prototype instead of an error. `binfera-ghidra`'s `packed_archive_types_and_prototypes_decode` test decodes the whole pack through the real engine and fails if that count grows. To regenerate the pack, see `scripts/decompiler_types/README.md`. The archives are derived from Microsoft SDK and OpenSSL headers by the Ghidra project (Apache-2.0); the pack is a transformation of them.

Default limits are 10 seconds, 10,000 instructions and 20,000,000 work units (the bounds are 60 seconds, 100,000 instructions and 200,000,000 work units). Each phase of a request (the function, its data symbols, callee inference) gets the full deadline, so a request can take several times it. A function whose flow passes the instruction limit is retried with the flow truncated, as Ghidra does, and reported incomplete. The deadline is cooperative: a native operation between checkpoints can overshoot it. This is not a hard wall-clock or memory sandbox. See the [design decision](decompiler-design.md) for ownership, resource policy and the scope of exception handling.

## Fixtures and reference comparison

```sh
scripts/build_decompiler_fixtures.sh
cargo test --release -p binfera --features decompiler --test decompiler
GHIDRA_HOME=/path/to/ghidra_12.1.4_PUBLIC scripts/decompiler_reference.sh
cargo run --release -p binfera --features decompiler --example decompiler_bench
```

The checked-in fixture DLL is built from `tests/decompiler/fixtures.c` with MinGW GCC, without a CRT or timestamp. Rebuilding requires development-time MinGW; normal tests use the checked-in DLL. Seven exports cover arithmetic, branches, a sum-of-squares loop, a seven-case switch, volatile stack variables, GetTickCount and non-returning ExitProcess. Tests check useful source logic, repeatability, session ownership and malformed/limited requests. Source-logic tests supply the known fixture signatures, including the two Windows imports. Separate tests verify that unknown call prototypes are reported as incomplete.

`tests/decompiler/reference/*.c` is produced by the pinned Ghidra 12.1.4 headless release (the fixture output is identical to 11.4.2) and its default PE analyzer. The reference script is exclusively a development tool. It is not part of the native build or runtime. Its full analyzer supplies broader types and metadata than the embedded adapter. Compare control flow, operations, constants, arguments and effects rather than requiring identical variable names. The checked comparison found:

| Fixture | Source and reference logic preserved with supplied signatures |
|---|---|
| arithmetic | `x * 7 + y - 3` |
| branches | absolute value for negative input, clamp above 100, otherwise increment |
| loops | sum of squares from zero through `n - 1` |
| switches | seven cases, constants and forwarded arguments |
| stack_variables | two local stores and a dynamic index masked by one |
| imported_call | GetTickCount return value plus the incoming argument |
| nonreturn | ExitProcess receives the incoming exit code and has no fallthrough |

The ordinary CLI can reconstruct arithmetic and control flow without these signatures. It reports incomplete call reconstruction where metadata is missing. `nonreturn` also retains Ghidra's own no-return warning, so its incomplete flag is conservatively set even with the supplied signature.

## Performance

Run the benchmark in a fresh release process. It reports cold session setup including recovery and library matching, and 100 requests per function with p50, p95 and maximum latency. Pass a repetition count to compare retention:

```sh
cargo build --release -p binfera --features decompiler --example decompiler_bench
/usr/bin/time -l target/release/examples/decompiler_bench 100
/usr/bin/time -l target/release/examples/decompiler_bench 1000
```

On Linux use `/usr/bin/time -v` instead of `-l`. The resulting process maximum RSS includes loading, recovery and all requests. Timings are observations of the current binary, not cached acceptance numbers. Fixture-scale targets are established from the measurements collected by the benchmark; large real functions can hit limits and need separate evaluation.

## Validation

On the branch prepared for push, the default workspace suite passed 564 tests (six slow gates remained ignored), the optional native/adapter/CLI suites passed 18 tests, and all four feature-parity tests passed. The uncached native smoke differential run matched all 23 samples and all 731 reference-matched rules with zero missing or extra matches and no baseline regressions. The ten Python harness tests, source checksums, environment pins and formatting checks passed.

Strict Clippy currently reports existing unknown-lint attributes and a nonminimal Boolean expression in unchanged recovery code. Workspace Clippy and the optional targets with Rust 1.87 pass when only those categories are allowed:

```sh
cargo clippy --workspace --all-targets -- -D warnings -A unknown-lints -A clippy::nonminimal-bool
cargo +1.87.0 clippy --release -p binfera -p binfera-cli -p binfera-ghidra \
  --all-targets --features binfera/decompiler,binfera-cli/decompiler,binfera-ghidra/native \
  -- -D warnings -A unknown-lints -A clippy::nonminimal-bool
```

Linux and macOS CI exercise the optional feature; only macOS was run locally.
