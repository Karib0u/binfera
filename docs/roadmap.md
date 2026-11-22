# Roadmap

Updated: 2026-11-22. This page lists planned work, ranked by **reward for effort**, and how each item is tested. It also lists what already exists, so that work is not planned twice.

**Scope.** binfera answers "what does this one executable do?" by reading its code. These belong to the File Analysis Bus project instead: file-format parsing, unpacking, analysis of installer and bytecode scripts, and verdicts.

**Goal.** Every result an analyst sees should be:

- **Complete:** every function, every reachable block and every call is found.
- **Exact:** no false function starts, no merged or split bodies, no wrong arguments.
- **Readable:** the C output can be trusted without reading the assembly.
- **Editable:** names, types and prototypes the analyst supplies flow through the decompiler, not over its text.

This must hold for the binaries analysts actually get: stripped, often packed, and with no source or symbols.

## Principles

1. **Analysis uses only the binary.** Evidence comes from the binary itself, or from public vendor artifacts such as Microsoft's symbol server or distribution debuginfo. Source code is never assumed.
2. **Rank evidence; do not vote.** Linker and ABI structures outrank control-flow discovery, which outranks heuristics. A heuristic never overrides structural evidence.
3. **Every heuristic states what proves its result.** For example, "outside every `.pdata` extent, a function must leave RSP alone." If no such rule can be stated, the heuristic is not ready to ship.
4. **Other tools are witnesses, not judges.** A start binfera finds and another disassembler misses is not a false positive by default. Classify the disagreement instead (see [Methodology](#methodology)).
5. **A recall gain must not hide a precision loss.** Measure both over the whole corpus before merging.
6. **Rust owns the analyst's model; Ghidra analyzes it.** binfera stores what the analyst asserts and replays it into the native decompiler. It does not reimplement Ghidra's type system.
7. **Extend Ghidra at stated seams.** Vendored sources stay byte-identical to `SHA256SUMS`. Output improvements go, in order of preference, into facts binfera supplies (prototypes, types, resolved tables), rules and actions registered by the bridge, and, last, a build-time hook in `binfera-ghidra/build.rs` that asserts its anchor and is listed in `third_party/ghidra/README.md` with a regression test.
8. **Rank by what the analyst reads, divided by effort.** An item's reward is the number of functions whose output goes from wrong or unreadable to right, measured on the [review set](#review-set) and the corpus. How often a pattern appears in the corpus is not reward by itself. Wrong output comes before unreadable output, and unreadable before missing.

## Already covered (do not re-plan)

- **PE:**
  - Metadata: resources, version info, manifest, Authenticode, Rich header, imphash, compiler traces, COFF/object loading, packer detection.
  - Function sources: unwind data, SafeSEH, x86 SEH3 scope tables, MSVC RTTI and C++ exception metadata.
  - Incremental-link thunk tables: every target is recovered, and no stub absorbs a body.
  - x64 frameless leaves in code gaps, with switch cases rejected.
  - Delay-load stubs. x64 language handlers and the C++ `ThrowInfo` destructors and copy constructors.
  - No x64 start strictly inside another function's unwind row, unless structural evidence names it (#56).
- **ELF:** `.eh_frame` and `.ARM.exidx` function entries, init and fini arrays.
- **Mach-O:** `LC_FUNCTION_STARTS`, code signatures, chained fixups.
- **Detail views:** ELF and Mach-O, plus a hex view whose header fields are colored for PE, ELF and Mach-O.
- **Language and library support:** Go `pclntab`, DWARF, Delphi VMTs and RTTI, Nim, Itanium and MS demangling, FLIRT and Function ID.
- **Other recovery:** relocations, vtables, pointer recovery, jump tables, and prologue and unclaimed-gap sweeps.
- **Typed input to the decompiler:** debug types (structures, pointers, arrays, aliases), locked signatures, typed stack locals and named data symbols, all through the Ghidra bridge.
- **Windows type packs:** Win32 metadata, the phnt native API and loader structures, and CRT exports (#57). APIs resolved by `GetProcAddress` with a literal name into a global are registered as imports and typed (#59). A global that only ever holds one of the program's own functions is called directly (#64).
- **Prototype propagation:** a caller inherits API parameter names and types from the inferred prototypes of its callees (#58).
- **Decompilation:** x86, x86-64, AArch64, ARM32/Thumb and MIPS32. One line per statement, wrapped by the viewer with a hanging indent; `NULL` and `INVALID_HANDLE_VALUE` (#65). Win32 enum and flag arguments by name (#62). Calls through a register loaded from an import slot (#61).
- **Other analysis:** capa, function emulation and diffing.
- **Viewers:** entropy, hex, strings and imports, and a .NET IL listing. An IDA-style listing with typed data items (`dd offset FUN_x`, `dd ?` for uninitialized data) and a frame header per function; argument and stack-variable comments in the assembly; import-stub names (#58); the API names of `GetProcAddress` globals in the assembly and the listing (#64).
- **Measurement:** the recovery benchmark harness, `scripts/bench/recovery.py` (#52), the type-coverage report, `scripts/decompiler_types/coverage.py` (#57), and the output-quality report, `scripts/bench/quality.py` (#64): untyped imports, unresolved indirect calls and numeric API arguments per file, base against head, with a CI subset.
- **Archives:** zip and 7z, with known-password probing.
- **Integrations:** MCP and the agent.

## How work is ranked

Each item states three things:

| Field | Meaning |
|---|---|
| **Effort** | **S**: under about 200 lines, a day. **M**: a few days. **L**: weeks, or a design that must be proven first. |
| **Reward** | The functions whose output changes from wrong or unreadable to right, with the measurement behind the number. |
| **Done when** | A check that can fail: a review-set reading, a `quality.py` count, or a test. An item without one is not ready to start. |

**Why the order changed (2026-11-22).** The first ranking followed how often a pattern appears in the corpus. Measured afterwards, that predicted reward poorly:

- The type-knowledge passes (#57–#64) helped each sample that uses their pattern, but moved the corpus totals little: unresolved indirect calls 1,789 → 1,741 and untyped imports 3,628 → 3,619.
- A first attempt at the hidden-API passes (decoded names, hashes, syscalls; about 3,100 lines) left its target sample unchanged, and was not merged.
- A 43-line fix (#65) made every long call on every sample readable. It was not on the roadmap: an analyst found it by reading one function on a phone.

So the plan now starts from what analysts read. The [review set](#review-set) is the first item, and every output change reports its effect on it.

**Where the output stands.** Measured over 11 samples (9 malware demos and 2 corpus PEs, 8,412 functions) on 2026-11-22:

| Defect | Functions | Share | Typical cause |
|---|---:|---:|---|
| Flagged incomplete | 4,537 | 53% | A callee of the program's own has no known prototype, so arguments or a used return value may be missing. |
| `goto` in the body | 1,253 | 15% | Loop and `switch` structuring. |
| Exception-frame setup printed as code | 514 | 6% | `*in_FS_OFFSET = &local` for an x86 `__try` (MSVC) or `try` (Delphi; 474 in DarkGate), and the handler shown as a separate function. |
| `unaff_` registers | 514 | 6% | Frames set up by a helper (`__SEH_prolog`), and callee-saved registers. |
| `in_` register parameters | 368 | 4% | Register-passed arguments the prototype does not declare. |
| Unrecovered switch table | 177 | 2% | Jump-table resolution. |
| Bad instruction data | 172 | 2% | Decoding into data, or a wrong function start. |

## Now: output an analyst can trust

Ordered by reward for effort. Wrong output before unreadable output.

| # | Item | Effort | Reward | Done when |
|---|---|---|---|---|
| 1 | <a id="review-set"></a>**Review set.** About 30 functions from the demos and the corpus (WannaCry, NotPetya, DarkGate, BlackCat, Hive, Stuxnet, and so on), each with a hand-written expected reading: what it does, the calls and arguments that must appear, and the lines that must not (`unaff_`, `*in_FS_OFFSET =`). Add the share of incomplete functions and the defect counts above to `quality.py`. | S | Enables every item below: each PR states which readings it fixed or broke. | The set runs in CI next to the `quality.py` subset and fails when a passing reading regresses. The [Methodology](#metrics) output review set grows from it to about 100 functions. |
| 2 | **x86 exception frames.** Recognize the MSVC SEH3 and SEH4 prologue and the Delphi `try` frame on `fs:[0]`. Hide the setup and teardown; print the try level writes as `__try {` … `}`; print the `__finally` or `__except` handler inside its function with the function's own variable names, instead of as a separate `FUN_x` reading `*(unaff_EBP + -0x28)`. Stack slots read only by the handler (`hFile` in WannaCry `0x4018f9`) then stay in the frame, so the listing names them. | M | 514 functions (6%), and the output is wrong today: the cleanup (`CloseHandle(hFile)`) is missing from the function that owns it. | WannaCry `0x4018f9` prints `__try { … } __finally { … CloseHandle(hFile); }`; no review-set function prints `*in_FS_OFFSET =`; the count of functions with frame setup falls by at least 80% on the demos. |
| 3 | **`unaff_` and `in_` registers.** A frame set up by `__SEH_prolog`/`__SEH_prolog4` gives `EBP` its value; a register-passed argument is added to the callee's prototype when every caller sets it. | M | 882 functions (10%) show a placeholder register. | `unaff_EBP` does not appear in any demo function that uses the SEH prolog helpers; `in_` and `unaff_` counts in `quality.py` fall, with no review-set regression. |
| 4 | **Signatures of the program's own functions.** Callee-first over the call graph, iterated within recursive groups: what the callee reads before writing and whether it sets the return register, combined with what every call site passes and reads back, checked against `ret imm`, Win64 home space and variadic calls. Supplied signatures always win. | L | The largest: 53% of functions are incomplete, about 4,000 uncertain calls. | The incomplete share falls by half on the demos; at least 20 changed call sites checked by hand against the assembly; output identical with `--jobs 1`, `2` and `4`; batch time on BlackCat, Hive and DarkGate within 1.5× of today. |
| 5 | **Switch tables and bad instruction data.** Resolve the tables in the [jump-table row](#function-recovery) below; find why decoding runs into data. | M | 349 functions (4%), whose control flow is cut short. | Both warning counts in `quality.py` fall by half, with no new function start rejected by the recovery benchmark. |

## Next: the viewer

Cheap, and seen on every function.

| Item | Effort | Reward | Done when |
|---|---|---|---|
| **Where a value comes from.** Hovering a variable shows the statement that sets it (`hFile = CreateFileA(lpFileName, GENERIC_READ, …) @ 0x40193a`), and a click goes there. The decompiler knows each variable's writes; export them for every variable, not only stack slots. | S–M | Replaces scrolling back for each variable, the most common reading step. | A web test hovers `hFile` in WannaCry `0x4018f9` and gets the `CreateFileA` line. |
| **Stack slots by name in the assembly.** `mov [ebp+hFile], eax` instead of `mov [ebp-28h], eax`, as IDA does. | S, after item 2 | Every function with a stack frame. | The listing of WannaCry `0x4018f9` shows `hFile` on the store after `CreateFileA` and on both reads. |
| **What a handle refers to.** At each use of a handle, a comment with the call that opened it: `ReadFile(hFile /* CreateFileA(lpFileName) */, …)`, with the string when the name is a constant or a caller passes one. Files, registry keys, mutexes, sockets and processes. Neither IDA nor Ghidra does this. | M | Malware reading: which file, key or mutex an operation touches. | Review-set functions that use handles show the opening call at each use. |

## Next: analyst-editable semantics

When the engine cannot infer a type or prototype, the analyst states it once and it flows through the decompiler. Effort L in all; step 1 is done.

The bridge can already inject typed structures, locked signatures and typed stack locals. That is how DWARF field names reach the output. What is missing is a persistent model owned by the analyst, which binfera replays into the decompiler.

Two parts of today's model are weak:

- Renames are text rewrites over cached C (`rewrite_identifiers` in `binfera-mcp/src/tools.rs`).
- The project store only holds string edits.

Deliver the steps in this order:

| Step | Work |
|---|---|
| 1. Proof of concept | Written. Properties 1–4 and 8 pass with today's bridge; 5 and 7 pass only by rebuilding the native session; 6 and 7 through the store wait on step 2. The test `binfera/tests/decompiler_user_types.rs` uses a stripped function that accesses a struct through an untyped pointer. It must show eight things:<ul><li>a user struct is injected without DWARF;</li><li>a signature refers to it;</li><li>field accesses appear in the output;</li><li>callers benefit where data flow allows;</li><li>renaming a field changes the output;</li><li>the edit survives reopening the project;</li><li>removing it restores the original;</li><li>output does not depend on which functions were decompiled first.</li></ul> |
| 2. Semantic model | Add `binfera/src/decompiler/semantics.rs`, a neutral Rust model.<ul><li>Types: primitive, pointer, array, struct, enum and alias.</li><li>Function signatures, and type bindings to data and stack locations.</li><li>Type IDs scoped to a type library, so types can be shared across samples of a family.</li><li>Validation of size, alignment, overlap and recursion before anything reaches C++.</li><li>SQLite schema version 4: tables for types, bindings and signatures, using the existing revision, change-journal and undo machinery, with transactional edits.</li><li>A C-declaration parser as an input format, for analysts, agents and imported headers.</li></ul> |
| 3. Bridge | Today a type id is fixed for the life of a native session: re-sending an id with a new layout is silently ignored, and the internal `_dwarf_<id>` suffix can reach the printed output. User and DWARF types share one id space and one load at session build. Generalize `add_debug_types()` into one loader for any type graph, with separate id spaces per source and internal names that never print, and `set_debug_signature()` into `set_user_signature()`. Add global-data and stack-slot typing with storage validation. Do not change the vendored Ghidra algorithms. |
| 4. Session replay | Load user types after DWARF, type packs and library data, and before signatures. Precedence: user, then DWARF and trusted symbols, then type packs, then binfera's inference. User edits must clear the bridge's inferred cross-function facts (`invalidateInferred`) and change the inference-cache key. Today only `set_debug_signature` clears them; the type loader must too. Analyst edits must not be carried on `Analysis`, which the base analysis cache stores. |
| 5. Reanalysis and caches | A completed Ghidra structure cannot be changed in place.<ul><li>A changed layout gets a new version under a fresh internal name, and its bindings are repointed to it.</li><li>Deletions, or an overlay that has drifted, rebuild the native session, but not the Rust recovery analysis.</li><li>Split the caches. The base analysis cache is keyed by binary SHA-256 and engine version. The pseudocode cache adds the overlay hash, the function address and the options. Comments and stars do not invalidate pseudocode.</li><li>Start by invalidating all pseudocode; later, only the functions that depend on a changed type.</li></ul> |
| 6. Workflows | Ship three workflows across desktop, browser and MCP: define a struct and assign it to a parameter; edit a prototype; type a data location. The UI shows a C preview. Add the MCP tools `list_types`, `define_type`, `set_function_signature` and `set_data_type`, and import or export type libraries. Replace text-rewrite renames with native symbols. Before starting, confirm the browser build uses the same bridge path. Desktop and MCP share the SQLite store; the browser persists the same snapshot locally. |
| 7. Local variables (later) | Allow retyping locals only once their identity survives reanalysis. Key them by storage plus first-use address (the use point `add_debug_local` leaves empty today), not by names like `iVar3`. |

## Later: when a review-set function needs it

These are planned and specified, but each waits until a review-set reading fails because of it. Then it moves up with that reading as its test.

**Hidden API calls.** Results of `GetProcAddress` kept in locals and struct fields, `LdrGetProcedureAddress`, API hashes, direct syscalls, decoded names and strings. A first attempt at all five (about 3,100 lines, not merged) left its target sample unchanged. Restart one pass at a time, from a sample where the review set shows the defect.

**Packed images.** Count the packed files in the corpus before giving this a slot: the packer check flags none of the 11 samples measured above.

**Function recovery.** Tier B recall is 99.9% (#52) and the x64 interior false starts are gone (#56). What remains mostly affects Microsoft binaries, except jump tables (item 5 above).

### Function recovery

Order these by the evidence census. Guard CF and the C++ handler tables are common in Microsoft binaries and may be rare in malware. The first census (376 PE and ELF files in `tests/testfiles`) found 100% tier B recall on PE x64 and about 1,300 starts inside x64 `.pdata` extents, so false starts came first; #56 removed the 1,090 on PE x64 with tier B recall unchanged.

| Item | Work | Proof |
|---|---|---|
| Interior false starts | **Done for PE x64 (#56).** Remaining: the ELF x64 interior starts the census found (about 309 from `PointerTarget` and 58 from `CallTarget`), bounded by `.eh_frame` FDEs instead of `.pdata`. | `.pdata` or an FDE names the extent of every non-leaf function. |
| PLT sections | Treat `.plt`, `.plt.got` and `.plt.sec` FDEs as stub ranges, not one function each, in both recovery and scoring. | The section and its relocations. |
| Guard CF table | Parse `GuardCFFunctionTable` from the load config, including the per-entry metadata stride, and seed each entry as authoritative. Today only the `GUARD_CF` flag is displayed. | The linker emits the table. |
| x86 gap recovery | x86 has no `.pdata`, so validate candidates in code gaps with other evidence: a relocation or Guard CF entry naming them; an MSVC, gcc or Delphi prologue with a matching epilogue; a `ret imm` that matches the stack arguments; padding before the start. | At least one structural witness and a coherent body. |
| Jump-table resolution | Resolve tables loaded into a register (`lea r, [table]` then `movsxd`, `add`, `jmp`), relative tables, and two-level byte-index tables. Then drop the leaf sweep's dispatch exclusion. | The case count is bounded by a `cmp`/`ja` guard, and every target decodes. |
| x64 C scope tables | Read the filter, handler and termination funclets from `__C_specific_handler` scope records. | `UNWIND_INFO` names the handler. |
| `__CxxFrameHandler4` | Decode the compressed FH4 catch and unwind maps. | `UNWIND_INFO` names the handler. |

### Recovery measurement

| Item | Work |
|---|---|
| Benchmark harness | **First version done (#52).** Remaining: a small subset in CI. A script that runs the per-change workflow (see [Methodology](#methodology)) over a corpus manifest and compares two commits. It writes recall, precision, merged and split bodies, and timing as JSON. A small subset runs in CI. Its first truth source is tier B evidence extracted from the existing corpus, so it is useful before the symbol corpus exists. |
| Evidence census | For each evidence source (`.pdata`, Guard CF, thunk tables, FH4, C scope tables, `.eh_frame`, Go `pclntab`, and so on), report how many corpus binaries contain it and how many starts it alone contributes. This orders the recovery items below. |
| Baseline | Publish the first numbers per format, architecture and compiler in [benchmarks.md](benchmarks.md), and set the targets in [Definition of "best"](#definition-of-best) from them. |
| Symbol corpus | Fetch about 200 Windows binaries with PDBs (x86, x64, ARM64) and about 200 Linux binaries with debuginfo. Commit the extracted truth (start, size, name) as manifests, not the binaries. |
| Compiler matrix | A reproducible build of test programs with MSVC, clang-cl, gcc, clang, Go and Rust first; MinGW, Delphi and Nim later (Delphi needs a commercial toolchain). Build at `-O0`, `-O2` and `-Os`, with LTO, incremental and not. Keep symbols for the truth; analyze stripped copies. |

### Packed and dumped images

The goal assumes binaries that are often packed. Until these exist, recovery work on a packed sample only improves the unpacker stub.

| Item | Work |
|---|---|
| Static unpacking | UPX first (PE, ELF, Mach-O), with the original file and the unpacked image both kept in the project. Then the next packers by frequency in the malware corpus. |
| Dumped images | Open PE images dumped from memory or injected into a process (unaligned sections, rebuilt imports). Reuse an intact `.pdata`. This lets binfera read modules the File Analysis Bus project recovers from minidumps. |

### Type knowledge

The decompiler can only print what it knows about the APIs and structures a sample uses. The Windows packs come from Ghidra's Visual Studio 2012 archives plus a driver-header supplement, and keep only types that some prototype refers to. That leaves out structures reached through registers, such as `_PEB` through `gs:[0x60]`.

Measured over the 365 PE files in `tests/testfiles` before #57:

- 16.3% of named imports (6,948 of 42,677) had no prototype. After #57, `coverage.py` reports 8.5% (3,628) over 347 PEs; the rest are class-typed decorated names (mfc42, msvcp*, Qt), data exports, third-party DLLs, ordinal-only imports and about 95 `ntdll` leftovers.
- The untyped APIs found in the most files are Toolhelp (`CreateToolhelp32Snapshot` in 84 files, `Process32*` in 37 to 40), WinINet (`InternetReadFile` in 45, `InternetOpenA` in 34, `HttpSendRequestA` in 21), WinHTTP, and undocumented `ntdll` exports (`NtQuerySystemInformation` in 19, `Ldr*`, `NtCreateThreadEx`).
- 280 files import `GetProcAddress` and 72 import `CoCreateInstance`. Since #59, an API resolved with a literal name into a global prints as a typed call; one kept in a local, or whose name is decrypted at run time (`GetProcAddress(h, decode("HfuQspdBeesftt"))`, about 330 of 412 unnamed calls in one corpus sample), still prints as `(*pFVar5)(...)`, and a COM call prints as a vtable offset.

#### Data

All data is generated by development scripts and checked in as packs, like today's prototype packs. Nothing is downloaded at build time or at analysis time. Each pack is a type library in the format of semantic-editing step 2, so analysts can apply its types by hand and later passes can use them. Packs load lazily, so the browser downloads only the packs a sample needs. Not done yet: since #57 the Windows packs are embedded in the wasm, which grew the web download by about 5 MB.

| Pack | Content | Source |
|---|---|---|
| Win32 (**done, #57**) | Every documented Win32 function, structure, enum and constant, including WinINet, WinHTTP, Toolhelp, BCrypt, netapi and the APIs added after Windows 8. Parameters carry the enum or flag set they take. | Microsoft's Win32 metadata (`Windows.Win32.winmd`), read with the `windows-metadata` crate. No Java and no C parsing are needed. |
| COM | Interface vtable layouts with method names and signatures, keyed by IID; class names keyed by CLSID. | The same Win32 metadata. The existing `binfera/data/com_interfaces.json` (used only by capa today) supplies extra GUID names. |
| Native API (**done, #57**) | `Nt*`, `Zw*`, `Rtl*` and `Ldr*` prototypes, and the loader structures `_PEB`, `_TEB`, `_PEB_LDR_DATA` and `_LDR_DATA_TABLE_ENTRY`. | The phnt headers from System Informer (MIT), parsed by the same C-declaration parser as step 2. The WDK metadata (`Windows.Wdk.winmd`) is the fallback. |
| PE structures (**done, #57**) | `IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS32/64`, `IMAGE_EXPORT_DIRECTORY`, `IMAGE_IMPORT_DESCRIPTOR` and the other headers that manual loaders parse. | The Win32 metadata. |
| C runtime (**done, #57**) | MSVCRT, UCRT (`api-ms-win-crt-*`) and VCRUNTIME startup and helper exports. | The Win32 metadata and the MinGW-w64 headers already used for the driver supplement. |
| Windows syscalls | System call number to `Nt*` name, for each Windows build. | Extracted from the `ntdll.dll` and `win32u.dll` builds on Microsoft's public symbol server, by decoding their stubs. Not copied from third-party tables, whose license is unclear. |
| API hashes | Hash value to API name, for the common algorithms (ROR13 additive, DJB2, FNV-1a, CRC32, and the hash variants malware families use). | Computed from the export names of the packs above. OALabs HashDB (Apache-2.0) is a reference for which algorithms to cover. |
| Static libraries | Function ID packs for OpenSSL, mbedTLS, zlib, libcurl, Boost and the Delphi runtime. | Built at several versions and optimization levels with the compiler matrix. |

The Win32 metadata repository is MIT, but its notice says the metadata does not change the license of the SDK headers it was generated from. windows-rs redistributes the `.winmd` files under MIT or Apache-2.0, and today's packs already come from SDK-derived Ghidra archives. Confirm this before the first Win32 pack ships.

#### Passes

| Item | Work | Proof |
|---|---|---|
| Untyped imports | **Pack lookup done (#57); allow-list widened (#64):** `pdh`, `msi`, `credui`, `fwpkclnt`, DirectX and 47 more system DLLs (53 in all) whose exports the packs type (the corpus has few of them: 3,628 to 3,619 untyped imports). Remaining: class-typed decorated names, data exports and ordinal-only imports. Look up every import in the packs above. Derive prototypes for MSVC- and Itanium-mangled imports (`msvcp*`, `mfc*`, Qt) from the mangled name, which encodes the parameter and return types. | The import name, or its mangled signature. |
| Resolved APIs | **Globals with a literal name done (#59):** WannaCry 13 of 13 calls, DarkGate 58. The Asm view, the graph and the Listing name these slots and their calls like imports (#64; WannaCry 13 of 13, DarkGate 55 slots), and argument comments follow. Remaining: results kept in locals and struct fields, `LdrGetProcedureAddress`, hashes. A `GetProcAddress` (or `LdrGetProcedureAddress`) call whose name argument is a constant string types its result as that API's function pointer. The global or local that receives it is named after the API. Do the same for hash-resolved APIs once the hash and the algorithm are identified. | A constant name argument, or a hash found in the hash pack for exactly one API. |
| Constant function pointers | **Done for globals (#64):** a global written only with the same one function of the program, or never written and initialised with it, is registered as a code pointer, so `(*DAT_x)(a, b)` prints as `FUN_00401234(a, b)` with that function's prototype. DarkGate 117 to 94 indirect calls, the Nim demo 35 to 17; 244 corpus PEs 15,766 to 15,602, with no new decompile error. A global with two different values, a zero reset, a taken address or an unknown writer is left alone. Not detected: a write through a pointer to an enclosing object. Remaining: pointers kept in struct fields and arrays, and in locals. | Every write in the image stores that one entry, and the address is never taken. |
| Symbolic constants | **Done in #62** for Win32 enum and flag sets (9 Windows demos: numeric arguments at enum parameters 251 → 17). Remaining: sets the metadata lacks (service-manager access, `socket` family and protocol). Print constant arguments as their enum or flag names: `MEM_COMMIT \| MEM_RESERVE`, `PAGE_EXECUTE_READWRITE`, `CREATE_SUSPENDED`, `HKEY_LOCAL_MACHINE`. | The parameter's enum in the Win32 metadata. A value that does not decompose into the set's flags stays numeric. |
| COM calls | Type the output pointer of `CoCreateInstance`, `QueryInterface` and `CoGetObject` from a constant IID, so vtable calls print as `pService->Connect(...)`. | A constant IID found in the COM pack. |
| Windows syscalls | Name direct `syscall` and `int 2e` stubs from a constant `eax`. Use the build of the closest match when the target build is unknown, and mark the name as a guess. | A constant system call number; the build when known. |
| Strings | Run identified decryption routines in the existing function emulator, and annotate their call sites with the plaintext. | The emulator's result at the call site. |
| Measure | **Done (#64):** `scripts/bench/quality.py` reports untyped imports, `(*X)(...)` call sites, unknown-callee calls and numeric constants at enum parameters per file, compares two binaries and writes JSON. Seven small PEs (`scripts/corpus-quality.txt`) run in CI on Linux, about 30 seconds, and fail when a count rises above `scripts/bench/quality-baseline.json`. Remaining: gate a release on the whole corpus, not the subset. | |

### Other decompiler output

| Area | Remaining work |
|---|---|
| Signatures | Items 3 and 4 above. |
| Types | Propagate import prototypes and RTTI class layouts. Recover structures from base-plus-offset accesses, and arrays from indexed accesses. |
| Control flow | x86 `__try` is item 2 above. Remaining: x64 `__try` from `__C_specific_handler` scope records, C++ `try`/`catch` from FH3 and FH4 tables, `switch` from resolved tables, and fewer `goto` (15% of functions) through better loop structuring. |
| Idioms | Inline `memcpy` and `memset`, stack strings, string decryption loops, API hashing (see [Type knowledge](#type-knowledge)), and the CRT and STL inlines (`std::string`, `std::vector`). |
| Correctness gate | In CI, run differential emulation of the IR against the machine code on the compiler matrix. |
| Go | AArch64 support; string constants; signatures for the program's own methods; the closure context register; the goroutine register on x86 and before Go 1.17. |
| C++ | Itanium RTTI, class layouts, constructors and destructors, virtual bases, `try`/`catch` syntax. |
| Rust | Signatures for stripped functions, generic aggregates, `String` and `Vec` layouts. |
| DWARF | Split DWARF, separate type units, debug links, unions and bit fields, register locals and location lists. |
| PDB | Load external PDB files for names and types. |

### Other formats and architectures

| Item | Work |
|---|---|
| ELF | Name `.plt`, `.plt.sec` and `.plt.got` stubs from their relocations. Use `endbr64`/`endbr32` as an entry hint in code gaps; it is only a hint, because landing pads start with it too. Sweep code outside every FDE for leaves, accounting for the System V red zone. |
| Mach-O | Objective-C method lists, including relative ones. Swift metadata accessors and protocol witness tables. Chained-fixup pointers as pointer evidence. Stub helpers. |
| ARM64 PE | Packed unwind data. ARM64EC and ARM64X images that mix x64 and ARM64 code. |
| ARM32/Thumb | Track the interworking bit through `bx`, `blx` and pointers. Keep literal pools out of the decoder. Resolve `tbb`/`tbh` switch tables. |
| MIPS | Delay slots when finding boundaries and tail calls. `$gp`-relative calls through `.got`. `lui`/`addiu` pairs as pointer evidence. |
| AArch64 | `adrp` pairs as pointer evidence. `br` switch tables with `ldrb`/`ldrh` offsets. `paciasp` as an entry marker. |
| Runtimes | Rust panic `Location` records, and Nim and Delphi initialization tables. |

## P2

| Area | Remaining work |
|---|---|
| Obfuscation | Opaque predicates (fold with emulation, then prune); `call $+5`/`pop` sequences and overlapping instructions; junk code; flattened control flow (recover the dispatcher's state variable). |
| Shellcode and blobs | No headers to start from: seed from position-independent idioms (PEB walks, API-hashing loops), prologue statistics, and what is reachable from offset 0. |
| Confidence | Mark functions whose boundaries or CFG rest only on heuristics. |
| YARA in the workbench | Scan the open file with YARA-X rules and jump from a hit to its hex offset or function. Reuse the File Analysis Bus project's rules. |
| .NET decompilation | C# pseudocode; only IL is listed today. |
| File Analysis Bus hand-off | Open a file from a link by SHA-256. Align capa rule and engine versions with the File Analysis Bus project. |

## P3: built only if analysts ask

| Area | Remaining work |
|---|---|
| Bytecode viewers | Disassembly views for Python 2.7 and 3.6+, pickle and VB P-code. The File Analysis Bus project does the triage parsing; build these only if analysts need to read the code. |
| Architectures | PowerPC (including ELFv1 function descriptors), RISC-V (including linker relaxation), MIPS64. |
| Hex structure templates | PE, ELF and Mach-O headers are already colored. Remaining: import and export tables, the resource tree, certificate, debug and TLS directories, overlay and embedded-file boundaries, and custom templates. |
| Start overrides | Let analysts promote or demote a function start, stored in the project overlay. |
| Learned start classifiers | Byte n-gram models that only propose candidates. Their results must still pass each heuristic's proof rule. |

## Methodology

### Ground truth without source

These sources are ordered by trust. The benchmark records which of them confirm each function start.

| Tier | Source | Formats | What it proves |
|---|---|---|---|
| A | Public symbols: Microsoft PDBs, distribution debuginfo, dSYM | PE, ELF, Mach-O | Exact starts, sizes, names and types. Used to build the benchmark, never at analysis time. Public Microsoft PDBs mostly hold `S_PUB32` records: starts and names without sizes, so sizes come from `.pdata` where it exists. |
| B | Incremental-link thunk table | PE (MSVC) | Every function the linker kept, referenced or not. |
| B | `.pdata`, ARM64 packed unwind | PE x64, ARM64 | The extent of every non-leaf function. Gaps between them can only hold leaves. |
| B | Guard CF function table | PE | Every valid indirect-call target. |
| B | `.eh_frame`, `.ARM.exidx` | ELF | Almost every compiled function, even when stripped. |
| B | `LC_FUNCTION_STARTS` | Mach-O | Every function start. |
| B | `pclntab`, Swift and Objective-C metadata, Delphi VMTs, RTTI and exception tables | Several | Entries named by runtime metadata. |
| C | Exports, entry points, TLS callbacks, init and fini arrays, relocations, vtables | All | Individual entries. |
| D | Direct calls, resolved pointers, emulation | All | Reachability. |
| E | Gap sweeps, prologue shapes, signatures | All | Candidates only. Each must pass its heuristic's proof rule. |

### Metrics

The metrics are computed per binary, then grouped by format, architecture, compiler and malware family.

- **Start recall and precision:** exact address match against tier A or B truth.
- **Boundary errors:** bodies merged into another function, and blocks split off into their own function. A function may be non-contiguous: a cold or PGO-separated block that the truth assigns to its parent, and that binfera attaches to the same parent, is not a split.
- **CFG:** unresolved indirect jumps, switch tables with the correct case count, blocks reached.
- **Calls:** indirect calls resolved, and argument and return counts for known callees.
- **Types:** parameter and local types compared to PDB or DWARF types, where symbols exist.
- **Correctness:** differential emulation of the IR against the machine code, recompiling small leaf functions, and round-tripping the compiler matrix through decompile, recompile and test.
- **Readability:** counts of `goto`, casts, temporaries and unnamed globals. These are tracked as trends, not gates.
- **Output review set:** started as [item 1](#review-set) with about 30 functions, growing to about 100 malware functions (string decryption, API resolution, configuration parsing, C2 dispatch) with a hand-checked expected reading. Each release reports, for each function, whether the output still supports that reading.
- **Cost:** wall time and peak memory, per function and per image.

### Corpus

| Set | Content | Truth |
|---|---|---|
| Symbol corpus | Windows system binaries with PDBs, Linux packages with debuginfo, macOS binaries | Tier A |
| Compiler matrix | Builds across compilers, optimization levels and link modes, analyzed stripped | Tier A from the build |
| Malware corpus | `tests/testfiles` and curated families: loaders, RATs, ransomware, shellcode | Tiers B and C, plus triage |
| Adversarial set | Obfuscated, overlapping and packed samples, with memory dumps | Labeled by hand |

### Classifying a disagreement

When binfera and another tool disagree on a start, put the address in one of these classes:

1. **Confirmed by linker or ABI evidence.** binfera is right.
2. **Clean code head.** It is aligned, follows padding or a function end, and has a coherent body. Probably real.
3. **Mid-instruction.** It is a false start; find the pass that produced it.
4. **Data.** A jump table, constant pool or string. It is a false start.
5. **Interior block.** A switch case, funclet or cold block. Exception funclets have their own unwind data; switch cases do not.

Every class 3, 4 or 5 start binfera produces becomes a regression test.

### Workflow for each recovery change

1. Inventory every corpus binary at the base and at the change, with `--decompile-all --jobs 1 --shard 0/65536`.
2. Diff the start lists. An unexplained removed start blocks the merge.
3. Classify the added starts in the most-changed files, and report the counts for each class.
4. Score recall and precision against the symbol corpus.
5. Check that time and memory have not regressed.
6. Add a synthetic test for each new rule and for each class of false positive it fixed.

### Definition of "best"

Targets are set per format and architecture once the [baseline](#measurement) is published, and are raised as results improve. The initial aims, to be confirmed against the baseline, on PE x86, x64 and ARM64, ELF x64 and AArch64, and Mach-O ARM64:

- Start recall of at least 99.5% and precision of at least 99.9% where tier B truth covers every function (x64 `.pdata`, `.eh_frame`, `LC_FUNCTION_STARTS`). x86 PE has its own, lower target.
- Merged or split bodies below 0.1%.
- At least 98% of switch tables recovered.
- Every mismatch found by differential emulation is a release blocker until it is fixed or explained.

On the malware corpus, a release removes no start, and every added start is classified. Each release publishes these numbers in [benchmarks.md](benchmarks.md).

## Handled by the File Analysis Bus project

NSIS and Inno Setup script analysis, AutoIt, PyInstaller, py2exe and Nuitka unpacking, minidumps, archives beyond zip and 7z, documents, and SQLite and media parsers.
