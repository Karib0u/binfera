# Roadmap

Updated: 2026-11-20. This page lists planned work and how it will be measured. It also lists what already exists, so that work is not planned twice. Priorities describe relative value, not delivery dates.

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
8. **Prioritize by frequency in the malware corpus.** An item's rank follows how many corpus binaries it affects and how many functions or results it changes, measured by the harness. Coverage of Windows system binaries alone does not raise a priority.

## Already covered (do not re-plan)

- **PE:**
  - Metadata: resources, version info, manifest, Authenticode, Rich header, imphash, compiler traces, COFF/object loading, packer detection.
  - Function sources: unwind data, SafeSEH, x86 SEH3 scope tables, MSVC RTTI and C++ exception metadata.
  - Incremental-link thunk tables: every target is recovered, and no stub absorbs a body.
  - x64 frameless leaves in code gaps, with switch cases rejected.
  - Delay-load stubs. x64 language handlers and the C++ `ThrowInfo` destructors and copy constructors.
- **ELF:** `.eh_frame` and `.ARM.exidx` function entries, init and fini arrays.
- **Mach-O:** `LC_FUNCTION_STARTS`, code signatures, chained fixups.
- **Detail views:** ELF and Mach-O, plus a hex view whose header fields are colored for PE, ELF and Mach-O.
- **Language and library support:** Go `pclntab`, DWARF, Delphi VMTs and RTTI, Nim, Itanium and MS demangling, FLIRT and Function ID.
- **Other recovery:** relocations, vtables, pointer recovery, jump tables, and prologue and unclaimed-gap sweeps.
- **Typed input to the decompiler:** debug types (structures, pointers, arrays, aliases), locked signatures, typed stack locals and named data symbols, all through the Ghidra bridge.
- **Decompilation:** x86, x86-64, AArch64, ARM32/Thumb and MIPS32.
- **Other analysis:** capa, function emulation and diffing.
- **Viewers:** entropy, hex, strings and imports, and a .NET IL listing.
- **Archives:** zip and 7z, with known-password probing.
- **Integrations:** MCP and the agent.

## P0

### Measurement

| Item | Work |
|---|---|
| Benchmark harness | A script that runs the per-change workflow (see [Methodology](#methodology)) over a corpus manifest and compares two commits. It writes recall, precision, merged and split bodies, and timing as JSON. A small subset runs in CI. Its first truth source is tier B evidence extracted from the existing corpus, so it is useful before the symbol corpus exists. |
| Evidence census | For each evidence source (`.pdata`, Guard CF, thunk tables, FH4, C scope tables, `.eh_frame`, Go `pclntab`, and so on), report how many corpus binaries contain it and how many starts it alone contributes. This orders the recovery items below. |
| Baseline | Publish the first numbers per format, architecture and compiler in [benchmarks.md](benchmarks.md), and set the targets in [Definition of "best"](#definition-of-best) from them. |
| Symbol corpus | Fetch about 200 Windows binaries with PDBs (x86, x64, ARM64) and about 200 Linux binaries with debuginfo. Commit the extracted truth (start, size, name) as manifests, not the binaries. |
| Compiler matrix | A reproducible build of test programs with MSVC, clang-cl, gcc, clang, Go and Rust first; MinGW, Delphi and Nim later (Delphi needs a commercial toolchain). Build at `-O0`, `-O2` and `-Os`, with LTO, incremental and not. Keep symbols for the truth; analyze stripped copies. |

### Windows function recovery

Order these by the evidence census. Guard CF and the C++ handler tables are common in Microsoft binaries and may be rare in malware. The first census (376 PE and ELF files in `tests/testfiles`) found 100% tier B recall on PE x64 and about 1,300 starts inside x64 `.pdata` extents, so false starts come first.

| Item | Work | Proof |
|---|---|---|
| Interior false starts | Reject starts strictly inside a `.pdata` extent unless they are a funclet or a chained entry. The first census found 521 from `Vtable`, 372 from `MsvcCookieBlock`, 309 from `PointerTarget` and 94 from `Emulated`, some at odd addresses. | `.pdata` names the extent of every non-leaf function. |
| PLT sections | Treat `.plt`, `.plt.got` and `.plt.sec` FDEs as stub ranges, not one function each, in both recovery and scoring. | The section and its relocations. |
| Guard CF table | Parse `GuardCFFunctionTable` from the load config, including the per-entry metadata stride, and seed each entry as authoritative. Today only the `GUARD_CF` flag is displayed. | The linker emits the table. |
| x86 gap recovery | x86 has no `.pdata`, so validate candidates in code gaps with other evidence: a relocation or Guard CF entry naming them; an MSVC, gcc or Delphi prologue with a matching epilogue; a `ret imm` that matches the stack arguments; padding before the start. | At least one structural witness and a coherent body. |
| Jump-table resolution | Resolve tables loaded into a register (`lea r, [table]` then `movsxd`, `add`, `jmp`), relative tables, and two-level byte-index tables. Then drop the leaf sweep's dispatch exclusion. | The case count is bounded by a `cmp`/`ja` guard, and every target decodes. |
| x64 C scope tables | Read the filter, handler and termination funclets from `__C_specific_handler` scope records. | `UNWIND_INFO` names the handler. |
| `__CxxFrameHandler4` | Decode the compressed FH4 catch and unwind maps. | `UNWIND_INFO` names the handler. |

## P1

### Packed and dumped images

The goal assumes binaries that are often packed. Until these exist, recovery work on a packed sample only improves the unpacker stub.

| Item | Work |
|---|---|
| Static unpacking | UPX first (PE, ELF, Mach-O), with the original file and the unpacked image both kept in the project. Then the next packers by frequency in the malware corpus. |
| Dumped images | Open PE images dumped from memory or injected into a process (unaligned sections, rebuilt imports). Reuse an intact `.pdata`. This lets binfera read modules the File Analysis Bus project recovers from minidumps. |

### Analyst-editable semantics

Step 1 does not depend on the measurement work and can start alongside P0.

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

### Decompiler output

| Area | Remaining work |
|---|---|
| Signatures | Infer argument counts and types from every call site and from how the callee uses its registers. Reconcile them with ABI evidence: Win64 home space, `ret imm` on x86, variadic calls. |
| Types | Propagate import prototypes and RTTI class layouts. Recover structures from base-plus-offset accesses, and arrays from indexed accesses. |
| Control flow | Structure `try`/`catch` and `__try`/`__except` from exception metadata. Emit `switch` from resolved tables. Reduce `goto` with better loop structuring. |
| Idioms | Inline `memcpy` and `memset`, stack strings, string decryption loops, API hashing (resolve hashes to API names), and the CRT and STL inlines (`std::string`, `std::vector`). |
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
- **Output review set:** about 100 malware functions (string decryption, API resolution, configuration parsing, C2 dispatch) with a hand-checked expected reading. Each release reports, for each function, whether the output still supports that reading.
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
