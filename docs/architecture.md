# Architecture

`binfera` has one Rust analysis library, a CLI, an MCP server with a shared project database, Python bindings, and a browser and desktop workbench. The library owns input handling, recovery, feature extraction, matching, and decompilation policy. The CLI supplies arguments and serialization. The browser runs that CLI as WebAssembly in workers and presents its structured results.

## Workspace map

```text
binfera/
├── binfera/                 analysis library
│   ├── rules/              rule grammar, validation, and dependency graph
│   ├── extract/loader/image/ shared image model's PE, ELF, Mach-O loaders and decoding
│   ├── extract/recovery/engine/ seed discovery, flow traversal, and function views
│   ├── extract/features/   feature extraction over recovered code
│   ├── image_info/         normalized headers, sections, imports, exports, and file mappings
│   ├── decompiler/batch/   whole-image selection, typed events, graphs, and alternate listings
│   ├── freeze.rs           capa freeze-format reader and data model
│   ├── capabilities/       static and dynamic rule matching
│   ├── result_document/    canonical result document model
│   ├── diff/               fingerprints, function matching and the diff document
│   └── render/             text and JSON renderers
├── binfera-cli/             command-line loading and presentation
├── binfera-ghidra/          optional native decompiler bridge
├── binfera-mcp/             MCP server (`binfera mcp`)
├── binfera-project/         project database shared by the MCP server and the desktop app
├── binfera-python/          PyO3 declarations around the library API
├── web/src-tauri/          desktop app shell (Tauri)
├── web/src/engine/         worker protocol, assets, and metadata presentation helpers
├── web/src/workspace/      navigation, ownership, and reference indexes
├── web/src/views/          capability, function, string, and section views
├── third_party/dnfile/     checked vendored CLR metadata and CIL parser
├── rules/                  pinned capa-rules submodule
├── reference/capa/         pinned Python capa behavioral reference
└── scripts/                differential tests, benchmarks, and maintenance
```

`binfera-python` contains binding declarations only. It does not duplicate analysis logic. The vendored `dnfile` fork is a path dependency of `binfera`, kept outside the workspace because its optional command-line targets are not part of this project's build.

## The freeze-format seam

Extraction and matching communicate through `binfera::freeze::Freeze`. A backend converts bytes into a static or dynamic feature tree with ordered addresses. The matching engine consumes that tree without knowing whether it came from PE, ELF, shellcode, .NET, Mach-O, or a precomputed freeze file.

This boundary keeps two kinds of correctness independent:

- extractor tests can compare recovered features with an upstream or native oracle without involving rule evaluation;
- engine tests can validate rule parsing, statement evaluation, scopes, and evidence using freeze fixtures without loading a binary.

Ordering is part of the contract. Feature collections retain the order needed by capa's short-circuiting string and regular-expression evaluation, while address-keyed scopes are traversed in canonical address order.

## Data flow

```text
bytes or freeze file
        │
        ▼
load and identify format
        │
        ▼
recover code and extract file features
        │
        ▼
Freeze::Static or Freeze::Dynamic
        │
        ▼
match validated rules and collect evidence
        │
        ▼
build ResultDocument
        │
        ├── render text or JSON in binfera-cli
        └── serialize through binfera-python
```

The public library entry point is `binfera::api::analyze`. It accepts input bytes, a built `MatchingRuleSet`, and `AnalysisOptions`, then returns a `ResultDocument`. `load_input` is also public for file-only and diagnostic surfaces that need the freeze data before matching. Reading files and rules, argument parsing, and presentation flags stay at the edges.

Bundled FLIRT signatures are parsed once per process and shared immutably across analyses. The first caller's job count controls initialization; subsequent calls reuse the same databases. This avoids repeated parsing for library and Python callers, at the cost of retaining the databases until process exit. Custom signature paths are loaded afresh on each call so edits, removed files, and parse errors remain visible.

## Backend integration points

Each backend has the same broad responsibilities: validate its container, recover code where applicable, emit capa-shaped features, and hand the result to the shared freeze and matching layers.

- **PE and ELF x86/x64:** format loaders emit file features; the shared recovery code finds functions and basic blocks; the x86 decoder and feature modules emit instruction and operand features. FLIRT enrichment is an optional PE step before matching. Compatibility recovery evaluates undefined pointer and operand-reference targets with a bounded abstract interpreter over iced-x86, before late signature scans. It tracks private state without executing samples; unsupported paths retain diagnostics. Windows callback recovery reuses this state for typed API arguments. Import-call fragments run before entry signatures and preserve each callee's instruction view at creation, keeping later loose instructions separate from function ownership. The compatibility ELF loader binds only reference import relocation types; native loading retains broader bindings. Compatibility blocks distinguish opcode locations from the instruction streams extracted from their byte intervals, preserving overlapping reference blocks. Legacy BOUND and ModRM aliases follow the pinned decoder. Switch tables stop at definite candidate-evaluation failures in table order. Native recovery retains modern decoding and complete guarded switches. Full PE analysis uses workspace segment names, while file-only analysis uses pefile section names. File-only PE/ELF format features have file scope. x86/x64 compatibility recovery uses registered entry signatures rather than broad prologue and raw call scans; native recovery retains those fallbacks.
- **Raw shellcode:** the shellcode loader supplies an explicitly selected architecture, then uses the shared recovery and x86 feature pipeline without a container loader.
- **.NET:** the CLR path validates the managed PE and uses the vendored `dnfile` fork for metadata and CIL. The .NET feature extractor emits the same static freeze structure consumed by the common matcher.
- **Mach-O:** the Mach-O loader validates thin and fat images and selects a slice. x86_64 uses the shared x86 path; AArch64 uses the AArch64 decoder and feature modules.
- **AArch64 ELF and PE:** format-specific loading and relocation handling feed the AArch64 recovery and feature modules. The result is still a normal static freeze tree.
- **Freeze input:** the freeze reader skips binary extraction entirely and enters at the shared matching stage.

Adding a backend therefore changes format dispatch and extraction modules. It does not require a second rule engine, result schema, or renderer.

## Optional function decompilation

The `decompiler` feature provides a separate `Decompilation` result for x86, x86-64 and AArch64 PE, ELF and Mach-O functions, ARM32/Thumb (PE, ELF) and classic MIPS32 (ELF), or explicitly selected x86 raw code. Existing recovery supplies discovery metadata; native SLEIGH translates the bytes and Ghidra performs decompilation. The bridge crate owns the FFI boundary while analysis crates forbid unsafe code. Normal capability analysis never initializes the engine. See [usage](decompiler.md) and [ownership, integration and resource policy](decompiler-design.md).

`decompiler::decompile_all(bytes, options, emit)` streams typed `BatchEvent` values. The library reconciles compatibility and native function inventories, selects shards, discovers supporting callees, and applies bounded session rebuilds and resource retries. A callback error stops the batch. The CLI only serializes these events as NDJSON. Managed assemblies produce named IL listings; ELF CPUs without a decoder produce file-wide diagnostics through the same event API.

Native function events also carry recovered basic blocks, edges, direct calls and data references. The browser uses these structures without decoding assembly text again. Listings without a complete recovery graph, including IL and some extra callees, retain a listing-based fallback. Graph layout and presentation stay in TypeScript.

## Binary comparison

`diff::fingerprint` reduces a binary to a `Fingerprint`, read from native recovery or, for managed code and freeze files, from features. `diff::compare` takes two fingerprints and optionally two `ResultDocument`s, and never sees the samples, so the browser fingerprints each side in its own worker and compares in a third. See [comparing binaries](comparison.md).

## Browser metadata boundary

`image_info::inspect(bytes, arch)` reads metadata without code recovery, signatures or rules. It uses the recovery loaders' address mappings and Mach-O slice selection. Its sections and regions refer to offsets in the original input file, including universal containers. ELF CPUs without a decoder retain header, symbol and segment metadata.

`image_info::details` adds what an analyst reads before the code: every header field laid out at its file offset and address, triage facts (hashes, hardening, dependencies, build traces), findings, the overlay, PE resources and version information, and Authenticode and Apple code signatures. Collection never fails an inspection, and every length and offset it reads from the file is bounded. Signatures are compared with the file's own digest or page hashes; certificate chains and trust are not evaluated, so a match means the file is intact, not that its signer is trustworthy. Imphash follows pefile, including its ordinal names, so values can be compared with those from other tools. Overlay excludes debug data and COFF symbol tables, which pefile counts.

The browser first loads the WebAssembly module and runs `--image-info` in a short-lived inspection worker. This result supplies pointer width, byte order, entry point, sections, imports, exports, file details and the Function ID pack selection. TypeScript wraps those mappings for navigation and scans display strings against them; it contains no separate PE, ELF or Mach-O parser. Capability and decompilation workers then run independently, using the existing memory limits and shard policy.
