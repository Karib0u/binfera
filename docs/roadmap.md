# Roadmap

Updated: 2026-11-26 (Code origin, phone rework, and calmer workbench shipped). Ranked by **analyst value for effort**. Every item has an effort estimate (`S`: ~1 day, `M`: a few days, `L`: weeks) and a concrete **Done when** check.

**Goal:** Build the next-generation IDA/Ghidra — fast, responsive on desktop and mobile, and effortless to work in:
- **Immediate:** 60fps navigation and search at scale, zero-friction triage, and native-feeling mobile + desktop UI.
- **Readable:** C output, provenance, and emulation that explain what a function does without fighting the tool.
- **Editable:** analyst-supplied names, types, structs, and prototypes flow through Ghidra, not over its text.
- **Exact:** high-precision recovery guarded by benchmarks, without blocking product progress on small edge cases.

**Scope:** Binfera focuses on binary code analysis ("what does this executable do?"). File-format unpacking, installer/bytecode scripts (NSIS, Inno, AutoIt, PyInstaller, py2exe, Nuitka), minidumps, and verdicts belong to **File Analysis Bus**.

---

## Now — Workflows IDA & Ghidra Don't Have

Differentiating features that work on every binary, building on engine code that mostly already exists.

| # | Item | Effort | Done when |
|---|---|---|---|
| 1 | **Function Emulation in the UI (Desktop & Browser)** — Expose existing `emulate_function` and `emulate_call_sites` in `FunctionView` across both the native desktop engine and WASM: set args/buffers → run → inspect return value, registers, written memory/decoded strings, or decrypt call sites. | M | Analyst can run a string-decryption routine from `FunctionView` in both desktop and browser and inspect/copy the decoded output. |
| 2 | **Instant Search at Scale** — Move global code/asm search into a Web Worker; add local in-pane `⌘F` (including 1–2 char tokens), wildcard hex byte search (`b: 4d 5a ?? 00`), `Tab` scope cycling in `Palette`, and `>` command actions in `⌘K`. | M | `⌘K` stays 60fps on a 10 MB+ binary; `⌘F` steps matches in-function; `b:` finds wildcard byte patterns in `HexView`. |
| 3 | **Variable provenance on hover** — Hovering a variable shows the statement that sets it (`hFile = CreateFileA(…) @ 0x40193a`) and clicks to jump there. | S–M | Web test hovers `hFile` in WannaCry `0x4018f9` and shows the `CreateFileA` line. |
| 4 | **Handle provenance (beyond files)** — File handles already trace to opening calls in `fileHandleOrigins.ts` (#70). Extend the same inline provenance comments to registry keys, mutexes, sockets, and processes (including caller-passed names). | S | Functions using registry, mutex, socket, and process handles display their opening call at each use. |
| 5 | **Portable snapshots & Notes panel** — Add `.binfera` snapshot import/export and a unified Notes/Comments panel so renames, comments, and stars move cleanly between browser, mobile, and desktop. | S | Exporting and re-importing a snapshot in a clean browser restores all renames, comments, and stars. |
| 6 | **Lazy-load Windows type packs in WASM** — Split the ~5 MB Windows type packs out of the initial `.wasm` bundle so cold browser and mobile loads stay fast. | M | Initial `.wasm` shrinks by >4 MB while Windows samples still load their packs on demand. |
| 7 | **Named stack slots in assembly** — Print `mov [ebp+hFile], eax` instead of `mov [ebp-28h], eax` in Asm and Listing. | S | WannaCry `0x4018f9` listing shows `hFile` on the store after `CreateFileA` and on both reads. |

---

## Next — Inline Semantic Editing

The core `L` leap: press `Y` on any function, parameter, or global to edit its prototype, retype it, or define/apply a struct — flowing live through Ghidra across Desktop, Web, and MCP. *(Step 1 PoC is done in `binfera/tests/decompiler_user_types.rs`.)*

| Step | Work |
|---|---|
| 1. Semantic model | `binfera/src/decompiler/semantics.rs` (primitives, pointers, arrays, structs, enums, aliases, signatures, data/stack bindings), validation, C-declaration parser, and SQLite v4 tables using existing revision/undo machinery. |
| 2. Bridge | Generalize `add_debug_types()` / `set_debug_signature()` into a unified loader with separate source ID spaces, hidden internal names, and global-data / stack-slot typing without modifying vendored Ghidra algorithms. |
| 3. Session replay | Precedence: user → DWARF/symbols → type packs → inference. Clear `invalidateInferred` on type edits; keep analyst edits off cached `Analysis`. |
| 4. Split caches | Base analysis cache keyed by `(sha256, engine_version)`; pseudocode cache keyed by `(overlay_hash, fn_addr, options)`. Comments/stars never invalidate pseudocode. |
| 5. Workflows (UI & MCP) | Define/apply struct, edit prototype (`Y`), type global data with live C preview; MCP tools `list_types`, `define_type`, `set_function_signature`, `set_data_type`; replace text-rewrite renames with native symbols. |
| 6. Local variables | Retype locals once identity survives reanalysis (keyed by storage + first-use address, not `iVar3`). |

---

## Later — Engine, Formats & Ecosystem (Pain-Driven)

Pulled opportunistically when real samples or analyst pain justify the effort; regressions are guarded in CI by `scripts/bench/quality.py` and `scripts/bench/recovery.py`.

| Area | Remaining work |
|---|---|
| **Decompiler output** | Own-function signature propagation (`L`, 53% incomplete share), x86 SEH3/4 & Delphi `try` frames (`M`, 6%), `unaff_`/`in_` register cleanup (`M`, 10%), switch-table & bad-instruction fixes (`M`, 4%), small CI review set (~30 functions). |
| **Type knowledge** | COM vtable typing from IIDs; Windows syscall tables; API hash resolution; `GetProcAddress` in locals/structs; external PDB loading; mangled C++ import signatures (`msvcp*`/`mfc*`/`Qt`); static library FID packs (OpenSSL, zlib, libcurl, Boost). |
| **Recovery & formats** | ELF `.plt` stubs & `.eh_frame` interior starts; PE x64 C scope / FH4 tables, x86 gap validation; Mach-O ObjC/Swift metadata; ARM64/ARM32/MIPS recovery details; Go/Rust/C++ idioms. |
| **Packed & dumped** | Static UPX unpacking (keeping original + unpacked image); dumped/injected PE images with unaligned sections. |
| **Ecosystem (P2)** | YARA-X scanning in the workbench (jump to hex/function); .NET C# decompilation (beyond IL); obfuscation folding; File Analysis Bus hand-off by SHA-256. |
| **On demand (P3)** | PowerPC / RISC-V / MIPS64, bytecode viewers, custom hex templates, manual function start overrides. |

---

## Already Shipped (Do Not Re-Plan)

- **Formats & metadata:** PE (resources, version info, manifest, Authenticode, Rich header, imphash, COFF, packer detection, unwind/SafeSEH/SEH3/RTTI/thunks), ELF (`.eh_frame`, `.ARM.exidx`, init/fini), Mach-O (thin/fat, `LC_FUNCTION_STARTS`, signatures, chained fixups), .NET/CLR IL, raw shellcode, zip & 7z archives (with known-password probing).
- **Recovery & types:** Go `pclntab`, DWARF, Delphi VMTs/RTTI, Nim, demangling, FLIRT & Function ID, Win32 metadata + phnt native API + CRT prototype packs (#57), `GetProcAddress` global resolution (#59, #64), single-function global calls (#64), symbolic Win32 enum/flag constants (#62), import-register call resolution (#61).
- **Decompiler & engines:** Embedded Ghidra C++ core + SLEIGH (x86, x64, AArch64, ARM32/Thumb, MIPS32), native Rust capa, binary diffing (`binfera diff` + Compare workspace), isolated p-code function emulation (CLI & MCP), MCP server + shared SQLite project DB + desktop Agent dock.
- **Viewers:** Tiling code panes, C (one line per statement, viewer-wrapped, `NULL`/`INVALID_HANDLE_VALUE` #65), Assembly, CFG, Call graph, virtualized IDA-style Listing (#51, #58), colored header Hex view, Entropy strip, Strings/Indicators, Imports/Exports, jumpable uncertain call-site warnings (#69), file-handle provenance (#70).
- **Code origin (#94–#100, #102):** offline `BXFAM002`/`BXFAM003` family and library fingerprint matching across CLI, Desktop, MCP and WASM; trusted library symbols, string reuse and `string_only_hint`; layered overlay packs; calm header verdict, First look summary, Fingerprint packs dialog and single origin filter in Functions and Strings.
- **Recovery & format fixes (#78–#89, #92):** preserved ELF hashes after repair (#78), universal `arm64e` ABI slice selection (#79), .NET CLR header routing and invalid GUID tolerance (#80, #85), PE Guard CF and mixed unwind table recovery (#86, #89), Go and ELF unwind recovery during capability scans (#87, #88), ELF copy-relocated data imports and phone workspace rework (#92), browser `window.opener` binary handoff (#93).
- **Workbench & mobile polish (#72–#77, #101–#102):** triage sidebar with Importance / Bottom-up sorts, Hide library and Examined / Documented progress (#72); File map, Overview Sections jump and `n` on any local, with right-click Rename variable (#73); hex byte selection, Redo and action toasts (#74); windowed phone function list, 16px / 44px palette, comment sheet and keyboard-aware sheets (#75); tapped-word action bar, header Star and call-graph pinch / tap-to-open (#76); Analyze on embedded resources and overlays, Compare… from an open file, compare report export, theme toggle and persisted manual pairs (#77); steady single progress bar, layout-safe side peek panes with Undo and portal bottom sheets (#102).
- **Benchmarks:** `scripts/bench/recovery.py` (#52), `scripts/decompiler_types/coverage.py` (#57), `scripts/bench/quality.py` (#64).

---

## Principles

1. **Rank by analyst value divided by effort.** Improvements seen on every binary beat deep passes for narrow edge cases.
2. **Analysis uses only the binary** (or public vendor symbols/metadata). Never assume source code.
3. **Rank evidence; do not vote.** Linker/ABI structures outrank control-flow discovery, which outranks heuristics. Every heuristic states its proof rule.
4. **No silent regressions.** Recovery changes check recall and precision together; decompiler changes run `quality.py`.
5. **Rust owns the analyst's model; Ghidra analyzes it.** Keep vendored Ghidra sources unmodified; extend at stated bridge seams.
