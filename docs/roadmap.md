# Roadmap

Updated: 2026-11-23. Ranked by **analyst value for effort**. Every item has an effort estimate (`S`: ~1 day, `M`: a few days, `L`: weeks) and a concrete **Done when** check.

**Goal:** Build the next-generation IDA/Ghidra — fast, responsive on desktop and mobile, and effortless to work in:
- **Immediate:** 60fps navigation and search at scale, zero-friction triage, and native-feeling mobile + desktop UI.
- **Readable:** C output, provenance, and emulation that explain what a function does without fighting the tool.
- **Editable:** analyst-supplied names, types, structs, and prototypes flow through Ghidra, not over its text.
- **Exact:** high-precision recovery guarded by benchmarks, without blocking product progress on small edge cases.

**Scope:** Binfera focuses on binary code analysis ("what does this executable do?"). File-format unpacking, installer/bytecode scripts (NSIS, Inno, AutoIt, PyInstaller, py2exe, Nuitka), minidumps, and verdicts belong to **File Analysis Bus**.

---

## Now — Workbench & Mobile Polish

High-impact `S` PRs that improve every binary on desktop and mobile right away.

| # | Item | Effort | Done when |
|---|---|---|---|
| 1 | **Triage sidebar parity with MCP** — Port MCP's `importance` sort (capabilities, strings, imports, callers, size), `bottom_up` sort, **Hide library (FLIRT/FID)** toggle, and **Examined / Documented** progress to the UI function list. | S | Sorting WannaCry/DarkGate by Importance puts payload core functions in the top 10 with library functions hidden. |
| 2 | **Desktop UX fixes** — Fix Data-mode File map (`Navigator`) clicks, Overview "Sections" jump, and the `n` variable-rename check (so `unaff_`/`in_`/`auStack_`/DWARF locals rename the variable, not the function). Add right-click "Rename variable…". | S | Web tests cover Data-mode Navigator clicks, Overview Sections jump, and renaming any local token with `n`. |
| 3 | **Hex selection, Undo toast & Redo** — Add drag and `Shift+Click` byte selection in `HexView` (unlocking Copy as hex / C array / text), `⌘⇧Z` redo, and a non-blocking toast for Copy, Undo, and Star. | S | Drag-selecting bytes enables the copy-selection menu; `⌘Z` announces what was reverted and `⌘⇧Z` restores it. |
| 4 | **Mobile performance & input polish** — Virtualize mobile `fnList` (`VirtualList`), fix `Palette` (`16px` input to stop iOS auto-zoom, `dvh` sheet, `44px` targets), move mobile `CommentEditor` into `Sheet`, and widen `Sheet` drag-to-dismiss to its header. | S | Mobile Playwright check on a 3,000+ function binary scrolls smoothly; search and comment stay above the software keyboard. |
| 5 | **Touch parity: Token Action Bar & `CallGraph`** — Tapping a token/line on mobile opens a slim contextual bar (`Rename · Xrefs · Comment · Copy · Hex`). Add tap-to-open and pinch-zoom to `CallGraph`, plus a 1-tap Star button in `.m-bar`. | S | Touch users can rename variables, view xrefs, and navigate `CallGraph` without double-click or right-click. |
| 6 | **Multi-stage & Compare completions** — Add **Analyze** next to Save on embedded PE/ZIP resources and overlays in `FileView`; add **Compare with…** from an open `Workspace`; add Compare report export (MD/HTML/JSON), `ThemeToggle`, and persisted manual pairs. | S | Opening WannaCry's embedded resource takes 1 click; Compare exports MD/HTML/JSON and keeps manual pairs across reloads. |

---

## Next — Workflows IDA & Ghidra Don't Have

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
| **Recovery & formats** | ELF `.plt` stubs & `.eh_frame` interior starts; PE Guard CF table, x64 C scope / FH4 tables, x86 gap validation; Mach-O ObjC/Swift metadata; ARM64/ARM32/MIPS recovery details; Go/Rust/C++ idioms. |
| **Packed & dumped** | Static UPX unpacking (keeping original + unpacked image); dumped/injected PE images with unaligned sections. |
| **Ecosystem (P2)** | YARA-X scanning in the workbench (jump to hex/function); .NET C# decompilation (beyond IL); obfuscation folding; File Analysis Bus hand-off by SHA-256. |
| **On demand (P3)** | PowerPC / RISC-V / MIPS64, bytecode viewers, custom hex templates, manual function start overrides. |

---

## Already Shipped (Do Not Re-Plan)

- **Formats & metadata:** PE (resources, version info, manifest, Authenticode, Rich header, imphash, COFF, packer detection, unwind/SafeSEH/SEH3/RTTI/thunks), ELF (`.eh_frame`, `.ARM.exidx`, init/fini), Mach-O (thin/fat, `LC_FUNCTION_STARTS`, signatures, chained fixups), .NET/CLR IL, raw shellcode, zip & 7z archives (with known-password probing).
- **Recovery & types:** Go `pclntab`, DWARF, Delphi VMTs/RTTI, Nim, demangling, FLIRT & Function ID, Win32 metadata + phnt native API + CRT prototype packs (#57), `GetProcAddress` global resolution (#59, #64), single-function global calls (#64), symbolic Win32 enum/flag constants (#62), import-register call resolution (#61).
- **Decompiler & engines:** Embedded Ghidra C++ core + SLEIGH (x86, x64, AArch64, ARM32/Thumb, MIPS32), native Rust capa, binary diffing (`binfera diff` + Compare workspace), isolated p-code function emulation (CLI & MCP), MCP server + shared SQLite project DB + desktop Agent dock.
- **Viewers:** Tiling code panes, C (one line per statement, viewer-wrapped, `NULL`/`INVALID_HANDLE_VALUE` #65), Assembly, CFG, Call graph, virtualized IDA-style Listing (#51, #58), colored header Hex view, Entropy strip, Strings/Indicators, Imports/Exports, jumpable uncertain call-site warnings (#69), file-handle provenance (#70).
- **Benchmarks:** `scripts/bench/recovery.py` (#52), `scripts/decompiler_types/coverage.py` (#57), `scripts/bench/quality.py` (#64).

---

## Principles

1. **Rank by analyst value divided by effort.** Improvements seen on every binary beat deep passes for narrow edge cases.
2. **Analysis uses only the binary** (or public vendor symbols/metadata). Never assume source code.
3. **Rank evidence; do not vote.** Linker/ABI structures outrank control-flow discovery, which outranks heuristics. Every heuristic states its proof rule.
4. **No silent regressions.** Recovery changes check recall and precision together; decompiler changes run `quality.py`.
5. **Rust owns the analyst's model; Ghidra analyzes it.** Keep vendored Ghidra sources unmodified; extend at stated bridge seams.
