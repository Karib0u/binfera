# Changelog

Notable changes to binfera. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses [semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Resolved API names in the viewer:** the assembly, the graph and the listing show the API a global holds when the program loads it with `GetProcAddress` and a literal name (`call dword ptr ds:[ReadFile]`, `dd ReadFile ; resolved with GetProcAddress`), with argument comments on the call. The batch `start` record carries them as `resolved`.
- **Calls through a global that holds one function:** a global the program only ever sets to the same function of its own, or never sets and starts as that function, prints calls as `FUN_00401234(a, b)` with the callee's prototype instead of `(*DAT_x)(a, b)`. A global with another value, a reset, a taken address or an unknown writer is left alone.
- **Quality report:** `scripts/bench/quality.py` compares two binaries on untyped imports, unresolved indirect calls and numeric arguments at enum parameters, and a small subset runs in CI against a checked-in baseline.

### Changed

- **System DLL prototypes:** imports of `pdh`, `msi`, `credui`, `fwpkclnt`, `xinput1_4` and 48 other system DLLs (53 in all) now get their prototypes from the Windows packs.

## [1.0.1]

### Fixed

- **Windows install script:** `install.ps1` found no release under Windows PowerShell 5.1, the version built into Windows, because it passes the whole release list down the pipeline as one object.
- **Desktop app:** opening a file no longer starts the analyst's Claude Code or Codex. The hidden agent panel mounted with every file and asked the agent for its model list, so each file opened made the agent contact its provider, with no file data sent. The panel now mounts the first time it is opened.
- **Desktop app:** the Linux AppImage aborted at start-up on recent Wayland desktops such as Ubuntu 26.04. Its bundled GTK now runs through XWayland. The `.deb` and `.rpm` packages were not affected.

### Changed

- **One release per version:** the command-line archives and the desktop installers now ship together in one `vX.Y.Z` release. The desktop app's interim `desktop-v1.0.1` release is replaced by this one.

## [1.0.0]

First public release: a native Rust backend for unmodified upstream capa rules, with a decompiler, a desktop and browser app, a command-line tool, an MCP server and Python bindings.

### Analysis

- **Formats:** PE and ELF (x86, x86-64, AArch64), Mach-O (thin and fat, including chained fixups), raw shellcode, .NET/CLR and capa freeze files.
- **Code recovery and features:** native loaders, function discovery, FLIRT and Function ID signature matching, and capa-compatible feature extraction, checked against pinned Python capa ([`PINNED.md`](PINNED.md), [`docs/compatibility.md`](docs/compatibility.md)).
- **Decompiler:** the Ghidra decompiler core and SLEIGH specs, embedded with no JVM. Decompiled C for x86, x86-64, AArch64, ARM32/Thumb and classic MIPS32 ([`docs/decompiler.md`](docs/decompiler.md)).
- **Binary comparison:** `binfera diff` reports changed capabilities, functions and file contents ([`docs/comparison.md`](docs/comparison.md)).

### Interfaces

- **Command line:** JSON output, `--jobs N` bounded parallelism (byte-identical to `--jobs 1`), `--timing`, `fetch-rules`, `diff` and `fingerprint` ([`docs/cli.md`](docs/cli.md)).
- **MCP server:** `binfera mcp` lets an agent open binaries, read decompiled code and save reversible work ([`docs/mcp.md`](docs/mcp.md)).
- **Desktop and web apps:** the same UI in the browser (WebAssembly) and as a Tauri app with saved projects, analyst comments, starred functions and session undo.
- **Archives:** ZIP and 7z inputs are opened in the app, with limits on input size, expanded size and entry count.
- **Python:** a binding for CPython 3.9 and later, installed from source, with `Rules.from_directory`, `analyze`, `inspect`, `Decompiler` and `decompile_all`; it includes the decompiler.

### Distribution

- Release archives for Linux (x86_64, arm64; glibc 2.35 or newer), macOS (arm64, x86_64; signed and notarised) and Windows (x86_64), each carrying the pinned capa-rules.
- Desktop installers for macOS (signed and notarised), Windows (unsigned) and Linux.
- Declared `rust-version = "1.89"`, guarded by a CI job on exactly that toolchain.
- Measurements: a function list a median of 23 times sooner than Ghidra's headless analyzer on 39 files across PE, ELF and Mach-O, and identical results to Python capa on 376 of 376 corpus files ([`docs/benchmarks.md`](docs/benchmarks.md)).
