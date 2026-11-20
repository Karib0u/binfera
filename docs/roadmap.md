# Roadmap

Updated: 2026-11-20. Planned work, plus what already exists so it is not
re-planned. Priorities describe relative value, not delivery dates.

Scope rule: binfera answers "what does this one executable do?" by reading
code. File-format parsing, unpacking, installer and bytecode script analysis,
and verdicts belong in filebus.

## Already covered (do not re-plan)

- PE: resources, version info, manifest, Authenticode, Rich header, imphash,
  compiler traces, COFF/object loading, packer detection.
- Mach-O code signatures; ELF and Mach-O detail views.
- Go `pclntab`, DWARF, MSVC RTTI and exceptions, Delphi VMTs/RTTI, Nim and
  Itanium/MS demangling, FLIRT and Function ID.
- Hex view with header-field coloring for PE, ELF and Mach-O.
- Decompilation for x86, x86-64, AArch64, ARM32/Thumb and MIPS32; capa;
  function emulation; diffing; entropy; hex, strings and imports views;
  zip and 7z with known-password probing; .NET IL listing; MCP/agent.

## P1: gaps listed in binfera's own docs

| Area | Remaining work |
|---|---|
| Go | Go on AArch64; string constants; signatures for the program's own methods; closure context register; goroutine register on x86 and before Go 1.17. |
| C++ | Itanium RTTI; class layouts; constructors and destructors; virtual bases; `try`/`catch` syntax; `__CxxFrameHandler4` metadata. |
| Rust | Signatures for stripped functions; generic aggregates; `String`/`Vec` layouts. |
| DWARF | Split DWARF; separate type units; debug links; unions and bit fields; register locals and location lists. |
| PDB | Load external PDB files for names and types (docs list it as unsupported). |

## P2: new proposals

| Area | Remaining work |
|---|---|
| Unpacking | Static unpacking for the common cases (UPX first); today packers are only flagged, so the decompiler shows the stub. |
| Dumped images | Open memory-dumped or injected PE images (unaligned sections, rebuilt imports) so modules recovered by filebus from minidumps can be read. |
| YARA in the workbench | Scan the open file with YARA-X rules and jump from a hit to its hex offset or function; reuse filebus rules. |
| .NET decompilation | C# pseudocode; only IL is listed today. |
| filebus hand-off | Open-from-link by SHA-256, and align capa rule/engine versions with filebus. |

## P3: demand-gated

| Area | Remaining work |
|---|---|
| Bytecode viewers | Python 2.7/3.6+, pickle and VB P-code disassembly views. filebus does the triage parsing; build these only if analysts need to read the code. |
| Architectures | PowerPC, RISC-V, MIPS64. |
| Hex structure templates | Partly done: PE, ELF and Mach-O headers (DOS/NT headers, data directories, section, program and segment headers) are colored by field in the hex view with a field tooltip. Remaining: import/export tables, resource tree, certificate, debug and TLS directories, overlay and embedded-file boundaries, and a way to add custom templates. |

## Moved to filebus

NSIS and Inno Setup script analysis, AutoIt, PyInstaller/py2exe/Nuitka
unpacking, minidump, archives beyond zip/7z, documents, SQLite and media
parsers. See `docs/roadmap/modules.md` in filebus.
