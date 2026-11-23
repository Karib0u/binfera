# Compatibility

Binfera runs the pinned capa rules. Python capa 10.0.0 is the behavioral reference for the inputs listed below. The [pins](https://github.com/Karib0u/binfera/blob/main/PINNED.md) identify the rule and reference versions. Published parity results measure agreement on rule names and match addresses for a specific corpus and build. Function coverage can differ even when those matches agree.

## Inputs

| Input | Status | Oracle |
|---|---|---|
| PE x86/x64 | Supported | Python capa 10.0.0 (Vivisect) |
| ELF x86/x64 | Supported | Python capa 10.0.0 (Vivisect) |
| Raw shellcode, 32/64-bit | Supported | Python capa 10.0.0 (`sc32`/`sc64`) |
| .NET / CLR managed PE | Supported | Python capa 10.0.0 (`dnfile`) |
| capa freeze files | Supported | Python capa 10.0.0 |
| ELF AArch64 | Supported | Pinned Ghidra BinExport2 fixtures (no raw-AArch64 Python oracle) |
| PE AArch64 | **Extension** | None |
| Mach-O x86_64 / arm64 / arm64e | **Extension** | None |
| ARM32/Thumb (PE, ELF), MIPS32 (ELF) | **Extension** | None (source-built fixtures) |
| External disassembler databases and BinExport | Non-goal | n/a |

Unsupported inputs are rejected with context, never silently accepted or partially analyzed.

### Claim classes

| Class | Members | Evidence |
|---|---|---|
| Upstream comparison | PE, ELF, shellcode, .NET | Direct comparison with Python capa ([benchmarks](benchmarks.md)) |
| Cross-backend parity | AArch64 ELF | Feature- and rule-level comparison with Ghidra BinExport2 ([benchmarks](benchmarks.md)) |
| binfera extension | Mach-O, AArch64 PE, ARM32/Thumb, MIPS32 | Hand-built or source-built fixtures; never claimed as upstream parity |
| Not covered | Evidence-tree identity, ISAs not listed above, dynamic extractors | n/a |

## Function recovery differences

Binfera uses validated compiler and linker metadata to improve function recovery. An additional function scope can produce a new capability match or a new match address using the same rules. The upstream comparison tracks regressions, and the binary's own metadata provides independent evidence of function starts.

- **Available on main.** Capability analysis and decompilation of native PE files use validated Control Flow Guard function table entries. This can recover indirect call targets absent from the default capa scan. [Guard CF recovery](https://github.com/Karib0u/binfera/pull/86)
- **Go.** PE and ELF capability analysis uses Go's linker function table to recover application functions such as `main.main`. [Go function recovery](https://github.com/Karib0u/binfera/pull/87)
- **Windows x64 unwind recovery.** Capability analysis uses non-chained `.pdata` entries with version 1 or 2 unwind headers. It skips unsupported or unreadable rows and keeps processing the table. In capa 10.0.0, the pinned Vivisect parser stops on those rows, so Binfera can report capabilities at additional function addresses. [Vivisect source](https://github.com/vivisect/vivisect/blob/v1.3.2/vivisect/parsers/pe.py#L525-L542)

### Format notes

- **Mach-O** is not accepted by pinned capa at all, so it is an extension. `-f auto` detects it after PE and ELF and before freeze files, which keeps upstream's order for every format capa knows; `-f macho` forces it. Thin and fat binaries are supported; `--arch` selects a slice, otherwise the first supported slice in fat-header order is used.
- **AArch64** decoding, recovery, and extraction (`disarm64`, no external disassembler) are shared by ELF, Mach-O, and PE. Only ELF has an oracle.
- **ARM32/Thumb and MIPS32** use Capstone for decoding. Rules accept `arch: arm` and `arch: mips` (both byte orders). See [Decompiler](decompiler.md#arm32-thumb-and-mips32) for the supported profiles.
- **.NET**: a CLR PE is auto-detected and routed to the .NET backend. `-f pe` forces the native x86 path, `-f dotnet` forces .NET. Mixed-mode assemblies are analyzed for managed methods only, as in upstream, and carry the "mixed mode" characteristic feature.
- **ELF unwind recovery.** Capability analysis uses validated `.eh_frame` records, including via `PT_GNU_EH_FRAME` in binaries with stripped section headers. These entries can add function scopes and match locations beyond the default Python capa 10.0.0 scan.

Measurements (accuracy, performance, reproduction) are in [benchmarks.md](benchmarks.md).

binfera follows upstream capa on a best-effort basis; each supported version is re-verified with the full differential suite before the pin moves.
