# Binfera

**See what a binary does.** Binfera shows decompiled C, the capabilities a file implements mapped onto its code, and what changed between two builds, for Windows, Linux and macOS executables. Analysis runs on your machine: in a browser tab, a desktop app, the command line, or through your AI agent.

<video src="images/tour.mp4" poster="images/code.webp" autoplay loop muted playsinline controls style="width:100%"></video>

The [tour](tour.md) shows every view on a real sample.

Binfera pairs a Rust analysis engine with an embedded native decompiler (Ghidra's C++ core and SLEIGH, no JVM). Capability matches come from a native Rust implementation of [Mandiant capa](https://github.com/mandiant/capa) that runs the unmodified capa rules.

## Choose how to use it

| I want to… | Use | Start |
|---|---|---|
| Try it now, with nothing to install | Browser | [binfera.io](https://binfera.io) |
| Analyze files day to day and keep my notes | Desktop app | [Installation](installation.md#desktop-app) |
| Analyze with an AI agent | Desktop app, or command line and MCP | [Connect an AI agent](mcp.md) |
| Check builds in a script or CI | Command line | [Command line](cli.md) |

## What it does

- **Decompiled C for every function.** x86, x86-64 and AArch64 in PE, ELF and supported Mach-O images, plus ARM32/Thumb and classic MIPS32. See the [decompiler scope](decompiler.md).
- **Capabilities on the code.** capa rule matches, with ATT&CK ids, on the functions that triggered them.
- **Compare two binaries.** Which capabilities, functions and file contents changed, down to the instruction. See [comparing binaries](comparison.md).
- **Read it your way.** Control-flow graph, assembly, strings, imports and sections; FLIRT signatures and Function ID packs name library code.
- **Bring your own AI agent.** An [MCP server](mcp.md) lets any MCP client name functions, comment code and save reports with evidence. Binfera runs no model.
- **Local by design.** Nothing is uploaded. The browser build runs the engine as WebAssembly, with no backend.

## What it is not

Binfera is built for the first hours with an unknown file, not as a replacement for a full reverse-engineering suite. It has no debugger, no plugin or scripting ecosystem, no type or prototype editing and no patching, and it supports fewer architectures and file formats than Ghidra or radare2. Use it alongside them.

## Where to go next

- [Installation](installation.md): the desktop app, the command-line tool, or a build from source.
- [Quickstart](getting-started.md): a first analysis in each interface.
- [Tour](tour.md): every view, on the WannaCry demo.
- [Benchmarks](benchmarks.md): speed against Ghidra and agreement with capa, with the commands to reproduce them.
