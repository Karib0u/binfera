# FAQ

## Is my file uploaded anywhere?

No. The browser build runs the analysis engine as WebAssembly inside the page, and the site has no backend. The desktop app and the command-line tool run a native engine on your machine. The command-line tool makes no network requests except `binfera fetch-rules`, which you run yourself.

## Does Binfera run the file I open?

No. Analysis is static. [Function emulation](emulation.md) interprets a single function in an isolated emulator, only when you ask for it, and never hands control to the host system.

## How does it relate to capa?

Binfera includes an independent Rust implementation of [Mandiant capa](https://github.com/mandiant/capa)'s capability detection and runs the unmodified capa rules. Agreement with Python capa is measured and published in [Benchmarks](benchmarks.md), and the known differences are in [Compatibility](compatibility.md). Binfera is not affiliated with or endorsed by Google LLC or Mandiant, Inc.

## How does it relate to Ghidra?

The decompiler is Ghidra's own C++ decompiler core and SLEIGH processor specifications, embedded without the JVM. Loading, function discovery and everything around the decompiler are Binfera's own Rust code. Binfera is not affiliated with or endorsed by the NSA. See [Speed against Ghidra](benchmarks.md#speed-against-ghidra) for a measured comparison and [Decompiler](decompiler.md) for what is supported.

## Which files can it read?

PE, ELF and Mach-O executables (including fat Mach-O), raw shellcode, .NET assemblies and capa freeze files. Decompilation covers x86, x86-64, AArch64, ARM32/Thumb and classic MIPS32. Details and limits are in [Decompiler](decompiler.md) and [Compatibility](compatibility.md).

## Why does Windows warn me about the installer?

The Windows builds are not code-signed, so SmartScreen warns on first run. Check the download against the release's `SHA256SUMS`, then choose **More info** and **Run anyway**. See [Code signing](installation.md#code-signing).

## Why does my antivirus flag it?

Binfera ships detection rules and signatures for malicious behaviour, and the website offers real malware samples for analysis, encoded so they cannot run. Both can trigger antivirus heuristics. The samples on the site are decoded only in the page's memory.

## Does Binfera include an AI model?

No. The [MCP server](mcp.md) exposes data and actions to an agent you already use. The desktop app's **Agent** panel connects to supported local agent installations. What the agent sends to its provider is governed by the agent, not by Binfera.

## Where are my notes stored?

In a local SQLite database in your user data directory. The location and how to override it are under [What is stored](mcp.md#what-is-stored).

## How do I report a bug or a vulnerability?

Open an [issue](https://github.com/Karib0u/binfera/issues) for bugs and accuracy differences. For security problems, use private vulnerability reporting as described in the [security policy](https://github.com/Karib0u/binfera/blob/main/SECURITY.md). Never attach live malware to a public issue.

## What licence is it under?

Apache License 2.0. Third-party components and their licences are listed in [NOTICE](https://github.com/Karib0u/binfera/blob/main/NOTICE).
