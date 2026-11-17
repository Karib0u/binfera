# Pinned native Ghidra sources

Upstream: https://github.com/NationalSecurityAgency/ghidra

The authoritative version and commit are in [PINNED.md](../../PINNED.md).
This is a source subset from Ghidra 12.1.4, developed by the US National
Security Agency and Ghidra contributors, licensed under Apache-2.0. See
[LICENSE](LICENSE) and the attribution and license headers in each file.
Generated parser sources retain their upstream parser-generator notices.

`cpp/` comes from `Ghidra/Features/Decompiler/src/decompile/cpp/`.
`data/RustFunctionsThatDoNotReturn` comes from `Ghidra/Features/Base/data/`.
`specs/rust/` contains the unchanged `probe_fixup.xml` and four platform `try_fixup.xml` files
from `Ghidra/Processors/x86/data/extensions/rust/`; the probe is identical on all four platforms.
The bridge also transcribes `rust-common.gdt`'s two-field `Str` layout for each pointer width.
`specs/` comes from `Ghidra/Processors/x86/data/languages/` and contains the
x86-64 and x86-32 SLEIGH inputs, included instruction definitions, both processor
contexts and both Windows compiler specifications (`x86-64-win.cspec`, `x86win.cspec`), the System V
compiler specifications (`x86-64-gcc.cspec`, `x86gcc.cspec`), the Delphi and Borland C++ ones
(`x86delphi.cspec`, `x86borland.cspec`), the Swift one (`x86-64-swift.cspec`), and the Go ones (`x86-64-golang.cspec`,
`x86-32-golang.cspec`, with their `.register.info` files, which the build does not read: the
register lists they give are transcribed in `native/bridge.cc`). Each shares its SLEIGH language with
the Windows one of the same width.
`data/GolangFunctionsThatDoNotReturn` comes from `Ghidra/Features/Base/data/` and lists the Go
runtime functions that never return.
Upstream `x86.ldefs` identifies the languages as `x86:LE:64:default` and
`x86:LE:32:default`, version 4.6, compiler `windows`.
Both are pinned to the same source commit. No JVM components are included.

Vendored files are unmodified. `SHA256SUMS` records their original contents.
From this directory, verify with `shasum -a 256 -c SHA256SUMS`.
The build compiles only CORE, DECCORE, SLEIGH, `sleigh_arch`, and
`inject_sleigh`, using the source groups in the upstream Makefile. The
SLEIGH compiler is a build-time executable; it compiles the pinned x86-64 and
x86-32 specifications into binaries embedded in the final library with the XML specs.

## Build-directory integration patches

`binfera-ghidra/build.rs` copies only modified translation units to OUT_DIR
and asserts each original hook occurs exactly once before changing it:

- `sleigh.cc`: load the embedded SLA stream instead of opening a runtime file;
  check the request budget before translating an instruction.
- `action.cc`: check the budget at action iterations and p-code rule processing.
- `subflow.cc`: concatenate split structure fields relative to the original aggregate
  storage. A field's smaller register join cannot cover its following fields, as seen
  when forwarding a Go rune, string and error result.
- `dynamic.cc`: extend local-hash collision indexes from 8 to 128 entries using
  unused bits, and retain the hash/address of the selected collision list. SIMD
  lane lowering can create more than eight indistinguishable locals.
- `condexe.cc`: preserve the dominating input of a COPY when its definition is
  outside the conditional block being removed. Such a COPY passed validation
  but failed replacement with `Illegal op in iblock` (Go Vidar's heap reclamation).
- `coreaction.cc`: extend ABI-aligned input containers in both directions so an
  overlapping later stack input is not cut in half. Preserve a verified tail
  call or resolved syscall result that reaches every normal return unchanged.
- `jumptable.cc`: stop speculative table enumeration at an interior address in a
  different declared unwind range. Separate entries/cold fragments remain valid;
  truncation retains the engine's incomplete-analysis warning. For a wrapped
  byte range starting in a foreign interior, validate its finite low segment.
  Final normalization must reproduce exactly the saved target addresses.
  `JumpTable::recoverLabels` catches a `LowlevelError` (such as `Backward normalization not
  implemented`), warns, and labels the table with the trivial model instead of failing the function.
- `op.cc` and `varnode.cc`: check the budget before creating analysis objects.
- `varmap.cc`: check the budget in `AliasChecker::gatherOffset`, whose unmemoized recursion over
  shared add trees can otherwise run for minutes past the deadline.
- `varnode.cc`: `Varnode::eraseDescend` also stops at the end of the descendant list and throws a
  `LowlevelError`; without it a missing op loops forever through the list's sentinel.
- `funcdata_op.cc`: validate removed input-slot indexes and accept already detached inputs.
  Conditional-execution cleanup can leave an empty phi input in a dead block before
  unreachable-edge removal; unlinking that input again dereferenced null.
- `heritage.cc`: `splitJoinRead` assumes a free joined varnode has one reader and dereferences
  a null op when it has none or several (seen on four malware samples); throw a `LowlevelError`
  so the request fails instead of the process.

`native/hooks.hh` declares these hooks. The deadline and work counter are
thread-local and active only during an explicit request. A thrown budget
exception crosses the bridge as a Rust error. Failed sessions are rejected
on subsequent calls and their state is released on drop. No native thread
is abandoned or asynchronously terminated.

To update, deliberately change PINNED.md, copy the same upstream paths,
regenerate SHA256SUMS, review every hook and specification change, rebuild,
and regenerate the fixture reference with the matching Ghidra release.

## AArch64 data

`specs/aarch64/` comes from `Ghidra/Processors/AARCH64/data/languages/` at the same
pinned commit. It contains `AARCH64.slaspec`, its instruction includes and processor
context, the Linux/default, Windows and Apple compiler specifications, and the Go
compiler specification and register information. Files are
unchanged and their hashes are in `SHA256SUMS`. One compiled little-endian SLA is shared
by all three compiler models. Its build-time limit is 2 MiB (495,185 bytes at this pin).

Host integration follows the pinned `AARCH64PltThunkAnalyzer` and
`AARCH64_ElfRelocationHandler`: complete PLT patterns receive call-return flow and
linked ELF dynamic pointer relocations are applied without executing resolvers.
The host lays out allocated native ELF relocatable sections. Supported x86,
ARM/Thumb, AArch64 and classic MIPS32 fixups share section and symbol layout;
instruction relocations follow the pinned processor handlers and Arm ABI tables. Unsupported kinds are diagnosed. This is not
a general object linker. PE images remain loaded at their preferred base.

The build composes compiler models in its output directory without changing these
upstream files. System V x64 also receives Swift's `__swiftcall` and its R13 `this`
model (renamed `__swiftself`). Each Go arm64 model receives the corresponding
platform's C model for native imports. `native/bridge.cc` transcribes Go arm64's
x0-x15 and vector argument registers and tracks the goroutine in x28.

## ARM32/Thumb and MIPS32 data

`specs/arm/` comes from `Ghidra/Processors/ARM/data/languages/` and
`specs/mips/` from `Ghidra/Processors/MIPS/data/languages/` at the same pinned
commit. These unchanged files include the ARMv7 little-endian ARM/Thumb SLEIGH
inputs, processor contexts, AAPCS and Windows compiler models, and classic
MIPS32 SLEIGH inputs and o32 compiler models for both byte orders. Original hashes
are recorded in `SHA256SUMS`. Language definition files preserve upstream IDs.

The bridge embeds one shared ARM/Thumb SLA and separate MIPS little/big-endian
SLAs. It selects ARM `TMode` context at address ranges, the ELF hard/soft-float
prototype, and tracked MIPS `gp`/`t9` values. ARM/MIPS use their own compiler models
without borrowing the x86 platform C archives or function ID signatures.
Host pointer relocation handling follows the pinned `ARM_ElfRelocationHandler`
and `MIPS_ElfRelocationHandler`; unsupported instruction relocations are diagnosed.
