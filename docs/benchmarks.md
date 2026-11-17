# Benchmarks

Two questions: how fast Binfera finds the code in a file compared with Ghidra, and whether its capability results match Python capa. The numbers hold for these files, versions and this machine; they are not universal claims.

<div class="grid cards" markdown>

-   **23×** median

    Sooner to a function list than Ghidra headless, on 39 comparable files.

-   **376 / 376**

    Corpus files with capa results identical to Python capa.

</div>

## Speed against Ghidra

**Binfera lists the functions of a file a median of 23 times sooner than Ghidra's headless analyzer** (geometric mean 31×, range 1.5× to 346×). On files of 1 MB and more it is 20× on average.

| File | Binfera | Ghidra |
|---|---:|---:|
| Hive (Go, 2.3 MB) | 2.8 s | 42 s |
| BlackCat (Rust, 1.2 MB) | 2.4 s | 56 s |
| ARM32 ELF (5.3 MB) | 10 s | 3 min 7 s |

### By file type

| Type | Files | Speed-up (geometric mean) | Range |
|---|---:|---:|---:|
| PE32 x86 EXE | 6 | 13× | 7× to 23× |
| PE32 x86 DLL | 3 | 17× | 15× to 21× |
| PE32+ x64 EXE | 4 | 18× | 15× to 23× |
| PE32+ x64 DLL | 3 | 16× | 9× to 27× |
| PE32+ x64 driver | 1 | 13× | |
| ELF x86 | 3 | 57× | 32× to 85× |
| ELF x86-64 | 4 | 63× | 34× to 134× |
| ELF ARM32 | 3 | 32× | 18× to 83× |
| ELF AArch64 | 2 | 17× | 3× to 90× |
| ELF MIPS32 | 2 | 14× | 2× to 122× |
| Mach-O x86_64 | 4 | 136× | 106× to 209× |
| Mach-O arm64 | 4 | 88× | 24× to 346× |

!!! info "Why small files show the biggest ratios"
    Each Ghidra run pays 5 to 10 s to start the JVM and create a project, most of its time on a 50 KB file. Binfera pays about 0.7 s to load library signatures for Windows files, which is why PE ratios are lower. The weakest results are a 1.5 MB MIPS ELF (20 s against 31 s) and a 0.7 MB AArch64 ELF (3.0 s against 9.2 s).

### Method

| | |
|---|---|
| **Binfera** | Time until `binfera FILE --decompile-all --jobs 1` prints its first record: the list of every recovered function. |
| **Ghidra** | `analyzeHeadless -import FILE` with default auto-analysis, JVM start-up and project creation included. Ghidra does more than find functions (types, references, many analyzers), so this is its time to a fully analysed program. |
| **Comparable** | Function counts agree within 25%, excluding Ghidra's import thunks (ELF PLT entries, Mach-O stubs). 39 of 45 files. |
| **Runs** | Median of three; files where Ghidra took over 60 s were run once in Ghidra. |
| **Machine** | Apple M1 Max (10 cores, 64 GB), macOS 27.2, warm disk cache, 2026-11-16. |
| **Versions** | Binfera 1.0.0 release build with the decompiler; Ghidra 12.1.4 on Temurin JDK 27.0.1. |

Both tools decompile with Ghidra's C++ core, so the difference measured here is discovery, not decompilation.

??? note "Six files that are not comparable"
    Function counts differ by more than 25%:

    - **DarkGate** (Delphi, PE32, 0.24 MB): Binfera 1,483, Ghidra 981.
    - **elf.chalubo** (MIPS32 ELF, 0.89 MB): Binfera 2,506, Ghidra 1,888.
    - **Mirai** (x86 ELF, 0.05 MB): Binfera 91, Ghidra 142.
    - **Stuxnet driver** (PE32, 0.02 MB): Binfera 82, Ghidra 65.
    - Two PE32 files in which both tools find almost no code, one packed with Themida (1.6 MB) and one 2.6 MB DLL: Binfera 12 and 10, Ghidra 3 each.

??? note "All 45 files"
    Families are from [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) and the demos on [binfera.io](https://binfera.io); hash prefixes are files from [capa-testfiles](https://github.com/mandiant/capa-testfiles). Functions are Binfera / Ghidra without thunks; n/c is not comparable.

    | File | Type | Size | binfera | Ghidra | Functions | Speed-up |
    |---|---|---:|---:|---:|---:|---:|
    | Industroyer2 (C/C++) | PE32 x86 EXE | 0.04 MB | 0.73 s | 10.2 s | 159 / 159 | 14× |
    | `009c2377…` | PE32 x86 EXE | 0.09 MB | 0.75 s | 10.7 s | 239 / 239 | 14× |
    | DarkGate (Delphi) | PE32 x86 EXE | 0.24 MB | 1.94 s | 18.8 s | 1,483 / 981 | n/c |
    | `02179f3b…` | PE32 x86 EXE | 0.27 MB | 0.97 s | 7.2 s | 6 / 7 | 7× |
    | BlackCat (Rust) | PE32 x86 EXE | 1.18 MB | 2.40 s | 55.9 s | 1,707 / 1,653 | 23× |
    | `2826b762…` | PE32 x86 EXE | 1.60 MB | 0.91 s | 7.0 s | 12 / 3 | n/c |
    | Hive (Go) | PE32 x86 EXE | 2.29 MB | 2.83 s | 41.8 s | 2,324 / 2,369 | 15× |
    | WannaCry (C/C++) | PE32 x86 EXE | 3.51 MB | 1.09 s | 8.9 s | 134 / 120 | 8× |
    | `09bf850b…` | PE32 x86 DLL | 0.12 MB | 1.07 s | 22.9 s | 591 / 491 | 21× |
    | NotPetya (C/C++) | PE32 x86 DLL | 0.36 MB | 0.80 s | 13.0 s | 172 / 171 | 16× |
    | `17264e31…` | PE32 x86 DLL | 0.54 MB | 1.99 s | 30.6 s | 1,609 / 1,704 | 15× |
    | `8a132663…` | PE32 x86 DLL | 2.58 MB | 1.24 s | 7.1 s | 10 / 3 | n/c |
    | Stuxnet (C/C++) | PE32 x86 driver | 0.02 MB | 0.67 s | 10.2 s | 82 / 65 | n/c |
    | `0a30182f…` | PE32+ x64 EXE | 0.09 MB | 0.74 s | 15.2 s | 102 / 101 | 20× |
    | `152d4c9f…` | PE32+ x64 EXE | 0.41 MB | 1.70 s | 24.7 s | 972 / 969 | 15× |
    | NimBlackout (Nim) | PE32+ x64 EXE | 0.50 MB | 0.99 s | 22.3 s | 541 / 540 | 23× |
    | `0da87fcc…` | PE32+ x64 EXE | 5.25 MB | 1.07 s | 16.7 s | 445 / 438 | 16× |
    | `0f33c2fe…` | PE32+ x64 DLL | 0.05 MB | 1.64 s | 15.2 s | 163 / 165 | 9× |
    | `03b236b2…` | PE32+ x64 DLL | 0.58 MB | 2.28 s | 62.4 s | 1,769 / 1,696 | 27× |
    | `7cd03db8…` | PE32+ x64 DLL | 1.72 MB | 1.06 s | 16.9 s | 589 / 570 | 16× |
    | `3e528207…` | PE32+ x64 driver | 0.04 MB | 0.74 s | 9.8 s | 43 / 40 | 13× |
    | Mirai (C/C++) | ELF x86 | 0.05 MB | 0.10 s | 6.7 s | 91 / 142 | n/c |
    | elf.torii | ELF x86 | 0.07 MB | 0.06 s | 5.4 s | 49 / 43 | 85× |
    | elf.xagent | ELF x86 | 0.18 MB | 0.19 s | 13.1 s | 406 / 406 | 67× |
    | elf.clop | ELF x86 | 1.25 MB | 1.56 s | 50.0 s | 3,331 / 3,131 | 32× |
    | elf.hideandseek | ELF x86-64 | 0.07 MB | 0.18 s | 7.9 s | 328 / 292 | 44× |
    | elf.boldmove | ELF x86-64 | 0.29 MB | 0.39 s | 13.3 s | 886 / 901 | 34× |
    | Cloud Snooper (C/C++) | ELF x86-64 | 0.31 MB | 0.16 s | 12.7 s | 468 / 442 | 81× |
    | elf.nextcry | ELF x86-64 | 5.38 MB | 0.07 s | 9.1 s | 81 / 78 | 134× |
    | elf.owari | ELF ARM32 | 0.13 MB | 0.15 s | 12.1 s | 268 / 255 | 83× |
    | elf.vpnfilter | ELF ARM32 | 0.28 MB | 0.66 s | 13.8 s | 863 / 838 | 21× |
    | elf.r2r2 | ELF ARM32 | 5.29 MB | 10.36 s | 186.5 s | 4,911 / 4,920 | 18× |
    | `687e79cd…` | ELF AArch64 | 0.07 MB | 0.07 s | 6.1 s | 52 / 51 | 90× |
    | elf.peer_time | ELF AArch64 | 0.71 MB | 3.03 s | 9.2 s | 267 / 258 | 3× |
    | elf.jenx | ELF MIPS32 | 0.05 MB | 0.10 s | 11.9 s | 94 / 108 | 122× |
    | elf.chalubo | ELF MIPS32 | 0.89 MB | 1.50 s | 47.9 s | 2,506 / 1,888 | n/c |
    | elf.sshdoor | ELF MIPS32 | 1.47 MB | 20.28 s | 30.6 s | 909 / 909 | 2× |
    | 3CX (C/C++) | Mach-O x86_64 | 0.04 MB | 0.05 s | 6.2 s | 11 / 11 | 122× |
    | osx.retefe | Mach-O x86_64 | 0.10 MB | 0.07 s | 13.9 s | 53 / 53 | 209× |
    | osx.proton_rat | Mach-O x86_64 | 0.72 MB | 0.34 s | 36.3 s | 1,425 / 1,416 | 106× |
    | osx.komplex | Mach-O x86_64 | 1.77 MB | 0.07 s | 8.4 s | 63 / 63 | 126× |
    | osx.amodaltea | Mach-O arm64 | 0.04 MB | 0.05 s | 4.9 s | 13 / 13 | 107× |
    | RustBucket (Swift) | Mach-O arm64 | 0.11 MB | 0.05 s | 18.4 s | 77 / 75 | 346× |
    | osx.lockbit | Mach-O arm64 | 0.41 MB | 0.18 s | 12.4 s | 373 / 343 | 67× |
    | osx.insidiousgh0st | Mach-O arm64 | 5.67 MB | 2.98 s | 70.6 s | 5,136 / 5,136 | 24× |

## Agreement with capa

Binfera runs the unmodified capa rules. Results are compared file by file with pinned Python capa 10.0.0 and capa-rules v10.0.0.

| Backend | Reference | Result |
|---|---|---|
| x86 / x64 PE, ELF, shellcode | Python capa | **376 / 376** files identical: same rule names, same match addresses (11,412 matches, none missing or extra) |
| .NET | Python capa with `dnfile` | **8 / 8** files identical |
| AArch64 ELF | Ghidra BinExport2 | **29 / 29** rules, 3 / 3 files identical |
| Mach-O (x86_64, arm64) | hand-built fixtures | 30 / 30 tests pass |
| AArch64 PE | hand-built fixtures | 15 / 15 tests pass |

Evidence trees and duplicate-match counts are not compared. The reference rejects one further malformed ELF. Measured on 2026-10-21; the capability backend has not changed since. Known differences are in [Compatibility](compatibility.md).

## Reproduce

```bash
cargo build --release -p binfera-cli --features decompiler
```

=== "Against Ghidra"

    ```bash
    # One JSON line per file, then the tables above
    scripts/bench/bench_vs_ghidra.py target/release/binfera /path/to/ghidra_12.1.4_PUBLIC FILE...
    ```

=== "Against capa"

    ```bash
    # Needs scripts/setup_dev.sh
    python3 scripts/difftest.py --mode full-exact --samples scripts/corpus-full-static.txt \
      --capa-cli target/release/binfera --no-rust-cache --no-expected
    python3 scripts/difftest.py --mode full-exact --samples scripts/corpus-dotnet.txt \
      --capa-cli target/release/binfera --no-rust-cache --no-expected
    python3 scripts/difftest.py --profile aarch64-binexport --mode full --samples scripts/corpus-aarch64.txt \
      --capa-cli target/release/binfera --no-rust-cache --no-expected
    cargo test --release -p binfera --test macho_features --test aarch64_pe_features
    ```
