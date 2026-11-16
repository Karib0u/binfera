# Benchmarks

The only place measurements live. Unless a section states otherwise, measurements were taken on 2026-10-21 against binfera release build of `main` at `2d9862a` (plus comment-only changes), Python capa 10.0.0, and capa-rules v10.0.0. Results hold for this implementation, ruleset, corpus, and host. They are not universal claims. Re-run before quoting: commands are at the bottom.

## Accuracy

**x86/x64 PE, ELF, and shellcode vs Python capa 10.0.0.** 377 corpus inputs; the reference rejects one malformed ELF, leaving 376 comparable.

| Metric | Result |
|---|---:|
| Rule-name agreement | 100.00% |
| Reference rule/sample matches | 11,412 |
| Missing / extra rules | 0 / 0 |
| Samples with identical rule names | 376/376 |
| Samples with identical rule names and match addresses (`full-exact`) | 376/376 |

Evidence-tree identity and duplicate-match multiplicity are not compared.

**Other backends.**

| Backend | Oracle | Result |
|---|---|---|
| .NET / CLR | Python capa + `dnfile` | 8/8 samples identical (`full-exact`) |
| AArch64 ELF | Ghidra BinExport2 | 29/29 rules, 3/3 samples identical |
| Mach-O (x86_64, AArch64) | None (hand-built fixtures) | 30/30 fixture tests pass |
| AArch64 PE | None (hand-built fixtures) | 15/15 fixture tests pass |

## Performance

Host: MacBook Pro, Apple M1 Max, 10 logical CPUs, macOS 27.0.1. Median of 5 runs after one warm-up, wall time including process start-up and output.

### binfera vs Python capa

`binfera --jobs 1` against Python capa 10.0.0 (single-threaded), producing identical results on each sample. Speedups are per sample, not a corpus average.

| Sample | binfera `--jobs 1` | Python capa | Speedup |
|---|---:|---:|---:|
| `Practical Malware Analysis Lab 18-03.exe_` | 0.835 s | 3.781 s | 4.5x |
| `055da8e6…elf_` (ELF64, 22 KB) | 0.215 s | 1.949 s | 9.1x |
| `a198216798…exe_` (PE32, 293 KB) | 0.867 s | 6.023 s | 6.9x |
| `79cde1aa…exe_` (PE32, 77 KB) | 0.921 s | 13.217 s | 14.4x |
| `03b236b2…dll_` (PE32+ DLL) | 2.236 s | 38.647 s | 17.3x |

Median speedup is 9.1x. binfera pays a fixed start-up cost (about 1 s to load the rules and signatures), which dominates on small files.

### Parallel scaling

10 samples from `scripts/corpus-bench.txt`.

| Jobs | Total | Speedup |
|---:|---:|---:|
| 1 | 30.7 s | 1.00x |
| 2 | 27.2 s | 1.13x |
| 4 | 26.1 s | 1.18x |
| 10 (default) | 25.4 s | 1.21x |

Median per-sample speedup at the default job count is 1.85x (best 3.12x, a small ELF). The total barely moves because one 9.6 MB PE takes 22 s, of which about 20 s is load and recovery, which is serial by design.

Two results fall short of the project's own bar (median at least 1.5x with no sample below 0.91x):

- `03b236b2…dll_` slows down with more jobs: 2.41 s at 1 job, 2.86 s at the default (0.84x).
- The largest PE reaches only 1.13x.

### Memory

Peak resident set size is about 660 MB for typical PE files, 63 MB for small ELF files, 770 MB for the PE32+ DLL, and 2.1 GB for the 9.6 MB PE. It does not change with job count.

### Phase times

Sum over the 10-sample corpus, in seconds.

| Phase | `--jobs 1` | `--jobs 2` | `--jobs 4` | default |
|---|---:|---:|---:|---:|
| rules | 2.62 | 1.71 | 1.22 | 1.00 |
| load and recovery | 25.07 | 23.08 | 23.05 | 22.92 |
| extraction | 0.49 | 0.34 | 0.20 | 0.12 |
| matching | 2.19 | 1.66 | 1.14 | 0.91 |
| result | 0.03 | 0.03 | 0.03 | 0.03 |
| total | 30.71 | 27.24 | 26.08 | 25.41 |

## Reproduce

```bash
scripts/setup_dev.sh && cargo build --release

# accuracy (rule names, then rule names plus addresses)
python3 scripts/difftest.py --mode full \
  --samples scripts/corpus-full-static.txt --capa-cli target/release/binfera \
  --no-rust-cache --no-expected
python3 scripts/difftest.py --mode full-exact \
  --samples scripts/corpus-full-static.txt --capa-cli target/release/binfera \
  --no-rust-cache --no-expected

# other backends
python3 scripts/difftest.py --mode full-exact --samples scripts/corpus-dotnet.txt \
  --capa-cli target/release/binfera --no-rust-cache --no-expected
python3 scripts/difftest.py --profile aarch64-binexport --mode full \
  --samples scripts/corpus-aarch64.txt --capa-cli target/release/binfera \
  --no-rust-cache --no-expected
cargo test --release -p binfera --test macho_features --test aarch64_pe_features

# determinism across job counts
python3 scripts/determinism.py \
  --samples scripts/corpus-jobs.txt --capa-cli target/release/binfera

# performance
python3 scripts/bench.py --samples scripts/corpus-bench.txt \
  --capa-cli target/release/binfera --jobs 1,2,4,default --runs 5 --markdown
python3 scripts/bench.py --samples <samples.txt> --capa-cli target/release/binfera \
  --jobs 1 --runs 5 --python .venv/bin/capa --markdown
```

Older reports, per-sample tables, and the divergence catalogue were removed from the tree; they remain in git history before the docs restructure.

## Optional native decompiler

Measured on 2026-10-21 with the release build on Apple M1 Max, 64 GiB RAM, macOS arm64, Rust 1.96.0. Each process reuses one session across seven compiled source fixtures, with no supplied prototypes. Raw outputs, process RSS, and executable/source hashes are in [tests/decompiler/measurements](https://github.com/Karib0u/binfera/tree/main/tests/decompiler/measurements/).

| Requests | Cold session setup | Highest function warm p95 | Peak RSS |
|---|---:|---:|---:|
| 700 | 52.482 ms | 3.104 ms | 36.250 MiB |
| 7,000 | 31.803 ms | 3.016 ms | 36.031 MiB |

Cold setup includes recovery and runtime recognition. The highest p95 is for the switch fixture, which also analyzes supporting callees. These local observations meet fixture regression targets of cold setup below 100 ms, warm p95 below 5 ms, peak RSS below 64 MiB, and less than 8 MiB growth between 700 and 7,000 requests. They do not establish limits for large corpus functions or prove leak freedom. Background machine activity and filesystem caches were not controlled.

Reproduce with:

```sh
cargo build --release -p binfera --features decompiler --example decompiler_bench
/usr/bin/time -l target/release/examples/decompiler_bench 100
/usr/bin/time -l target/release/examples/decompiler_bench 1000
```

Use `/usr/bin/time -v` on Linux. See [the decompiler guide](decompiler.md) for scope, cooperative resource limits, and native-engine ownership.


## Local analysis optimization check, 2026-11-03

Compared the release CLI at `ad9d6f87bcddbe86585b3198dc6e2b6e7a17cb81` with the following changes on macOS arm64, Rust 1.99.1 and Emscripten 6.0.13:

- Share the parsed MSVC runtime signature database between native and compatibility recovery. Database order, matching rules and custom-file reload behavior stay intact. Mounted bundled bytes must match the compiled database before sharing its cache.
- Read the deadline clock on the first checkpoint and then every 64 checkpoints. Work limits still charge every checkpoint; the existing deadline test passes.
- Stop recursive child inference when an unresolved direct call cannot be repaired by those children. Keep inference invalidation for temporary return and calling-convention hints.
- Clear inference when the instruction limit changes, so a smaller retry cannot reuse evidence completed under a larger instruction limit.
- For non-PE browser inputs, omit the three unused FLIRT assets: 14.476 MiB of downloads and per-worker buffer copies. No asset is removed from PE analysis.

Other analysis jobs were active on this host. These wall times are provisional, not an isolated performance guarantee. The small native cases use three alternating before/after process pairs; BlackCat uses one full run per version. All use `--decompile-all --shard 0/1`, including recovery, initialization and JSON output. Samples are the IDs in `web/demo/samples.json`.

| Native sample | Functions | Before | After | Peak RSS before / after |
|---|---:|---:|---:|---:|
| Stuxnet | 83 | 2.209 s | 1.722 s | 793.8 / 648.5 MiB |
| Mirai | 142 | 11.023 s | 10.902 s | 82.5 / 82.5 MiB |
| 3CX | 11 | 0.485 s | 0.546 s | 61.5 / 61.0 MiB |
| BlackCat | 1,742 | 278.390 s | 282.432 s | 1,065.7 / 921.2 MiB |

There is no demonstrated BlackCat time improvement. Its memory saving is about 145 MiB per native process. The small native 3CX case regressed by about 62 ms in this run; the patch does not establish a universal speedup. Mirai body-analysis passes fell from 1,543 to 1,491; BlackCat passes increased from 5,048 to 5,073 while preserving the final outputs.

The actual WebAssembly engine was also run in Node, with a fresh instance and an already compiled module. This excludes downloads, module compilation, UI work and browser worker contention. Its before version already shares the parsed signature database, so this comparison measures the subsequent Ghidra and non-PE asset changes. Two alternating process pairs per sample, reporting medians:

| WebAssembly sample | Functions | Before | After |
|---|---:|---:|---:|
| Stuxnet | 83 | 2.939 s | 2.715 s |
| Mirai | 142 | 16.920 s | 13.513 s |
| 3CX | 11 | 1.305 s | 1.236 s |

Heap capacity did not increase in these WebAssembly pairs. The final module has one copy of the runtime signature bytes, matching the previous module's approximately 24.66 MB size.

Validation:

- All 1,978 distinct native function records matched, across the four samples and every repeat. Compare all fields except `ms` and `timings`, including C text, warnings, errors, incomplete markers and retries. Start inventories and final warnings matched as well.
- All WebAssembly function records and batch metadata matched in all six pairs. The final non-PE runs mounted no FLIRT assets, matching the browser's asset selection.
- Full capability JSON matched on all four samples, removing only `meta.timestamp`.
- Rust library and CLI suite: 856 passed, 6 ignored. Native Ghidra suite: 59 passed; the deadline and CLI checks also passed. The final signature-sharing test group passed all 10 tests after consolidating the embedded byte storage.
- Browser build, `test:assets`, `test:analyze`, `test:image` and `test:macho` passed.

A more aggressive inference-cache experiment was rejected. Restoring cached prototypes across temporary hints changed two BlackCat function records, including a 64-bit return narrowed to 32 bits. Ghidra retains ABI state beyond explicit prototype lock flags. Keeping that cache would violate output parity. An alternative WebAssembly allocator was also rejected after mixed timing results and a larger module.

For larger gains, investigate the long tail of the browser's round-robin function shards and repeated whole-file recovery across workers. The native and compatibility recovery passes find different functions, and data-symbol reanalysis changes types. Removing those passes outright would need coverage and typing evidence that this experiment does not establish.

To repeat the native check, build each revision separately and run the same sample and flags:

```bash
cargo build --release -p binfera-cli --features decompiler
/usr/bin/time -l target/release/binfera <sample> --decompile-all --shard 0/1
```
