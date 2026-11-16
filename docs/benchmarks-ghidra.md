# binfera and Ghidra: time to a function list

How long each tool takes to find the functions in a file. This is the step an analyst waits for before anything else can be read, and the one where a native engine has the most to gain over a JVM one.

## Result

On x86 and x86-64 Windows executables of 0.2 to 3.8 MB, binfera reaches its function list **8 to 21 times faster** than Ghidra's headless analyzer finishes importing and analysing the same file.

| File | Size | binfera: function list | Ghidra: import + analysis | Functions found (binfera / Ghidra) | Ratio |
|---|---|---|---|---|---|
| PE32, x86 | 0.17 MB | 1.0 s | 17.7 s | 681 / 686 | 18× |
| PE32+, x86-64 | 1.32 MB | 2.8 s | 57.9 s | 2,336 / 2,500 | 21× |
| PE32+, x86-64 | 3.76 MB | 4.2 s | 34.4 s | 1,867 / 1,746 | 8× |

Decompiling every function of the 3.76 MB file on one job took binfera a further 90 s (1,867 functions). Ghidra was not asked to decompile in these runs.

## Where the numbers are not comparable

Two other files were measured and are left out of the table, because the tools did not find comparable sets of functions:

- **A 0.70 MB ELF:** binfera listed 367 functions and Ghidra 4,399, so Ghidra did far more work and the timings say little. That is a coverage gap on this kind of file, not a speed result.
- **A 1.23 MB PE:** binfera listed no functions at all (Ghidra found 18). This was not investigated.

The speed-up holds where the function counts agree to within about 10%: the three files above.

## What it measures, and what it does not

- **binfera** is timed to the first record `binfera FILE --decompile-all` prints, which lists every recovered function once code recovery has finished.
- **Ghidra** is timed for `analyzeHeadless -import FILE` with its default auto-analysis, JVM start-up and project creation included. Its auto-analysis does more than find functions (data types, stack analysis, many analyzers), so this is the time to a fully analysed program, which is what Ghidra offers, not to a bare function list. Turning analyzers off would shorten Ghidra's time but also what it finds.
- Both tools find slightly different sets of functions, as the counts show.
- The decompiler itself is Ghidra's C++ core in both cases, so decompilation quality and per-function speed are the same kind of work. The difference measured here is in discovery.
- One run each, on one machine, with a warm disk cache: Apple M1 Max (10 cores, 64 GB), macOS 27.2, Ghidra 12.1.4 on Temurin JDK 27.0.1, binfera 1.0.0. Treat the ratios as indicative.
- Only small and medium files were run.

## Reproduce

```sh
scripts/bench/bench_vs_ghidra.py target/release/binfera /path/to/ghidra_12.1.4_PUBLIC file1.exe file2.exe
```

Set `DISCOVERY_ONLY=1` to skip the timing of decompiling every function. The script prints the table above.
