#!/usr/bin/env python3
"""Times binfera against Ghidra's headless analyzer on the same files.

    scripts/bench/bench_vs_ghidra.py BINFERA GHIDRA_DIR FILE [FILE ...]

binfera is timed to its function list: the first record `--decompile-all` prints, once code
recovery is done. Ghidra is timed for `analyzeHeadless -import` with its default auto-analysis,
JVM start-up included. CountFunctions.java reports Ghidra's functions, split into thunks (import
stubs such as ELF PLT entries and Mach-O stubs) and the rest.

Each file is run three times and the median kept; a file whose Ghidra run exceeds 60 s is run
once in Ghidra. A file counts towards the speed-up only when binfera's function count and
Ghidra's non-thunk count agree within 25%. The headline is the geometric mean of those ratios.

Prints one JSON line per file, then the Markdown tables of docs/benchmarks.md.
See that page for what the numbers do and do not say.
"""
import json
import math
import os
import re
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
RUNS = 3
SLOW_GHIDRA = 60.0
AGREEMENT = 1.25


def binfera(exe, path):
    """Seconds until the function list, and its length."""
    t0 = time.time()
    p = subprocess.Popen([exe, path, "--decompile-all", "--jobs", "1"], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True, bufsize=1)
    line = p.stdout.readline()
    elapsed = time.time() - t0
    p.kill()
    p.wait()
    try:
        return elapsed, len(json.loads(line)["functions"])
    except (ValueError, KeyError):
        return elapsed, None


def ghidra(ghidra_dir, path, timeout=1800):
    """Seconds for import and auto-analysis, and the function counts."""
    work = tempfile.mkdtemp(prefix="bench-ghidra-")
    t0 = time.time()
    r = subprocess.run([f"{ghidra_dir}/support/analyzeHeadless", work, "p", "-import", path,
                        "-scriptPath", HERE, "-postScript", "CountFunctions.java", "-deleteProject"],
                       capture_output=True, text=True, timeout=timeout)
    elapsed = time.time() - t0
    shutil.rmtree(work, ignore_errors=True)
    text = r.stdout + r.stderr

    def count(key):
        m = re.search(key + r"=(\d+)", text)
        return int(m.group(1)) if m else None

    return elapsed, count("BENCH_FUNCTIONS"), count("BENCH_THUNKS")


def kind(path):
    """A short format and architecture label read from the headers."""
    with open(path, "rb") as f:
        head = f.read(4096)
    if head[:4] == b"\x7fELF":
        big = head[5] == 2
        machine = struct.unpack((">" if big else "<") + "H", head[18:20])[0]
        return "ELF " + {3: "x86", 62: "x86-64", 40: "ARM32", 183: "AArch64", 8: "MIPS32"}.get(machine, f"machine {machine}")
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        cpu = struct.unpack("<I", head[4:8])[0]
        return "Mach-O " + {0x01000007: "x86_64", 0x0100000C: "arm64", 7: "i386"}.get(cpu, f"cpu {cpu:#x}")
    if head[:2] == b"MZ" and len(head) >= 0x40:
        pe = struct.unpack("<I", head[0x3C:0x40])[0]
        if head[pe:pe + 4] == b"PE\0\0":
            machine, = struct.unpack("<H", head[pe + 4:pe + 6])
            flags, = struct.unpack("<H", head[pe + 22:pe + 24])
            subsystem, = struct.unpack("<H", head[pe + 24 + 68:pe + 24 + 70])
            what = "driver" if subsystem == 1 else "DLL" if flags & 0x2000 else "EXE"
            return {0x14C: "PE32 x86", 0x8664: "PE32+ x64"}.get(machine, f"PE machine {machine:#x}") + " " + what
    return "other"


def measure(exe, ghidra_dir, path):
    bt, bn = zip(*(binfera(exe, path) for _ in range(RUNS)))
    gt, ga, gth = [], None, None
    for _ in range(RUNS):
        t, ga, gth = ghidra(ghidra_dir, path)
        gt.append(t)
        if t > SLOW_GHIDRA:
            break
    real = ga - gth if ga is not None and gth is not None else None
    return dict(file=os.path.basename(path), kind=kind(path), bytes=os.path.getsize(path),
                binfera_s=statistics.median(bt), binfera_functions=bn[0],
                ghidra_s=statistics.median(gt), ghidra_runs=len(gt),
                ghidra_functions=ga, ghidra_thunks=gth, ghidra_non_thunks=real)


def comparable(r):
    a, b = r["binfera_functions"], r["ghidra_non_thunks"]
    return bool(a and b) and max(a, b) / min(a, b) <= AGREEMENT


def geomean(values):
    return math.exp(sum(math.log(v) for v in values) / len(values))


def report(rows):
    good = [r for r in rows if comparable(r)]
    if good:
        ratios = [r["ghidra_s"] / r["binfera_s"] for r in good]
        print(f"\n{len(good)} of {len(rows)} files comparable; geometric mean {geomean(ratios):.1f}x "
              f"(range {min(ratios):.0f}x to {max(ratios):.0f}x).\n")
        print("| Type | Files | Speed-up (geometric mean) | Range |")
        print("|---|---:|---:|---:|")
        for k in sorted({r["kind"] for r in good}):
            rs = [r["ghidra_s"] / r["binfera_s"] for r in good if r["kind"] == k]
            print(f"| {k} | {len(rs)} | {geomean(rs):.0f}x | {min(rs):.0f}x to {max(rs):.0f}x |")
    print("\n| File | Type | Size | binfera | Ghidra | Functions (binfera / Ghidra without thunks) | Speed-up |")
    print("|---|---|---:|---:|---:|---:|---:|")
    for r in rows:
        ratio = f"{r['ghidra_s'] / r['binfera_s']:.0f}x" if comparable(r) else "not comparable"
        print(f"| {r['file'][:16]} | {r['kind']} | {r['bytes'] / 1e6:.2f} MB | {r['binfera_s']:.2f} s | "
              f"{r['ghidra_s']:.1f} s | {r['binfera_functions']} / {r['ghidra_non_thunks']} | {ratio} |")


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    exe, ghidra_dir, files = sys.argv[1], sys.argv[2], sys.argv[3:]
    rows = []
    for path in files:
        rows.append(measure(exe, ghidra_dir, path))
        print(json.dumps(rows[-1]), flush=True)
    report(rows)


if __name__ == "__main__":
    main()
