#!/usr/bin/env python3
"""Times binfera against Ghidra's headless analyzer on the same files.

    scripts/bench/bench_vs_ghidra.py BINFERA GHIDRA_DIR FILE [FILE ...]

binfera is timed to its function list (the first record `--decompile-all` prints, once code recovery
is done); set DISCOVERY_ONLY=1 to stop there, otherwise it also times decompiling every function
on one job. Ghidra is timed for `analyzeHeadless -import` with its default auto-analysis, JVM start-up
included, and its function count is read by CountFunctions.java. See docs/benchmarks-ghidra.md for
what the numbers do and do not say.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def binfera(exe, path):
    t0 = time.time()
    p = subprocess.Popen([exe, path, "--decompile-all", "--jobs", "1"], stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True, bufsize=1)
    first = functions = None
    for line in p.stdout:
        if first is None:
            first = time.time() - t0
            try:
                functions = len(json.loads(line)["functions"])
            except Exception:
                pass
            if os.environ.get("DISCOVERY_ONLY"):
                p.kill()
                p.wait()
                return first, first, functions
    p.wait()
    return first, time.time() - t0, functions


def ghidra(ghidra_dir, path, timeout=1800):
    work = tempfile.mkdtemp(prefix="bench-ghidra-")
    t0 = time.time()
    r = subprocess.run([f"{ghidra_dir}/support/analyzeHeadless", work, "p", "-import", path,
                        "-scriptPath", HERE, "-postScript", "CountFunctions.java", "-deleteProject"],
                       capture_output=True, text=True, timeout=timeout)
    elapsed = time.time() - t0
    shutil.rmtree(work, ignore_errors=True)
    functions = None
    for line in (r.stdout + r.stderr).splitlines():
        if "BENCH_FUNCTIONS=" in line:
            functions = int(line.split("BENCH_FUNCTIONS=")[1].split()[0])
    return elapsed, functions


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    exe, ghidra_dir, files = sys.argv[1], sys.argv[2], sys.argv[3:]
    print("| File | Size | binfera: function list | binfera: functions | Ghidra: import + analysis | Ghidra: functions | Ratio |")
    print("|---|---|---|---|---|---|---|")
    for f in files:
        first, _, nb = binfera(exe, f)
        gt, ng = ghidra(ghidra_dir, f)
        ratio = f"{gt / first:.0f}x" if first else "n/a"
        print(f"| {os.path.basename(f)[:24]} | {os.path.getsize(f) / 1e6:.2f} MB | {first:.2f} s | {nb} | {gt:.1f} s | {ng} | {ratio} |", flush=True)


if __name__ == "__main__":
    main()
