#!/usr/bin/env python3
"""Run Binfera and rev.ng on the same inputs in rev.ng's Linux container."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import statistics
import subprocess
import tempfile
import time

from bench_vs_binja import FIXTURES, binfera_inventory, file_offset, fixture_cases


def timed(command, timeout):
    started = time.perf_counter()
    try:
        run = subprocess.run(command, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, b"", f"Timed out after {timeout}s"
    elapsed = time.perf_counter() - started
    if run.returncode:
        return None, run.stdout, f"Exit {run.returncode}: {run.stderr.decode(errors='replace').strip()}"
    return elapsed, run.stdout, None


def meta_address(value):
    return int(value.split(":", 1)[0], 0)


def compare(binfera_model, binfera_regions, revng_model):
    revng_regions = [{"va": meta_address(segment["StartAddress"]),
                      "off": segment.get("StartOffset", 0), "size": segment.get("FileSize", 0)}
                     for segment in revng_model.get("Segments", [])]

    def offsets(starts, regions):
        return {offset for start in starts if (offset := file_offset(start, regions)) is not None}

    our_starts = binfera_model["functions"]
    their_starts = [meta_address(function["Entry"]) for function in revng_model.get("Functions", [])]
    ours = offsets(our_starts, binfera_regions)
    theirs = offsets(their_starts, revng_regions)
    return {"binfera_count": len(our_starts), "revng_count": len(their_starts),
            "binfera_offsets": sorted(ours), "revng_offsets": sorted(theirs),
            "shared": len(ours & theirs), "overlap": len(ours & theirs) / len(ours | theirs) if ours | theirs else None}


def benchmark(path, options, folder):
    import yaml

    folder.mkdir()
    binfera = [options.binfera, str(path), "--decompile-all", "--jobs", "1"]
    revng = ["revng", "quick"]
    record = {"file": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
              "bytes": path.stat().st_size}
    timings = {key: [] for key in ["binfera_inventory", "revng_analysis", "binfera_batch", "revng_c"]}
    errors = {}
    inventory = None
    for run in range(options.runs):
        calls = [
            ("binfera_inventory", None, "binfera-inventory.json"),
            ("revng_analysis", revng + ["analyze", str(path)], "revng.yml"),
            ("binfera_batch", binfera, "binfera.jsonl"),
            ("revng_c", revng + ["artifact", "emit-c-as-single-file", str(path)], "revng.ptml"),
        ]
        if run % 2:
            calls = [calls[1], calls[0], calls[3], calls[2]]
        for key, command, filename in calls:
            if key in errors:
                continue
            if command is None:
                try:
                    elapsed, inventory = binfera_inventory(options.binfera, path, options.timeout)
                except (ValueError, RuntimeError, TimeoutError) as error:
                    errors[key] = str(error)
                    continue
                output, error = json.dumps(inventory).encode(), None
            else:
                elapsed, output, error = timed(command, options.timeout)
            if error:
                errors[key] = error
                continue
            timings[key].append(elapsed)
            (folder / filename).write_bytes(output)

    record.update(timings=timings, medians={k: statistics.median(v) for k, v in timings.items() if v}, errors=errors)
    if inventory and "revng_analysis" not in errors:
        raw = subprocess.check_output([options.binfera, str(path), "--image-info"], timeout=options.timeout)
        model = yaml.safe_load((folder / "revng.yml").read_text())
        record.update(compare(inventory, json.loads(raw)["regions"], model))
    if "revng_c" not in errors:
        plain = subprocess.check_output(["revng", "ptml"], input=(folder / "revng.ptml").read_bytes(),
                                        timeout=options.timeout)
        (folder / "revng.c").write_bytes(plain)
    return record


def extract(text, name, file):
    symbols = [name, name.removeprefix("_")]
    if name == "_add" and "/macho/" in file:
        # Both checked-in Mach-O fixtures link this local function at the same VA.
        arch = "x86_64" if file.endswith("symbols-x86_64-exe") else "aarch64"
        symbols.append(f"function_0x1000005c0_Code_{arch}")
    for symbol in dict.fromkeys(symbols):
        pattern = rf"^[^\s#][^\n]*?\b{re.escape(symbol)}\([^;{{}}]*\)\s*\{{.*?^\}}"
        match = re.search(pattern, text, re.MULTILINE | re.DOTALL)
        if match:
            return symbol, match[0]
    return name, None


def check_case(file, text, spec, headers):
    name, dependencies, inputs, expected, bits = spec
    record = {"file": file, "function": name, "input_count": len(inputs)}
    functions = [extract(text, function, file) for function in [*dependencies, name]]
    if any(not body for _, body in functions):
        return dict(record, status="function absent")

    target = functions[-1][0]
    prelude = '#include <stdio.h>\n#include "attributes.h"\n#include "primitive-types.h"\n'
    calls = []
    values = []
    for args in inputs:
        arguments = ", ".join(map(repr, args))
        if bits:
            calls.append(f'printf("%llu\\n", (unsigned long long)(uint{bits}_t){target}({arguments}));')
            values.append(expected(*args) & ((1 << bits) - 1))
        else:
            calls.append(f'printf("%.17g\\n", (double){target}({arguments}));')
            values.append(expected(*args))
    source = prelude + "\n".join(body for _, body in functions)
    source += "\nint main(void) {\n" + "\n".join(calls) + "\n}\n"

    with tempfile.TemporaryDirectory() as temporary:
        exe = Path(temporary) / "probe"
        command = ["clang", "-x", "c", "-O0", "-fwrapv", "-Werror=return-type",
                   "-Wno-constant-conversion", "-I", str(headers), "-o", str(exe), "-"]
        build = subprocess.run(command, input=source, text=True, capture_output=True, timeout=30)
        if build.returncode:
            return dict(record, status="cannot compile isolated function", diagnostics=build.stderr[:900])
        try:
            run = subprocess.run([exe], text=True, capture_output=True, check=True, timeout=3)
        except subprocess.SubprocessError as error:
            return dict(record, status="execution failed", diagnostics=str(error))

    parse = int if bits else float
    actual = [parse(line) for line in run.stdout.splitlines()]
    return dict(record, status="executed", inputs=inputs, expected=values, actual=actual,
                passed=sum(a == b for a, b in zip(actual, values)))


def check_quality(results_dir, headers):
    entries = [json.loads(line) for line in (results_dir / "results.jsonl").read_text().splitlines()]
    # This whitelist comes from the same source fixture set as the Binary Ninja check.
    cases = [fixture_cases(entry["file"]) for entry in entries]
    results = []
    for index, (entry, specs) in enumerate(zip(entries, cases), 1):
        name = Path(entry["file"]).name
        path = results_dir / f"{index:02d}-{name}" / "revng.c"
        text = path.read_text() if path.exists() else ""
        results.extend(check_case(entry["file"], text, spec, headers) for spec in specs)
    print(json.dumps(results, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binfera")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fixtures", action="store_true", help="Use the eight source-backed fixtures")
    parser.add_argument("--quality", type=Path, metavar="RESULTS_DIR",
                        help="Check saved results from the benign source fixtures")
    parser.add_argument("--headers", type=Path, help="rev.ng's share/revng/include directory")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("files", nargs="*", type=Path)
    options = parser.parse_args()
    if options.quality:
        if options.headers is None:
            parser.error("--quality requires --headers")
        check_quality(options.quality, options.headers)
        return
    if not options.binfera or options.output is None or not (options.files or options.fixtures):
        parser.error("measurements require --binfera, --output and inputs (FILE or --fixtures)")
    if options.fixtures:
        root = Path(__file__).resolve().parents[2]
        options.files.extend(root / fixture for fixture in FIXTURES)
    if options.runs < 1 or options.timeout < 1:
        parser.error("runs and timeout must be positive")
    options.output.mkdir(parents=True, exist_ok=False)
    with (options.output / "results.jsonl").open("w") as results:
        for index, path in enumerate(options.files, 1):
            print(f"[{index}/{len(options.files)}] {path.name}", flush=True)
            row = benchmark(path, options, options.output / f"{index:02d}-{path.name}")
            results.write(json.dumps(row) + "\n")
            results.flush()
            print(row["medians"], list(row["errors"]), flush=True)


if __name__ == "__main__":
    main()
