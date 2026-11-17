#!/usr/bin/env python3
"""Compare Binfera with Binary Ninja Free's running GUI MCP server.

Uses only Python's standard library. See docs/benchmarks.md for setup,
measurement boundaries, corpus selection, and interpretation.
"""
import argparse
import ctypes
import hashlib
import itertools
import json
import os
from pathlib import Path
import platform
import re
import selectors
import statistics
import subprocess
import tempfile
import time
import urllib.request

from bench_vs_ghidra import kind


class MCP:
    def __init__(self, url, timeout=600):
        self.url = url
        self.timeout = timeout
        self.session = None
        self.sequence = 0
        initialized = self.request("initialize", {"protocolVersion": "2025-03-26",
                                   "capabilities": {}, "clientInfo": {"name": "binfera-bench", "version": "1"}})
        self.server_info = initialized.get("serverInfo")
        self.request("notifications/initialized", notification=True)

    def request(self, method, params=None, notification=False):
        self.sequence += 1
        payload = {"jsonrpc": "2.0", "method": method}
        if not notification:
            payload["id"] = self.sequence
        if params is not None:
            payload["params"] = params
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        token = os.environ.get("BN_MCP_TOKEN")
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(self.url, json.dumps(payload).encode(), headers)
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            self.session = response.headers.get("Mcp-Session-Id", self.session)
            if response.status in (202, 204):
                return None
            if "text/event-stream" in response.headers.get("Content-Type", ""):
                for line in response:
                    if line.startswith(b"data:"):
                        message = json.loads(line[5:])
                        if message.get("id") == payload.get("id"):
                            break
                else:
                    raise RuntimeError("MCP stream ended without a result")
            else:
                message = json.load(response)
        if "error" in message:
            raise RuntimeError(message["error"])
        return message.get("result")

    def call(self, name, **arguments):
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError"):
            raise RuntimeError(f"{name}: {result}")
        if "structuredContent" in result:
            return result["structuredContent"]
        texts = [item["text"] for item in result.get("content", []) if item["type"] == "text"]
        if len(texts) != 1:
            raise RuntimeError(f"Unexpected {name} response: {result}")
        text = texts[0]
        if not text.startswith("---\n"):
            return json.loads(text)
        front, body = text[4:].split("\n---\n", 1)
        metadata = {key: json.loads(value) for key, value in
                    (line.split(": ", 1) for line in front.splitlines())}
        lines = [line for line in body.splitlines() if line.startswith("| ")]
        rows = []
        if lines:
            cells = lambda line: [cell.strip().replace(r"\|", "|") for cell in
                                  re.split(r"(?<!\\)\|", line)[1:-1]]
            columns = cells(lines[0])
            rows = [dict(zip(columns, cells(line))) for line in lines[2:]]
        code = re.search(r"(`{3,})[^\n]*\n(.*?)\n\1", body, re.S)
        return {"metadata": metadata, "rows": rows, "text": code[2] if code else body,
                "raw": text}

    def pages(self, name, **arguments):
        rows, offset = [], 0
        while True:
            page = self.call(name, offset=offset, limit=1000, **arguments)
            rows.extend(page["rows"])
            if not page["metadata"]["truncated"]:
                return rows
            next_offset = page["metadata"]["nextOffset"]
            if next_offset is None or next_offset <= offset:
                raise RuntimeError(f"Invalid pagination from {name}")
            offset = next_offset


def binfera_inventory(exe, path, timeout):
    started = time.perf_counter()
    with subprocess.Popen([str(exe), str(path), "--decompile-all", "--jobs", "1"],
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                line = bytearray()
                deadline = started + timeout
                while b"\n" not in line:
                    remaining = deadline - time.perf_counter()
                    if remaining <= 0 or not selector.select(remaining):
                        raise TimeoutError(f"Binfera inventory timed out: {path}")
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        raise RuntimeError(f"Binfera exited without a function inventory: {path}")
                    line.extend(chunk)
            line = line.split(b"\n", 1)[0]
            elapsed = time.perf_counter() - started
            record = json.loads(line)
            if record.get("type") != "start":
                raise RuntimeError(f"Missing function inventory: {record}")
            return elapsed, record
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()


def binja_inventory(client, path):
    started = time.perf_counter()
    opened = client.call("bn_open_item_open", path=str(path), kind="file")
    handle = opened["openItem"]["handle"]
    try:
        view = opened["activeBinaryView"]
        if view["viewType"] == "Raw" or not view["architecture"]:
            raise RuntimeError(f"No supported analyzed view: {view}")
        analysis = client.call("bn_analysis_update_and_wait")
        elapsed = time.perf_counter() - started
        if analysis["after"]["state"] != "IdleState":
            raise RuntimeError(f"Analysis did not finish: {analysis}")
        functions = client.pages("bn_function_list")
        return elapsed, functions, view, handle
    except TimeoutError:
        # A blocking analysis call can leave the GUI server unable to process a
        # close request. Let the caller report the timeout without waiting again.
        raise
    except BaseException:
        client.call("bn_open_item_close", openItem=handle, save="discard")
        raise


def address(value):
    return int(value, 0) if isinstance(value, str) else value


def file_offset(va, regions):
    """Compare instructions by input bytes, independent of each loader's base."""
    matches = {r["off"] + va - r["va"] for r in regions if r["va"] <= va < r["va"] + r["size"]}
    if len(matches) > 1:
        raise ValueError(f"Ambiguous file mapping for {va:#x}")
    return next(iter(matches), None)


def normalize(row, image_info, segments):
    ours = {file_offset(va, image_info["regions"]): va for va in row["binfera_inventory"]["functions"]}
    regions = [{"va": address(s["start"]), "off": address(s["dataOffset"]),
                "size": address(s["dataLength"])} for s in segments]
    theirs = {file_offset(address(f["function"]), regions): f for f in row["binja_inventory"]}
    ours.pop(None, None)
    theirs.pop(None, None)
    shared = sorted(ours.keys() & theirs.keys())
    union = ours.keys() | theirs.keys()
    row.update(coordinate_system="file_offset", binfera_regions=image_info["regions"], binja_segments=segments,
               shared_functions=len(shared), address_jaccard=len(shared) / len(union) if union else None,
               binfera_mapped_functions=len(ours), binja_mapped_functions=len(theirs),
               binfera_only=sorted(ours.keys() - theirs.keys()), binja_only=sorted(theirs.keys() - ours.keys()))
    return ours, theirs, shared


def inventory_digest(functions):
    values = sorted(functions)
    return {"count": len(values), "sha256": hashlib.sha256(json.dumps(values).encode()).hexdigest()}


def decompile_binja(client, function):
    chunks, offset = [], 0
    while True:
        part = client.call("bn_function_decompile", function=function["function"],
                           arch=function["arch"], offset=offset, limit=1000)
        chunks.append(part["text"])
        if part["metadata"].get("needsUpdate"):
            raise RuntimeError("Decompiler output needs an analysis update")
        if not part["metadata"]["truncated"]:
            return "\n".join(chunks)
        next_offset = part["metadata"]["nextOffset"]
        if next_offset is None or next_offset <= offset:
            raise RuntimeError("Invalid decompiler pagination")
        offset = next_offset


def measure(client, exe, path, args):
    bt, nt, binfera_sets, binja_sets = [], [], [], []
    handle = None
    try:
        for run in range(args.runs):
            # Alternate ordering to reduce systematic cache and thermal bias.
            if run % 2 == 0:
                elapsed, inventory = binfera_inventory(exe, path, args.timeout)
                bt.append(elapsed)
            elapsed, functions, view, handle = binja_inventory(client, path)
            nt.append(elapsed)
            if run % 2:
                elapsed, inventory = binfera_inventory(exe, path, args.timeout)
                bt.append(elapsed)
            binfera_sets.append(set(inventory["functions"]))
            binja_sets.append({address(f["function"]) for f in functions})
            print(f"  trial {run + 1}: {bt[-1]:.3f}s / {nt[-1]:.3f}s; "
                  f"{len(binfera_sets[-1])} / {len(binja_sets[-1])} functions", flush=True)
            if run + 1 < args.runs:
                client.call("bn_open_item_close", openItem=handle, save="discard")
                handle = None
        ours, theirs = binfera_sets[-1], binja_sets[-1]
        shared = sorted(ours & theirs)
        union = ours | theirs
        row = {"file": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
               "kind": kind(path), "bytes": path.stat().st_size,
               "binfera_inventory_s": bt, "binja_analysis_s": nt,
               "binfera_median_s": statistics.median(bt), "binja_median_s": statistics.median(nt),
               "binfera_functions": len(ours), "binja_functions": len(theirs),
               "shared_functions": len(shared), "address_jaccard": len(shared) / len(union) if union else None,
               "binfera_only": sorted(ours - theirs), "binja_only": sorted(theirs - ours),
               "stable_inventory": all(s == ours for s in binfera_sets) and all(s == theirs for s in binja_sets),
               "binfera_inventory_runs": [inventory_digest(s) for s in binfera_sets],
               "binja_inventory_runs": [inventory_digest(s) for s in binja_sets],
               "binja_view": view, "binfera_inventory": inventory, "binja_inventory": functions}
        info = json.loads(subprocess.check_output([str(exe), str(path), "--image-info"], timeout=args.timeout))
        segments = client.pages("bn_segment_list")
        ours_by_offset, lookup, shared = normalize(row, info, segments)
        # All source-backed fixture functions, or evenly spaced common functions.
        count = min(args.decompile, len(shared))
        selected = shared if args.all_functions else [shared[i * (len(shared) - 1) // max(1, count - 1)]
                                                     for i in range(count)]
        pseudocode = []
        for offset in selected:
            va = ours_by_offset[offset]
            entry = {"address": va, "file_offset": offset, "binja_name": lookup[offset]["name"]}
            try:
                result = subprocess.run([str(exe), str(path), "--decompile-function", hex(va), "--json"],
                                        capture_output=True, text=True, timeout=args.timeout, check=True)
                entry["binfera"] = json.loads(result.stdout)
            except (subprocess.SubprocessError, ValueError) as error:
                entry["binfera_error"] = str(error)
            try:
                entry["binja"] = decompile_binja(client, lookup[offset])
            except (RuntimeError, ValueError) as error:
                entry["binja_error"] = str(error)
            pseudocode.append(entry)
        row["pseudocode"] = pseudocode
        return row
    finally:
        if handle:
            client.call("bn_open_item_close", openItem=handle, save="discard")


FIXTURES = (
    "tests/decompiler/fixtures.dll",
    "binfera/tests/fixtures/elf64_sysv/freestanding.elf",
    "binfera/tests/fixtures/aarch64_decompiler/executable.elf",
    "binfera/tests/fixtures/aarch64_decompiler/windows.exe",
    "binfera/tests/fixtures/risc/arm.elf",
    "binfera/tests/fixtures/risc/thumb.elf",
    "binfera/tests/fixtures/macho/symbols-x86_64-exe",
    "binfera/tests/fixtures/macho/thin-arm64-exe",
)


def fixture_cases(path):
    """name, dependencies, inputs, expected result, result bits (0 means double)."""
    if not any(path == fixture or path.endswith("/" + fixture) for fixture in FIXTURES):
        raise ValueError(f"Not a recognized source-backed fixture: {path}")
    small = [-100, -1, 0, 1, 7, 99, 100, 101, 1024]
    branch = lambda x: -x if x < 0 else 100 if x > 100 else x + 1
    squares = lambda n: sum(i * i for i in range(max(0, n)))
    arithmetic = lambda x, y: x * 7 + y - 3
    if path.endswith("tests/decompiler/fixtures.dll"):
        def switch(x, y):
            return {0: lambda: arithmetic(y, 13), 1: lambda: branch(y),
                    2: lambda: squares(y), 3: lambda: arithmetic(y, 27),
                    4: lambda: arithmetic(y, 91), 5: lambda: branch(y + 12),
                    6: lambda: squares(y + 2)}.get(x, lambda: -1)()
        return [("arithmetic", [], list(itertools.product(small, [-31, -1, 0, 1, 13, 91])), arithmetic, 32),
                ("branches", [], [(x,) for x in small], branch, 32),
                ("loops", [], [(x,) for x in [-2, -1, 0, 1, 2, 7, 31, 100, 256]], squares, 32),
                ("switches", ["arithmetic", "branches", "loops"],
                 list(itertools.product([-1, 0, 1, 2, 3, 4, 5, 6, 7, 100], [-10, -1, 0, 1, 2, 7, 31])), switch, 32)]
    if "/elf64_sysv/" in path:
        total = lambda n: n * (n + 1) if n > 0 else 0
        return [("sum_to", [], [(x,) for x in small], total, 32),
                ("classify", ["sum_to"], [(x,) for x in small],
                 lambda x: -1 if x < 0 else 0 if x == 0 else 2 if total(x) > 100 else 1, 32)]
    if "/aarch64_decompiler/" in path:
        bits = 32 if path.endswith(".exe") else 64
        return [("arithmetic", [], list(itertools.product(small, [-7, 0, 7])), lambda x, y: x * 3 + y, 32),
                ("caller", ["arithmetic"], [(x,) for x in small], lambda x: x * 3 + 16, 32),
                ("ninth", [], [tuple(range(9)), (1,) * 9, (-1,) * 9,
                                (0, 0, 0, 0, 0, 0, 0, 0, 12345)], lambda *xs: sum(xs), bits),
                ("floating", [], [(1.0, 2.0), (-3.0, 0.5), (0.0, -1.0), (0.25, 0.125)],
                 lambda x, y: x * 2.0 + y, 0)]
    if "/risc/" in path:
        mix = lambda a, b: ((a ^ b) + 11 if a > 7 else a + b) & 0xffffffff
        values = [0, 1, 7, 8, 9, 0x7fffffff, 0x80000000, 0xffffffff]
        return [("mix", [], list(itertools.product(values, [0, 3, 17])), mix, 32),
                ("invoke", ["mix"], [(x,) for x in values], lambda x: mix(x, 3) + 5, 32)]
    if "/macho/" in path:
        return [("_add", [], list(itertools.product(small, [-1, 0, 1])), lambda a, b: a + b, 32)]
    raise ValueError(f"Not a recognized source-backed fixture: {path}")


PRELUDE = """#include <stdint.h>
#include <stdbool.h>
#include <math.h>
typedef unsigned int uint;
typedef double float8;
/* Pseudo C intrinsic: fused multiply-add with accumulator first. */
static double vfma_f64(double acc, double x, double y) { return fma(x, y, acc); }
"""


def check_case(row, tool, spec, output):
    name, dependencies, inputs, expected, bits = spec
    record = {"file": row["file"], "tool": tool, "function": name,
              "cases": len(inputs), "inputs": inputs,
              "expected": [expected(*args) & ((1 << bits) - 1) if bits else expected(*args) for args in inputs],
              "actual": [], "passed": 0, "failures": []}
    lookup = {f["binja_name"]: f for f in row["pseudocode"]}
    texts = []
    for needed in dependencies + [name]:
        entry = lookup[needed]
        text = entry.get("binfera", {}).get("text") if tool == "binfera" else entry.get("binja")
        if not text:
            record["error"] = f"Missing pseudocode for {needed}"
            return record
        # Remove display-only effect annotations, without changing expressions or types.
        texts.append(text.replace("__pure", ""))
    target = lookup[name].get("binfera", {}).get("name", name) if tool == "binfera" else name
    floating = bits == 0
    ctype = "double" if floating else "int64_t"
    result_type = "double" if floating else "uint64_t"
    parameters = ", ".join(f"{ctype} a{i}" for i in range(len(inputs[0])))
    arguments = ", ".join(f"a{i}" for i in range(len(inputs[0])))
    source = PRELUDE + "\n".join(texts) + f"\n{result_type} bench_call({parameters}) {{ return {target}({arguments}); }}\n"
    stem = output / (Path(row["file"]).parent.name + "-" + Path(row["file"]).name + "-" + tool + "-" + name)
    cfile = stem.with_suffix(stem.suffix + ".c")
    library = stem.with_suffix(stem.suffix + ".dylib")
    cfile.write_text(source)
    command = ["clang", "-dynamiclib", "-O0", "-fwrapv", "-Werror=return-type",
               str(cfile), "-o", str(library)]
    compilation = subprocess.run(command, capture_output=True, text=True, timeout=30)
    record["compiler_stderr"] = compilation.stderr
    if compilation.returncode:
        record["compile_error"] = True
        return record
    function = ctypes.CDLL(str(library.resolve())).bench_call
    function.argtypes = [ctypes.c_double if floating else ctypes.c_int64] * len(inputs[0])
    function.restype = ctypes.c_double if floating else ctypes.c_uint64
    for args in inputs:
        actual, wanted = function(*args), expected(*args)
        if not floating:
            mask = (1 << bits) - 1
            actual, wanted = actual & mask, wanted & mask
        record["actual"].append(actual)
        if actual == wanted:
            record["passed"] += 1
        else:
            record["failures"].append({"inputs": args, "actual": actual, "expected": wanted})
    return record


def check_quality(results_file, output):
    rows = [json.loads(line) for line in results_file.read_text().splitlines()]
    # Validate the entire input before compiling or executing anything.
    cases = [fixture_cases(row["file"]) for row in rows]
    output.mkdir(parents=True, exist_ok=False)
    results = [check_case(row, tool, spec, output) for row, specs in zip(rows, cases)
               for spec in specs for tool in ("binfera", "binja")]
    (output / "quality.json").write_text(json.dumps(results, indent=2) + "\n")
    for tool in ("binfera", "binja"):
        selected = [r for r in results if r["tool"] == tool]
        print(tool, "functions", len(selected), "compile failures", sum(bool(r.get("compile_error")) for r in selected),
              "cases passed", sum(r["passed"] for r in selected), "/", sum(r["cases"] for r in selected))
        for result in selected:
            if result.get("compile_error") or result["failures"]:
                print(" ", Path(result["file"]).name, result["function"],
                      "compile failure" if result.get("compile_error") else result["failures"][:3])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:24642/mcp")
    parser.add_argument("--tools", action="store_true", help="Print the server's tool schemas")
    parser.add_argument("--binfera", type=Path, default=Path("target/release/binfera"))
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fixtures", action="store_true", help="Use the eight source-backed fixtures")
    parser.add_argument("--quality", type=Path, metavar="RESULTS_JSONL",
                        help="Check saved results from the benign source fixtures")
    parser.add_argument("--decompile", type=int, default=3, help="Common functions sampled per file")
    parser.add_argument("--all-functions", action="store_true", help="Decompile every common function (fixtures)")
    parser.add_argument("--samples", type=Path, help="Corpus list with paths relative to tests/testfiles")
    parser.add_argument("--demos", action="store_true", help="Include the 12 locally packed web demos")
    parser.add_argument("files", nargs="*", type=Path)
    args = parser.parse_args()
    if args.runs < 1 or args.timeout <= 0 or args.decompile < 0:
        parser.error("runs and timeout must be positive; decompile must be nonnegative")
    if args.quality:
        if args.output is None:
            parser.error("--quality requires --output")
        check_quality(args.quality, args.output)
        return
    client = MCP(args.url, args.timeout)
    if args.tools:
        print(json.dumps(client.request("tools/list"), indent=2))
        return
    if not (args.files or args.samples or args.demos or args.fixtures) or args.output is None:
        parser.error("provide inputs with FILE, --samples, --demos or --fixtures, and set --output")
    exe = args.binfera.resolve(strict=True)
    paths = [path.resolve(strict=True) for path in args.files]
    root = Path(__file__).resolve().parents[2]
    if args.fixtures:
        paths.extend(root / fixture for fixture in FIXTURES)
        args.all_functions = True
    if args.samples:
        for line in args.samples.read_text().splitlines():
            name = line.split("#", 1)[0].strip()
            if name:
                paths.append((root / "tests/testfiles" / name).resolve(strict=True))
    temporary = tempfile.TemporaryDirectory(prefix="binfera-binja-demos-")
    if args.demos:
        key = b"binfera-demo-sample"
        index = json.loads((root / "web/public/demos/index.json").read_text())
        for item in index:
            encoded = (root / "web/public/demos" / (item["id"] + ".bin")).read_bytes()
            decoded = bytes(value ^ key[i % len(key)] for i, value in enumerate(encoded))
            if hashlib.sha256(decoded).hexdigest() != item["sha256"]:
                raise ValueError(f"Demo checksum mismatch: {item['id']}")
            path = Path(temporary.name) / (item["id"] + ".sample")
            path.write_bytes(decoded)
            paths.append(path)
    args.output.mkdir(parents=True, exist_ok=False)
    metadata = {"date": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "platform": platform.platform(),
                "binfera_version": subprocess.check_output([str(exe), "--version"], text=True).strip(),
                "binfera_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
                "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
                "runs": args.runs, "decompile_sample": args.decompile, "all_functions": args.all_functions,
                "mcp_url": args.url, "server_info": client.server_info,
                "server_tools": client.request("tools/list")}
    (args.output / "manifest.json").write_text(json.dumps(metadata, indent=2) + "\n")
    with (args.output / "results.jsonl").open("w") as output:
        failures = 0
        for index, path in enumerate(paths):
            print(f"[{index + 1}/{len(paths)}] {path.name}", flush=True)
            timed_out = False
            try:
                row = measure(client, exe, path, args)
                print(f"  {row['binfera_median_s']:.3f}s / {row['binja_median_s']:.3f}s; "
                      f"{row['binfera_functions']} / {row['binja_functions']} functions; "
                      f"{row['shared_functions']} shared", flush=True)
            except Exception as error:
                failures += 1
                timed_out = isinstance(error, TimeoutError)
                row = {"file": str(path), "error": str(error)}
                print(f"  ERROR: {error}", flush=True)
            output.write(json.dumps(row) + "\n")
            output.flush()
            if timed_out:
                print("Stopping after timeout; restart the GUI server before continuing.", flush=True)
                break
    temporary.cleanup()
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
