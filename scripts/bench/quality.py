#!/usr/bin/env python3
"""Decompiler output-quality report: untyped imports, unresolved indirect calls, numeric API arguments.

    python3 scripts/bench/quality.py --base-bin OLD/binfera --head-bin target/release/binfera \
        --samples scripts/corpus-quality.txt --json /tmp/quality.json
    python3 scripts/bench/quality.py --head-bin target/release/binfera \
        --samples scripts/corpus-quality.txt --baseline scripts/bench/quality-baseline.json --check

Like scripts/bench/recovery.py it compares a base and a head binary (a revision is built in a
temporary worktree, `--base REV` / `--head REV`, or the working tree is built when `--head` is
omitted) over a sample list, and writes JSON. Where recovery.py scores function starts, this scores
what the decompiler prints, per file:

* `untyped_imports`: named imports of a PE file that reach the decompiler without a prototype. This
  is `scripts/decompiler_types/coverage.py`'s lookup, run against the Windows pack and the system-DLL
  allow-list (`system_import_function` in binfera/src/decompiler.rs) of the side's own revision. A
  prebuilt binary (`--base-bin`) has no revision: its source is the checkout.
* `indirect_calls`: call sites printed as `(*X)(...)` in the C text, that is, calls whose target the
  decompiler could not name.
* `unknown_callee_calls`: calls the decompiler warned about as having no known prototype
  ("Uncertain calls (N)").
* `numeric_api_args`: non-zero numeric constants passed at parameters that have a `P:` enum or flag
  record in the Windows pack, so the symbolic-constants pass could have named them
  (`VirtualAlloc(0, 0x1000, 0x3000, 0x40)`).
* `errors`: functions the decompiler failed on.

The decompiler's own output is read from

    binfera FILE --decompile-all

so a file takes as long as its decompilation: keep the sample list small (scripts/corpus-quality.txt
is the CI subset). Results are cached by the sample's SHA-256 and the tool's identity, like
recovery.py's, when the tool is a revision.

A baseline is a checked-in JSON of each metric per sample for one binary. `--check` fails (exit 1)
when a head metric is above its baseline, and reports (exit 0) a metric below it as an improvement
to record with `--write-baseline`. A metric the baseline lacks is a failure too: record it. Without
`--check` the run only reports. Samples missing from the checkout are skipped, with a message.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "scripts" / "bench"))
sys.path.insert(0, str(ROOT / "scripts" / "decompiler_types"))
import coverage  # noqa: E402
from difftest import read_sample_list  # noqa: E402
from recovery import DEFAULT_CACHE, git, resolve_tool, sample_key, sha256_file  # noqa: E402

CACHE_VERSION = 1
METRICS = ("untyped_imports", "indirect_calls", "unknown_callee_calls", "numeric_api_args", "errors")

# --------------------------------------------------------------------------- pure logic


def indirect_call_sites(text: str) -> list[str]:
    """The callee expressions of `(*X)(...)` calls in C text: a parenthesized dereference, directly
    followed by an argument list, with or without a cast before it. A cast `(code *)p` does not
    start with `(*`, and a bare `(*p)` that is not called is a dereference."""
    sites, at = [], 0
    while True:
        at = text.find("(*", at)
        if at < 0:
            return sites
        before = text[at - 1] if at else " "
        # `f(*p)(x)` and `a[i](*p)` are not this; `(T)(*p)(x)` is: a cast of the call's result.
        if before.isalnum() or before in "_]":
            at += 2
            continue
        depth, end = 0, at
        while end < len(text):
            if text[end] == "(":
                depth += 1
            elif text[end] == ")":
                depth -= 1
                if depth == 0:
                    break
            end += 1
        else:
            return sites
        # The argument list may follow on the next line when the printer wraps a long call.
        if CALL_ARGUMENTS.match(text, end + 1):
            sites.append(text[at + 1:end])
        at += 2


CALL_ARGUMENTS = re.compile(r"\s*\(")
IDENTIFIER_CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
NUMBER = re.compile(r"^(?:\([A-Za-z_][\w\s\*]*\))*\s*(-?(?:0[xX][0-9a-fA-F]+|[0-9]+))[uUlL]*$")
KEYWORDS = {"if", "while", "for", "switch", "return", "sizeof", "do", "else"}


def split_arguments(text: str, open_at: int) -> list[str] | None:
    """The top-level, comma-separated arguments of the call whose `(` is at `open_at`."""
    depth, start, args, i = 0, open_at + 1, [], open_at
    quote = ""
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = ""
        elif c in "\"'":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                tail = text[start:i].strip()
                if tail or args:
                    args.append(tail)
                return args
        elif c == "," and depth == 1:
            args.append(text[start:i].strip())
            start = i + 1
        i += 1
    return None


def numeric_value(argument: str) -> int | None:
    match = NUMBER.match(argument.strip())
    return int(match.group(1), 0) if match else None


def api_candidates(name: str) -> list[str]:
    """The pack names a printed callee might have: as printed, without its module prefix
    (`kernel32_CreateFileA`), and the same with a leading underscore dropped."""
    out = [name]
    if "_" in name:
        out.append(name.split("_", 1)[1])
    out.extend(n[1:] for n in list(out) if n.startswith("_"))
    return out


def numeric_api_arguments(text: str, enums: dict[str, dict[int, str]]) -> list[tuple[str, int, int, str]]:
    """Non-zero numeric constants at parameters with a `P:` record: [(function, index, value, enum)]."""
    found = []
    for match in IDENTIFIER_CALL.finditer(text):
        name = match.group(1)
        if name in KEYWORDS:
            continue
        function = next((c for c in api_candidates(name) if c in enums), None)
        if function is None:
            continue
        args = split_arguments(text, match.end() - 1)
        if not args:
            continue
        for index, enum in enums[function].items():
            if index < len(args):
                value = numeric_value(args[index])
                if value:
                    found.append((function, index, value, enum))
    return found


def parse_decompile_all(lines) -> dict:
    """Metrics from the NDJSON of `--decompile-all` (an iterable of lines)."""
    # A function that hit a resource limit is reported twice: a `retry_pending` error, then the
    # result of the retry. Only the last record of an address counts.
    last: dict[int, dict] = {}
    for line in lines:
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("type") == "function":
            last[record["address"]] = record
    functions = errors = unknown = indirect = 0
    texts = []
    for address, record in last.items():
        functions += 1
        if record.get("error"):
            errors += 1
            continue
        text = record.get("text") or ""
        texts.append((address, text))
        indirect += len(indirect_call_sites(text))
        for warning in record.get("warnings") or []:
            found = re.search(r"Uncertain calls \((\d+)\)", warning)
            if found:
                unknown += int(found.group(1))
    return {"functions": functions, "errors": errors, "indirect_calls": indirect,
            "unknown_callee_calls": unknown, "texts": texts}


def compare(base: dict, head: dict) -> dict:
    """Per-metric deltas (head - base) of two metric dicts."""
    return {m: head[m] - base[m] for m in METRICS if m in base and m in head}


def check_against_baseline(baseline: dict, head_files: dict) -> tuple[list[str], list[str]]:
    """(failures, improvements): head metrics above, or below, the baseline's, per sample."""
    failures, improvements = [], []
    for name, now in sorted(head_files.items()):
        recorded = baseline.get(name)
        if recorded is None:
            failures.append(f"{name}: not in the baseline (record it with --write-baseline)")
            continue
        for metric in METRICS:
            if metric not in recorded:
                failures.append(f"{name}: {metric} not in the baseline")
            elif now[metric] > recorded[metric]:
                failures.append(f"{name}: {metric} {recorded[metric]} -> {now[metric]}")
            elif now[metric] < recorded[metric]:
                improvements.append(f"{name}: {metric} {recorded[metric]} -> {now[metric]}")
    for name in sorted(set(baseline) - set(head_files)):
        failures.append(f"{name}: in the baseline but not measured")
    return failures, improvements


# --------------------------------------------------------------------------- running


def source_at(tool: dict, path: str) -> bytes:
    """A repository file as the tool's source revision has it: the commit a tool was built from, or
    the one given with `--base-source` / `--head-source`; the checkout otherwise (the working tree,
    or a prebuilt binary with no source revision)."""
    commit = tool.get("source")
    if commit is None and tool.get("rev") not in (None, "working tree"):
        commit = tool["id"]
    if commit is not None:
        return subprocess.run(["git", "show", f"{commit}:{path}"], cwd=ROOT, check=True,
                              capture_output=True).stdout
    return (ROOT / path).read_bytes()


class TypeKnowledge:
    """The Windows packs and allow-list of one tool, read once."""

    def __init__(self, tool: dict):
        self.modules = coverage.allowed_modules(source_at(tool, "binfera/src/decompiler.rs").decode())
        self.names, self.enums = {}, {}
        for arch in ("x86", "x64"):
            pack = source_at(tool, f"binfera-ghidra/data/{coverage.pack_name(arch)}")
            self.names[arch] = coverage.read_function_names(pack)
            self.enums[arch] = coverage.read_enum_parameters(pack)


def image_imports(binary: str, sample: Path) -> tuple[str | None, list]:
    try:
        out = subprocess.run([binary, str(sample), "--image-info", "--json"], capture_output=True,
                             timeout=120, stdin=subprocess.DEVNULL).stdout
        info = json.loads(out)
        return info.get("arch"), info.get("imports") or []
    except Exception:
        return None, []


def measure(binary: str, sample: Path, knowledge: TypeKnowledge, timeout: float) -> dict:
    """All metrics of one sample for one tool."""
    arch, imports = image_imports(binary, sample)
    result = subprocess.run([binary, str(sample), "--decompile-all"], capture_output=True, text=True,
                            timeout=timeout, stdin=subprocess.DEVNULL)
    if result.returncode != 0:
        return {"error": (result.stderr.strip().splitlines() or [f"exit {result.returncode}"])[-1]}
    parsed = parse_decompile_all(result.stdout.splitlines())
    out = {k: parsed[k] for k in ("functions", "errors", "indirect_calls", "unknown_callee_calls")}
    if arch in knowledge.names:
        missing = coverage.untyped_imports(imports, knowledge.names[arch], knowledge.modules)
        out["untyped_imports"] = len(missing)
        out["untyped_import_names"] = sorted(f"{dll}!{function}" for dll, function, _ in missing)
        enums = knowledge.enums[arch]
    else:
        out["untyped_imports"], out["untyped_import_names"], enums = 0, [], {}
    numeric = [hit for _, text in parsed["texts"] for hit in numeric_api_arguments(text, enums)]
    out["numeric_api_args"] = len(numeric)
    by_enum = Counter(f"{function}#{index}={enum}" for function, index, _, enum in numeric)
    out["numeric_api_arg_sites"] = dict(by_enum.most_common(10))
    return out


def cached_measure(tool, knowledge, sample, digest, cache, timeout):
    # Only a result whose sources are a revision is reusable: the checkout changes under a
    # prebuilt binary or a working tree.
    reusable = tool.get("source") is not None or tool.get("rev") not in (None, "working tree")
    key = cache / "quality" / f"{tool['id']}-{(tool.get('source') or '')[:12]}-{digest}-v{CACHE_VERSION}.json"
    if reusable and key.exists():
        return json.loads(key.read_text())
    value = measure(tool["binary"], sample, knowledge, timeout)
    if reusable and "error" not in value:
        key.parent.mkdir(parents=True, exist_ok=True)
        key.write_text(json.dumps(value))
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", help="base revision")
    parser.add_argument("--head", help="head revision [default: the working tree]")
    parser.add_argument("--base-bin", type=Path, help="prebuilt base binary instead of --base")
    parser.add_argument("--head-bin", type=Path, help="prebuilt head binary instead of --head")
    parser.add_argument("--base-source", help="revision whose allow-list and packs the base binary has (for --base-bin)")
    parser.add_argument("--head-source", help="the same for --head-bin")
    parser.add_argument("--samples", type=Path, default=ROOT / "scripts" / "corpus-quality.txt")
    parser.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    parser.add_argument("--timeout", type=float, default=300, help="seconds per file")
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--json", type=Path, help="write the full report here")
    parser.add_argument("--baseline", type=Path, help="checked-in per-sample metrics of the head binary")
    parser.add_argument("--check", action="store_true", help="exit 1 when a head metric is above the baseline")
    parser.add_argument("--write-baseline", type=Path, help="record the head metrics as a baseline here")
    args = parser.parse_args(argv)
    if args.check and not args.baseline:
        parser.error("--check needs --baseline")
    compare_sides = args.base is not None or args.base_bin is not None
    if args.base and args.base_bin:
        parser.error("--base and --base-bin are exclusive")
    if args.head and args.head_bin:
        parser.error("--head and --head-bin are exclusive")
    if not compare_sides and not args.baseline and not args.write_baseline and not args.json:
        parser.error("give a base to compare with, a --baseline, or an output to write")

    cache = args.cache_dir.resolve()
    tools = {"head": resolve_tool(args.head, args.head_bin, cache)}
    if compare_sides:
        tools["base"] = resolve_tool(args.base, args.base_bin, cache)
    for side, revision in (("base", args.base_source), ("head", args.head_source)):
        if revision and side in tools:
            tools[side]["source"] = git("rev-parse", "--verify", f"{revision}^{{commit}}")
    knowledge = {side: TypeKnowledge(tool) for side, tool in tools.items()}

    samples = read_sample_list(args.samples)
    missing = [s for s in samples if not s.is_file()]
    for sample in missing:
        print(f"skipping {sample_key(sample)}: not in the checkout", file=sys.stderr)
    samples = [s for s in samples if s.is_file()]
    digests = {s: sha256_file(s) for s in samples}

    jobs = [(side, sample) for sample in samples for side in tools]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        values = list(pool.map(lambda job: cached_measure(tools[job[0]], knowledge[job[0]], job[1],
                                                          digests[job[1]], cache, args.timeout), jobs))
    results = dict(zip(jobs, values))

    files, errors = {}, []
    totals = {side: Counter() for side in tools}
    for sample in samples:
        name = sample_key(sample)
        entry = {"sha256": digests[sample]}
        for side in tools:
            value = results[(side, sample)]
            entry[side] = value
            if "error" in value:
                errors.append(f"{name} ({side}): {value['error']}")
            else:
                totals[side].update({m: value[m] for m in (*METRICS, "functions")})
        if "base" in tools and all("error" not in entry[s] for s in tools):
            entry["delta"] = compare(entry["base"], entry["head"])
        files[name] = entry
    report = {"samples": str(args.samples),
              "tools": {side: {k: tool[k] for k in ("rev", "binary", "id")} for side, tool in tools.items()},
              "totals": {side: dict(counter) for side, counter in totals.items()},
              "files": files}
    if "base" in tools:
        report["totals"]["delta"] = compare(totals["base"], totals["head"])

    head_metrics = {name: {m: e["head"][m] for m in METRICS} for name, e in files.items() if "error" not in e["head"]}
    status = 0
    if errors:
        print("errors:\n  " + "\n  ".join(errors), file=sys.stderr)
        status = 1
    if args.baseline:
        baseline = json.loads(args.baseline.read_text())["files"]
        failures, improvements = check_against_baseline(baseline, head_metrics)
        report["baseline"] = {"failures": failures, "improvements": improvements}
        for line in improvements:
            print(f"improved: {line}", file=sys.stderr)
        for line in failures:
            print(f"{'REGRESSION' if args.check else 'above the baseline'}: {line}", file=sys.stderr)
        if failures and args.check:
            status = 1
        if improvements and not failures:
            print("a metric is below its baseline: record it with --write-baseline", file=sys.stderr)
    if args.write_baseline:
        args.write_baseline.parent.mkdir(parents=True, exist_ok=True)
        args.write_baseline.write_text(json.dumps(
            {"about": "Per-sample decompiler quality metrics of scripts/bench/quality.py; regenerate with --write-baseline.",
             "files": head_metrics}, indent=1, sort_keys=True) + "\n")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=1) + "\n")
    summary = {side: {m: totals[side][m] for m in METRICS} for side in tools}
    print(json.dumps({"files": len(samples), **summary}), file=sys.stderr)
    return status


if __name__ == "__main__":
    sys.exit(main())
