#!/usr/bin/env python3
"""Function-recovery benchmark: compare two commits' function starts, and score them.

    python3 scripts/bench/recovery.py \
        --base origin/main --head HEAD \
        --samples scripts/corpus-smoke.txt --workers 8 \
        --json /tmp/recovery.json --markdown /tmp/recovery.md

`--head` defaults to the working tree, built in place. A revision is built with
`cargo build --release -p binfera-cli --features decompiler` in a temporary git
worktree; the binary is kept under the cache directory, so a commit is built once.
`--base-bin` and `--head-bin` take prebuilt binaries instead.

The inventory of a file is the first record (`start`) of

    binfera FILE --decompile-all --jobs 1 --shard 0/65536 [--start-evidence]

The process is killed as soon as that line is read, so the wall time is the time
to the function list (recovery, not decompilation), and the peak RSS, read with
`os.wait4` as in scripts/bench.py, is the peak up to that point. Results are
cached by the sample's SHA-256 and the tool's identity (the commit, or the
binary's SHA-256 for a working tree or a prebuilt binary). When the base and head
resolve to the same identity, every file runs once.

Three reports come from one run (see docs/roadmap.md, Methodology):

1. Diff. The starts per file, added and removed. The script exits 1 when a start is
   removed, unless the `--allow-removed` file lists it. Each line of that file is
   `<sample path as in --samples> <0xaddress|*>`; `#` starts a comment.
2. Tier B. Truth read from the binary's own tables, which binfera parses and
   reports through the hidden `--start-evidence` flag (seed kinds per address,
   chained x64 unwind fragments, table extents, names): x64/ARM64 `.pdata`
   entries (chains followed to the primary entry), incremental-link thunk
   targets, ELF `.eh_frame` FDEs and `.ARM.exidx`, Mach-O `LC_FUNCTION_STARTS`
   and Go `pclntab`. Recall is truth found over truth. The precision proxy counts
   starts that fall inside a table extent without being a table entry. Funclets
   (MSVC C++ exception targets that have their own `.pdata` row), chained unwind
   fragments and `.cold` parts have table entries but are not functions: they are
   counted in their own columns, never as misses. The truth is binfera's own
   parse, so a table binfera fails to parse is invisible here.
3. Evidence census. For each seed kind: the binaries whose inventory has a start
   carrying it, the starts carrying it, and the starts it alone produced.

A binary built before `--start-evidence` existed still diffs; it just has no
tier-B or census columns.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from time import perf_counter

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from difftest import DEFAULT_SAMPLES_ROOT, read_sample_list  # noqa: E402

RSS_TO_MIB = 1 / (1024 * 1024) if sys.platform == "darwin" else 1 / 1024
DEFAULT_CACHE = ROOT / ".cache" / "recovery-bench"
INVENTORY_ARGS = ["--decompile-all", "--jobs", "1", "--shard", "0/65536"]
# Bump when the cached record's shape changes.
CACHE_VERSION = 1

# Seed kinds that come from a table listing every function the toolchain emitted.
TABLE_SOURCES = {
    "Unwind": "pdata",
    "IncrementalTarget": "ilt",
    "EhFrame": "eh_frame",
    "ArmExidx": "arm_exidx",
    "MachoFunctionStarts": "function_starts",
    "GoFunctionTable": "pclntab",
}
COLD_NAME = re.compile(r"\.cold(\.\d+)?$|\.cold\.")
FRAGMENT_KINDS = ("funclet", "chained", "cold")


# --------------------------------------------------------------------------- pure logic


def parse_start_record(record: dict) -> dict:
    """Normalizes a `start` record: integer addresses, sets of seed kinds."""
    out = {
        "starts": sorted(int(a) for a in record.get("functions", [])),
        "names": {int(a): n for a, n in record.get("names", {}).items()},
        "arch": record.get("arch"),
        "packed": bool(record.get("packed")),
        "evidence": None,
    }
    evidence = record.get("evidence")
    if evidence is not None:
        names = {int(a): n for a, n in evidence.get("names", {}).items()}
        out["evidence"] = {
            "seeds": {int(a): set(kinds) for a, kinds in evidence.get("seeds", {}).items()},
            "chained": {int(a): int(p) for a, p in evidence.get("chained_unwind", {}).items()},
            "regions": {int(a): int(e) for a, e in evidence.get("regions", {}).items()},
            "names": {**names, **out["names"]},
        }
    return out


def diff_starts(base: list[int], head: list[int]) -> tuple[list[int], list[int]]:
    """Returns (added, removed), each sorted."""
    base_set, head_set = set(base), set(head)
    return sorted(head_set - base_set), sorted(base_set - head_set)


def read_allow_removed(text: str) -> dict[str, set]:
    """Parses `<sample> <0xaddress|*>` lines into {sample: {address or "*"}}."""
    allowed: dict[str, set] = defaultdict(set)
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        sample, _, address = line.rpartition(" ")
        sample, address = sample.strip(), address.strip()
        if not sample:
            raise ValueError(f"allow-removed line needs a sample and an address: {raw!r}")
        allowed[sample].add("*" if address == "*" else int(address, 0))
    return dict(allowed)


def split_allowed(sample: str, removed: list[int], allowed: dict[str, set]) -> tuple[list, list]:
    """Returns (blocking, allowed) removed starts for one sample."""
    entries = allowed.get(sample, set())
    if "*" in entries:
        return [], list(removed)
    return [a for a in removed if a not in entries], [a for a in removed if a in entries]


def tier_b_truth(evidence: dict) -> tuple[dict[int, set], dict[int, str]]:
    """Returns ({truth address: sources}, {fragment address: category}).

    Funclets (MSVC exception targets), chained x64 unwind fragments and `.cold`
    parts have table entries but are not functions, so they become fragments.
    A chained fragment's primary entry is truth from `.pdata`.
    """
    truth: dict[int, set] = defaultdict(set)
    for address, kinds in evidence["seeds"].items():
        for kind in kinds:
            if kind in TABLE_SOURCES:
                truth[address].add(TABLE_SOURCES[kind])
    for primary in evidence["chained"].values():
        truth[primary].add("pdata")
    fragments: dict[int, str] = {}
    for address in evidence["chained"]:
        if address not in truth:
            fragments[address] = "chained"
    for address in list(truth):
        kinds = evidence["seeds"].get(address, set())
        name = evidence["names"].get(address, "")
        if COLD_NAME.search(name):
            fragments[address] = "cold"
        elif "MsvcException" in kinds and truth[address] <= {"pdata"}:
            # A funclet only has its own unwind row; an exception target that a
            # second table also names is a real function.
            fragments[address] = "funclet"
        else:
            continue
        del truth[address]
    return dict(truth), fragments


def covering_region(regions: list[tuple[int, int]], address: int) -> tuple[int, int] | None:
    """The extent containing `address`, from regions sorted by start (binary search)."""
    lo, hi = 0, len(regions)
    while lo < hi:
        mid = (lo + hi) // 2
        if regions[mid][0] <= address:
            lo = mid + 1
        else:
            hi = mid
    # Extents can nest (a funclet inside its parent's row), so look back a little.
    for index in range(lo - 1, max(lo - 9, -1), -1):
        start, end = regions[index]
        if start <= address < end:
            return start, end
    return None


def score_tier_b(starts: list[int], evidence: dict) -> dict:
    """Scores one file's starts against its tier-B truth."""
    truth, fragments = tier_b_truth(evidence)
    listed = set(starts)
    by_source: dict[str, dict[str, int]] = defaultdict(lambda: {"truth": 0, "found": 0})
    for address, sources in truth.items():
        for source in sources:
            by_source[source]["truth"] += 1
            by_source[source]["found"] += address in listed
    missed = sorted(a for a in truth if a not in listed)
    fragment_counts = {
        kind: {
            "total": sum(1 for c in fragments.values() if c == kind),
            "listed": sum(1 for a, c in fragments.items() if c == kind and a in listed),
        }
        for kind in FRAGMENT_KINDS
    }
    regions = sorted(evidence["regions"].items())
    in_regions = 0
    interior = []
    for address in starts:
        if covering_region(regions, address) is None:
            continue
        in_regions += 1
        if address not in truth and address not in fragments:
            interior.append(address)
    return {
        "truth": len(truth),
        "found": len(truth) - len(missed),
        "missed": missed,
        "sources": {k: dict(v) for k, v in sorted(by_source.items())},
        "fragments": fragment_counts,
        "starts_in_regions": in_regions,
        "interior": interior,
    }


def ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def aggregate_tier_b(files: list[tuple[str, str, dict]]) -> dict[str, dict]:
    """Sums per-file scores, `files` being (format, arch, score), per format/arch and overall."""
    groups: dict[str, dict] = {}

    def bucket(key: str) -> dict:
        return groups.setdefault(
            key,
            {
                "files": 0,
                "truth": 0,
                "found": 0,
                "sources": defaultdict(lambda: {"truth": 0, "found": 0}),
                "fragments": {k: {"total": 0, "listed": 0} for k in FRAGMENT_KINDS},
                "starts_in_regions": 0,
                "interior": 0,
            },
        )

    for fmt, arch, score in files:
        if not score["truth"]:
            continue
        for key in (f"{fmt} {arch}", "all"):
            group = bucket(key)
            group["files"] += 1
            group["truth"] += score["truth"]
            group["found"] += score["found"]
            for source, counts in score["sources"].items():
                group["sources"][source]["truth"] += counts["truth"]
                group["sources"][source]["found"] += counts["found"]
            for kind, counts in score["fragments"].items():
                group["fragments"][kind]["total"] += counts["total"]
                group["fragments"][kind]["listed"] += counts["listed"]
            group["starts_in_regions"] += score["starts_in_regions"]
            group["interior"] += len(score["interior"])
    for group in groups.values():
        group["sources"] = {k: dict(v) for k, v in sorted(group["sources"].items())}
        group["recall"] = ratio(group["found"], group["truth"])
        group["precision_proxy"] = (
            1 - ratio(group["interior"], group["starts_in_regions"])
            if group["starts_in_regions"]
            else None
        )
    return dict(sorted(groups.items(), key=lambda kv: (kv[0] == "all", kv[0])))


def census(files: list[tuple[list[int], dict]]) -> dict[str, dict]:
    """Per seed kind: binaries, seeded addresses, listed starts, starts it alone produced.

    `files` holds (starts, evidence). A start with no seed counts under `(none)`:
    recovery reached it by following code.
    """
    table: dict[str, Counter] = defaultdict(Counter)
    for starts, evidence in files:
        seeds = evidence["seeds"]
        present = set()
        for kinds in seeds.values():
            for kind in kinds:
                table[kind]["seeded"] += 1
        for address in starts:
            kinds = seeds.get(address) or {"(none)"}
            for kind in kinds:
                table[kind]["listed"] += 1
                present.add(kind)
            if len(kinds) == 1:
                table[next(iter(kinds))]["only"] += 1
        for kind in present:
            table[kind]["binaries"] += 1
    return {
        kind: {k: counts[k] for k in ("binaries", "seeded", "listed", "only")}
        for kind, counts in sorted(table.items(), key=lambda kv: (-kv[1]["only"], kv[0]))
    }


def sniff_format(head: bytes) -> str:
    if head[:4] == b"\x7fELF":
        return "ELF"
    if head[:2] == b"MZ":
        return "PE"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        return "Mach-O"
    if head[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        return "Mach-O"
    return "other"


# --------------------------------------------------------------------------- running


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(*args: str, cwd: Path = ROOT) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def cargo_build(source: Path, target_dir: Path | None) -> Path:
    env = dict(os.environ)
    if target_dir is not None:
        env["CARGO_TARGET_DIR"] = str(target_dir)
    subprocess.run(
        ["cargo", "build", "--release", "-p", "binfera-cli", "--features", "decompiler"],
        cwd=source,
        env=env,
        check=True,
    )
    return (target_dir or source / "target") / "release" / "binfera"


def build_revision(rev: str, cache: Path) -> tuple[Path, str]:
    """Builds `rev` in a temporary worktree; returns (binary, tool id = commit)."""
    commit = git("rev-parse", "--verify", f"{rev}^{{commit}}")
    kept = cache / "builds" / commit / "binfera"
    if kept.exists():
        return kept, commit
    scratch = Path(tempfile.mkdtemp(prefix=f"recovery-bench-{commit[:12]}-"))
    tree = scratch / "src"
    git("worktree", "add", "--detach", str(tree), commit)
    try:
        print(f"building {rev} ({commit[:12]})", file=sys.stderr)
        built = cargo_build(tree, cache / "target")
        kept.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(built, kept)
    finally:
        git("worktree", "remove", "--force", str(tree))
        shutil.rmtree(scratch, ignore_errors=True)
    return kept, commit


def build_working_tree() -> tuple[Path, str]:
    """Builds the checkout in place; the id covers uncommitted changes."""
    binary = cargo_build(ROOT, None)
    head = git("rev-parse", "HEAD")
    status = git("status", "--porcelain", "--untracked-files=no", "--ignore-submodules")
    if not status:
        return binary, head
    return binary, f"{head}-dirty-{sha256_file(binary)[:16]}"


def resolve_tool(rev: str | None, prebuilt: Path | None, cache: Path) -> dict:
    if prebuilt is not None:
        binary = prebuilt.resolve()
        return {"rev": None, "binary": str(binary), "id": f"bin-{sha256_file(binary)[:16]}"}
    if rev is None:
        binary, tool_id = build_working_tree()
        return {"rev": "working tree", "binary": str(binary), "id": tool_id}
    binary, tool_id = build_revision(rev, cache)
    return {"rev": rev, "binary": str(binary), "id": tool_id}


def supports_evidence(binary: str) -> bool:
    """`--start-evidence` exists from the benchmark's first version; older binaries reject it."""
    probe = subprocess.run(
        [binary, "--decompile-all", "--start-evidence", "/nonexistent-recovery-bench-probe"],
        capture_output=True,
        text=True,
    )
    return "--start-evidence" not in probe.stderr


def run_inventory(binary: str, sample: Path, timeout: float, evidence: bool) -> dict:
    """Runs one inventory; returns the parsed start record, wall seconds and peak RSS."""
    args = [binary, str(sample), *INVENTORY_ARGS] + (["--start-evidence"] if evidence else [])
    with tempfile.TemporaryFile() as stderr:
        started = perf_counter()
        proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=stderr)
        line, timed_out = bytearray(), False
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while b"\n" not in line:
                remaining = started + timeout - perf_counter()
                if remaining <= 0:
                    timed_out = True
                    break
                if not selector.select(remaining):
                    continue
                chunk = os.read(proc.stdout.fileno(), 1 << 20)
                if not chunk:
                    break
                line += chunk
        wall = perf_counter() - started
        # Not `proc.poll()` or `proc.kill()`: they can reap the child, and then
        # `wait4` has no rusage to return. An exited, unreaped child ignores the kill.
        os.kill(proc.pid, signal.SIGKILL)
        _, status, usage = os.wait4(proc.pid, 0)
        proc.returncode = status
        proc.stdout.close()
        stderr.seek(0)
        err = stderr.read().decode(errors="replace")
    result = {"wall": round(wall, 3), "rss_mib": round(usage.ru_maxrss * RSS_TO_MIB, 1)}
    if timed_out:
        return {**result, "error": f"timeout after {timeout:g}s"}
    first = bytes(line).split(b"\n", 1)[0]
    try:
        record = json.loads(first)
    except json.JSONDecodeError:
        return {**result, "error": (err.strip() or "no start record")[-400:]}
    if record.get("type") != "start":
        return {**result, "error": f"first record is {record.get('type')!r}, not start"}
    return {**result, "record": record}


def cached_inventory(
    tool: dict, sample: Path, digest: str, cache: Path, timeout: float, evidence: bool
) -> dict:
    path = cache / "inventory" / tool["id"] / f"{digest}.json"
    if path.exists():
        stored = json.loads(path.read_text())
        if stored.get("version") == CACHE_VERSION and stored.get("evidence") == evidence:
            return {**stored["result"], "cached": True}
    result = run_inventory(tool["binary"], sample, timeout, evidence)
    if not str(result.get("error", "")).startswith("timeout"):
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps({"version": CACHE_VERSION, "evidence": evidence, "result": result})
        )
        tmp.replace(path)
    return result


def sample_key(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(DEFAULT_SAMPLES_ROOT.resolve()))
    except ValueError:
        return str(path)


def side_summary(result: dict) -> tuple[dict, dict | None]:
    """Returns (JSON for one side of a file, parsed record or None)."""
    out = {"wall": result["wall"], "rss_mib": result["rss_mib"], "cached": result.get("cached", False)}
    if "error" in result:
        return {**out, "error": result["error"]}, None
    parsed = parse_start_record(result["record"])
    return {**out, "count": len(parsed["starts"]), "starts": [hex(a) for a in parsed["starts"]]}, parsed


def evidence_reports(rows: list[tuple[str, str, dict]]) -> dict:
    """Tier-B scores and census for one side; rows are (sample, format, parsed)."""
    scored, census_input, per_file = [], [], {}
    for sample, fmt, parsed in rows:
        evidence = parsed["evidence"]
        if evidence is None:
            continue
        score = score_tier_b(parsed["starts"], evidence)
        arch = parsed["arch"] or "?"
        if parsed["packed"]:
            # A packer's tables describe code that is not there yet.
            arch += " packed"
        scored.append((fmt, arch, score))
        census_input.append((parsed["starts"], evidence))
        per_file[sample] = {
            **{k: v for k, v in score.items() if k not in ("missed", "interior")},
            "recall": ratio(score["found"], score["truth"]),
            "missed": [hex(a) for a in score["missed"]],
            "interior": {
                hex(a): sorted(evidence["seeds"].get(a, ())) for a in score["interior"]
            },
        }
    if not scored:
        return {}
    return {"files": per_file, "groups": aggregate_tier_b(scored), "census": census(census_input)}


def pct(value: float | None) -> str:
    return "-" if value is None else f"{100 * value:.2f}%"


def short_id(tool: dict) -> str:
    return tool["id"][:12] + (" with uncommitted changes" if "-dirty-" in tool["id"] else "")


def render_markdown(report: dict) -> str:
    lines = []
    base, head = report["base"], report["head"]
    totals = report["totals"]
    lines += [
        "# Function recovery benchmark",
        "",
        f"Base: `{base['rev'] or base['binary']}` ({short_id(base)}). "
        f"Head: `{head['rev'] or head['binary']}` ({short_id(head)}). "
        f"{totals['files']} files from `{report['samples']}`.",
        "",
        "## Diff",
        "",
        "| | Base | Head |",
        "|---|---:|---:|",
        f"| Starts | {totals['base_starts']:,} | {totals['head_starts']:,} |",
        f"| Errors | {totals['base_errors']} | {totals['head_errors']} |",
        f"| Wall, sum (s) | {totals['base_wall']:.1f} | {totals['head_wall']:.1f} |",
        f"| Peak RSS, max (MiB) | {totals['base_rss_max']:.0f} | {totals['head_rss_max']:.0f} |",
        "",
        f"Added: {totals['added']:,}. Removed: {totals['removed']:,} "
        f"({totals['removed_allowed']:,} allowed, **{totals['removed_blocking']:,} blocking**).",
        "",
    ]
    changed = [
        (name, f) for name, f in report["files"].items() if f.get("added") or f.get("removed")
    ]
    changed.sort(key=lambda kv: -(len(kv[1]["added"]) + len(kv[1]["removed"])))
    if changed:
        lines += ["| File | Added | Removed |", "|---|---:|---:|"]
        for name, f in changed[:20]:
            lines.append(f"| `{name}` | {len(f['added'])} | {len(f['removed'])} |")
        lines.append("")
    errors = [(n, f) for n, f in report["files"].items() if "error" in f["head"] or "error" in f["base"]]
    if errors:
        lines += ["Errors:", ""]
        for name, f in errors:
            err = f["head"].get("error") or f["base"].get("error")
            lines.append(f"- `{name}`: {err.splitlines()[-1] if err else ''}")
        lines.append("")
    for side in ("head", "base"):
        if side == "base" and base["id"] == head["id"]:
            continue
        evidence = report["evidence"].get(side)
        if not evidence:
            lines += [f"No evidence for {side}: its binary has no `--start-evidence`.", ""]
            continue
        lines += [
            f"## Tier B ({side})",
            "",
            "Recall is table entries listed as starts over table entries. Fragments are table "
            "entries that are not functions, shown as total/listed. Interior starts lie inside a "
            "table extent without being an entry.",
            "",
            "| Group | Files | Truth | Recall | By source | Funclets | Chained | Cold | Interior | Precision proxy |",
            "|---|---:|---:|---:|---|---:|---:|---:|---:|---:|",
        ]
        for key, g in evidence["groups"].items():
            sources = ", ".join(
                f"{s} {pct(ratio(c['found'], c['truth']))} of {c['truth']:,}"
                for s, c in g["sources"].items()
            )
            frag = g["fragments"]
            lines.append(
                f"| {'**all**' if key == 'all' else key} | {g['files']} | {g['truth']:,} | "
                f"{pct(g['recall'])} | {sources} | "
                + " | ".join(f"{frag[k]['total']}/{frag[k]['listed']}" for k in FRAGMENT_KINDS)
                + f" | {g['interior']:,} of {g['starts_in_regions']:,} | {pct(g['precision_proxy'])} |"
            )
        worst = sorted(
            ((n, f) for n, f in evidence["files"].items() if f["truth"] and f["missed"]),
            key=lambda kv: -len(kv[1]["missed"]),
        )
        if worst:
            lines += ["", "Most truth missed:", "", "| File | Truth | Missed | Recall |", "|---|---:|---:|---:|"]
            for name, f in worst[:15]:
                lines.append(f"| `{name}` | {f['truth']:,} | {len(f['missed']):,} | {pct(f['recall'])} |")
        interior_kinds = Counter(
            "+".join(kinds) or "(none)"
            for f in evidence["files"].values()
            for kinds in f["interior"].values()
        )
        if interior_kinds:
            lines += ["", "Interior starts by evidence:", "", "| Evidence | Starts |", "|---|---:|"]
            for kinds, count in interior_kinds.most_common(15):
                lines.append(f"| {kinds} | {count:,} |")
        lines += [
            "",
            f"## Evidence census ({side})",
            "",
            "Binaries: files whose inventory has a start with this evidence. Seeded: addresses "
            "recovery seeded with it. Listed: inventory starts carrying it. Only: starts it alone "
            "produced.",
            "",
            "| Evidence | Binaries | Seeded | Listed | Only |",
            "|---|---:|---:|---:|---:|",
        ]
        for kind, c in evidence["census"].items():
            lines.append(f"| {kind} | {c['binaries']} | {c['seeded']:,} | {c['listed']:,} | {c['only']:,} |")
        lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--base", help="base revision (any git rev)")
    parser.add_argument("--head", help="head revision [default: the working tree]")
    parser.add_argument("--base-bin", type=Path, help="prebuilt base binary instead of --base")
    parser.add_argument("--head-bin", type=Path, help="prebuilt head binary instead of --head")
    parser.add_argument("--samples", type=Path, default=ROOT / "scripts" / "corpus-smoke.txt")
    parser.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    parser.add_argument("--timeout", type=float, default=300, help="seconds per file")
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--allow-removed", type=Path, help="removed starts that do not fail the run")
    parser.add_argument("--json", type=Path, help="write the full report here")
    parser.add_argument(
        "--markdown", type=Path, nargs="?", const=Path("-"), help="write the summary here (- for stdout)"
    )
    parser.add_argument("--no-evidence", action="store_true", help="skip tier B and the census")
    args = parser.parse_args(argv)
    if args.base is None and args.base_bin is None:
        parser.error("one of --base and --base-bin is required")
    if args.base and args.base_bin:
        parser.error("--base and --base-bin are exclusive")
    if args.head and args.head_bin:
        parser.error("--head and --head-bin are exclusive")

    cache = args.cache_dir.resolve()
    base = resolve_tool(args.base, args.base_bin, cache)
    head = resolve_tool(args.head, args.head_bin, cache)
    for tool in (base, head):
        tool["evidence"] = not args.no_evidence and supports_evidence(tool["binary"])
    allowed = read_allow_removed(args.allow_removed.read_text()) if args.allow_removed else {}

    samples = read_sample_list(args.samples)
    missing = [s for s in samples if not s.is_file()]
    if missing:
        print(f"{len(missing)} samples missing, e.g. {missing[0]}", file=sys.stderr)
        samples = [s for s in samples if s.is_file()]
    info = {}
    for sample in samples:
        with sample.open("rb") as handle:
            fmt = sniff_format(handle.read(4))
        info[sample] = (sample_key(sample), sha256_file(sample), fmt)

    tools = {"base": base} if base["id"] == head["id"] else {"base": base, "head": head}
    jobs = [(side, sample) for sample in samples for side in tools]
    results: dict[tuple[str, Path], dict] = {}
    done = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(
                cached_inventory, tools[side], sample, info[sample][1], cache, args.timeout,
                tools[side]["evidence"],
            ): (side, sample)
            for side, sample in jobs
        }
        for future in as_completed(futures):
            side, sample = futures[future]
            results[(side, sample)] = future.result()
            done += 1
            r = results[(side, sample)]
            status = r.get("error", "").splitlines()[-1:] or [f"{r['wall']:.1f}s"]
            print(f"[{done}/{len(jobs)}] {side} {info[sample][0]}: {status[0]}", file=sys.stderr)
    if "head" not in tools:
        for sample in samples:
            results[("head", sample)] = results[("base", sample)]

    files, rows = {}, {"base": [], "head": []}
    totals = Counter()
    rss_max = {"base": 0.0, "head": 0.0}
    for sample in samples:
        name, digest, fmt = info[sample]
        entry = {"sha256": digest, "format": fmt}
        parsed = {}
        for side in ("base", "head"):
            result = results[(side, sample)]
            entry[side], parsed[side] = side_summary(result)
            totals[f"{side}_wall"] += result["wall"]
            rss_max[side] = max(rss_max[side], result["rss_mib"])
            if parsed[side] is None:
                totals[f"{side}_errors"] += 1
            else:
                totals[f"{side}_starts"] += len(parsed[side]["starts"])
                rows[side].append((name, fmt, parsed[side]))
        if parsed["head"]:
            entry["arch"] = parsed["head"]["arch"]
            entry["packed"] = parsed["head"]["packed"]
        if parsed["base"] or parsed["head"]:
            added, removed = diff_starts(
                parsed["base"]["starts"] if parsed["base"] else [],
                parsed["head"]["starts"] if parsed["head"] else [],
            )
            blocking, allowed_here = split_allowed(name, removed, allowed)
            entry["added"] = [hex(a) for a in added]
            entry["removed"] = [hex(a) for a in removed]
            entry["removed_blocking"] = [hex(a) for a in blocking]
            totals["added"] += len(added)
            totals["removed"] += len(removed)
            totals["removed_blocking"] += len(blocking)
            totals["removed_allowed"] += len(allowed_here)
        files[name] = entry

    summary = {
        "files": len(samples),
        **{k: totals[k] for k in ("base_starts", "head_starts", "base_errors", "head_errors",
                                  "added", "removed", "removed_blocking", "removed_allowed")},
        "base_wall": round(totals["base_wall"], 1),
        "head_wall": round(totals["head_wall"], 1),
        "base_rss_max": rss_max["base"],
        "head_rss_max": rss_max["head"],
    }
    report = {
        "samples": str(args.samples),
        "base": base,
        "head": head,
        "totals": summary,
        "files": files,
        "evidence": {
            side: evidence_reports(rows[side])
            for side in (("base",) if base["id"] == head["id"] else ("base", "head"))
        },
    }
    if base["id"] == head["id"]:
        report["evidence"]["head"] = report["evidence"]["base"]

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=1) + "\n")
    if args.markdown:
        text = render_markdown(report)
        if str(args.markdown) == "-":
            sys.stdout.write(text)
        else:
            args.markdown.parent.mkdir(parents=True, exist_ok=True)
            args.markdown.write_text(text)
    print(
        f"{summary['files']} files: +{summary['added']} -{summary['removed']} "
        f"({summary['removed_blocking']} blocking)",
        file=sys.stderr,
    )
    return 1 if summary["removed_blocking"] else 0


if __name__ == "__main__":
    sys.exit(main())
