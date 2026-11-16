#!/usr/bin/env python3
"""Score `binfera diff` function matching against ground truth from symbols.

Each source file is built twice with a change between the builds, and the *stripped* copies are
compared, so names cannot help. The unstripped copies say which pair is right: BinDiff and Diaphora
are heuristics too, and can only be a baseline, not an oracle.

    python3 -I scripts/diff_eval/eval.py target/release/binfera [--min-f1 0.6]

Only our own builds of our own sources are read, and nothing is run. Needs clang and a host whose
symbol table survives `strip -x` at the same addresses (macOS and Linux both do).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent
SOURCES = sorted((ROOT / "src").glob("*.c"))
EXTRA_FLAGS: list[str] = []

# name, flags for A, flags for B. Same-flag pairs test what an analyst usually has (a patched
# variant); the others are harder, since the compiler rewrites and inlines.
SCENARIOS = [
    ("same build", ["-O1"], ["-O1"]),
    ("patched source", ["-O1"], ["-O1", "-DVARIANT"]),
    ("patched source -O2", ["-O2"], ["-O2", "-DVARIANT"]),
    ("O1 vs O2", ["-O1"], ["-O2"]),
    ("O2 vs Os", ["-O2"], ["-Os"]),
    ("O0 vs O1", ["-O0"], ["-O1"]),
]


def build(flags: list[str], out: pathlib.Path) -> pathlib.Path:
    # Inlining is left on: the point is what a real build does.
    subprocess.run(
        ["clang", *EXTRA_FLAGS, *flags, "-fno-stack-protector", "-w", "-o", out, *SOURCES],
        check=True,
    )
    stripped = out.with_name(out.name + ".stripped")
    shutil.copy(out, stripped)
    subprocess.run(["strip", "-x", stripped], check=True)
    return stripped


def names(binary: str, path: pathlib.Path) -> dict[int, str]:
    lines = subprocess.run(
        [binary, "fingerprint", "--no-detail", path], check=True, capture_output=True, text=True
    ).stdout.splitlines()
    found = {}
    for line in lines:
        record = json.loads(line)
        if record.get("record") == "function" and record.get("name"):
            found[record["address"]] = record["name"].lstrip("_")
    return found


def score(binary: str, flags_a, flags_b, work: pathlib.Path):
    a, b = work / "a", work / "b"
    strip_a, strip_b = build(flags_a, a), build(flags_b, b)
    truth_a, truth_b = names(binary, a), names(binary, b)
    done = subprocess.run(
        [binary, "diff", "--no-capabilities", "--json", strip_a, strip_b],
        capture_output=True,
        text=True,
    )
    if done.returncode not in (0, 1):
        raise SystemExit(done.stderr)
    document = json.loads(done.stdout)
    right = wrong = 0
    errors = []
    for match in document["matches"]:
        left, other = truth_a.get(match["a_addr"]), truth_b.get(match["b_addr"])
        if left is None or other is None:
            continue
        if left == other:
            right += 1
        else:
            wrong += 1
            errors.append(f"{left} -> {other} ({match['method']})")
    common = len(set(truth_a.values()) & set(truth_b.values()))
    precision = right / (right + wrong) if right + wrong else 1.0
    recall = right / common if common else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    changed = sum(match["changed"] for match in document["matches"])
    return precision, recall, f1, changed, common, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("binary")
    parser.add_argument("--min-f1", type=float, default=0.0)
    parser.add_argument("--show-errors", action="store_true")
    parser.add_argument("--cflag", action="append", default=[], help="extra compiler flag")
    args = parser.parse_args()
    binary = str(pathlib.Path(args.binary).resolve())
    EXTRA_FLAGS.extend(args.cflag)
    failed = False
    print(f"{'scenario':<22}{'precision':>10}{'recall':>8}{'f1':>7}{'changed':>9}{'common':>8}")
    with tempfile.TemporaryDirectory() as temp:
        for name, flags_a, flags_b in SCENARIOS:
            precision, recall, f1, changed, common, errors = score(
                binary, flags_a, flags_b, pathlib.Path(temp)
            )
            print(f"{name:<22}{precision:>10.3f}{recall:>8.3f}{f1:>7.3f}{changed:>9}{common:>8}")
            if args.show_errors:
                for error in errors:
                    print(f"    {error}")
            failed = failed or f1 < args.min_f1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
