#!/usr/bin/env python3
"""Development-only: how many named PE imports reach the decompiler without a prototype.

usage: coverage.py [--binfera PATH] [--corpus DIR] [--packs DIR] [--top N] [--json FILE]

Runs `binfera FILE --image-info --json` over every PE file directly inside the corpus directory
(default tests/testfiles) and looks each named import up in the matching Windows pack
(`winapi64.pack` for x86-64 images, `winapi32.pack` for x86), the way the decompiler does:

* the exact name, then the name without a leading underscore, then a bare name whose `A` and `W`
  variants both exist (`apply_pack_prototype` in binfera-ghidra/native/bridge.cc);
* only for imports of a module in `system_import_function`'s allow-list
  (binfera/src/decompiler.rs) or an `api-ms-win-*` API set. The list is read from that file.

An import is "untyped" when the lookup fails or its module is not in the list. The report splits
the two causes, per DLL and per API, so a pack gap and an allow-list gap are not confused.
"""
import argparse
import collections
import concurrent.futures as cf
import json
import pathlib
import re
import struct
import subprocess
import sys
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[2]


def read_function_names(path):
    """Every `F:` key of a CXPROTO1 pack (format: pack_prototypes.py)."""
    data = path.read_bytes()
    if data[:8] != b"CXPROTO1":
        raise SystemExit(f"{path}: not a prototype pack")
    count, = struct.unpack_from("<I", data, 8)
    position, blocks = 12, []
    for _ in range(count):
        offset, length, _raw, key_size = struct.unpack_from("<IIIH", data, position)
        position += 14 + key_size
        blocks.append((offset, length))
    names = set()
    for offset, length in blocks:
        raw = zlib.decompress(data[position + offset:position + offset + length])
        for line in raw.split(b"\n"):
            if line.startswith(b"F:"):
                names.add(line[2:].split(b"\t", 1)[0].decode("utf-8", "replace"))
    return names


def allowed_modules():
    source = (ROOT / "binfera/src/decompiler.rs").read_text()
    body = re.search(r"fn system_import_function.*?const MODULES: &\[&str\] = &\[(.*?)\];", source, re.S)
    return set(re.findall(r'"([^"]+)"', body.group(1)))


def lookup(names, function):
    if function in names or (len(function) > 1 and function[0] == "_" and function[1:] in names):
        return True
    return function + "A" in names and function + "W" in names


def module_key(dll):
    dll = dll.lower()
    for suffix in (".dll", ".exe", ".sys"):
        if dll.endswith(suffix):
            return dll[: -len(suffix)]
    return dll


def run(binfera, path):
    try:
        out = subprocess.run([binfera, str(path), "--image-info", "--json"],
                             capture_output=True, timeout=120).stdout
        info = json.loads(out)
        return path.name, info.get("arch"), info.get("imports") or []
    except Exception:
        return path.name, None, None


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binfera", default=str(ROOT / "target/release/binfera"))
    parser.add_argument("--corpus", default=str(ROOT / "tests/testfiles"))
    parser.add_argument("--packs", default=str(ROOT / "binfera-ghidra/data"))
    parser.add_argument("--top", type=int, default=25, help="rows per table")
    parser.add_argument("--json", help="also write the full result to this file")
    args = parser.parse_args()

    packs = {"x64": read_function_names(pathlib.Path(args.packs) / "winapi64.pack"),
             "x86": read_function_names(pathlib.Path(args.packs) / "winapi32.pack")}
    modules = allowed_modules()
    files = sorted(p for p in pathlib.Path(args.corpus).iterdir()
                   if p.is_file() and p.read_bytes()[:2] == b"MZ")

    totals = collections.Counter()
    per_dll = collections.defaultdict(collections.Counter)
    per_api = collections.defaultdict(set)          # (dll, function) -> files, untyped imports
    per_api_cause = {}
    files_seen = 0
    with cf.ThreadPoolExecutor(8) as pool:
        for name, arch, imports in pool.map(lambda p: run(args.binfera, p), files):
            if imports is None or arch not in packs:
                continue
            files_seen += 1
            names = packs[arch]
            for entry in imports:
                function = entry.get("name")
                if not function:
                    continue
                dll = module_key(entry.get("dll") or "")
                api_set = dll.startswith(("api-ms-win-", "api_ms_win_"))
                found = lookup(names, function)
                reachable = dll in modules or api_set
                totals["named"] += 1
                per_dll[dll]["named"] += 1
                if found and reachable:
                    continue
                cause = "no_prototype" if not found else "module_not_listed"
                if not found and function.startswith(("?", "_Z")):
                    # Typed at analysis time from the decoration when every type is a scalar or
                    # pointer (`demangle::Prototype`); no pack holds these.
                    totals["mangled"] += 1
                totals["untyped"] += 1
                totals[cause] += 1
                per_dll[dll]["untyped"] += 1
                per_dll[dll][cause] += 1
                per_api[(dll, function)].add(name)
                per_api_cause[(dll, function)] = cause

    named, untyped = totals["named"], totals["untyped"]
    print(f"PE files {files_seen}, named imports {named}, untyped {untyped} ({100 * untyped / max(named, 1):.1f}%): "
          f"{totals['no_prototype']} without a prototype ({totals['mangled']} of them C++-decorated names, typed at "
          f"analysis time only when the decoration has scalar and pointer types), "
          f"{totals['module_not_listed']} typed but from an unlisted module")
    print("\nby DLL (untyped / named imports)")
    rows = sorted(per_dll.items(), key=lambda kv: -kv[1]["untyped"])[: args.top]
    print(f"{'untyped':>8} {'named':>7} {'share':>6} {'no proto':>9} {'unlisted':>9}  dll")
    for dll, c in rows:
        print(f"{c['untyped']:8d} {c['named']:7d} {100 * c['untyped'] / c['named']:5.1f}% "
              f"{c['no_prototype']:9d} {c['module_not_listed']:9d}  {dll}")
    print("\nby API (files importing it)")
    for key in sorted(per_api, key=lambda k: (-len(per_api[k]), k))[: args.top * 2]:
        print(f"{len(per_api[key]):6d}  {key[0]}!{key[1]}  [{per_api_cause[key]}]")
    if args.json:
        pathlib.Path(args.json).write_text(json.dumps({
            "files": files_seen, "named": named, "untyped": untyped,
            "causes": {k: totals[k] for k in ("no_prototype", "module_not_listed")},
            "dlls": {d: dict(c) for d, c in per_dll.items()},
            "apis": [{"dll": k[0], "name": k[1], "files": len(v), "cause": per_api_cause[k]}
                     for k, v in sorted(per_api.items(), key=lambda kv: -len(kv[1]))],
        }, indent=1))


if __name__ == "__main__":
    sys.exit(main())
