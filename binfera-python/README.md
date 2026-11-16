# binfera-python

In-process Python binding for [binfera](https://github.com/Karib0u/binfera): detect capabilities in PE/ELF/shellcode/.NET/Mach-O programs, called through the C ABI. No subprocess, no Python at analysis time, nothing reimplemented -- Python calls straight into binfera's own `binfera` analysis code.

Distributed as **`binfera`** wheels, importable as **`binfera`** -- deliberately neither name Mandiant's own PyPI package (`flare-capa`, imported as `capa`) uses, so the two are never confused for one another.

## Install

binfera does not publish to PyPI. Prebuilt `abi3` wheels (one per platform, covering every CPython >= 3.9) are attached to each [GitHub release](https://github.com/Karib0u/binfera/releases); download the one matching your platform and install it directly:

```bash
pip install binfera-<version>-cp38-abi3-<platform>.whl
```

Or build from a source checkout with [maturin](https://www.maturin.rs/):

```bash
pip install maturin
cd binfera-python
maturin develop --release
```

Wheels ship no rules (`capa-rules` is a 4.2 MB, 1,045-file corpus that pinning it into the wheel would fork on every install); point `Rules.from_directory` at a checkout, or fetch the pinned release explicitly:

```python
import binfera

binfera.fetch_rules("rules")  # clones the pinned capa-rules release
```

## Quickstart: load once, scan many

```python
import binfera

rules = binfera.Rules.from_directory("rules")  # parse + validate once

for sample_path in samples:
    try:
        result = binfera.analyze(sample_path, rules)
    except binfera.CapaError as e:
        print(f"{sample_path}: {e}")
        continue
    print(sample_path, sorted(result["rules"].keys()))
```

`analyze()` returns upstream capa's own `ResultDocument` schema as a plain `dict` -- the same shape `binfera -j` prints, and the same shape `capa.render.result_document.ResultDocument.model_validate_json` accepts unmodified, so existing tooling written against Python capa's result documents keeps working.

`jobs=1` reproduces `binfera --jobs 1`'s document byte for byte; omit `jobs` to use all available cores.

## Inspect and decompile

```python
info = binfera.inspect("sample.exe")            # format, arch, sections, imports, exports, details
# info["imports"][0] -> {"dll": ..., "name": ..., "va": ...}

dec = binfera.Decompiler("sample.exe")          # recovers the image once
for address in dec.functions[:5]:
    result = dec.decompile(address)
    print(result["name"], result["incomplete"])
    print(result["text"])                      # C; result["lines"] maps each line to instruction addresses

unit = dec.unit(dec.functions[:3])             # one self-contained C file a compiler accepts

# Every function, streamed: the records `binfera --decompile-all` prints
binfera.decompile_all("sample.exe", on_event=lambda event: ...)
```

- `inspect` reads headers only (PE, ELF, Mach-O, or raw shellcode with `format="sc32"`/`"sc64"`) and is in every build.
- `Decompiler`, `decompile_all` and `binfera.HAS_DECOMPILER` need a build with the native decompiler. The published wheels include it; a source build needs `--features decompiler` and a C++ compiler.
- A `Decompiler` belongs to the thread that created it and holds the GIL while it works; use `decompile_all` or separate processes for parallelism.
- Failures raise the same `binfera.CapaError` family as `analyze`.

## Errors

Every failure raises a typed exception under one `binfera.CapaError` base -- a hard error never becomes `None`, an empty result, or a warning:

| Exception | Meaning |
|---|---|
| `InvalidRuleError` | a rule file failed to parse, or the rule set is invalid (raised by `Rules.from_directory`) |
| `UnsupportedFormatError` | the format could not be auto-detected, or an unknown `format=` value |
| `InvalidSignatureError` | a FLIRT signature file failed to parse |
| `CorruptFileError` | the input could not be parsed or analyzed |

## What this is not

A replacement for capa's internal Python API (`capa.features.*`, `capa.engine`, rule authoring), Python-side extractors, or bindings for any other language. It also does not expose the MCP server or saved projects. See the main repository's architecture and contributor documentation for the supported scope.
