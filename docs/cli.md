# Command line

`binfera` is a plain command-line tool: no server, no network. Output is JSON with `-j`, and the exit status says what happened, so it fits a shell script or a CI job. For the AI agent server, see [Binfera MCP server](mcp.md).

![binfera in a terminal: the capability report for WannaCry, one function decompiled to C, then all 134 functions decompiled](images/cli.gif)

## Recipes

```sh
# What can this file do? One capability per line.
binfera sample.exe -j -q | jq -r '.rules | keys[]'

# Fail the build if a binary gains a capability you do not expect.
binfera build/app.exe -j -q | jq -e '.rules | has("create service") | not' >/dev/null

# What changed between two builds? Exits 1 when they differ, 0 when they do not.
binfera diff old.exe new.exe -j > diff.json
jq '{verdict, similarity: .similarity.overall, added: [.capability_delta.added[].name]}' diff.json

# Keep a small baseline instead of the old binary, and compare against it later.
binfera fingerprint release-1.0.exe > release-1.0.fp
binfera diff release-1.0.fp new.exe

# Decompile one function as JSON (needs a build with the decompiler).
binfera sample.exe --decompile-function 0x140001000 --json

# Decompile every function, one JSON object per line, using four worker processes.
binfera sample.exe --decompile-all --jobs 4
```

## Code Origin

```bash
binfera family info --json
binfera family match sample.exe --json
binfera family match --pack /path/to/custom.bxfam sample.exe
binfera family match --pack base.bxfam --pack my-org-trusted.bxfam sample.exe
```

Both commands look for packs in this order:

1. The paths passed with `--pack`
2. The existing files listed in `BINFERA_FAMILY_PACKS`, or else in `BINFERA_FAMILY_PACK`. Either holds one path or a path list (`:`-separated on macOS and Linux, `;` on Windows).
3. `family.bxfam` in the [user data directory](mcp.md#what-is-stored)
4. `family.bxfam` beside the executable

`family info` reads one pack's header: the format (`BXFAM002` or `BXFAM003`), counts, and LSH configuration. For `BXFAM003` it also reports the trusted symbol, trusted string, and exclusive malware string counts. The format has no build metadata. `family match` loads the fingerprint tables and reports trusted, malware-family, shared and unique functions. The desktop app also checks these default locations and lets you select a local pack from the **Code origin** card.

`family match` layers several packs, base first. A function or string that any pack trusts is Trusted, so an organization's Trusted overlay silences false positives from the base pack. Trusted names come from the last pack that has one. A malware family matched by several packs counts each function once, and each match records its `pack_name`.

`BXFAM003` packs can add two optional sections, and `BXFAM002` packs stay readable:

- **Trusted symbols:** names for Trusted functions, reported as `trusted_symbols`.
- **String Reuse:** a Trusted string filter and an index of strings exclusive to up to three malware families. `family match` extracts ASCII and UTF-16LE strings, normalizes them (whitespace collapsed, at least 8 characters, no pure hex, numbers, UUIDs, boilerplate or common Win32 API names), and reports them under `strings` as malware, shared, unique or trusted.

String Reuse is supporting evidence only. It never adds, removes or rescores a code family. When code attribution abstains and at least three distinct exclusive malware strings name one family more than any other, the report adds `string_only_hint`, a lead to verify rather than a verdict.

The web and desktop apps show the same data. **Add overlay pack…** in the **Code origin** card layers another pack over the active ones, shown as removable chips with each pack's format and size, and matching runs again whenever a pack is added or removed. In the browser, packs stay in the tab and are never uploaded. A Trusted function with no analyst name, file symbol, signature name or export is labeled with its pack symbol and a **Trusted** tag. With `BXFAM003` string data, the card adds a **String reuse** section and the Strings view gets origin filters and **Hide trusted**. A `string_only_hint` is shown as a low-confidence hint, never as a match. With `BXFAM002` packs, none of the string or symbol UI appears. Reports and the JSON export include the string summary and the pack-derived names.

## Input formats

PE and ELF inputs use recovered code scopes with FLIRT library-function exclusion. Raw x86/x64 shellcode (`-f sc32` or `-f sc64`) uses no FLIRT signatures. Capability results place it at capa's [shellcode base address](https://github.com/Karib0u/binfera/blob/main/binfera/src/extract/loader/image.rs), `0x690000`, so addresses match Python capa; decompilation and emulation map it at zero, so their addresses are offsets in the file. Freeze files are also accepted.

Managed PE inputs are automatically routed to `dotnet` before native PE detection. They use CIL decoding without FLIRT. Mixed-mode assemblies expose only their managed methods; there is no cross-runtime call graph into the native code. Use `-f pe` to force native extraction. Native PE supports x86/x64 and ARM64, plus ARM32/Thumb (see [Decompiler](decompiler.md#windows-pe)).

Mach-O is detected automatically (or forced with `-f macho`), for thin or universal x86_64, arm64 and arm64e files. Use `--arch` to select a universal slice.

## Exit status

| Status | Meaning |
|---|---|
| `0` | Done (for `diff`: nothing differs) |
| `1` | `diff` only: the two inputs differ |
| `11` | Input file does not exist |
| `12` | Invalid rule |
| `13` | Corrupt or unreadable file |
| `14` | File refused as too large (see `--max-instructions`) |
| `15` | Invalid signature file (`-s`) |
| `16` | Format not recognized (pass `-f` for raw shellcode) |

## Useful flags

| Flag | What it does |
|---|---|
| `-j`, `--json` | JSON instead of text |
| `-q`, `--quiet` | Errors only |
| `-r`, `--rules <DIR>` | Rules to use. Default: `BINFERA_RULES_DIR`, then `./rules`, then `rules/` beside the executable, then the rules built into the binary |
| `-t`, `--tag <TAG>` | Filter rules by a meta field value |
| `-f`, `--format <FORMAT>` | `auto`, `pe`, `elf`, `macho`, `dotnet`, `sc32`, `sc64` (raw shellcode), `freeze` |
| `--os <OS>`, `--arch <ARCH>` | Override detection |
| `--jobs <N>` | Threads for rules and matching; with `--decompile-all`, worker processes |
| `--max-instructions <N>` | Refuse a file once recovery has decoded N instructions (exit status 14) |
| `--timing` | Per-phase timings on stderr and `timings` in decompiler JSON |
| `--no-resource-retry` | With `--decompile-all`, emit resource-limited records without automatically retrying them |
| `--resource-retry` | With `--decompile-function`, use the longer retry limits |

`binfera --help` and `binfera diff --help` list the rest. Python users can call the same engine (capability analysis, diff, image inspection and decompilation) through [`binfera-python`](https://github.com/Karib0u/binfera/tree/main/binfera-python/). The decompiler's scope and limits are in [Decompiler](decompiler.md), its API in [Decompiler design](decompiler-design.md).

## Decompilation stream

`--decompile-all` emits NDJSON in this order:

1. `start`: sorted `functions`, optional `names` (decimal address keys to supplied names), optional `resolved` (decimal addresses of globals the program fills with `GetProcAddress` and a literal name, to the API each holds), architecture, packing and warnings.
2. `function`: text when available, assembly, graph, calls and data references. A resource-limited attempt retains its name and supporting data and sets `retry_pending: true`.
3. `settled`: all ordinary attempts have finished. Consumers can build indexes and enable reports now.
4. Deferred retry results, followed by `done`. A later record replaces an earlier record for the same address. Retries can discover additional callees after `settled`.

The default retry policy is deferred, capped at 16 resource retries per image. With `--jobs N`, ordinary workers finish first, then up to N retry processes run concurrently using the same recovery snapshot. The longer limits are 60 seconds per phase (at most 120 seconds overall), 100,000 instructions and 200,000,000 work units. `--no-resource-retry` leaves the pending records in the completed stream. An explicit `--decompile-function ADDRESS --resource-retry --json` retries one function with these limits and includes line mappings and stack symbols.

Records carry `ms` by default; `timings` needs `--timing`. Older streams without `settled` can use `done` as the readiness signal. The library side of the stream is in [Decompiler design](decompiler-design.md#batch-stream).
