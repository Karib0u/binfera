# binfera web

A browser UI: drop a supported PE, ELF or Mach-O (x86 / x64 / AArch64 / ARM32 / MIPS32), get every recovered function decompiled and the capa rule matches mapped onto them. There is no backend: the Rust engine and the native Ghidra decompiler are compiled to WebAssembly and run in Web Workers, so the binary never leaves the page.

Header-free files also get an experimental x86/x64 shellcode guess. The engine compares bounded entry-reachable decoding, scoring instruction quality and architecture clues instead of instruction count. It handles NOP sleds, direct branches, prefixed REX instructions, RIP-relative loads and syscall stubs. The banner shows ambiguous guesses and the clues found. Linux `int 0x80` and Windows PEB access provide OS hints; otherwise Windows is explicitly shown as a default. A `syscall` alone does not infer an OS.

Import accepts binary bytes, compact/spaced hex, `0xNN` arrays and `\xNN` strings, including simple C/Python literal assignments. Only complete literals are decoded; source text is never executed. Hashes and addresses refer to the decoded payload. **Start offset** skips a prefix in those decoded bytes, with addresses beginning at zero for the selected payload. Architecture and calling convention can be changed, and a rejected file can be opened explicitly as raw x86 or x64.

Automatic detection rejects empty, zero-filled and ordinary ASCII text input. Explicit raw import accepts printable code too. Detection is a heuristic and can mistake data for code; encrypted or self-modifying payloads still require unpacking. Raw ARM/ARM64 and other architectures are not supported. Executable headers keep their normal loaders. Small raw inputs use one decompiler worker.

One-time toolchain setup (macOS shown):

```sh
brew install emscripten
rustup target add wasm32-unknown-emscripten
```

Then, from `web/`:

```sh
npm install
npm run prepare-assets   # build the wasm module and bundle the capa rules
npm run dev              # http://localhost:5173
npm run build            # static site in dist/ -- serve it from any static host
```

`prepare-assets` runs two steps you can repeat on their own:

- `npm run build:wasm` builds `binfera-cli --features decompiler` for `wasm32-unknown-emscripten` (see `../.cargo/config.toml` for the link flags), copies `binfera.js` / `binfera.wasm` into `src/wasm/`, and copies the signature databases into `public/sigs/`. Function ID packs are gzip-compressed as `fid-x64.packz` and `fid-x86.packz`; the page decompresses them before mounting the original `.pack` names in each worker. The Windows prototype packs `winapi64.pack` and `winapi32.pack` (4 MB each) are copied uncompressed to `public/sigs/`: native builds embed them, but the wasm build does not, to keep `binfera.wasm` under Cloudflare's 25 MiB asset limit. The page mounts the one for the sample's architecture (x86 → 32, x64 and AArch64 PE → 64) next to the others, and `binfera/src/bundled.rs` hands it to the decompiler bridge before the first session. A pack that is not mounted is reported on stderr and Windows imports stay untyped.
- `npm run pack-rules` writes `public/rules.json` from `BINFERA_RULES_DIR`, `../rules`, or the main checkout's `rules/` when run from a git worktree.

All outputs are generated and git-ignored.

## Delivery

`npm run build` prerenders the existing landing page into `dist/index.html`, including its headings, feature descriptions and documentation links. This uses Vite and React at build time; hosting still needs only static files. React mounts the interactive app over that HTML in the browser, preserving browser-specific themes and URL hashes. Development and desktop builds keep their existing client rendering.

After building, run `npx playwright install chromium` once and `npm run test:prerender` to check the HTML-only page and the interactive themes, links, tabs and file analysis. CI runs this check against the production build in the `web-engine` job.

ZIP support loads only when a ZIP archive is opened. In the phase 3 production build, the main JavaScript chunk is 471.95 kB (155.29 kB gzip), down from 589.61 kB (209.37 kB gzip); the ZIP reader is a separate 129.91 kB chunk. Tour screenshots are 1600-pixel WebP images at quality 80, each below 150 kB.

`worker.js` handles `/assets/*` before the static asset binding. Successful hashed assets remain immutable for one year; missing assets and other errors use `Cache-Control: no-store`. Route selection is configured in `wrangler.jsonc`. The `_headers` rule also covers static hosts. Deploy the browser build:

```sh
npm run build
npx wrangler deploy
```

Publishing a `v*` release deploys the site automatically: `.github/workflows/site.yml` builds the wasm engine from the release tag, builds the site and runs `wrangler deploy`, then checks that binfera.io serves the new bundle, the demos and the install scripts. Run it from the Actions tab to deploy another branch or tag. It needs the `binfera.io` environment's `CLOUDFLARE_API_TOKEN` (a token with the Workers Scripts: Edit permission) and `CLOUDFLARE_ACCOUNT_ID` secrets. CI has no malpedia checkout, so `npm run fetch-demos` downloads the packed demos binfera.io already serves, checks each one's SHA-256, and rebuilds the index from `demo/samples.json`. It fails when a sample is added, removed or replaced: pack that change locally (`npm run pack-demos`) and deploy by hand once.

Run `npm run test:delivery` for cache-header behavior and `npm run test:assets` for compressed pack selection, decompression, and worker buffer ownership. With Wrangler running locally, a real hashed `/assets/` URL should return `immutable`, while a missing URL returns status 404 and `no-store`.

## CI and wasm size

The `web` job in `.github/workflows/ci.yml` uses Node 22 and runs TypeScript plus the layout, text diff, entropy, report, delivery, project and RISC graph checks without generated engine files. The ambient declarations in `src/wasm.d.ts` cover that clean-checkout case.

The `web-engine` job builds the engine and production site on every push to `main`, on manual runs, and on pull requests changing the web app, engine, toolchain, rules or CI configuration. It pins Emscripten to 7.0.0, matching the local Homebrew release (`emcc --version` reports `7.0.0-git`), and caches npm, Cargo and wasm build outputs. It runs the analyze, compare, shellcode, archive, assets, image, Mach-O and RISC checks. The Mach-O and RISC fixtures are source-controlled; malware demos are checked locally because their packed assets are not in the repository.

`build:wasm` prints the wasm byte count, warns at 98% of the 26,214,400-byte asset limit (25 MiB), and fails above the limit. Native release profiles are unchanged.

The browser uses the dedicated `[profile.wasm]` in `../Cargo.toml`: release inheritance, size optimization (`opt-level = "s"`), fat LTO, one codegen unit and symbol stripping. A fresh local build on 2026-11-15 produced **24,125,192 bytes**, leaving **2,089,208 bytes (8.0%)** below the deployment limit. The page continues loading the raw wasm asset. The trials below describe the earlier engine source.

Size trials on 2026-11-10 used engine sources from `686db72`, Rust 1.99.1 and Emscripten 7.0.0 on an M1 Max:

| Build | Raw wasm bytes |
|---|---:|
| Original release defaults | 26,094,835 |
| Release plus `wasm-opt -Oz` | 25,857,874 |
| Wasm profile with LTO, one codegen unit and stripping | 25,894,893 |
| Wasm profile plus `opt-level = "s"` (shipped) | 24,111,045 |

The standalone `wasm-opt` trial also used `--strip-debug --strip-producers --enable-exception-handling --enable-bulk-memory --enable-nontrapping-float-to-int`. The original module's `wasm-objdump -h` breakdown was 9,415,555 bytes of code and 16,646,508 bytes of data. `twiggy top -n 25` attributed the largest items to data segments of 4,720,812, 1,678,791 and 1,527,431 bytes.

To check the size profile's runtime cost, three alternating, unsharded WannaCry decompile runs used the LTO profile at the default optimization level and at `"s"`. Median wall time was 4.623 s and 4.721 s respectively (+2.1%, within a 3% budget); median process CPU time was 6.184 s and 5.943 s. Every run decompiled all 134 functions without errors. These measurements exclude module instantiation and signature mounting.

All four builds completed `npm run test:demos` for all 12 samples using Node 26.13.0. The selected profile produced 7,482 decompiled functions with no failed function records. Full-corpus runs overlapped local compilation and each other, so the following wall times are smoke-test measurements rather than controlled speed comparisons. Values are decompile seconds, taking the slowest shard for each demo:

| Demo | Release | Release + Oz | LTO | LTO + s |
|---|---:|---:|---:|---:|
| wannacry | 6.83 | 10.73 | 7.82 | 3.51 |
| notpetya | 11.57 | 38.16 | 16.51 | 10.05 |
| stuxnet | 1.32 | 4.49 | 1.73 | 1.29 |
| mirai | 5.76 | 21.74 | 7.22 | 5.12 |
| 3cx | 0.56 | 2.66 | 0.74 | 0.49 |
| blackcat | 294.57 | 268.81 | 91.65 | 78.08 |
| hive | 145.17 | 136.30 | 146.77 | 139.11 |
| darkgate | 79.52 | 35.98 | 30.18 | 26.00 |
| rustbucket | 1.31 | 0.93 | 0.88 | 0.80 |
| industroyer2 | 5.40 | 3.53 | 3.44 | 3.26 |
| nimblackout | 19.74 | 10.98 | 10.47 | 9.42 |
| cloudsnooper | 5.38 | 2.06 | 2.12 | 1.90 |

## Compare example

The preview under **Compare two files** on the landing page opens `public/demo-v1.exe` and `public/demo-v2.exe`, both built by `demo/build-compare.sh` from `demo/demo.rs`, so the differences come from the source and not from a toolchain. They are harmless and never run. The second build drops the debugger check, adds a user-name lookup and an XOR function, and changes a delay and a file name.

## Malware demos

`demo/samples.json` selects 12 local samples across Windows, Linux and macOS, x86, x64 and AArch64, and native C/C++, Go, Rust, Delphi, Nim, Objective-C and Swift. The landing page leads with WannaCry, a Stuxnet driver, Mirai and 3CX, and lists the rest under **All 12 malware samples**. Each entry describes the specific component or variant and suggests what to explore. BlackCat uses the smaller Windows x86 Rust build after the Linux x64 candidate proved too slow for a featured demo.

```sh
npm run pack-demos       # requires MALPEDIA_DIR pointing at a local malpedia checkout
npm run test:demos       # requires prepare-assets; checks all packed samples with the wasm engine
npm run dev
```

The packer XOR-encodes the samples into the ignored `public/demos/` directory. The page decodes them in memory for static analysis. RustBucket uses the ARM64 slice of a universal Swift loader so every analysis stage uses Apple silicon. Its index entry records both the extracted slice's SHA-256 and `sourceSha256` for the original universal file; the picker tooltip shows both hashes.

`test:demos` verifies decoded hashes, sizes, architecture labels and image mappings, then runs capability analysis and decompiles every recovered function. It reports capability counts, decompiled and failed function counts, and wasm timings. Demos above 1 MiB use four parallel decompiler shards, following the app's worker model. Each worker runs in a separate process with a ten-minute timeout. These checks exercise the engine without executing any sample; they do not establish semantic correctness of the generated C. The generated demo files are copied by `npm run build`.

Local validation on 2026-11-02 completed all 12 demos with 7,482 decompiled functions. Hive had one failed function; the other demos had none. Larger Rust and Go demos still take longer than the compact samples.

The two previews on the landing page (`src/Landing.tsx`) are real engine output copied into the source: WannaCry's `FUN_00401ce8` and the compare example. Copy them again if that output changes.

## Graph view

The **Graph** view of a code pane (or the Graph tab on a phone) draws the control-flow graph, as IDA's graph mode does. Native function records supply recovered basic blocks and edges; `src/graph.ts` lays them out. Listings without a complete recovery graph fall back to splitting the instruction listing. Edges are green (taken), red (not taken) and blue (jump / fall-through); loop back edges are dashed and routed round the side. Drag to pan, scroll to pan, Ctrl/Cmd+scroll or pinch to zoom, click a block to highlight its edges, click a call target to open that function. Recovered jump-table edges are included; branches out of the function get no edge. A graph too large to read when fitted opens on its entry block with a minimap; **Fit** shows all of it. It follows the shared cursor. Only blocks within one viewport of the visible area are mounted; edges and the complete minimap stay available while panning.

## Code panes

A function shows one code pane or two, each picking C, Asm, Graph or Listing, so any pair sits side by side; the shared cursor keeps them on the same address. Picking a view the other pane has swaps the two. The choice is remembered, and is part of the URL (`view=c+graph`).

Asm and Listing draw branch arrows beside the addresses, as IDA does: green for conditional branches, blue for jumps, dashed when going backward. Click an arrow to go to its other end. Only direct branches inside a function are drawn, and phones leave them out. A branch's target address always goes to code: to its row, or to the Listing when the function does not list it.

Asm windows functions above 1,500 instructions with fixed 20 px rows. Large listings scroll long operands horizontally on phones. Branch arrows keep their full-height SVG layer and mount paths intersecting the visible rows. `npx playwright install chromium --only-shell` then `npm run test:virtualization` checks scrolling, selection and graph culling in headless Chromium without engine assets. An optional function-record JSON path (`npm run test:virtualization -- /path/to/function.json`) measures a real listing as well. On Hive `0x4e5aa0` (9,931 instructions), the production-component harness in headless Chromium mounted 435 DOM nodes for Asm and 3,399 for Graph, with no opening task above 100 ms.

Click a word to highlight its uses in every pane; numbers match by value, so `0xc` and `0Ch` are the same. Hover a link to a function for a preview of its C and capabilities.

Selecting a C line marks its instructions in Asm, Graph and Listing. The decompiler only names the operations that survive, so instructions it folded away, such as a call's pushes, join the next statement in their block. That makes the marking an estimate: it can include saved registers or unrelated setup. Instruction comments show the string at an address the instruction takes, including short ones the Strings list leaves out, such as `"rb"`. Clicking a string or data label goes to its address in the Listing, and Back returns.

## Indicators

The **indicators** toggle in Strings shows only URLs, IP addresses, domains, email addresses, commands, user agents, registry keys, named objects and file paths (`src/indicators.ts`), each with the functions that use it. These are pattern matches to check, and values encoded or built at run time do not appear.

## Links and history

Every place is a browser history entry and a URL hash, such as `#demo=wannacry&fn=0x401000&view=c+graph&at=0x401010` (`src/workspace/location.ts`), so Back and Forward work and a demo link opens that demo at that place. A file cannot be reopened from a URL: after a reload the page asks for the same file, then returns to the place. **New** leaves the analysis running behind the landing page, which offers to continue with it.

Names and stars are stored in this browser under the file's SHA-256. Press **?** in the workspace for the keyboard shortcuts.

## Packed files

When the engine sees signs of packing (`binfera/src/packing.rs`: packer section names, UPX's header, high-entropy or file-less executable sections), the Capabilities view and every function show a warning naming the packer and the evidence: the code shown is the unpacker, not the program.

## How it runs

`src/analyze.ts` first downloads the wasm module (`src/engine/assets.ts`, with a progress bar in the header), compiled once and shared with every worker. An inspection worker calls `binfera --image-info` to obtain the entry point, pointer width, byte order, sections, imports, exports and address mappings from the Rust loaders. The page uses these mappings for hex navigation and display strings; it has no separate binary-format parser.

It then downloads the three FLIRT databases, the Function ID pack selected by the metadata (x86 or x64 PE only), the Windows prototype pack for a PE's pointer width, and the rules. The browser caches them. The signature data is deliberately not embedded in the wasm build: native builds still embed it, and on Emscripten `binfera/src/bundled.rs` reads it from `/sigs` in the module's in-memory file system.

Completed browser analyses are kept locally in IndexedDB as image metadata, capability JSON and decompiler NDJSON Blobs. Reopening the same bytes replays those results without analysis workers. Entries use the sample SHA-256, content-hashed wasm URL and rules SHA-256; changing either engine input causes a miss. Storage is capped at 300 MiB, evicting the least recently used samples before a write. Only a successful complete analysis is committed, and storage or WebCrypto failures fall back to normal analysis. Forced shellcode formats bypass this cache. Nothing is uploaded, and input files are not stored in it: choose the file again after a reload, or reopen its demo link. Use **Analyze again** in More or Report to discard the sample's cached results and rerun it. Notes are kept separately.

The desktop and MCP share a disk cache with a 2 GiB budget, overridable with `BINFERA_CACHE_MAX_MB` (in MiB). Startup pruning removes partial writes older than one day and then the oldest unused result files until the budget fits. Cache hits refresh modification times; different engine versions share the budget and are not removed solely for being older. Active partial writes are excluded from eviction. The cap is applied at startup, so a running session can temporarily exceed it.

Run `npm run test:cache` for browser cache persistence, replay and failure-path checks without the wasm engine.

Run `npm run test:release` after preparing assets, packing the local demos, and building the native CLI and production web app. It measures native Hive and the full production browser UI, verifies worker-free cached reopening, and checks the real large-function Asm/Graph views. It writes its measurements under `web/evidence/` (git-ignored), or to the path given as its first argument. `npm run test:deployment` verifies successful and missing hashed-asset headers on the production host.

## Archive resource limits

ZIP and 7z inputs and extracted output are bounded to 256 MiB. ZIP directory reads stop after 10,000 entries; 7z file listings stop after 10,000 files and their diagnostic text is bounded. ZIP extraction counts actual streamed output, independently of advertised sizes. The 7z worker counts filesystem writes before accepting output. Each extraction has a 30-second deadline. Leaving the archive screen aborts ZIP work or terminates its 7z worker, including password attempts. These limits bound output and elapsed work; they do not make the native decompressor a memory sandbox.

Then it starts workers (`src/engine/engine.worker.ts`), each with its own module instance: one runs `binfera --json --jobs 1` against the mounted rules, and up to six run `binfera --decompile-all --no-resource-retry --shard I/N`, which splits the recovered functions round-robin and streams NDJSON lines back as they print. The page keeps the first copy of any function more than one shard reports, except that a later record replaces one marked `retry_pending`. `start.names` supplies names before decompilation. Once every shard emits `settled` (or `done` for older streams), reference indexes, code search, call graphs, listings, reports and exports become usable. The status dot still tracks final completion.

Browser analyses skip automatic resource retries: large functions retain assembly and references and offer **Try with a longer limit**, which runs `decompileOne` with `--resource-retry`. The desktop build defers these retries until ordinary workers finish, then runs them concurrently. A replacement refreshes the indexes.

Batch selection, sharding, session rebuilds and resource retries are implemented by `binfera::decompiler::decompile_all`; the CLI serializes its typed events. `src/workspace/` owns navigation and reference indexes; `src/views/` holds the capability, function, string and section views. `App.tsx` selects the file and starts an analysis.

Notes:

- The decompiler's output can depend on which functions the same session decompiled earlier (callee prototypes it inferred). On the test sample, 1 of 420 functions printed a callee differently when sharded (`FUN_1400091a4` vs a cast of its address). Sharding is therefore deterministic per shard count, but not byte-identical to an unsharded run; `--shard` is only for the web UI.
- Each worker holds its own engine and signatures in memory, hence the cap of six decompiler workers (two cores are left for capa and the page). Every worker recovers the whole file, so a file over 2 MB gets four decompiler workers, one over 4 MB two and one over 16 MB one.

## Large files

A WebAssembly module addresses at most 4 GB, and memory grows with the code recovery decodes. The browser build therefore stops recovery after 2,500,000 instructions (`DEFAULT_INSTRUCTION_LIMIT` in `binfera/src/extract/recovery/engine.rs`) and exits with status 14. Decompiler workers pass `--max-instructions 3500000`: they need about half the memory per instruction and hold no rules. When only the capability worker refuses, the page says so on the Capabilities view and still lists the decompiled functions; when a decompiler worker refuses, it stops every worker and says the file is too large for the browser. Both point to the command-line tool, which has no limit unless given `--max-instructions`.

Measured in this build (peak module memory, one worker):

| Sample | Instructions | Capabilities | Decompiler shard |
|---|---:|---:|---:|
| win.castleloader | 0.65 M | 1,031 MB | 382 MB |
| win.sliver | 0.92 M | 1,324 MB | 935 MB |
| win.overlord | 1.2 M | 1,610 MB | — |
| win.trustconnect | 1.5 M | 2,091 MB | 839 MB |
| win.hackbrowserdata | 2.7 M | 3,055 MB | 1,511 MB |
| win.magic_rat | 3.15 M | out of memory | 1,896 MB |

The capability worker costs about 460 MB (rules and signatures) plus about 1 KB per instruction, the decompiler worker 0.6–1 KB per instruction. Instruction counts are the decompiler's recovery; the capability recovery counts a few percent fewer.

Mach-O uses the same automatic detection and decompiler pipeline as the native CLI. Universal files default to the first supported slice in file order. After `npm run build:wasm`, `npm run test:macho` checks thin x86-64/ARM64 files, explicit universal selection, Objective-C selectors and capability extraction through the WebAssembly engine.

ARM32/Thumb PE32 and little-endian ELF32, plus classic MIPS32 o32 ELF in both byte orders, share the native and WASM analysis path. See [the architecture scope](../docs/decompiler.md#arm32-thumb-and-mips32) for limits. `npm run test:risc` checks branch graphs and exercises metadata, capability rules and Ghidra decompilation against the source-built ARM/Thumb/MIPS fixtures.

## Desktop app (Tauri)

`src-tauri/` wraps this same UI in a native window (Windows, Linux, macOS) and runs the engine as the native `binfera` binary instead of WebAssembly: no download, every core (`--jobs`), no 4 GB memory limit. `vite --mode desktop` swaps `src/engine/assets.ts` and `run.ts` for their `.native.ts` twins; everything else is shared with the browser build.

```sh
npm run prepare-desktop   # builds the native engine sidecar and bundles the capa rules (once, and on engine changes)
npm run tauri dev         # the app, with Vite hot reload
npm run tauri build       # installers in src-tauri/target/release/bundle/
```

- The webview never chooses a command line: `run_engine` only accepts the argument shapes `run.native.ts` builds (`validate_args` in `src-tauri/src/engine.rs`, with tests: `cargo test` there), and the app ships a restrictive CSP (`tauri.conf.json`).
- Every platform includes the decompiler: `binfera-ghidra/build.rs` builds it natively on Linux, macOS and Windows (MSVC), so `prepare-desktop.sh` always enables the feature.
- `.github/workflows/desktop.yml` builds the installers for macOS (arm64, x64), Linux x64 and Windows x64. It runs when triggered by hand, and `release.yml` calls it for every `v*` tag.
- The macOS app and disk images are signed and notarised. The Windows installers are not signed, so SmartScreen warns on first run.

## Analyst notes

Press `;` at the cursor, use the comment button, or choose Add/Edit comment in a code row's context menu. Enter saves, Shift+Enter adds a line, Escape cancels, and saving an empty comment removes it. Your comments carry the You label and are included with their addresses in JSON exports and Markdown/HTML reports.

Cmd/Ctrl+Z outside text fields, or Undo in More, reverses your names, variable names, comments and stars for the current workspace session. Browser notes share one localStorage record per sample. Desktop notes, including stars, are saved in the project database and synchronized with MCP. Existing local stars and comments import once even when names were imported by an older build.
