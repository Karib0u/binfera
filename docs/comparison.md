# Comparing binaries

`binfera diff` says what changed between two binaries: capabilities, functions and file contents. The web app offers the same comparison under **Compare two files**.

```sh
binfera diff old.exe new.exe                # text; rules from ./rules, or -r DIR
binfera diff old.exe new.exe --json         # the DiffDocument
binfera diff old.exe new.exe --no-capabilities
binfera diff old.exe new.exe --pair 0x401000:0x401200   # one pair, to its instructions
binfera fingerprint old.exe > old.idx       # keep one side's facts, then diff the .idx later
```

The exit status is 0 when nothing compared differs (`identical` or `equivalent`), 1 when something does (`changed`), and binfera's usual error codes otherwise. From Python, use `binfera.diff(a, b, rules=None, pair=None)`.

## How it fits together

`diff::fingerprint` reduces one binary to a `Fingerprint`, and `diff::compare` takes two of them, plus the samples' `ResultDocument`s if capabilities are wanted. The samples are not needed after that, so each browser worker holds only one, and fingerprints can be cached. `diff::diff_functions` compares one pair from the listings the fingerprints carry, which is why opening a pair does not recover the files again.

Native code is read from native recovery, because `Freeze` has no instruction bytes, operands or edges. .NET assemblies and freeze files only have features, so their records are built from those; their "listing" is what the features say about each instruction.

## Normalization

Each instruction's text has the operands that move when code moves replaced with `@`: branch and call targets, resolved memory operands, immediates that fall inside a section, and both halves of an address built in two steps (`adrp`/`add`, `lui`/`addiu`). Registers, stack offsets and real constants stay.

This is deliberately not Function ID's hash, which is x86-only, pinned to Ghidra's output, and ignores operand values that a patch can change. Instead:

- `shape` hashes the normalized instructions.
- `content` adds the strings and imports they reference, resolved through import stubs.
- A call is "unchanged" only if it goes to the match of the old callee, checked after matching.

So a patched string or a redirected call marks the function as changed, even though its instructions look the same once masked.

## Matching

Passes run from most to least certain, and each sees only what is left:

1. `exact`: `content` unique on both sides.
2. `shape`: `shape` unique on both sides; references differ.
3. `name`: symbol, export or Go `pclntab` name unique on both sides, and supported by the code.
4. `propagated`: free neighbours of matched pairs in the call graph.
5. `fuzzy`: candidates found by minhash bands and shared rare features, up to 24 per function, scored on imports, strings, constants, mnemonic 3-grams, CFG shape, size and call-graph agreement.
6. `duplicate`: identical functions left over, paired by position.

Steps 4 and 5 repeat until nothing moves. A pair from 4 or 5 is accepted only when each side is the other's best by a clear margin. Ambiguous functions stay unmatched instead of being settled by order. `confidence` says how sure the pairing is and `similarity` how alike the functions are; they are separate on purpose. Results do not depend on `--jobs`, because matching is serial and uses no randomized hashing.

Functions are compared only between files of the same architecture. The capability and file deltas work across architectures.

## Checking a match

Every match carries its `evidence`: whether the instructions and control flow are the same, the strings, imports, constants, callees and rules only one side has, and the signals its score weighed. An exact unchanged pair has no signals, since its hashes are the proof.

`--pair` lists instructions with the string or import each one refers to. A row compares as changed when that differs, or when a call does not go to the match of the old callee, so a redirected call shows up even though it reads the same with addresses masked. `--function-map` supplies the match when the inputs hold only listings.

In the C diff, `FUN_` names go through the function match, other address names are set aside, and local variables are numbered by first use, so only real differences read as changes: the same code with other variable numbers is the same, and `x - y` against `y - x` is not.

## In the web app

A comparison is one workspace with four views:

- **Changes** opens first: the comparison in a sentence, then everything that differs, most telling first, each in a few plain words. Capabilities rank above imports, then new callees, strings and plain code. Choosing one shows its difference as a split or unified diff of its decompiled C and its assembly, with unchanged lines folded, plus its graph and a **Why** tab holding the evidence. A function named in a diff can be followed to its own difference, and clicking a block in the graph goes to it in the assembly. **All changes** puts every difference on one page, each computed as it comes into view, and **File details** holds the file-level facts.
- **A** and **B** are the whole single-file workspace for that file, analyzed the first time it is opened. The function list marks what changed, and each function says what happened to it.
- **A | B** is both side by side, each with its own place, Back and Forward. **Linked** moves the other side to the matching function.

Keys: `d` shows the difference for what is open, `a` and `b` show it in that file, `n` and `p` move between changes, `j` and `k` between functions, and `v` marks a function as viewed. Search reaches both files.

Three things are the reader's rather than the engine's. **Diff against…** pairs two functions by hand when the matcher missed or got them wrong; such a pair lasts until the page closes, and carries no evidence. A rename carries to the matching function unless it already has a name. **Viewed** is remembered in the browser for that pair of files.

The Strings list under File details is read from the two fingerprints, since `FileDelta` does not carry strings. It lists what the strings score counts: strings that code refers to.

## Capabilities

The delta lists rules gained and lost, and rules present in both that moved: a rule is `retargeted` when it matched a function whose counterpart no longer matches it, or the reverse. Library and sub-scope rules are left out.

Rule matches come from capability recovery and functions from native recovery, whose function starts can differ. A match is tied to the function containing its address; matches outside every function are counted as `unmapped` rather than guessed at.

A delta is only meaningful if the two analyses agree, so the document warns when they used different rule directories, binfera versions or extractors, or when only one sample looks packed.

## What "equivalent" does not cover

`equivalent` means different bytes with no difference in anything compared. PE headers are excluded, since they hold the image base and timestamp, and base relocation slots are masked in section hashes so a rebased copy stays equivalent. ELF and Mach-O have no such masking. Data that code references but that is not a string is compared only through section hashes, not per function.

## Evaluation

`scripts/diff_eval/eval.py` builds a known source twice with a change in between, compares the stripped copies, and scores pairs against the unstripped symbols. BinDiff and Diaphora are heuristics too, so they can be baselines but not ground truth.

```sh
cargo build --release -p binfera-cli
python3 -I scripts/diff_eval/eval.py target/release/binfera
```

Results on the one small test program (19 functions), clang on macOS. Precision is 1.000 throughout. This corpus is too small to promise the same on large or heavily optimized binaries.

| Scenario | Recall, arm64 | Recall, x86-64 |
| --- | --- | --- |
| Same build | 1.000 | 1.000 |
| Patched source, `-O1` | 1.000 | 1.000 |
| Patched source, `-O2` | 1.000 | 1.000 |
| `-O1` vs `-O2` | 1.000 | 1.000 |
| `-O2` vs `-Os` | 1.000 | 1.000 |
| `-O0` vs `-O1` | 0.789 | 0.895 |
