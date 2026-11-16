# Compact decompiler runtime signatures

`decompiler-runtime.pat` is a generated subset of the existing Mandiant `1_flare_msvc_rtf_32_64.sig`, under the same Apache-2.0 license as capa. The upstream version is the `mandiant/capa` pin in `PINNED.md`. Every pattern is derived from that pinned database without sample-specific byte matching.

- Source SIG SHA-256: `e0042918fa80d432a1914680816996ac397afc30b05d3161192f29de63e66e79`
- Generated PAT SHA-256: `21a275fce96cd9114bc4d4c9489ff33c744c8700ac6667588769c8bf84327b1b`
- 54 patterns, 6,091 bytes.

Regenerate from the repository root:

```sh
cargo run --release -p binfera --example decompiler_runtime_signatures > /tmp/decompiler-runtime.pat
cmp /tmp/decompiler-runtime.pat binfera/sigs/decompiler-runtime.pat
```

The generator selects security-cookie initialization/checking and DLL startup routines. It excludes signatures with reference dependencies and any candidate whose byte prefix overlaps a different root name in the source database. The latter deliberately rejects even overlaps that CRC/tail bytes might have disambiguated: removing other candidates must not create a newly unambiguous name. Wildcard padding preserves the original CRC start, and all CRC and tail constraints remain in the PAT output. Coverage is intentionally narrower than full library recognition.

The optional decompiler now loads the full existing `1_flare_msvc_rtf_32_64.sig` database through the cached lossless matcher, including reference, CRC and tail validation. This recovers older MSVC and UCRT C runtime names. Matching C runtime names receive prototypes from the existing type archive. C++ identities remain with Function ID and RTTI rather than replacing them with an ambiguous library alias. Capability analysis still uses its original databases.

The compact subset and its generator remain as reproducible historical artifacts; they are no longer the decompiler's runtime input. Full matching costs more on a cold request but avoids excluding most runtime names by construction.

`kernel-runtime.pat` supplements that database with the x64 WDK memory routines identified in the round-1 Daxin sample, SHA-256 `6908ebf52eb19c6719a0b508d1e2128f198d10441551cbfb9f4031d382f5229f`:

| Name | Address | Bytes |
|---|---:|---:|
| `memset` | `0x1c330` | `0xea` |
| `memmove` | `0x1c430` | `0x334` |

Both routines are position independent and contain no external references. Each pattern checks the first 32 bytes, the FLIRT CRC16 of the next up to 255 bytes, and a literal footer for every remaining byte. Matching and ambiguity checks use the existing matcher. Matches receive the existing archive prototypes; no signature is applied from a short prologue alone.
