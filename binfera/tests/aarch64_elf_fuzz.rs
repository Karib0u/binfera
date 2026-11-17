//! Malformed-input robustness (gate J11) for the native
//! AArch64 ELF pipeline -- mutating the pinned corpus's raw bytes and
//! running the whole path task 1-4 landed (native decode, control-flow
//! recovery including the new decode-based prologue scan and PLT/GOT thunk
//! resolution, and `aarch64_features`/`aarch64_basicblock_features`'s own
//! address materialization) must never panic. `decoder.rs`'s own tests
//! already cover raw-word decode fuzzing (task 2's acceptance line); this
//! covers everything task 3/4 built on top of that decode step, mirroring
//! `macho_features.rs::mutated_macho_samples_never_panic`'s method.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::panic;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use binfera::extract::elf::extract_elf;
use binfera::extract::flirt::enrich_static_features;
use binfera::extract::recovery::{self, RecoveryError};
use binfera::parallel::AnalysisOptions;

/// Deterministic xorshift64 PRNG, matching `decoder.rs`'s own fuzz test and
/// `macho_features.rs`'s mutation harness -- reproducible across runs
/// without a `rand` dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() as usize) % n
    }
}

const MUTANTS_PER_SAMPLE: usize = 300;
const SAMPLES: [&str; 3] = [
    "687e79cde5b0ced75ac229465835054931f9ec438816f2827a8be5f3bd474929.elf_",
    "c7f38027552a3eca84e2bfc846ac1307fbf98657545426bb93a2d63555cbb486.elf_",
    "d1e6506964edbfffb08c0dd32e1486b11fbced7a4bd870ffe79f110298f0efb8.elf_",
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    let path = root().join("tests/testfiles/aarch64").join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

// 900 mutants through the full ELF pipeline: ~166 s single-threaded, the
// second largest cost in `cargo test --workspace`. It guards against rare
// panics on malformed input, not against the behavior an ordinary edit moves,
// so it is a pre-merge gate rather than an inner-loop test. CI runs it via
// `cargo test --workspace -- --include-ignored`.
//
// The mutants run on every available core. Each mutant's byte flips are drawn
// up front from its sample's seeded PRNG, exactly as a serial run draws them,
// so the mutants are the same; only the wall time changes. Workers take
// mutants from one shared queue because the samples differ a lot in cost.
#[test]
#[ignore = "slow robustness gate; run with --include-ignored"]
fn mutated_aarch64_elf_samples_never_panic() {
    let originals: Vec<Vec<u8>> = SAMPLES.iter().map(|name| fixture_bytes(name)).collect();
    let mutants: Vec<(usize, Vec<(usize, u8)>)> = originals
        .iter()
        .enumerate()
        .flat_map(|(sample, original)| {
            let mut rng = Rng(0x2545_f491_4f6c_dd1d ^ (SAMPLES[sample].len() as u64 + 1));
            (0..MUTANTS_PER_SAMPLE)
                .map(|_| {
                    let n_flips = 1 + rng.below(4);
                    let flips = (0..n_flips)
                        .map(|_| (rng.below(original.len()), (rng.next() & 0xFF) as u8))
                        .collect();
                    (sample, flips)
                })
                .collect::<Vec<_>>()
        })
        .collect();

    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));

    let next = AtomicUsize::new(0);
    let workers = std::thread::available_parallelism().map_or(1, |n| n.get());
    let failures: Vec<String> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(|| {
                    let mut failures = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some((sample, flips)) = mutants.get(i) else {
                            break;
                        };
                        let mut data = originals[*sample].clone();
                        for &(idx, byte) in flips {
                            data[idx] = byte;
                        }
                        if panic::catch_unwind(|| run_pipeline(&data)).is_err() {
                            failures.push(format!("{}: mutant panicked", SAMPLES[*sample]));
                        }
                    }
                    failures
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("mutation worker"))
            .collect()
    });

    panic::set_hook(default_hook);
    assert!(
        failures.is_empty(),
        "{} mutant(s) panicked instead of returning Err:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn run_pipeline(data: &[u8]) {
    let _: Result<_, binfera::extract::ExtractError> = extract_elf(data);
    let analysis: Result<_, RecoveryError> = recovery::analyze(data);
    if let Ok(analysis) = analysis {
        if let Ok(mut features) = extract_elf(data) {
            enrich_static_features(
                &mut features,
                &analysis,
                &BTreeMap::new(),
                &AnalysisOptions::SERIAL,
            );
        }
    }
}
