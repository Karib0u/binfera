//! Code-origin fingerprints cover the functions the decompiler lists, no more and no fewer: the
//! web UI colours, filters and opens functions by the addresses a family match reports.
#![cfg(feature = "decompiler")]
use binfera::decompiler::{decompile_all, BatchEvent, BatchOptions, DecompileError};
use binfera::family::sketch_bytes;
use std::collections::BTreeSet;

/// The decompiler's function inventory: its `start` record. Stops before decompiling anything.
fn decompiler_listing(bytes: &[u8]) -> anyhow::Result<BTreeSet<u64>> {
    let mut listed = None;
    let result = decompile_all(bytes, &BatchOptions::default(), |event| {
        if let BatchEvent::Start { functions, .. } = event {
            listed = Some(functions.into_iter().collect());
        }
        Err(DecompileError::Output("stop after the start record".into()))
    });
    listed.ok_or_else(|| anyhow::anyhow!("no start record: {result:?}"))
}

fn sketch_listing(bytes: &[u8]) -> anyhow::Result<BTreeSet<u64>> {
    Ok(sketch_bytes(bytes, "", "sample", false)?
        .functions
        .iter()
        .map(|f| f.address)
        .collect())
}

fn assert_same_listing(name: &str, bytes: &[u8]) -> anyhow::Result<()> {
    let decompiler = decompiler_listing(bytes)?;
    let sketch = sketch_listing(bytes)?;
    let extra: Vec<_> = sketch
        .difference(&decompiler)
        .map(|a| format!("{a:#x}"))
        .collect();
    let missing: Vec<_> = decompiler
        .difference(&sketch)
        .map(|a| format!("{a:#x}"))
        .collect();
    assert!(
        extra.is_empty() && missing.is_empty(),
        "{name}: fingerprints {} functions, the decompiler lists {}; only fingerprinted {extra:?}, only listed {missing:?}",
        sketch.len(),
        decompiler.len(),
    );
    Ok(())
}

#[test]
fn x86_pe_fingerprints_match_the_decompiler_listing() -> anyhow::Result<()> {
    assert_same_listing(
        "Lab 01-02 (x86 PE)",
        include_bytes!("../../tests/testfiles/Practical Malware Analysis Lab 01-02.exe_"),
    )
}

#[test]
fn dll_fingerprints_match_the_decompiler_listing() -> anyhow::Result<()> {
    assert_same_listing(
        "fixtures.dll",
        include_bytes!("../../tests/decompiler/fixtures.dll"),
    )
}

#[test]
fn arm64_pe_fingerprints_match_the_decompiler_listing() -> anyhow::Result<()> {
    assert_same_listing(
        "windows.exe (AArch64 PE)",
        include_bytes!("fixtures/aarch64_decompiler/windows.exe"),
    )
}

#[test]
fn i386_elf_fingerprints_match_the_decompiler_listing() -> anyhow::Result<()> {
    assert_same_listing(
        "i386 ELF",
        include_bytes!(
            "../../tests/testfiles/3da7c2c70a2d93ac4643f20339d5c7d61388bddd77a4a5fd732311efad78e535.elf_"
        ),
    )
}

/// `cargo test --features decompiler --test family_listing -- --ignored --nocapture` reports how
/// far the two listings differ on every sample in `tests/testfiles`, or in `BINFERA_LISTING_DIR`.
#[test]
#[ignore = "survey of the whole test corpus; slow"]
fn survey_listing_parity_across_the_test_corpus() -> anyhow::Result<()> {
    let dir = std::env::var_os("BINFERA_LISTING_DIR").map_or_else(
        || std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/testfiles"),
        std::path::PathBuf::from,
    );
    let mut paths: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();
    paths.sort();
    let (mut same, mut differ) = (0, 0);
    for path in paths {
        let bytes = std::fs::read(&path)?;
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let (Ok(decompiler), Ok(sketch)) = (decompiler_listing(&bytes), sketch_listing(&bytes))
        else {
            continue;
        };
        let extra = sketch.difference(&decompiler).count();
        let missing = decompiler.difference(&sketch).count();
        if extra + missing == 0 {
            same += 1;
        } else {
            differ += 1;
            let sample = |set: &BTreeSet<u64>, other: &BTreeSet<u64>| -> Vec<String> {
                set.difference(other)
                    .take(8)
                    .map(|a| format!("{a:#x}"))
                    .collect()
            };
            println!(
                "{name}: listed {} fingerprinted {}; only fingerprinted {extra} {:?}; only listed {missing} {:?}",
                decompiler.len(),
                sketch.len(),
                sample(&sketch, &decompiler),
                sample(&decompiler, &sketch),
            );
        }
    }
    println!("same listing: {same}, different: {differ}");
    Ok(())
}
