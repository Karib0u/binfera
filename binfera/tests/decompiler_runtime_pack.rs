//! The Windows API prototype pack can be supplied at runtime (the browser build embeds none).
//! Native builds embed it, so supplying the same bytes must change nothing, and supplying an empty
//! one must leave imports untyped without failing.
#![cfg(feature = "decompiler")]

use std::sync::Mutex;

use binfera::decompiler::DecompilerSession;

// The pack override is process-wide; tests in this file take turns.
static PACK: Mutex<()> = Mutex::new(());

const SAMPLE: &[u8] = include_bytes!(
    "../../tests/testfiles/98c37c3c23bbfb362dac7754c6ba48e75cf24d73bc963a4cdfca557b9e016909.exe_"
);

fn decompile() -> anyhow::Result<String> {
    let mut session = DecompilerSession::from_pe(SAMPLE)?;
    let mut text = String::new();
    for address in [0x4010c0, 0x40138f, 0x401d84] {
        text.push_str(&session.decompile_function(address)?.text);
    }
    Ok(text)
}

#[test]
fn a_pack_supplied_at_runtime_matches_the_embedded_one() -> anyhow::Result<()> {
    let _guard = PACK.lock().unwrap_or_else(|e| e.into_inner());
    binfera_ghidra::clear_windows_pack(false);
    let embedded = decompile()?;
    assert!(embedded.contains("wininet_InternetOpenA("), "{embedded}");
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../binfera-ghidra/data/winapi32.pack"
    ))?;
    binfera_ghidra::set_windows_pack(false, &bytes);
    let runtime = decompile();
    binfera_ghidra::clear_windows_pack(false);
    assert_eq!(runtime?, embedded);
    Ok(())
}

#[test]
fn a_missing_runtime_pack_leaves_imports_untyped() -> anyhow::Result<()> {
    let _guard = PACK.lock().unwrap_or_else(|e| e.into_inner());
    binfera_ghidra::set_windows_pack(false, &[]);
    let untyped = decompile();
    binfera_ghidra::clear_windows_pack(false);
    let untyped = untyped?;
    assert!(!untyped.contains("hInternet"), "{untyped}");
    assert!(!untyped.contains("nServerPort"), "{untyped}");
    Ok(())
}
