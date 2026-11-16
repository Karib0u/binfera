#![cfg(feature = "native")]
use binfera_ghidra::{Language, Session};

// Keep this timing check in its own test process. Other native tests share a
// process-wide engine mutex; waiting for them is outside the analysis deadline.
#[test]
fn deadline_is_checked_during_translation() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new(Language::X86Windows64)?;
    let mut bytes = vec![0x90; 60_000];
    bytes.push(0xc3);
    session.add_section(0x1000, &bytes, true, true)?;
    session.add_function(0x1000, "long_function", false)?;
    let started = std::time::Instant::now();
    let error = session
        .decompile(0x1000, 1, 100_000, 10_000_000)
        .err()
        .ok_or("expected deadline error")?;
    assert!(error.to_string().contains("deadline"), "{error}");
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    Ok(())
}
