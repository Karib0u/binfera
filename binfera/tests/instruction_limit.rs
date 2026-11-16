//! The instruction limit refuses a large image instead of running out of memory. The limit is
//! process-wide, so this test has a binary of its own.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use binfera::extract::recovery::{analyze, instruction_limit, set_instruction_limit, RecoveryError};

#[test]
fn recovery_refuses_an_image_past_the_instruction_limit() {
    let sample = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../tests/testfiles/Practical Malware Analysis Lab 01-01.dll_");
    let bytes = std::fs::read(&sample).expect("pinned PE sample exists");
    let decoded = analyze(&bytes)
        .expect("recovery succeeds")
        .instructions
        .len();
    assert!(decoded > 10, "sample decodes {decoded} instructions");

    set_instruction_limit(Some(decoded));
    assert_eq!(instruction_limit(), Some(decoded));
    analyze(&bytes).expect("an image exactly at the limit is accepted");

    set_instruction_limit(Some(decoded - 1));
    match analyze(&bytes) {
        Err(RecoveryError::TooLarge { limit }) => assert_eq!(limit, decoded - 1),
        other => panic!(
            "expected TooLarge, got {:?}",
            other.map(|a| a.instructions.len())
        ),
    }

    set_instruction_limit(None);
    assert_eq!(instruction_limit(), None);
    analyze(&bytes).expect("no limit");
}
