//! Item 42 of the IDA audit: every managed method with a body gets a named IL listing.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use binfera::extract::dotnet;
use binfera::extract::dotnet::function::managed_method_bodies;
use binfera::extract::dotnet::listing::method_listings;

#[test]
fn every_method_body_is_listed_with_resolved_operands() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/testfiles/dotnet");
    let mut samples = 0;
    let mut calls = 0;
    let mut strings = 0;
    for entry in std::fs::read_dir(dir).expect("corpus") {
        let path = entry.expect("entry").path();
        if !path.is_file() {
            continue;
        }
        let bytes = std::fs::read(&path).expect("sample");
        if !dotnet::looks_like_dotnet_pe(&bytes) {
            continue;
        }
        let Ok(pe) = dotnet::load(&bytes) else {
            continue;
        };
        let bodies = managed_method_bodies(&pe).expect("bodies");
        let listings = method_listings(&pe).expect("listings");
        assert_eq!(listings.len(), bodies.len(), "{}", path.display());
        for (listing, body) in listings.iter().zip(&bodies) {
            assert_eq!(listing.token, body.token);
            assert_eq!(listing.rows.len(), body.body.instructions.len());
            assert!(!listing.name.is_empty());
            assert!(listing.text.starts_with("// "));
            for row in &listing.rows {
                // A resolved call names a method; only a metadata gap prints a raw token.
                if row.text.starts_with("call ") || row.text.starts_with("callvirt ") {
                    calls += 1;
                }
                if row.text.starts_with("ldstr \"") {
                    strings += 1;
                }
            }
        }
        samples += 1;
    }
    assert!(samples > 0, "the corpus has managed samples");
    assert!(calls > 0 && strings > 0);
}
