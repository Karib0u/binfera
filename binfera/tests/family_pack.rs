use binfera::family::{
    is_known_library_symbol, minhash_bands, BandRecord, FamilyMeta, FamilyPack, FunctionEntry,
    HashRecord, MatchConfig, SampleSketch, SharedRecord, TrustedRecord,
};

fn make_fn(addr: u64, insns: u32, shape: u64, content: u64, minhash_seed: u32) -> FunctionEntry {
    let mh: Vec<u32> = (0..32).map(|i| minhash_seed.wrapping_add(i * 17)).collect();
    FunctionEntry {
        address: addr,
        instructions: insns,
        blocks: 4,
        shape,
        content,
        bands: minhash_bands(&mh),
        library: false,
    }
}

fn make_sketch(sha: &str, family: &str, functions: Vec<FunctionEntry>) -> SampleSketch {
    SampleSketch {
        sha256: sha.to_owned(),
        family: family.to_owned(),
        path: format!("{family}/{sha}"),
        format: "pe".to_owned(),
        arch: "x64".to_owned(),
        packed: false,
        unpacked_dump: true,
        functions,
    }
}

#[test]
fn pack_roundtrip_and_four_way_matching() -> Result<(), Box<dyn std::error::Error>> {
    let crt_fn = make_fn(0x1000, 30, 0xAAAA_0001, 0xAAAA_1001, 100);
    let shared_fn = make_fn(0x1100, 35, 0xBBBB_0001, 0xBBBB_1001, 200);
    let f4 = make_fn(0x2300, 42, 0x1004, 0x2004, 4000);
    let f4_bands = f4.bands.ok_or("expected bands")?;

    let pack = FamilyPack::from_tables(
        vec![FamilyMeta {
            name: "win.lummac2".to_owned(),
            sample_count: 12,
            unique_shapes: 4,
        }],
        vec!["windows-msvc-runtime".to_owned()],
        vec![TrustedRecord {
            shape: crt_fn.shape,
            source_id: 0,
        }],
        vec![SharedRecord {
            shape: shared_fn.shape,
            family_count: 5,
        }],
        vec![HashRecord {
            hash: 0x2001,
            family_id: 0,
            sample_count: 10,
            exclusivity: 1,
            avg_instructions: 40,
        }],
        vec![
            HashRecord {
                hash: 0x1001,
                family_id: 0,
                sample_count: 10,
                exclusivity: 1,
                avg_instructions: 40,
            },
            HashRecord {
                hash: 0x1002,
                family_id: 0,
                sample_count: 8,
                exclusivity: 1,
                avg_instructions: 55,
            },
        ],
        f4_bands
            .iter()
            .map(|&band_hash| BandRecord {
                band_hash,
                family_id: 0,
                sample_count: 7,
            })
            .collect(),
    );

    let bytes = pack.to_bytes()?;
    let loaded = FamilyPack::from_bytes(&bytes)?;
    assert_eq!(pack.stats(), loaded.stats());

    // Query variant: 1 trusted, 1 shared, 1 exact content, 1 exact shape, 1 fuzzy LSH (5/8 bands), 1 unique.
    let mut fuzzy_mh: Vec<u32> = (0..32).map(|i| 4000_u32.wrapping_add(i * 17)).collect();
    for slot in fuzzy_mh.iter_mut().take(12) {
        *slot = slot.wrapping_add(999_999);
    }
    let query = make_sketch(
        "q1",
        "",
        vec![
            crt_fn.clone(),
            shared_fn.clone(),
            make_fn(0x9000, 40, 0x1001, 0x2001, 1000),
            make_fn(0x9100, 55, 0x1002, 0xDEAD_BEEF, 9000),
            FunctionEntry {
                address: 0x9200,
                instructions: 42,
                blocks: 4,
                shape: 0xDEAD_0001,
                content: 0xDEAD_0002,
                bands: minhash_bands(&fuzzy_mh),
                library: false,
            },
            make_fn(0x9300, 30, 0xCAFE_0001, 0xCAFE_0002, 7777),
        ],
    );

    let report = loaded.match_sketch(&query, &MatchConfig::default());
    assert_eq!(report.eligible_functions, 6);
    assert_eq!(report.trusted_functions, 1);
    assert_eq!(report.shared_malware_functions, 1);
    assert_eq!(report.family_matched_functions, 3);
    assert_eq!(report.unique_functions, 1);
    assert_eq!(report.trusted_sources.len(), 1);
    assert_eq!(report.trusted_sources[0].source, "windows-msvc-runtime");
    assert_eq!(report.families.len(), 1);

    let top = report.families.first().ok_or("expected family match")?;
    assert_eq!(top.family, "win.lummac2");
    assert_eq!(top.exact_content_hits, 1);
    assert_eq!(top.exact_shape_hits, 1);
    assert_eq!(top.fuzzy_hits, 1);
    assert_eq!(top.exclusive_functions, 3);

    // Clean benign binary yields trusted breakdown and zero malware matches.
    let benign_query = make_sketch("bq1", "", vec![crt_fn, shared_fn]);
    let benign_report = loaded.match_sketch(&benign_query, &MatchConfig::default());
    assert_eq!(benign_report.trusted_functions, 1);
    assert_eq!(benign_report.shared_malware_functions, 1);
    assert!(benign_report.families.is_empty());

    assert!(is_known_library_symbol("std::vector::push_back"));
    assert!(is_known_library_symbol("runtime.mallocgc"));
    assert!(is_known_library_symbol("__security_check_cookie"));
    assert!(!is_known_library_symbol("decrypt_c2_config"));

    Ok(())
}

#[test]
fn corrupted_packs_are_rejected_cleanly() {
    assert!(FamilyPack::from_bytes(b"").is_err());
    assert!(FamilyPack::from_bytes(b"NOTAMAGIC12345678901234567890123456789012").is_err());
    let mut bad = Vec::from(&b"BXFAM002"[..]);
    bad.extend_from_slice(&[0_u8; 40]);
    assert!(FamilyPack::from_bytes(&bad).is_err());
}
