//! `BXFAM003` sections, `BXFAM002` compatibility, String Reuse precision, and pack layering.
//! Every pack here is synthetic and built in memory.

use binfera::family::{
    extract_origin_strings, normalize_origin_string, origin_string_hash, FamilyMeta, FamilyPack,
    FamilyPackSet, FunctionEntry, HashRecord, MalwareStringRecord, MatchConfig, MatchReport,
    OriginString, PackHeader, SampleSketch, StringEncoding, StringOriginKind, TrustedRecord,
    TrustedSymbol,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn function(address: u64, shape: u64) -> FunctionEntry {
    FunctionEntry {
        address,
        instructions: 60,
        blocks: 5,
        shape,
        content: shape ^ 0xc0de,
        bands: None,
        library: false,
    }
}

fn sketch(functions: Vec<FunctionEntry>) -> SampleSketch {
    SampleSketch {
        sha256: "00".repeat(32),
        family: String::new(),
        path: "sample".into(),
        format: "pe".into(),
        arch: "x64".into(),
        packed: false,
        unpacked_dump: false,
        functions,
    }
}

fn family(name: &str) -> FamilyMeta {
    FamilyMeta {
        name: name.into(),
        sample_count: 4,
        unique_shapes: 10,
    }
}

fn exclusive_shapes(family_id: u16, shapes: &[u64]) -> Vec<HashRecord> {
    shapes
        .iter()
        .map(|&hash| HashRecord {
            hash,
            family_id,
            sample_count: 4,
            exclusivity: 1,
            avg_instructions: 60,
        })
        .collect()
}

fn origin(value: &str) -> Result<OriginString, Box<dyn std::error::Error>> {
    let value = normalize_origin_string(value).ok_or("string is not eligible")?;
    Ok(OriginString {
        hash: origin_string_hash(&value),
        value,
        encoding: StringEncoding::Ascii,
        offset: 0,
    })
}

fn hashes(values: &[&str]) -> Result<Vec<u64>, Box<dyn std::error::Error>> {
    values.iter().map(|v| Ok(origin(v)?.hash)).collect()
}

const MALWARE_SHAPES: [u64; 4] = [0x1001, 0x1002, 0x1003, 0x1004];
const RUNTIME_SHAPE: u64 = 0xaaaa;
const EVIL_STRINGS: [&str; 4] = [
    "hxxp://evil.example/gate.php",
    "Global\\EvilLoaderMutex",
    "EvilLoader config v3",
    "evil-loader-campaign-2026",
];
const SHARED_STRING: &str = "Mozilla/5.0 (compatible; BotKit)";
const TRUSTED_STRING: &str = "Copyright (c) Example Runtime Authors";

/// Base pack: `win.evil` code and strings, one runtime function with a symbol.
fn base_v3() -> Result<FamilyPack, Box<dyn std::error::Error>> {
    let shared = MalwareStringRecord::new(origin_string_hash(SHARED_STRING), 9, &[0, 1])?;
    let mut malware: Vec<MalwareStringRecord> = hashes(&EVIL_STRINGS)?
        .into_iter()
        .map(|hash| MalwareStringRecord::new(hash, 4, &[0]))
        .collect::<Result<_, _>>()?;
    malware.push(shared);
    Ok(FamilyPack::from_tables(
        vec![family("win.evil"), family("win.other")],
        vec!["msvc-crt".into()],
        vec![TrustedRecord {
            shape: RUNTIME_SHAPE,
            source_id: 0,
        }],
        vec![],
        vec![],
        exclusive_shapes(0, &MALWARE_SHAPES),
        vec![],
    )
    .with_trusted_symbols(vec![TrustedSymbol {
        shape: RUNTIME_SHAPE,
        name: "__security_init_cookie".into(),
        source_id: Some(0),
    }])?
    .with_trusted_strings(hashes(&[TRUSTED_STRING])?)
    .with_malware_strings(malware)?)
}

fn sample_strings() -> Result<Vec<OriginString>, Box<dyn std::error::Error>> {
    let mut values: Vec<&str> = EVIL_STRINGS.to_vec();
    values.extend([SHARED_STRING, TRUSTED_STRING, "a string nobody has seen"]);
    values.into_iter().map(origin).collect()
}

fn single(pack: FamilyPack) -> FamilyPackSet {
    let mut set = FamilyPackSet::new();
    set.push("base.bxfam", pack);
    set
}

fn without_strings(mut report: MatchReport) -> MatchReport {
    report.strings = None;
    report
}

#[test]
fn bxfam003_round_trips_every_section() -> TestResult {
    let pack = base_v3()?;
    let bytes = pack.to_bytes()?;
    assert_eq!(&bytes[..8], b"BXFAM003");
    let header = PackHeader::read(bytes.as_slice())?;
    assert_eq!(header.format_version, 3);
    assert_eq!(header.format_name(), "BXFAM003");
    assert_eq!(header.stats.trusted_symbols, 1);
    assert_eq!(header.stats.trusted_strings, 1);
    assert_eq!(header.stats.malware_strings, 5);

    let loaded = FamilyPack::from_bytes(&bytes)?;
    assert_eq!(loaded.stats(), pack.stats());
    assert_eq!(loaded.stats(), header.stats);
    assert_eq!(loaded.format_version(), 3);
    let symbol = loaded
        .lookup_trusted_symbol(RUNTIME_SHAPE)
        .ok_or("missing symbol")?;
    assert_eq!(symbol.name, "__security_init_cookie");
    assert_eq!(symbol.source, Some("msvc-crt"));
    assert!(loaded.lookup_trusted_symbol(0xdead).is_none());
    assert!(loaded.is_trusted_string(origin_string_hash(TRUSTED_STRING)));
    assert!(!loaded.is_trusted_string(origin_string_hash(SHARED_STRING)));
    let shared = loaded
        .lookup_malware_string(origin_string_hash(SHARED_STRING))
        .ok_or("missing shared string")?;
    assert_eq!(shared.family_ids(), [0, 1]);
    Ok(())
}

#[test]
fn symbol_pool_is_deduplicated() -> TestResult {
    let symbol = |shape| TrustedSymbol {
        shape,
        name: "memcpy_s".into(),
        source_id: None,
    };
    let pack = FamilyPack::from_tables(vec![], vec![], vec![], vec![], vec![], vec![], vec![])
        .with_trusted_symbols(vec![symbol(3), symbol(1), symbol(2)])?;
    let one = FamilyPack::from_tables(vec![], vec![], vec![], vec![], vec![], vec![], vec![])
        .with_trusted_symbols(vec![symbol(1)])?;
    // Two more 16-byte records, and no repeated name bytes (before compression).
    assert!(pack.to_bytes()?.len() < one.to_bytes()?.len() + 3 * 16);
    let loaded = FamilyPack::from_bytes(&pack.to_bytes()?)?;
    for shape in 1..=3 {
        let symbol = loaded.lookup_trusted_symbol(shape).ok_or("missing")?;
        assert_eq!((symbol.name, symbol.source), ("memcpy_s", None));
    }
    Ok(())
}

#[test]
fn bxfam002_stays_bxfam002_and_reports_no_v3_data() -> TestResult {
    let pack = FamilyPack::from_tables(
        vec![family("win.evil")],
        vec!["msvc-crt".into()],
        vec![TrustedRecord {
            shape: RUNTIME_SHAPE,
            source_id: 0,
        }],
        vec![],
        vec![],
        exclusive_shapes(0, &MALWARE_SHAPES),
        vec![],
    );
    let bytes = pack.to_bytes()?;
    assert_eq!(&bytes[..8], b"BXFAM002");
    let header = PackHeader::read(bytes.as_slice())?;
    assert_eq!(
        (header.format_version, header.format_name().as_str()),
        (2, "BXFAM002")
    );
    assert_eq!(
        (
            header.stats.trusted_symbols,
            header.stats.trusted_strings,
            header.stats.malware_strings
        ),
        (0, 0, 0)
    );
    let loaded = FamilyPack::from_bytes(&bytes)?;
    assert_eq!(loaded.format_version(), 2);
    assert!(!loaded.has_string_data());
    assert!(loaded.lookup_trusted_symbol(RUNTIME_SHAPE).is_none());

    let functions = MALWARE_SHAPES
        .iter()
        .enumerate()
        .map(|(i, &shape)| function(0x1000 * (i as u64 + 1), shape))
        .chain([function(0x9000, RUNTIME_SHAPE)])
        .collect();
    let query = sketch(functions);
    let set = single(loaded.clone());
    let strings = sample_strings()?;
    let report = set.match_sample(&query, Some(&strings), &MatchConfig::default());
    // No string section: strings are unavailable rather than all "unique".
    assert!(report.strings.is_none());
    assert!(report.trusted_symbols.is_empty());
    assert_eq!(report.families[0].family, "win.evil");
    assert_eq!(
        report.families[0].functions[0].pack_name.as_deref(),
        Some("base.bxfam")
    );
    // FamilyPack::match_sketch keeps the BXFAM002 report shape.
    let plain = serde_json::to_value(loaded.match_sketch(&query, &MatchConfig::default()))?;
    assert!(plain.get("strings").is_none() && plain.get("trusted_symbols").is_none());
    assert!(plain["families"][0]["functions"][0]
        .get("pack_name")
        .is_none());
    Ok(())
}

#[test]
fn corrupt_bxfam003_sections_are_errors() -> TestResult {
    let good = base_v3()?.to_bytes()?;
    // Header claims one more trusted symbol than the section holds.
    let mut bad = good.clone();
    bad[40] = 2;
    assert!(FamilyPack::from_bytes(&bad).is_err());
    // Truncated v3 header.
    assert!(PackHeader::read(&good[..44]).is_err());
    assert!(FamilyPack::from_bytes(&good[..50]).is_err());
    // A malware string naming a family the pack does not have.
    let pack = FamilyPack::from_tables(
        vec![family("only")],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
    );
    assert!(pack
        .clone()
        .with_malware_strings(vec![MalwareStringRecord::new(1, 1, &[1])?])
        .is_err());
    assert!(MalwareStringRecord::new(1, 1, &[]).is_err());
    assert!(MalwareStringRecord::new(1, 1, &[0, 1, 2, 3]).is_err());
    assert_eq!(
        MalwareStringRecord::new(1, 1, &[2, 2, 1])?.family_ids(),
        [2, 1]
    );
    assert!(pack
        .with_trusted_symbols(vec![TrustedSymbol {
            shape: 1,
            name: "x".into(),
            source_id: Some(0),
        }])
        .is_err());
    Ok(())
}

#[test]
fn unknown_sections_are_skipped() -> TestResult {
    use std::io::{Read, Write};
    let good = base_v3()?.to_bytes()?;
    let mut body = Vec::new();
    flate2::read::ZlibDecoder::new(&good[56..]).read_to_end(&mut body)?;
    body.extend_from_slice(&99_u32.to_le_bytes());
    body.extend_from_slice(&3_u32.to_le_bytes());
    body.extend_from_slice(b"new");
    let pack_with = |body: &[u8]| -> Result<Vec<u8>, std::io::Error> {
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(body)?;
        Ok([&good[..56], &enc.finish()?].concat())
    };
    let loaded = FamilyPack::from_bytes(&pack_with(&body)?)?;
    assert_eq!(loaded.stats(), base_v3()?.stats());

    // Repeating a section, or a frame longer than the body, is rejected.
    body.extend_from_slice(&99_u32.to_le_bytes());
    body.extend_from_slice(&0_u32.to_le_bytes());
    assert!(FamilyPack::from_bytes(&pack_with(&body)?).is_err());
    body.truncate(body.len() - 8);
    body.extend_from_slice(&100_u32.to_le_bytes());
    body.extend_from_slice(&64_u32.to_le_bytes());
    assert!(FamilyPack::from_bytes(&pack_with(&body)?).is_err());
    Ok(())
}

#[test]
fn trusted_symbols_reach_the_report() -> TestResult {
    let set = single(base_v3()?);
    let report = set.match_sketch(
        &sketch(vec![
            function(0x9000, RUNTIME_SHAPE),
            function(0xa000, 0x77),
        ]),
        &MatchConfig::default(),
    );
    assert_eq!(report.trusted_functions, 1);
    assert_eq!(report.trusted_symbols.len(), 1);
    let hit = &report.trusted_symbols[0];
    assert_eq!(hit.address, 0x9000);
    assert_eq!(hit.trusted_symbol, "__security_init_cookie");
    assert_eq!(hit.source.as_deref(), Some("msvc-crt"));
    assert_eq!(hit.pack_name.as_deref(), Some("base.bxfam"));
    Ok(())
}

#[test]
fn strings_classify_four_ways_without_touching_code_attribution() -> TestResult {
    let set = single(base_v3()?);
    let functions = MALWARE_SHAPES
        .iter()
        .enumerate()
        .map(|(i, &shape)| function(0x1000 * (i as u64 + 1), shape))
        .collect();
    let query = sketch(functions);
    let strings = sample_strings()?;
    let config = MatchConfig::default();
    let with = set.match_sample(&query, Some(&strings), &config);
    let without = set.match_sketch(&query, &config);
    assert_eq!(without_strings(with.clone()), without);

    let s = with.strings.ok_or("missing string report")?;
    assert_eq!(
        (
            s.total_strings,
            s.malware_strings,
            s.shared_strings,
            s.trusted_strings,
            s.unique_strings
        ),
        (7, 4, 1, 1, 1)
    );
    assert_eq!(s.breakdown.malware_pct, 57.14);
    assert_eq!(s.families[0].family, "win.evil");
    assert_eq!(s.families[0].exclusive_strings, 4);
    assert_eq!(s.families[0].shared_strings, 1);
    assert!(s.families[0].corroborates_code);
    assert!(!s.families[1].corroborates_code);
    // Code attributed a family, so there is no string-only hint.
    assert!(s.string_only_hint.is_none());
    assert_eq!(s.entries.len(), 6);
    assert_eq!(s.entries[0].kind, StringOriginKind::Malware);
    assert_eq!(s.entries[4].kind, StringOriginKind::Shared);
    assert_eq!(s.entries[4].families, ["win.evil", "win.other"]);
    assert_eq!(s.entries[5].kind, StringOriginKind::Trusted);
    assert_eq!(
        s.entries[5].hash,
        format!("{:016x}", origin_string_hash(TRUSTED_STRING))
    );
    Ok(())
}

#[test]
fn string_hits_never_turn_an_abstention_into_a_verdict() -> TestResult {
    let set = single(base_v3()?);
    // Only one malware function: below every code threshold.
    let query = sketch(vec![
        function(0x1000, MALWARE_SHAPES[0]),
        function(0x2000, 0x5555),
        function(0x3000, 0x6666),
    ]);
    let strings = sample_strings()?;
    let config = MatchConfig::default();
    let report = set.match_sample(&query, Some(&strings), &config);
    assert!(report.families.is_empty(), "{:?}", report.families);
    assert_eq!(report.family_matched_functions, 0);
    assert_eq!(report.breakdown.malware_pct, 0.0);
    assert_eq!(
        without_strings(report.clone()),
        set.match_sketch(&query, &config)
    );
    let hint = report
        .strings
        .as_ref()
        .and_then(|s| s.string_only_hint.as_ref())
        .ok_or("missing hint")?;
    assert_eq!(
        (hint.family.as_str(), hint.exclusive_strings),
        ("win.evil", 4)
    );

    // Two exclusive strings are not enough for a hint.
    let few: Vec<OriginString> = sample_strings()?.into_iter().skip(2).collect();
    let report = set.match_sample(&query, Some(&few), &config);
    assert!(report.families.is_empty());
    let strings = report.strings.ok_or("missing string report")?;
    assert_eq!(strings.malware_strings, 2);
    assert!(strings.string_only_hint.is_none());
    Ok(())
}

#[test]
fn tied_string_families_give_no_hint() -> TestResult {
    let ids = hashes(&EVIL_STRINGS)?;
    let mut records = Vec::new();
    for (i, hash) in ids.into_iter().enumerate() {
        records.push(MalwareStringRecord::new(hash, 1, &[0])?);
        let other = origin_string_hash(&format!("other family marker {i}"));
        records.push(MalwareStringRecord::new(other, 1, &[1])?);
    }
    let pack = FamilyPack::from_tables(
        vec![family("win.a"), family("win.b")],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
    )
    .with_malware_strings(records)?;
    let mut strings = sample_strings()?;
    for i in 0..4 {
        strings.push(origin(&format!("other family marker {i}"))?);
    }
    let report = single(pack).match_sample(&sketch(vec![]), Some(&strings), &Default::default());
    let s = report.strings.ok_or("missing string report")?;
    assert_eq!(
        (
            s.families[0].exclusive_strings,
            s.families[1].exclusive_strings
        ),
        (4, 4)
    );
    assert!(s.string_only_hint.is_none());
    Ok(())
}

#[test]
fn overlay_trust_silences_base_malware_matches() -> TestResult {
    let functions: Vec<FunctionEntry> = MALWARE_SHAPES
        .iter()
        .enumerate()
        .map(|(i, &shape)| function(0x1000 * (i as u64 + 1), shape))
        .chain([function(0x9000, RUNTIME_SHAPE)])
        .collect();
    let query = sketch(functions);
    let strings = sample_strings()?;
    let config = MatchConfig::default();

    // An organization's Trusted overlay (BXFAM003) over the base (BXFAM002 + BXFAM003 mix).
    let overlay = FamilyPack::from_tables(
        vec![],
        vec!["my-org".into()],
        MALWARE_SHAPES[..2]
            .iter()
            .chain([&RUNTIME_SHAPE])
            .map(|&shape| TrustedRecord {
                shape,
                source_id: 0,
            })
            .collect(),
        vec![],
        vec![],
        vec![],
        vec![],
    )
    .with_trusted_symbols(vec![
        TrustedSymbol {
            shape: RUNTIME_SHAPE,
            name: "OrgRuntimeInit".into(),
            source_id: Some(0),
        },
        TrustedSymbol {
            shape: MALWARE_SHAPES[0],
            name: "OrgSharedHelper".into(),
            source_id: None,
        },
    ])?
    .with_trusted_strings(hashes(&EVIL_STRINGS[..1])?);
    let overlay = FamilyPack::from_bytes(&overlay.to_bytes()?)?;
    let base = FamilyPack::from_bytes(&base_v3()?.to_bytes()?)?;

    let base_only = single(base.clone()).match_sample(&query, Some(&strings), &config);
    assert_eq!(base_only.families[0].exclusive_functions, 4);

    let mut set = FamilyPackSet::new();
    set.push("base.bxfam", base);
    set.push("org.bxfam", overlay);
    let report = set.match_sample(&query, Some(&strings), &config);
    // Two of four malware functions are now Trusted; the rest fall below the score threshold.
    assert_eq!(report.trusted_functions, 3);
    assert!(report.families.is_empty(), "{:?}", report.families);
    assert_eq!(report.family_matched_functions, 0);
    assert_eq!(report.unique_addresses, [0x3000, 0x4000]);
    assert!(base_only.families[0]
        .functions
        .iter()
        .all(|f| f.pack_name.as_deref() == Some("base.bxfam")));
    // Overlay source and symbol win over the base for the shared runtime function.
    assert!(report
        .trusted_sources
        .iter()
        .any(|s| s.source == "my-org" && s.addresses == [0x1000, 0x2000, 0x9000]));
    let symbols: Vec<_> = report
        .trusted_symbols
        .iter()
        .map(|s| (s.address, s.trusted_symbol.as_str(), s.pack_name.as_deref()))
        .collect();
    assert_eq!(
        symbols,
        [
            (0x1000, "OrgSharedHelper", Some("org.bxfam")),
            (0x9000, "OrgRuntimeInit", Some("org.bxfam")),
        ]
    );
    // The overlay's Trusted string silences the base's malware string.
    let s = report.strings.ok_or("missing string report")?;
    assert_eq!((s.malware_strings, s.trusted_strings), (3, 2));
    Ok(())
}

#[test]
fn layers_merge_families_without_double_counting() -> TestResult {
    let pack = |name: &str| {
        FamilyPack::from_tables(
            vec![family("win.unrelated"), family(name)],
            vec![],
            vec![],
            vec![],
            vec![],
            exclusive_shapes(1, &MALWARE_SHAPES),
            vec![],
        )
    };
    let query = sketch(
        MALWARE_SHAPES
            .iter()
            .enumerate()
            .map(|(i, &shape)| function(0x1000 * (i as u64 + 1), shape))
            .collect(),
    );
    let config = MatchConfig::default();
    let one = single(pack("win.evil")).match_sketch(&query, &config);
    let mut set = FamilyPackSet::new();
    set.push("a.bxfam", pack("win.evil"));
    set.push("b.bxfam", pack("win.evil"));
    let two = set.match_sketch(&query, &config);
    assert_eq!(two.families.len(), 1);
    assert_eq!(two.families[0].exclusive_functions, 4);
    assert_eq!(two.families[0].score, one.families[0].score);
    assert_eq!(two.family_matched_functions, 4);
    Ok(())
}

#[test]
fn extracted_strings_feed_the_matcher() -> TestResult {
    let mut bytes = b"MZ\0\0hxxp://evil.example/gate.php\0\0".to_vec();
    for c in "Global\\EvilLoaderMutex".encode_utf16() {
        bytes.extend_from_slice(&c.to_le_bytes());
    }
    bytes.extend_from_slice(b"\0\0EvilLoader config v3\0");
    let strings = extract_origin_strings(&bytes);
    assert_eq!(strings.len(), 3);
    assert_eq!(strings[1].encoding, StringEncoding::Utf16le);
    let report =
        single(base_v3()?).match_sample(&sketch(vec![]), Some(&strings), &Default::default());
    let s = report.strings.ok_or("missing string report")?;
    assert_eq!(s.malware_strings, 3);
    assert_eq!(
        s.string_only_hint.map(|h| h.family).as_deref(),
        Some("win.evil")
    );
    Ok(())
}

/// Reads a real `BXFAM002` pack when `BINFERA_LIVE_FAMILY_PACK` names one. Packs are never
/// committed to this repository.
#[test]
fn live_bxfam002_pack_smoke() -> TestResult {
    let Some(path) = std::env::var_os("BINFERA_LIVE_FAMILY_PACK") else {
        return Ok(());
    };
    let bytes = std::fs::read(&path)?;
    let header = PackHeader::read(bytes.as_slice())?;
    let pack = FamilyPack::from_bytes(&bytes)?;
    assert_eq!(pack.stats(), header.stats);
    let set = single(pack);
    let sample = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/testfiles/mimikatz.exe_"
    ))?;
    let query = binfera::family::sketch_bytes(&sample, "", "mimikatz.exe_", false)?;
    let strings = extract_origin_strings(&sample);
    let config = MatchConfig::default();
    let report = set.match_sample(&query, Some(&strings), &config);
    assert_eq!(report.strings.is_some(), set.has_string_data());
    assert_eq!(without_strings(report), set.match_sketch(&query, &config));
    Ok(())
}
