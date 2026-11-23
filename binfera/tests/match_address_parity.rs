//! Exact rule and address regressions against the immutable capa 10.0.0 index.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::Path;

use binfera::address::Address;
use binfera::api::{analyze, Input};
use binfera::capabilities::MatchingRuleSet;
use binfera::parallel::AnalysisOptions;
use binfera::result_document::RdAddress;
use binfera::rules::{collect_rule_file_paths, Rule};
use flate2::read::GzDecoder;

#[derive(serde::Deserialize)]
struct MatchDelta {
    added: BTreeMap<String, Vec<u64>>,
    removed: BTreeMap<String, Vec<u64>>,
}

#[test]
fn recovered_functions_match_all_reference_rule_addresses() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut expected: BTreeMap<String, BTreeMap<String, BTreeSet<RdAddress>>> =
        serde_json::from_reader(GzDecoder::new(
            File::open(root.join("tests/reference-results/capa-10.0.0/matches.json.gz")).unwrap(),
        ))
        .unwrap();
    // The pinned reference does not seed Guard CF entries. This entry calls RtlGenRandom,
    // imported under its SystemFunction036 name.
    expected
        .get_mut("17264e3126a97c319a6a0c61e6da951e.dll_")
        .unwrap()
        .entry("generate random numbers via RtlGenRandom".to_string())
        .or_default()
        .insert(RdAddress::from(&Address::Absolute(0x5fda_ca40)));
    // Python capa 10.0.0 stops seeding at the first unusable x64 unwind row.
    // These four fixtures contain version 2 unwind headers or leading zero rows.
    // Check the observed match-location changes while keeping the upstream index pinned.
    let unwind_deltas: BTreeMap<String, MatchDelta> =
        serde_json::from_str(include_str!("fixtures/x64-unwind-match-deltas.json")).unwrap();
    for (sample, delta) in unwind_deltas {
        let rules = expected.get_mut(&sample).unwrap();
        for (rule, addresses) in delta.added {
            let locations = rules.entry(rule).or_default();
            for address in addresses {
                assert!(locations.insert(RdAddress::from(&Address::Absolute(address))));
            }
        }
        for (rule, addresses) in delta.removed {
            let locations = rules.get_mut(&rule).unwrap();
            for address in addresses {
                assert!(locations.remove(&RdAddress::from(&Address::Absolute(address))));
            }
        }
    }
    let mut paths = Vec::new();
    collect_rule_file_paths(&root.join("rules"), &mut paths);
    paths.sort();
    let rules = MatchingRuleSet::new(
        paths
            .iter()
            .map(|path| Rule::from_yaml_file(path).unwrap())
            .collect(),
    )
    .unwrap();
    for sample in [
        // A computed memory jump exposes a recursive callee before importcalls.
        "0ce3bfa972ced61884ae7c1d77c7d4c45e17c7d767e669610cf2ef72b636b464.exe_",
        // Existing typed data must not create additional loop-bearing functions.
        "17264e3126a97c319a6a0c61e6da951e.dll_",
        // SSE instructions in a pointer-backed function candidate.
        "22d0a2e4c9c2163b2bf5f0e41a2e1762.exe_",
        // A prefixed LOOP keeps the complete 32-bit branch address.
        "2826b762b9c268601a44974ef469a671b441e798a6c3cbb40070450c6c030ba2.exe_",
        // Import-fragment extents must also constrain no-return propagation.
        "e5369ac309f1be6d77afeeb3edab0ed8.exe_",
        // A function falls through an unwind entry but keeps its creation extent.
        "e3a6fbbc9b315141da37e5abbae05bf20aa9f48d5f569c6353360f59a0315245.exe_",
        // Extended selectors and image-relative dispatch without a nearby guard.
        "276f691a3df25481f59d79781799e35f.exe_",
        "82bf6347acf15e5d883715dc289d8a2b.exe_",
        "a6594d9550d56ddeaac8b3140821e698eefb7163ba29f0119c2ef19beb6040b0.exe_",
        "ad4229879180e267f431ac6666b6a0a2.exe_",
        "f59035192098e44b86c4648a0de4078edbe80352260276f4755d15d354f5fc58.exe_",
    ] {
        let bytes = std::fs::read(root.join("tests/testfiles").join(sample)).unwrap();
        let input = Input {
            bytes: &bytes,
            sample_path: sample.into(),
            rules_paths: vec!["rules".into()],
            argv: Some(Vec::new()),
        };
        let result = analyze(&input, &rules, &AnalysisOptions::SERIAL).unwrap();
        let actual: BTreeMap<_, BTreeSet<_>> = result
            .rules
            .into_iter()
            .map(|(name, rule)| {
                (
                    name,
                    rule.matches
                        .into_iter()
                        .map(|(address, _)| address)
                        .collect(),
                )
            })
            .collect();
        assert_eq!(&actual, expected.get(sample).unwrap(), "{sample}");
    }
}

#[test]
fn overlapping_data_and_calling_traces_do_not_add_rule_names() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let expected: BTreeMap<String, BTreeMap<String, BTreeSet<RdAddress>>> =
        serde_json::from_reader(GzDecoder::new(
            File::open(root.join("tests/reference-results/capa-10.0.0/matches.json.gz")).unwrap(),
        ))
        .unwrap();
    let mut paths = Vec::new();
    collect_rule_file_paths(&root.join("rules"), &mut paths);
    paths.sort();
    let rules = MatchingRuleSet::new(
        paths
            .iter()
            .map(|path| Rule::from_yaml_file(path).unwrap())
            .collect(),
    )
    .unwrap();
    // These samples still have address differences. This test specifically
    // guards the two rule-name regressions introduced by the preceding change.
    for sample in [
        "648fc498110b11b4313a47a776e6ba40.exe_",
        "971e599e6e707349eccea2fd4c8e5f67.exe_",
    ] {
        let bytes = std::fs::read(root.join("tests/testfiles").join(sample)).unwrap();
        let input = Input {
            bytes: &bytes,
            sample_path: sample.into(),
            rules_paths: vec!["rules".into()],
            argv: Some(Vec::new()),
        };
        let result = analyze(&input, &rules, &AnalysisOptions::SERIAL).unwrap();
        assert_eq!(
            result.rules.keys().collect::<BTreeSet<_>>(),
            expected[sample].keys().collect::<BTreeSet<_>>(),
            "{sample}"
        );
    }
}
