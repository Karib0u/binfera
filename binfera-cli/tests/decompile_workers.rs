#![cfg(feature = "decompiler")]
use serde_json::Value;
use std::collections::BTreeMap;
use std::process::Command;

#[test]
fn workers_match_serial_bodies_and_emit_one_inventory_and_completion() {
    let input =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/decompiler/fixtures.dll");
    let mut reference = None;
    for jobs in [1, 2, 3] {
        let output = Command::new(env!("CARGO_BIN_EXE_binfera"))
            .arg(&input)
            .args(["--decompile-all", "--jobs", &jobs.to_string()])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let events: Vec<Value> = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events.iter().filter(|v| v["type"] == "start").count(), 1);
        assert_eq!(events.iter().filter(|v| v["type"] == "done").count(), 1);
        assert_eq!(events.iter().filter(|v| v["type"] == "settled").count(), 1);
        assert!(events
            .iter()
            .filter(|v| v["type"] == "function")
            .all(|v| v.get("timings").is_none()));
        let mut functions = BTreeMap::new();
        for mut event in events {
            if event["type"] != "function" {
                continue;
            }
            let address = event["address"].as_u64().unwrap();
            event.as_object_mut().unwrap().remove("ms");
            event.as_object_mut().unwrap().remove("timings");
            assert!(functions.insert(address, event).is_none());
        }
        assert!(!functions.is_empty());
        if let Some(previous) = &reference {
            assert_eq!(previous, &functions);
        } else {
            reference = Some(functions);
        }
    }
}

#[test]
fn retry_only_selects_one_address_and_uses_longer_limits() {
    let input =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/decompiler/fixtures.dll");
    let export =
        binfera::decompiler::DecompilerSession::from_pe(&std::fs::read(&input).unwrap()).unwrap();
    // Pick a supplied name from the public inventory, independently of PE link addresses.
    let output = Command::new(env!("CARGO_BIN_EXE_binfera"))
        .arg(&input)
        .args(["--decompile-all", "--no-resource-retry", "--jobs", "1"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let start: Value = serde_json::from_str(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    let address = start["functions"][0].as_u64().unwrap();
    assert!(export.function_name(address).is_some());
    let output = Command::new(env!("CARGO_BIN_EXE_binfera"))
        .arg(&input)
        .args([
            "--decompile-all",
            "--decompile-retry",
            &format!("0x{address:x}"),
            "--timing",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let events: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(events[1]["type"], "settled");
    let records: Vec<_> = events.iter().filter(|v| v["type"] == "function").collect();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["address"], address);
    assert_eq!(records[0]["resource_retry"], true);
    assert!(records[0]["text"].is_string());
    assert!(records[0]["timings"].is_object());
}
