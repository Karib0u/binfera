#![allow(clippy::expect_used)]

use std::process::Command;

use serde_json::Value;

const ELF: &[u8] = include_bytes!("../../binfera/tests/fixtures/elf64_sysv/freestanding.elf");
const SHA256: &str = "1e4ad076d20d2b9ef28fa08d8eef32681b73b43af89e70167ec0ec633603d866";

fn run(cmd: &mut Command) -> String {
    let output = cmd.output().expect("CLI starts");
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("CLI emits UTF-8")
}

#[test]
fn repaired_elf_keeps_original_hashes() {
    let temp = tempfile::tempdir().expect("create temporary directory");
    let sample = temp.path().join("sample.elf");
    let other = temp.path().join("other.elf");
    let mut bytes = ELF.to_vec();
    // Both section tables are past EOF. Repair produces the same image for both files.
    let invalid_offset = bytes.len() as u64 + 1;
    bytes[0x28..0x30].copy_from_slice(&invalid_offset.to_le_bytes());
    std::fs::write(&sample, &bytes).expect("write first sample");
    bytes[0x28..0x30].copy_from_slice(&(invalid_offset + 1).to_le_bytes());
    std::fs::write(&other, &bytes).expect("write second sample");

    let bin = env!("CARGO_BIN_EXE_binfera");
    let rules = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../binfera/tests/fixtures/rules/flirt"
    );
    for flags in [&[][..], &["--format", "elf", "--file-only"]] {
        let output = run(Command::new(bin)
            .arg(&sample)
            .args(["-jq", "--rules", rules])
            .args(flags));
        let report: Value = serde_json::from_str(&output).expect("capability report");
        let hashes = &report["meta"]["sample"];
        assert_eq!(hashes["md5"], "cc5f7b368026865e297c12557a52d4bd");
        assert_eq!(hashes["sha1"], "22bf272681ed1e793a4367c967fccce16f060943");
        assert_eq!(hashes["sha256"], SHA256);
    }

    let output = run(Command::new(bin).arg("fingerprint").arg(&sample));
    let header: Value = serde_json::from_str(output.lines().next().expect("fingerprint header"))
        .expect("fingerprint JSON");
    assert_eq!(header["sha256"], SHA256);

    let output = run(Command::new(bin)
        .arg("diff")
        .args([&sample, &other])
        .args(["--no-capabilities", "-j"]));
    let report: Value = serde_json::from_str(&output).expect("diff report");
    assert_eq!(report["verdict"], "equivalent");
    assert_eq!(report["inputs"][0]["sha256"], SHA256);
    assert_ne!(report["inputs"][0]["sha256"], report["inputs"][1]["sha256"]);
}
