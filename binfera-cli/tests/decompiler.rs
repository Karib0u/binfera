use std::process::Command;
fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_binfera"));
    command.arg(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/decompiler/fixtures.dll"
    ));
    command
}
#[cfg(not(feature = "decompiler"))]
#[test]
fn disabled_backend_has_an_actionable_error() -> Result<(), Box<dyn std::error::Error>> {
    let output = command()
        .args(["--decompile-function", "0x140001000"])
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)?.contains("rebuild with --features decompiler"));
    Ok(())
}
#[cfg(feature = "decompiler")]
#[test]
fn explicit_function_json_is_independent_of_jobs() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = include_bytes!("../../tests/decompiler/fixtures.dll");
    let image = binfera::extract::image::LoadedImage::parse(bytes)?;
    // arithmetic is the fixture's first export, at RVA 0x1000.
    let address = format!("{:#x}", image.image_base + 0x1000);
    let mut outputs = Vec::new();
    for jobs in ["1", "4"] {
        let output = command()
            .args(["--decompile-function", &address, "--json", "--jobs", jobs])
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(
            json.get("name").and_then(|n| n.as_str()),
            Some("arithmetic")
        );
        assert!(json.get("timings").is_none());
        outputs.push(output.stdout);
    }
    assert_eq!(outputs.first(), outputs.get(1));
    let timed = command()
        .args(["--decompile-function", &address, "--json", "--timing"])
        .output()?;
    assert!(timed.status.success());
    let json: serde_json::Value = serde_json::from_slice(&timed.stdout)?;
    assert!(json.get("timings").is_some());
    Ok(())
}
#[test]
fn invalid_address_is_rejected_by_argument_parser() -> Result<(), Box<dyn std::error::Error>> {
    let output = command()
        .args(["--decompile-function", "not-hex"])
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)?.contains("invalid hexadecimal function address"));
    Ok(())
}

/// A file past `--max-instructions` is refused with capa's file-limitation code (14) and a message
/// that says why, instead of running out of memory.
#[test]
fn instruction_limit_refuses_the_file_with_a_clear_error() -> Result<(), Box<dyn std::error::Error>>
{
    let rules = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../binfera/tests/fixtures/rules/flirt"
    );
    let mut runs = vec![vec!["--json", "--rules", rules, "--max-instructions", "5"]];
    if cfg!(feature = "decompiler") {
        runs.push(vec!["--decompile-all", "--max-instructions", "5"]);
    }
    for args in runs {
        let output = command().args(&args).output()?;
        assert_eq!(output.status.code(), Some(14), "{args:?}");
        let stderr = String::from_utf8(output.stderr)?;
        assert!(
            stderr.contains("too large to analyze") && stderr.contains("5 instructions"),
            "{args:?}: {stderr}"
        );
    }
    let output = command()
        .args(["--json", "--rules", rules, "--max-instructions", "0"])
        .output()?;
    assert!(output.status.success(), "0 removes the limit");
    Ok(())
}

#[cfg(feature = "decompiler")]
#[test]
fn macho_cli_auto_detection_and_selected_slice_reach_decompiler(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../binfera/tests/fixtures/macho/fat-x86_64-arm64-exe"
    );
    for (arch, entry, convention) in [
        ("x86_64", "0x100000510", "darwin_x64"),
        ("arm64", "0x1000004f8", "darwin_a_arch64"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_binfera"))
            .args([
                path,
                "--arch",
                arch,
                "--decompile-function",
                entry,
                "--json",
            ])
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(result["calling_convention"], convention);
        assert!(result["text"]
            .as_str()
            .unwrap_or_default()
            .contains("malloc(0x10)"));
        let output = Command::new(env!("CARGO_BIN_EXE_binfera"))
            .args([path, "--arch", arch, "--decompile-all"])
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("malloc(0x10)"));
        // The viewer reads branches out of the listing by architecture, so the first record names
        // it, and AArch64 rows carry disassembly text as x86 ones do.
        let mut records = stdout
            .lines()
            .map(serde_json::from_str::<serde_json::Value>);
        let start = records.next().ok_or("no start record")??;
        assert_eq!(
            start["arch"],
            if arch == "arm64" { "aarch64" } else { "x64" }
        );
        assert_eq!(start["packed"], serde_json::Value::Null);
        for record in records {
            let record = record?;
            for row in record["asm"].as_array().into_iter().flatten() {
                assert_ne!(row[2], "", "{row}");
            }
        }
    }
    Ok(())
}

#[cfg(feature = "decompiler")]
#[test]
fn raw_code_decompiles_at_file_offsets_in_both_modes() -> Result<(), Box<dyn std::error::Error>> {
    let path =
        std::env::temp_dir().join(format!("binfera-raw-decompile-{}.bin", std::process::id()));
    let mut code = vec![0xe8, 11, 0, 0, 0, 0xc3];
    code.resize(16, 0xcc);
    code.extend_from_slice(&[0xb8, 42, 0, 0, 0, 0xc3]);
    std::fs::write(&path, &code)?;
    for format in ["sc32", "sc64"] {
        for os in ["windows", "linux"] {
            let output = Command::new(env!("CARGO_BIN_EXE_binfera"))
                .arg(&path)
                .args(["-f", format, "--os", os, "--decompile-all"])
                .output()?;
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let records = String::from_utf8(output.stdout)?
                .lines()
                .map(serde_json::from_str::<serde_json::Value>)
                .collect::<Result<Vec<_>, _>>()?;
            for address in [0, 16] {
                assert!(
                    records.iter().any(|r| r["type"] == "function"
                        && r["address"] == address
                        && r["text"].is_string()),
                    "{format} {os}: {records:?}"
                );
            }
            let output = Command::new(env!("CARGO_BIN_EXE_binfera"))
                .arg(&path)
                .args([
                    "-f",
                    format,
                    "--os",
                    os,
                    "--decompile-function",
                    "0x10",
                    "--json",
                ])
                .output()?;
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let result: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            assert!(result["text"]
                .as_str()
                .unwrap_or_default()
                .contains("return 0x2a;"));
        }
    }
    std::fs::remove_file(&path)?;
    Ok(())
}

#[test]
fn image_metadata_is_available_without_rules_or_the_decompiler(
) -> Result<(), Box<dyn std::error::Error>> {
    let output = command().arg("--image-info").output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(json["ptrSize"], 8);
    assert_eq!(json["format"], "pe");
    assert!(json["regions"].as_array().is_some_and(|r| !r.is_empty()));
    Ok(())
}
