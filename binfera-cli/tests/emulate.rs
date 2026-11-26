use std::process::Command;

#[cfg(not(feature = "decompiler"))]
#[test]
fn disabled_emulation_has_actionable_error() -> TestResult {
    let output = Command::new(env!("CARGO_BIN_EXE_binfera"))
        .args([
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../tests/decompiler/fixtures.dll"
            ),
            "--emulate",
            "0x140001000",
        ])
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)?.contains("rebuild with --features decompiler"));
    Ok(())
}

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[cfg(feature = "decompiler")]
#[test]
fn cli_emulates_raw_code_and_stdin_requests() -> TestResult {
    use std::io::Write;
    use std::process::Stdio;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("add.bin");
    // lea eax,[rcx+7]; ret
    std::fs::write(&path, [0x8d, 0x41, 7, 0xc3])?;
    let output = Command::new(env!("CARGO_BIN_EXE_binfera"))
        .arg(&path)
        .args(["-f", "sc64", "--emulate", "0", "--emulate-arg", "35"])
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(result["return_value"], 42);
    assert_eq!(result["stop"]["kind"], "returned");
    let mut child = Command::new(env!("CARGO_BIN_EXE_binfera"))
        .arg(&path)
        .args(["-f", "sc64", "--emulate", "0", "--emulate-request"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("missing stdin")?
        .write_all(br#"{"address":0,"args":[35]}"#)?;
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout)?["return_value"],
        42
    );
    let output = Command::new(env!("CARGO_BIN_EXE_binfera"))
        .arg(&path)
        .args(["-f", "sc64", "--emulate", "0", "--decompile-function", "0"])
        .output()?;
    assert!(!output.status.success());
    Ok(())
}

#[cfg(feature = "decompiler")]
#[test]
fn mcp_tools_emulate_a_project_in_child_processes() -> TestResult {
    use serde_json::json;
    let dir = tempfile::tempdir()?;
    let path = std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/decompiler/fixtures.dll"
    ))
    .canonicalize()?;
    let store = binfera_project::Store::open(&dir.path().join("projects.sqlite3"))?;
    let project = store.open_project(&path)?;
    drop(store);
    let mut server = binfera_mcp::Server::new(
        env!("CARGO_BIN_EXE_binfera").into(),
        dir.path(),
        "test-emulation",
    )?;
    let tools = server
        .handle(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
        .ok_or("missing response")?;
    for name in ["emulate_function", "emulate_call_sites"] {
        assert!(tools["result"]["tools"]
            .as_array()
            .ok_or("missing tools")?
            .iter()
            .any(|t| t["name"] == name));
    }
    let image = binfera::extract::image::LoadedImage::parse(&std::fs::read(&path)?)?;
    let address = format!("{:#x}", image.image_base + 0x1000);
    let response=server.handle(&json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"emulate_function","arguments":{"project_id":project.sha256,"address":address,"request":{"args":[6,3]}}}})).ok_or("missing response")?;
    assert_eq!(response["result"]["isError"], false, "{response}");
    let result = &response["result"]["structuredContent"]["result"];
    assert_eq!(result["stop"]["kind"], "returned");
    assert_eq!(result["return_value"], 42);
    let response=server.handle(&json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"emulate_call_sites","arguments":{"project_id":project.sha256,"address":address,"request":{"args":[0,6]},"max_sites":2}}})).ok_or("missing response")?;
    assert_eq!(response["result"]["isError"], false, "{response}");
    assert!(response["result"]["structuredContent"]["result"]["sites"].is_array());
    let response=server.handle(&json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"emulate_function","arguments":{"project_id":project.sha256,"address":address,"request":{"unknown":true}}}})).ok_or("missing response")?;
    assert_eq!(response["result"]["isError"], true);
    Ok(())
}

/// The web UI's call-site run: a string decryption helper, with the request on stdin as the
/// browser worker and the desktop app send it.
#[cfg(feature = "decompiler")]
#[test]
fn cli_call_sites_report_each_calls_own_writes() -> TestResult {
    use std::io::Write;
    use std::process::Stdio;
    // main: decrypt(s1, 5); decrypt(s2, 7). decrypt at 0x2f XORs each byte with 0x5a.
    const XOR_STRINGS: &[u8] = &[
        0x48, 0x83, 0xec, 0x28, 0x48, 0x8d, 0x0d, 0x39, 0, 0, 0, 0xba, 5, 0, 0, 0, 0xe8, 0x1a, 0,
        0, 0, 0x48, 0x8d, 0x0d, 0x2e, 0, 0, 0, 0xba, 7, 0, 0, 0, 0xe8, 9, 0, 0, 0, 0x48, 0x83,
        0xc4, 0x28, 0x31, 0xc0, 0xc3, 0xcc, 0xcc, 0x48, 0x89, 0xc8, 0x85, 0xd2, 0x74, 0x0a, 0x80,
        0x31, 0x5a, 0x48, 0xff, 0xc1, 0xff, 0xca, 0x75, 0xf6, 0xc3, 0xcc, 0xcc, 0xcc, 0x32, 0x3f,
        0x36, 0x36, 0x35, 0, 0x3f, 0x22, 0x3b, 0x37, 0x2a, 0x36, 0x3f, 0,
    ];
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("xor.bin");
    std::fs::write(&path, XOR_STRINGS)?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_binfera"))
        .arg(&path)
        .args([
            "--emulate",
            "0x2f",
            "--emulate-request",
            "--emulate-call-sites",
            "--emulate-max-sites",
            "64",
            "--format",
            "sc64",
            "--os",
            "windows",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("missing stdin")?
        .write_all(br#"{"address":47,"max_steps":2000000,"timeout_ms":15000}"#)?;
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(result["total_sites"], 2);
    let sites = result["sites"].as_array().ok_or("missing sites")?;
    let mut decoded = Vec::new();
    for site in sites {
        assert_eq!(site["reached"], true);
        assert_eq!(site["result"]["stop"]["kind"], "returned");
        // The string is the call's only write off the synthetic stack.
        let text = site["call_writes"]
            .as_array()
            .ok_or("missing call_writes")?
            .iter()
            .filter(|w| w["address"].as_u64().is_some_and(|a| a < 0x1000))
            .map(|w| {
                w["data"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|b| b.as_u64().map(|b| b as u8 as char))
                    .collect::<String>()
            })
            .collect::<Vec<_>>();
        decoded.push(text);
    }
    assert_eq!(decoded, [vec!["hello"], vec!["example"]]);
    Ok(())
}
