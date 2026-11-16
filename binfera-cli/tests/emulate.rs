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
