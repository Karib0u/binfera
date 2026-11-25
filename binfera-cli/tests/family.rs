#![cfg(not(target_arch = "wasm32"))]

use binfera::family::{
    sketch_bytes, BandRecord, FamilyMeta, FamilyPack, HashRecord, SharedRecord, TrustedRecord,
};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdout, Command, Stdio};

fn cli(data_dir: &Path) -> Command {
    let mut cli = Command::new(env!("CARGO_BIN_EXE_binfera"));
    cli.env("BINFERA_DATA_DIR", data_dir)
        .env_remove("BINFERA_FAMILY_PACK")
        .env_remove("BINFERA_RULES_DIR")
        .env_remove("CAPA_RULES_DIR");
    cli
}

fn family() -> FamilyMeta {
    FamilyMeta {
        name: "synthetic-family".into(),
        sample_count: 1,
        unique_shapes: 2,
    }
}

fn info(command: &mut Command) -> Value {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn family_info_resolves_paths_and_reads_only_the_header() {
    let dir = tempfile::tempdir().unwrap();
    let installed = dir.path().join("family.bxfam");
    let configured = dir.path().join("configured pack.bxfam");
    let pack = FamilyPack::from_tables(
        vec![family()],
        vec!["synthetic-runtime".into()],
        vec![TrustedRecord {
            shape: 1,
            source_id: 0,
        }],
        vec![],
        vec![],
        vec![],
        vec![BandRecord {
            band_hash: 2,
            family_id: 0,
            sample_count: 1,
        }],
    );
    let bytes = pack.to_bytes().unwrap();
    // The decompressor would reject this body. Info only needs the fixed header.
    fs::write(&installed, [&bytes[..40], b"invalid body"].concat()).unwrap();
    fs::write(&configured, &bytes).unwrap();
    let report = info(
        cli(dir.path())
            .args(["family", "info", "--json"])
            .env("BINFERA_FAMILY_PACK", dir.path().join("missing.bxfam")),
    );
    assert_eq!(report["path"], installed.to_string_lossy().as_ref());
    assert_eq!(report["size"], 52);
    assert_eq!(report["family_count"], 1);
    assert_eq!(report["trusted_source_count"], 1);
    assert_eq!(report["trusted_shape_count"], 1);
    assert_eq!(report["format_version"], 2);
    assert_eq!(
        report["lsh"],
        json!({"enabled":true, "bands":8, "slots_per_band":4, "band_records":1})
    );

    let report = info(
        cli(dir.path())
            .args(["family", "info", "--json"])
            .env("BINFERA_FAMILY_PACK", &configured),
    );
    assert_eq!(report["path"], configured.to_string_lossy().as_ref());
    let report = info(
        cli(dir.path())
            .args(["family", "info", "--json", "--pack"])
            .arg(&installed)
            .env("BINFERA_FAMILY_PACK", &configured),
    );
    assert_eq!(report["path"], installed.to_string_lossy().as_ref());

    fs::remove_file(&installed).unwrap();
    let output = cli(dir.path())
        .args(["family", "match", "input.exe"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("BINFERA_FAMILY_PACK") && error.contains("family.bxfam"),
        "{error}"
    );
}

struct Mcp {
    child: Child,
    stdout: BufReader<ChildStdout>,
}

impl Mcp {
    fn spawn(cli: &mut Command) -> Self {
        let mut child = cli
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self { child, stdout }
    }

    fn call(&mut self, name: &str, args: Value) -> Value {
        let message = json!({"jsonrpc":"2.0", "id":1, "method":"tools/call",
            "params":{"name":name, "arguments":args}});
        writeln!(self.child.stdin.as_mut().unwrap(), "{message}").unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        let response: Value = serde_json::from_str(&line).unwrap();
        let result = &response["result"];
        assert_eq!(result["isError"], false, "{name}: {response}");
        result["structuredContent"].clone()
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        self.child.stdin.take();
        let _ = self.child.wait();
    }
}

#[test]
fn mcp_code_origin_with_and_without_an_installed_pack() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("demo.exe");
    let bytes = include_bytes!("../../web/public/demo.exe");
    fs::write(&path, bytes).unwrap();
    let sketch = sketch_bytes(bytes, "", "demo.exe", false).unwrap();
    let mut eligible: Vec<_> = sketch
        .functions
        .iter()
        .filter(|f| !f.library && f.instructions >= 20 && f.blocks >= 2)
        .collect();
    eligible.sort_by_key(|f| std::cmp::Reverse(f.instructions));
    let [first, second, trusted, shared, unique, ..] = eligible.as_slice() else {
        panic!(
            "the demo needs five eligible functions, got {}",
            eligible.len()
        );
    };
    let pack = FamilyPack::from_tables(
        vec![family()],
        vec!["synthetic-runtime".into()],
        vec![TrustedRecord {
            shape: trusted.shape,
            source_id: 0,
        }],
        vec![SharedRecord {
            shape: shared.shape,
            family_count: 3,
        }],
        [first, second]
            .iter()
            .map(|f| HashRecord {
                hash: f.content,
                family_id: 0,
                sample_count: 1,
                exclusivity: 1,
                avg_instructions: f.instructions as u16,
            })
            .collect(),
        vec![],
        vec![],
    );
    let report = pack.match_sketch(&sketch, &Default::default());
    assert_eq!(report.family_matched_functions, 2, "{report:?}");
    assert!(
        report.unique_addresses.contains(&unique.address),
        "{report:?}"
    );

    // Seed the existing decompiler cache so this test also runs without the decompiler feature.
    let cache = dir.path().join("cache");
    fs::create_dir(&cache).unwrap();
    let version =
        binfera::VERSION_STRING.replace(|c: char| !c.is_ascii_alphanumeric() && c != '.', "_");
    let mut decompile =
        fs::File::create(cache.join(format!("{}-{version}.decomp.jsonl", sketch.sha256))).unwrap();
    for f in [first, second, trusted, shared, unique] {
        let name = format!("FUN_{:x}", f.address);
        writeln!(
            decompile,
            "{}",
            json!({"type":"function", "address":f.address,
            "name":name, "text":format!("void {name}(void) {{}}")})
        )
        .unwrap();
    }
    drop(decompile);

    let project_id = format!("sha256:{}", sketch.sha256);
    let project = json!({"project_id":project_id});
    let mut mcp = Mcp::spawn(&mut cli(dir.path()));
    assert_eq!(
        mcp.call("open_binary", json!({"path":path}))["project_id"],
        project_id
    );
    assert!(mcp
        .call("get_overview", project.clone())
        .get("code_origin")
        .is_none());
    assert_eq!(
        mcp.call("get_code_origin", project.clone()),
        json!({"status":"unavailable", "pack":{"available":false}})
    );
    let undocumented = json!({"project_id":project_id, "filter":"undocumented"});
    let functions = mcp.call("list_functions", undocumented.clone());
    assert_eq!(functions["total"], 5);
    assert!(functions["functions"][0].get("origin").is_none());
    assert_eq!(
        mcp.call(
            "list_functions",
            json!({"project_id":project_id, "origin":"trusted"})
        )["total"],
        0
    );
    let detail = json!({"project_id":project_id, "address":format!("{:#x}", trusted.address)});
    assert!(mcp
        .call("get_function", detail.clone())
        .get("origin")
        .is_none());

    let pack_path = dir.path().join("family.bxfam");
    fs::write(&pack_path, pack.to_bytes().unwrap()).unwrap();
    mcp.call("open_binary", json!({"path":path}));
    let overview = mcp.call("get_overview", project.clone());
    let summary = &overview["code_origin"];
    assert_eq!(summary["status"], "ready");
    assert_eq!(summary["top_family"]["name"], "synthetic-family");
    assert_eq!(
        summary["breakdown"]["trusted_pct"],
        report.breakdown.trusted_pct
    );

    let origin = mcp.call(
        "get_code_origin",
        json!({"project_id":project_id, "include_functions":true}),
    );
    assert_eq!(origin["pack"]["available"], true);
    assert_eq!(origin["pack"]["format_version"], 2);
    assert_eq!(
        origin["function_counts"],
        json!({
            "malware":2, "trusted":report.trusted_functions,
            "unique":report.unique_functions, "shared":report.shared_malware_functions
        })
    );
    assert_eq!(origin["families"][0]["matched_functions"], 2);
    assert_eq!(origin["families"][0]["shared_count"], 0);
    assert_eq!(origin["families"][0]["confidence"], "weak");
    assert!(origin["trusted_sources"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["name"] == "synthetic-runtime"));
    assert_eq!(origin["top_malware_functions"].as_array().unwrap().len(), 2);

    let functions = mcp.call("list_functions", undocumented.clone());
    assert_eq!(functions["total"], 4);
    for (kind, function, metadata) in [
        (
            "trusted",
            trusted,
            json!({"kind":"trusted", "trusted_source":"synthetic-runtime"}),
        ),
        (
            "malware",
            first,
            json!({"kind":"malware", "family":"synthetic-family"}),
        ),
        ("shared", shared, json!({"kind":"shared"})),
        ("unique", unique, json!({"kind":"unique"})),
    ] {
        let listed = mcp.call(
            "list_functions",
            json!({"project_id":project_id,"origin":kind}),
        );
        assert_eq!(listed["total"], if kind == "malware" { 2 } else { 1 });
        let address = format!("{:#x}", function.address);
        let listed = listed["functions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["address"] == address)
            .unwrap();
        assert_eq!(listed["origin"], metadata);
    }
    assert_eq!(
        mcp.call("get_function", detail)["origin"],
        json!({"kind":"trusted", "trusted_source":"synthetic-runtime"})
    );
    assert_eq!(
        fs::read_dir(cache)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry
                .file_name()
                .to_string_lossy()
                .ends_with(".family.json"))
            .count(),
        1
    );

    // The same sample needs a fresh match when the pack changes.
    let empty = FamilyPack::from_tables(vec![], vec![], vec![], vec![], vec![], vec![], vec![]);
    fs::write(&pack_path, empty.to_bytes().unwrap()).unwrap();
    let origin = mcp.call("get_code_origin", project.clone());
    assert_eq!(origin["status"], "ready");
    assert_eq!(origin["pack"]["family_count"], 0);
    assert_eq!(origin["function_counts"]["malware"], 0);
    assert_eq!(mcp.call("list_functions", undocumented)["total"], 5);

    // A new server can read the completed report even if the original input is gone.
    drop(mcp);
    fs::remove_file(path).unwrap();
    let mut mcp = Mcp::spawn(&mut cli(dir.path()));
    assert_eq!(mcp.call("get_code_origin", project), origin);
}
