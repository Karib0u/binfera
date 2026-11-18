//! Stamps the source commit and compresses the COM databases for embedding.
//! The databases are about 2 MB of text, which counts against
//! the size limit on the browser's WebAssembly module (see web/scripts/build-wasm.sh).
use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg("..")
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn source_commit() -> Option<String> {
    let git_entry = Path::new("../.git");
    // Source archives can be unpacked inside an unrelated checkout.
    if !git_entry.exists() {
        return None;
    }
    if git_entry.is_file() {
        println!("cargo:rerun-if-changed={}", git_entry.display());
    }

    // Git resolves paths for ordinary checkouts and linked worktrees. Track the
    // branch ref even when packed, since advancing it can create a loose ref.
    let mut paths = vec!["HEAD", "packed-refs", "reftable/tables.list"];
    let branch = git(&["symbolic-ref", "--quiet", "HEAD"]);
    if let Some(branch) = &branch {
        paths.push(branch);
    }
    let mut args = vec!["rev-parse", "--path-format=absolute"];
    for path in &paths {
        args.extend(["--git-path", path]);
    }
    if let Some(resolved) = git(&args) {
        for (name, path) in paths.into_iter().zip(resolved.lines()) {
            if Path::new(path).is_file() || Some(name) == branch.as_deref() {
                println!("cargo:rerun-if-changed={path}");
            }
        }
    }
    git(&["rev-parse", "--verify", "HEAD"])
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let commit = source_commit().unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=BINFERA_BUILD_COMMIT={commit}");
    let out = env::var("OUT_DIR")?;
    for name in ["com_classes.json", "com_interfaces.json"] {
        let source = format!("data/{name}");
        println!("cargo:rerun-if-changed={source}");
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&fs::read(&source)?)?;
        fs::write(Path::new(&out).join(format!("{name}.z")), encoder.finish()?)?;
    }
    println!("cargo:rerun-if-changed=build.rs");
    Ok(())
}
