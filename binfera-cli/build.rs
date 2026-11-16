//! Packs the capability rules into the binary, so a lone `binfera` works from any folder.
//!
//! The rules are read from `BINFERA_EMBED_RULES_DIR`, else `../rules` (the git submodule). The pack
//! is a flat sequence of `[u32 path length][path][u32 data length][data]` records, little endian,
//! one per `.yml` file. With no rules on disk the pack is empty and the binary falls back to a rules
//! folder beside it, as before. WebAssembly builds get the rules from the page and embed nothing.
use std::path::{Path, PathBuf};
use std::{env, fs};

fn collect(dir: &Path, root: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        // Only rule files; hidden entries (`.git`, `.github`) are never rules.
        if name.to_string_lossy().starts_with('.') {
            continue;
        }
        if path.is_dir() {
            collect(&path, root, out);
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yml" | "yaml")
        ) {
            let relative = path.strip_prefix(root).unwrap_or(&path);
            out.push((relative.to_string_lossy().replace('\\', "/"), path));
        }
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=BINFERA_EMBED_RULES_DIR");
    let mut pack = Vec::new();
    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("wasm32") {
        let root = env::var_os("BINFERA_EMBED_RULES_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                Path::new(&env::var("CARGO_MANIFEST_DIR").expect("manifest dir")).join("../rules")
            });
        println!("cargo:rerun-if-changed={}", root.display());
        let mut files = Vec::new();
        collect(&root, &root, &mut files);
        for (name, path) in files {
            let data = fs::read(&path).expect("reading a rule file");
            pack.extend((name.len() as u32).to_le_bytes());
            pack.extend(name.as_bytes());
            pack.extend((data.len() as u32).to_le_bytes());
            pack.extend(data);
        }
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("out dir")).join("rules.pack");
    fs::write(out, pack).expect("writing the rules pack");
}
