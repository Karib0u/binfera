#![allow(clippy::unwrap_used, clippy::expect_used)]
use binfera::{
    api,
    extract::{
        flirt::{identify_library_functions, Signatures},
        image::LoadedImage,
        recovery,
    },
    features::Feature,
    freeze::Freeze,
    parallel::AnalysisOptions,
};
use std::{fmt::Write, path::PathBuf};
struct Pack(PathBuf);
impl Pack {
    fn new(architecture: &str, pattern: &str) -> Self {
        // Not the clock: on Windows two parallel tests can read the same time.
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let nonce = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("binfera-isa-pack-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("fixture.pat"), pattern).unwrap();
        std::fs::write(
            root.join("pack.json"),
            serde_json::json!({"architecture":architecture,"signatures":["fixture.pat"]})
                .to_string(),
        )
        .unwrap();
        Self(root)
    }
    fn manifest(&self) -> PathBuf {
        self.0.join("pack.json")
    }
}
impl Drop for Pack {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/risc/{name}.elf",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}
fn pattern(bytes: &[u8]) -> String {
    let elf = goblin::elf::Elf::parse(bytes).unwrap();
    let symbol = elf
        .syms
        .iter()
        .find(|s| elf.strtab.get_at(s.st_name) == Some("mix"))
        .unwrap();
    let image = LoadedImage::parse(bytes).unwrap();
    let raw = image.bytes_at(symbol.st_value & !1, 32).unwrap();
    let length = (symbol.st_size as usize).min(32);
    let mut pattern = String::new();
    for byte in &raw[..length] {
        write!(pattern, "{byte:02X}").unwrap();
    }
    pattern.push_str(&"..".repeat(32 - length));
    format!(
        "{pattern} 00 0000 {:04X} :0000 fixture_library_mix\n---",
        symbol.st_size
    )
}
#[test]
fn scoped_packs_name_library_functions_and_enrich_callers_on_each_isa() {
    for (name, arch) in [
        ("arm", "arm"),
        ("thumb", "arm"),
        ("aarch64", "aarch64"),
        ("mips", "mips"),
        ("mipsel", "mipsel"),
    ] {
        let bytes = fixture(name);
        let pack = Pack::new(arch, &pattern(&bytes));
        let options = AnalysisOptions {
            signatures_path: Some(pack.manifest()),
            ..Default::default()
        };
        let (loaded, _) = api::load_input(&bytes, &options, &mut Default::default()).unwrap();
        assert!(
            loaded
                .library_functions
                .iter()
                .any(|f| f.name == "fixture_library_mix"),
            "{name}: {:?}",
            loaded.library_functions
        );
        let Freeze::Static(features) = loaded.freeze else {
            panic!("static")
        };
        assert!(
            features
                .functions
                .values()
                .flat_map(|f| f.basic_blocks.values())
                .flat_map(|b| b.instructions.values())
                .flat_map(|i| &i.features)
                .any(|(_, f)| matches!(f,Feature::Api(n) if n=="fixture_library_mix")),
            "{name}: no library call feature"
        );
        // An untagged pack never opts a non-x86 image into legacy x86 matching.
        let untagged = Signatures::from_path(&pack.0.join("fixture.pat")).unwrap();
        let analysis = recovery::analyze(&bytes).unwrap();
        assert!(identify_library_functions(&analysis, &untagged)
            .unwrap()
            .is_empty());
    }
}
#[test]
fn signature_manifests_reject_isa_mismatches_and_paths_outside_the_pack() {
    let bytes = fixture("arm");
    let pack = Pack::new("mipsel", &pattern(&bytes));
    let signatures = Signatures::from_path(&pack.manifest()).unwrap();
    let analysis = recovery::analyze(&bytes).unwrap();
    assert!(identify_library_functions(&analysis, &signatures)
        .unwrap_err()
        .to_string()
        .contains("signature pack targets mipsel"));
    std::fs::write(
        pack.manifest(),
        r#"{"architecture":"arm","signatures":["../fixture.pat"]}"#,
    )
    .unwrap();
    assert!(Signatures::from_path(&pack.manifest()).is_err());
    std::fs::write(
        pack.manifest(),
        r#"{"architecture":"arm","signatures":[],"other":true}"#,
    )
    .unwrap();
    assert!(Signatures::from_path(&pack.manifest()).is_err());
}
