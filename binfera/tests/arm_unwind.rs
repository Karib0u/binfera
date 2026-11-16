#![allow(clippy::unwrap_used)]
use binfera::extract::recovery::{self, RecoveryBackend, SeedKind};
fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/risc/{name}-unwind.elf",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}
#[test]
fn arm_exception_indexes_recover_unreferenced_leaves_without_symbols() {
    for mode in ["arm", "thumb"] {
        let original = fixture(mode);
        let elf = goblin::elf::Elf::parse(&original).unwrap();
        let orphan = elf
            .syms
            .iter()
            .find(|s| elf.strtab.get_at(s.st_name) == Some("orphan_leaf"))
            .unwrap()
            .st_value
            & !1;
        let mut bytes = original.clone();
        for (index, section) in elf.section_headers.iter().enumerate() {
            if section.sh_type == goblin::elf::section_header::SHT_SYMTAB {
                let at = elf.header.e_shoff as usize + index * elf.header.e_shentsize as usize + 4;
                bytes[at..at + 4].fill(0);
            }
        }
        for backend in [RecoveryBackend::Native, RecoveryBackend::VivisectCompat] {
            let analysis = recovery::analyze_with_backend(&bytes, backend).unwrap();
            assert!(
                analysis.seeds[&orphan].contains(&SeedKind::ArmExidx),
                "{mode}: {:?}",
                analysis.diagnostics
            );
            assert!(
                analysis.functions.contains_key(&orphan),
                "{mode}: {:?}",
                analysis.diagnostics
            );
            assert_eq!(analysis.image.is_thumb(orphan), mode == "thumb");
            #[cfg(feature = "decompiler")]
            if backend == RecoveryBackend::Native {
                let mut session = binfera::decompiler::DecompilerSession::from_elf(&bytes).unwrap();
                let output = session.decompile_function(orphan).unwrap();
                assert!(
                    output.text.contains("param_1") && output.text.contains("return"),
                    "{mode}: {}",
                    output.text
                );
                assert!(!output.incomplete, "{mode}: {:?}", output.warnings);
            }
        }
    }
}
#[test]
fn invalid_arm_exception_index_addresses_are_diagnosed_without_seeds() {
    let mut bytes = fixture("arm");
    let elf = goblin::elf::Elf::parse(&bytes).unwrap();
    let exidx = elf
        .section_headers
        .iter()
        .find(|s| s.sh_type == 0x70000001)
        .unwrap();
    let offset = exidx.sh_offset as usize;
    bytes[offset..offset + 4].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
    let analysis = recovery::analyze(&bytes).unwrap();
    assert!(analysis
        .diagnostics
        .iter()
        .any(|d| d.message.contains("ARM .exidx: invalid")));
    assert!(!analysis
        .seeds
        .values()
        .any(|kinds| kinds.contains(&SeedKind::ArmExidx)));
}
