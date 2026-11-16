#![cfg(feature = "decompiler")]
use binfera::{decompiler::DecompilerSession, extract::image::LoadedImage};

#[test]
fn relocatable_objects_map_zero_offset_symbols_bss_and_calls() -> anyhow::Result<()> {
    for bytes in [
        include_bytes!("fixtures/elf_rel/module64.elf").as_slice(),
        include_bytes!("fixtures/elf_rel/module32.elf").as_slice(),
    ] {
        let image = LoadedImage::from_elf(bytes)?;
        assert!(image
            .sections
            .iter()
            .any(|s| s.name == ".bss" && s.virtual_size > 0));
        assert!(
            image.load_diagnostics.is_empty(),
            "{:?}",
            image.load_diagnostics
        );
        let mut session = DecompilerSession::from_elf(bytes)?;
        let address = image
            .sections
            .iter()
            .find(|s| s.name == ".text")
            .ok_or_else(|| anyhow::anyhow!("text"))?
            .address;
        let out = session.decompile_function(address)?;
        assert_eq!(out.name.as_deref(), Some("entry"));
        assert!(out.text.contains("strlen("), "{}", out.text);
        assert!(!out.text.contains("halt_baddata"), "{}", out.text);
    }
    Ok(())
}

#[test]
fn relocations_cannot_escape_their_destination_section() -> anyhow::Result<()> {
    let mut bytes = include_bytes!("fixtures/elf_rel/module64.elf").to_vec();
    let elf = goblin::elf::Elf::parse(&bytes)?;
    let offset = elf
        .section_headers
        .iter()
        .find(|s| s.sh_type == goblin::elf::section_header::SHT_RELA)
        .ok_or_else(|| anyhow::anyhow!("relocation table"))?
        .sh_offset as usize;
    bytes[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(LoadedImage::from_elf(&bytes).is_err());
    Ok(())
}
