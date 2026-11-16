#![allow(clippy::unwrap_used, clippy::expect_used)]
use binfera::{
    api,
    extract::{image::LoadedImage, recovery},
    features::Feature,
    freeze::Freeze,
    parallel::AnalysisOptions,
};
fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/risc/{name}-rel.elf",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}
fn address(bytes: &[u8], image: &LoadedImage, name: &str) -> u64 {
    let elf = goblin::elf::Elf::parse(bytes).unwrap();
    let symbol = elf
        .syms
        .iter()
        .find(|s| elf.strtab.get_at(s.st_name) == Some(name))
        .unwrap();
    let section = &elf.section_headers[symbol.st_shndx];
    let mapped = image
        .sections
        .iter()
        .find(|s| {
            s.file_offset == section.sh_offset
                && s.name == elf.shdr_strtab.get_at(section.sh_name).unwrap()
        })
        .unwrap();
    (mapped.address + symbol.st_value) & !1
}
#[test]
fn objects_recover_named_functions_import_calls_and_relocated_strings() {
    for name in ["arm", "thumb", "aarch64", "mips", "mipsel"] {
        let bytes = fixture(name);
        let analysis = recovery::analyze(&bytes).unwrap();
        assert!(
            analysis.image.load_diagnostics.is_empty(),
            "{name}: {:?}",
            analysis.image.load_diagnostics
        );
        for function in ["entry", "read_result"] {
            let entry = address(&bytes, &analysis.image, function);
            assert!(analysis.functions.contains_key(&entry), "{name}/{function}");
            assert!(analysis.elf_function_symbols[&entry]
                .iter()
                .any(|n| n == function));
        }
        if name == "thumb" {
            assert!(analysis
                .image
                .is_thumb(address(&bytes, &analysis.image, "entry")));
        }
        let (loaded, _) =
            api::load_input(&bytes, &AnalysisOptions::default(), &mut Default::default()).unwrap();
        let Freeze::Static(features) = loaded.freeze else {
            panic!("static")
        };
        let code: Vec<_> = features
            .functions
            .values()
            .flat_map(|f| f.basic_blocks.values())
            .flat_map(|b| b.instructions.values())
            .flat_map(|i| i.features.iter().map(|(_, f)| f))
            .collect();
        assert!(
            code.iter()
                .any(|f| matches!(f,Feature::Api(n) if n=="strlen")),
            "{name}: no API: {code:?}"
        );
        assert!(
            code.iter().any(
                |f| matches!(f,Feature::String(s) if format!("{s:?}").contains("module relocation"))
            ),
            "{name}: no code string: {code:?}"
        );
    }
}
#[cfg(feature = "decompiler")]
#[test]
fn ghidra_decompiles_relocated_objects_with_a_known_import_signature() {
    use binfera::decompiler::{DecompilerSession, ValueType};
    for name in ["arm", "thumb", "aarch64", "mips", "mipsel"] {
        let bytes = fixture(name);
        let image = LoadedImage::parse(&bytes).unwrap();
        let entry = address(&bytes, &image, "entry");
        let mut session = DecompilerSession::from_elf(&bytes).unwrap();
        for slot in image.import_locations.keys() {
            session
                .set_signature(
                    *slot,
                    if name == "aarch64" {
                        ValueType::U64
                    } else {
                        ValueType::U32
                    },
                    &[ValueType::CharPointer],
                )
                .unwrap();
        }
        let result = session.decompile_function(entry).unwrap();
        assert_eq!(result.name.as_deref(), Some("entry"));
        assert!(result.text.contains("strlen("), "{name}: {}", result.text);
        assert!(
            result.text.contains("module relocation"),
            "{name}: {}",
            result.text
        );
        assert!(!result.incomplete, "{name}: {:?}", result.warnings);
    }
}
#[test]
fn object_fixups_cannot_escape_their_target_section() {
    for name in ["arm", "thumb", "aarch64", "mips", "mipsel"] {
        let mut bytes = fixture(name);
        let elf = goblin::elf::Elf::parse(&bytes).unwrap();
        let table = elf
            .section_headers
            .iter()
            .find(|s| {
                matches!(
                    s.sh_type,
                    goblin::elf::section_header::SHT_REL | goblin::elf::section_header::SHT_RELA
                )
            })
            .unwrap();
        let offset = table.sh_offset as usize;
        let width = if elf.is_64 { 8 } else { 4 };
        bytes[offset..offset + width].fill(0xff);
        assert!(LoadedImage::parse(&bytes).is_err(), "{name}");
    }
}

#[test]
fn common_symbols_receive_bounded_aligned_zero_filled_storage() {
    for name in ["arm-common", "mipsel-common"] {
        let bytes = fixture(name);
        let image = LoadedImage::parse(&bytes).unwrap();
        assert!(
            image.load_diagnostics.is_empty(),
            "{name}: {:?}",
            image.load_diagnostics
        );
        let common = image.sections.iter().find(|s| s.name == "COMMON").unwrap();
        assert!(common.address.is_multiple_of(4));
        assert_eq!(image.read_pointer(common.address), Some(0));
        let analysis = recovery::analyze(&bytes).unwrap();
        assert!(analysis
            .functions
            .contains_key(&address(&bytes, &image, "entry")));
    }
}

#[test]
fn mipshigh_without_a_low_is_diagnosed_and_instruction_classes_are_checked() {
    for name in ["mips", "mipsel"] {
        let original = fixture(name);
        let elf = goblin::elf::Elf::parse(&original).unwrap();
        let table = elf
            .section_headers
            .iter()
            .find(|s| {
                s.sh_type == goblin::elf::section_header::SHT_REL
                    && elf.section_headers[s.sh_info as usize].sh_flags & 4 != 0
            })
            .unwrap();
        let little = elf.little_endian;
        let mut bytes = original.clone();
        for offset in (table.sh_offset as usize..(table.sh_offset + table.sh_size) as usize)
            .step_by(table.sh_entsize as usize)
        {
            let raw: [u8; 4] = bytes[offset + 4..offset + 8].try_into().unwrap();
            let info = if little {
                u32::from_le_bytes(raw)
            } else {
                u32::from_be_bytes(raw)
            };
            if info & 255 == goblin::elf::reloc::R_MIPS_LO16 {
                let value = info & !255;
                bytes[offset + 4..offset + 8].copy_from_slice(&if little {
                    value.to_le_bytes()
                } else {
                    value.to_be_bytes()
                });
            }
        }
        let image = LoadedImage::parse(&bytes).unwrap();
        assert!(image
            .load_diagnostics
            .iter()
            .any(|d| d.contains("unpaired MIPS HI16")));
        let mut bytes = original.clone();
        let text = &elf.section_headers[table.sh_info as usize];
        // The trusted fixture's LUI at .text+8 receives HI16.
        bytes[text.sh_offset as usize + 8..text.sh_offset as usize + 12].fill(0);
        assert!(
            LoadedImage::parse(&bytes).is_err(),
            "{name}: invalid LUI accepted"
        );
    }
}

#[test]
fn mips_paired_highs_round_up_when_the_low_half_is_negative() {
    for name in ["mips", "mipsel"] {
        let original = fixture(name);
        let elf = goblin::elf::Elf::parse(&original).unwrap();
        let index = elf
            .section_headers
            .iter()
            .position(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".rodata"))
            .unwrap();
        let offset = elf.header.e_shoff as usize + index * elf.header.e_shentsize as usize + 32;
        let little = elf.little_endian;
        let mut bytes = original.clone();
        bytes[offset..offset + 4].copy_from_slice(&if little {
            0x8000u32.to_le_bytes()
        } else {
            0x8000u32.to_be_bytes()
        });
        let image = LoadedImage::parse(&bytes).unwrap();
        let text = image
            .sections
            .iter()
            .find(|s| s.name == ".text")
            .unwrap()
            .address;
        let rodata = image
            .sections
            .iter()
            .find(|s| s.name == ".rodata")
            .unwrap()
            .address;
        let high = image.read_pointer(text + 8).unwrap() as u32 & 0xffff;
        let low = image.read_pointer(text + 16).unwrap() as u16 as i16;
        assert_eq!(
            (high << 16).wrapping_add_signed(i32::from(low)),
            rodata as u32
        );
        assert_eq!(low, i16::MIN);
        let (loaded, _) =
            api::load_input(&bytes, &AnalysisOptions::default(), &mut Default::default()).unwrap();
        let Freeze::Static(features) = loaded.freeze else {
            panic!("static")
        };
        assert!(features.functions.values().flat_map(|f|f.basic_blocks.values()).flat_map(|b|b.instructions.values()).flat_map(|i|&i.features).any(|(_,f)|matches!(f,Feature::String(s) if format!("{s:?}").contains("module relocation"))));
    }
}

#[test]
fn unsupported_mips_gp_fixups_do_not_receive_fake_external_addresses() {
    let bytes = fixture("mipsel-pic");
    let elf = goblin::elf::Elf::parse(&bytes).unwrap();
    let gp = elf
        .syms
        .iter()
        .enumerate()
        .find(|(_, s)| elf.strtab.get_at(s.st_name) == Some("_gp_disp"))
        .unwrap()
        .0;
    let (index, relocations) = elf
        .shdr_relocs
        .iter()
        .find(|(_, r)| {
            r.iter()
                .any(|r| r.r_sym == gp && r.r_type == goblin::elf::reloc::R_MIPS_HI16)
        })
        .unwrap();
    let relocation = relocations
        .iter()
        .find(|r| r.r_sym == gp && r.r_type == goblin::elf::reloc::R_MIPS_HI16)
        .unwrap();
    let section = &elf.section_headers[elf.section_headers[*index].sh_info as usize];
    let offset = (section.sh_offset + relocation.r_offset) as usize;
    let original = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let image = LoadedImage::parse(&bytes).unwrap();
    let text = image
        .sections
        .iter()
        .find(|s| s.name == elf.shdr_strtab.get_at(section.sh_name).unwrap())
        .unwrap();
    assert_eq!(
        image.read_pointer(text.address + relocation.r_offset),
        Some(u64::from(original))
    );
    assert!(image
        .load_diagnostics
        .iter()
        .any(|d| d.contains("GP-dependent ET_REL")));
}
