//! The workbench must see the same addresses and selected slice as recovery.
use binfera::extract::image::{select_macho_slice, LoadedImage};
use binfera::image_info::inspect;

#[test]
fn pointer_width_and_regions_follow_the_loader() -> Result<(), Box<dyn std::error::Error>> {
    for (bytes, width) in [
        (
            include_bytes!("../../tests/decompiler/fixtures.dll").as_slice(),
            8,
        ),
        (
            include_bytes!("fixtures/elf32_sysv/dynamic.elf").as_slice(),
            4,
        ),
        (
            include_bytes!("fixtures/elf64_sysv/dynamic.elf").as_slice(),
            8,
        ),
        (
            include_bytes!("fixtures/macho/thin-x86_64-exe").as_slice(),
            8,
        ),
        (
            include_bytes!("fixtures/macho/thin-arm64-exe").as_slice(),
            8,
        ),
    ] {
        let metadata = inspect(bytes, None)?;
        let image = LoadedImage::parse(bytes)?;
        assert_eq!(metadata.ptr_size, width);
        assert_eq!(metadata.entry, image.entry_point);
        assert!(!metadata.sections.is_empty());
        for region in metadata.regions.iter().filter(|r| r.size > 0) {
            assert_eq!(image.va_to_file_offset(region.va), Some(region.off));
            assert!(region.off + region.size <= bytes.len() as u64);
        }
    }
    Ok(())
}

#[test]
fn universal_offsets_refer_to_the_original_file() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = include_bytes!("fixtures/macho/fat-x86_64-arm64-exe");
    for arch in [None, Some("arm64"), Some("x86_64")] {
        let (slice, _) = select_macho_slice(bytes, arch)?;
        let slice_offset = (slice.as_ptr() as usize - bytes.as_ptr() as usize) as u64;
        let image = LoadedImage::from_macho(bytes, arch)?;
        let metadata = inspect(bytes, arch)?;
        assert_eq!(metadata.ptr_size, 8);
        assert!(!metadata.sections.is_empty());
        for region in metadata.regions.iter().filter(|r| r.size > 0) {
            assert_eq!(
                image
                    .va_to_file_offset(region.va)
                    .map(|off| off + slice_offset),
                Some(region.off)
            );
            let off = region.off as usize;
            assert_eq!(bytes.get(off..off + 4), image.bytes_at(region.va, 4));
        }
        assert!(metadata
            .sections
            .iter()
            .all(|s| s.size == 0 || s.off >= slice_offset));
    }
    Ok(())
}

#[test]
fn data_only_elf_retains_metadata_without_a_decoder() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = include_bytes!("fixtures/elf32_sysv/dynamic.elf").to_vec();
    for machine in [20u16, 243u16] {
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        let metadata = inspect(&bytes, None)?;
        assert_eq!(metadata.format, "elf");
        assert_eq!(metadata.ptr_size, 4);
        assert!(metadata.arch.is_none());
        assert!(!metadata.sections.is_empty());
        assert!(!metadata.regions.is_empty());
    }
    Ok(())
}

#[test]
fn malformed_containers_return_errors() {
    let mut pe = vec![0; 128];
    pe[..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&0xfffffff0u32.to_le_bytes());
    assert!(inspect(&pe, None).is_err());
    for bytes in [
        b"".as_slice(),
        b"MZ",
        b"\x7fELF",
        include_bytes!("fixtures/macho/malformed/slice-offset-past-eof"),
        include_bytes!("fixtures/macho/malformed/truncated-load-commands"),
    ] {
        assert!(inspect(bytes, None).is_err());
    }
}

#[test]
fn macho_imports_and_exports_are_available_to_the_workbench(
) -> Result<(), Box<dyn std::error::Error>> {
    let info = inspect(include_bytes!("fixtures/macho/thin-x86_64-exe"), None)?;
    assert!(info.imports.iter().any(|i| i.name == "malloc"));
    let info = inspect(include_bytes!("fixtures/macho/thin-arm64.dylib"), None)?;
    assert!(!info.exports.is_empty());
    Ok(())
}

#[test]
fn ordinal_only_exports_remain_navigable() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = include_bytes!("../../tests/decompiler/fixtures.dll").to_vec();
    let image = LoadedImage::parse(&bytes)?;
    let pe = goblin::pe::PE::parse(&bytes)?;
    let directory = pe
        .header
        .optional_header
        .as_ref()
        .and_then(|h| h.data_directories.get_export_table())
        .ok_or("missing exports")?;
    let directory_off = image
        .va_to_file_offset(image.image_base + u64::from(directory.virtual_address))
        .ok_or("unmapped exports")? as usize;
    // Remove all exported names, leaving the address table and its ordinal base intact.
    bytes[directory_off + 24..directory_off + 28].copy_from_slice(&0u32.to_le_bytes());
    let info = inspect(&bytes, None)?;
    assert!(!info.exports.is_empty());
    assert!(info
        .exports
        .iter()
        .all(|e| e.name.starts_with("ord_") && e.va != 0));
    assert!(info
        .exports
        .iter()
        .any(|e| e.va == image.image_base + 0x1000));
    Ok(())
}

#[test]
fn managed_metadata_does_not_select_a_native_signature_pack(
) -> Result<(), Box<dyn std::error::Error>> {
    let info = inspect(
        include_bytes!("../../tests/testfiles/dotnet/dd9098ff91717f4906afe9dafdfa2f52.exe_"),
        None,
    )?;
    assert_eq!(info.arch.as_deref(), Some("cil"));
    assert!(info.fid_arch.is_none());
    assert!(!info.regions.is_empty());
    Ok(())
}

fn fact<'a>(info: &'a binfera::image_info::ImageInfo, label: &str) -> Option<&'a str> {
    info.details
        .facts
        .iter()
        .find(|fact| fact.label == label)
        .map(|fact| fact.value.as_str())
}

#[test]
fn pe_headers_are_laid_out_at_their_addresses() -> Result<(), Box<dyn std::error::Error>> {
    let info = inspect(include_bytes!("fixtures/pe32_delphi/plain.exe"), None)?;
    let dos = info.details.structures.first().ok_or("no structures")?;
    assert_eq!(dos.name, "IMAGE_DOS_HEADER");
    assert_eq!(dos.off, 0);
    assert_eq!(dos.size, 64);
    let base = info.sections.first().ok_or("no sections")?.va;
    assert_eq!(dos.va, Some(base));
    let magic = dos.fields.first().ok_or("no fields")?;
    assert_eq!(
        (magic.name.as_str(), magic.value.as_str()),
        ("e_magic", "5A4Dh")
    );
    let names: Vec<_> = info
        .details
        .structures
        .iter()
        .map(|s| s.name.as_str())
        .collect();
    assert!(names.contains(&"IMAGE_NT_HEADERS"));
    assert!(names.contains(&"IMAGE_DATA_DIRECTORY[]"));
    assert!(names
        .iter()
        .any(|name| name.starts_with("IMAGE_SECTION_HEADER")));
    assert!(fact(&info, "SHA-256").is_some());
    Ok(())
}

#[test]
fn elf_headers_map_through_load_segments() -> Result<(), Box<dyn std::error::Error>> {
    let info = inspect(include_bytes!("fixtures/elf32_sysv/dynamic.elf"), None)?;
    let header = info.details.structures.first().ok_or("no structures")?;
    assert_eq!(header.name, "Elf32_Ehdr");
    assert_eq!(header.va, Some(0x400000));
    assert_eq!(fact(&info, "Interpreter"), Some("/lib/ld-linux.so.2"));
    assert_eq!(fact(&info, "Needed"), Some("libstub.so"));
    assert_eq!(fact(&info, "NX stack"), Some("yes"));
    // Section headers follow the last segment, so only the file offset locates them.
    assert!(info
        .details
        .structures
        .iter()
        .filter(|s| s.name.starts_with("Shdr"))
        .all(|s| s.va.is_none()));
    Ok(())
}

#[test]
fn macho_load_commands_and_signature_are_read() -> Result<(), Box<dyn std::error::Error>> {
    let info = inspect(include_bytes!("fixtures/macho/thin-arm64.dylib"), None)?;
    assert_eq!(
        info.details.structures.first().map(|s| s.name.as_str()),
        Some("mach_header_64")
    );
    assert_eq!(fact(&info, "Machine"), Some("ARM64"));
    assert_eq!(
        fact(&info, "Code signature"),
        Some("linker-signed (ad hoc)")
    );
    let signature = info.details.signatures.first().ok_or("no signature")?;
    assert_eq!(signature.digest_matches, Some(true));
    assert!(signature.certificates.is_empty());
    Ok(())
}

#[test]
fn a_changed_macho_page_breaks_the_signature_match() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = include_bytes!("fixtures/macho/thin-arm64.dylib").to_vec();
    let text = inspect(&bytes, None)?
        .sections
        .iter()
        .find(|s| s.name == "__TEXT,__text")
        .map(|s| s.off as usize)
        .ok_or("no text section")?;
    let byte = bytes.get_mut(text).ok_or("text out of range")?;
    *byte ^= 0xff;
    let info = inspect(&bytes, None)?;
    let signature = info.details.signatures.first().ok_or("no signature")?;
    assert_eq!(signature.digest_matches, Some(false));
    assert!(info
        .details
        .anomalies
        .iter()
        .any(|a| a.severity == "warn" && a.text.contains("page hashes")));
    Ok(())
}

#[test]
fn appended_bytes_are_reported_as_an_overlay() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = include_bytes!("fixtures/pe32_delphi/plain.exe").to_vec();
    let clean = inspect(&bytes, None)?.details.overlay.is_none();
    assert!(clean);
    let end = bytes.len() as u64;
    bytes.extend_from_slice(b"PK\x03\x04appended payload");
    let info = inspect(&bytes, None)?;
    let overlay = info.details.overlay.ok_or("no overlay")?;
    assert_eq!(overlay.off, end);
    assert_eq!(overlay.size, 20);
    assert_eq!(overlay.kind, Some("ZIP"));
    Ok(())
}

/// Metadata reads every length and offset from the file, so damage must never panic.
#[test]
fn damaged_images_never_panic_the_metadata_parsers() {
    let inputs: &[&[u8]] = &[
        include_bytes!("fixtures/pe32_delphi/plain.exe"),
        include_bytes!("fixtures/elf32_sysv/dynamic.elf"),
        include_bytes!("fixtures/macho/thin-arm64.dylib"),
    ];
    for input in inputs {
        for keep in (0..input.len().min(0x1000)).step_by(61) {
            let _ = inspect(input.get(..keep).unwrap_or_default(), None);
        }
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..400 {
            let mut copy = input.to_vec();
            for _ in 0..8 {
                // xorshift keeps the damage reproducible.
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let span = copy.len().clamp(1, 0x2000) as u64;
                if let Some(byte) = copy.get_mut((state % span) as usize) {
                    *byte = (state >> 32) as u8;
                }
            }
            let _ = inspect(&copy, None);
        }
    }
}

/// Expected values come from pefile 2024.8.26 and signify 0.9.3.
#[test]
fn signed_pe_metadata_matches_reference_tools() -> Result<(), Box<dyn std::error::Error>> {
    let info = inspect(include_bytes!("../../tests/testfiles/mimikatz.exe_"), None)?;
    assert_eq!(
        fact(&info, "Imphash"),
        Some("f0d0a258ef4645aabe53a8c67d59a6e0")
    );
    assert_eq!(
        fact(&info, "Rich header hash"),
        Some("5ed46cd820490d3367963808a74baee8")
    );
    assert!(fact(&info, "Checksum").is_some_and(|value| value.ends_with("(valid)")));
    let signature = info
        .details
        .signatures
        .iter()
        .find(|s| s.digest_algorithm.as_deref() == Some("SHA-256"))
        .ok_or("no SHA-256 signature")?;
    assert_eq!(signature.digest_matches, Some(true));
    assert_eq!(
        signature.computed_digest.as_deref(),
        Some("e53106abb970882839558b0ac2166643752db51d9aca44b6d3c756910947d9c0")
    );
    assert!(signature.certificates.iter().any(|c| c.signer));
    Ok(())
}

#[test]
fn a_changed_signed_pe_no_longer_matches() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = include_bytes!("../../tests/testfiles/mimikatz.exe_").to_vec();
    let text = inspect(&bytes, None)?
        .sections
        .iter()
        .find(|s| s.name == ".text")
        .map(|s| s.off as usize)
        .ok_or("no text section")?;
    let byte = bytes.get_mut(text).ok_or("text out of range")?;
    *byte ^= 0xff;
    let info = inspect(&bytes, None)?;
    assert!(info
        .details
        .signatures
        .iter()
        .all(|s| s.digest_matches == Some(false)));
    assert!(info
        .details
        .anomalies
        .iter()
        .any(|a| a.text.contains("changed after it was signed")));
    Ok(())
}
