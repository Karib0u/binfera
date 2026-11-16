use super::*;

fn fixture(pointer_format: u16, import_format: u32, value: u64) -> (LoadedImage, Vec<u8>) {
    let width = match import_format {
        1 => 4,
        2 => 8,
        _ => 16,
    };
    let mut data = vec![0u8; 60 + width];
    for (at, value) in [
        (4, 28u32),
        (8, 60),
        (12, (60 + width) as u32),
        (16, 1),
        (20, import_format),
        (28, 1),
        (32, 8),
        (36, 24),
    ] {
        data[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    data[40..42].copy_from_slice(&4096u16.to_le_bytes());
    data[42..44].copy_from_slice(&pointer_format.to_le_bytes());
    data[44..52].copy_from_slice(&0x1000u64.to_le_bytes());
    data[56..58].copy_from_slice(&1u16.to_le_bytes());
    data[60] = 1; // lib ordinal 1, name offset 0
    data.extend_from_slice(b"_malloc\0");
    let mut mapped = vec![0u8; 4096];
    mapped[..8].copy_from_slice(&value.to_le_bytes());
    let image = LoadedImage::for_test(
        ImageFormat::Macho,
        Architecture::X64,
        0x1000,
        vec![MappedSection {
            name: "__DATA".into(),
            address: 0x2000,
            virtual_size: 4096,
            file_offset: 0,
            file_size: 4096,
            permissions: Permissions {
                read: true,
                write: true,
                execute: false,
            },
        }],
        BTreeMap::new(),
        mapped,
    );
    (image, data)
}

#[test]
fn chained_import_formats_and_authenticated_userland_binds() -> Result<(), ImageError> {
    for format in [1, 2, 3] {
        for pointer in [1, 2, 6, 9, 12] {
            let raw = if matches!(pointer, 1 | 9 | 12) {
                3u64 << 62
            } else {
                1u64 << 63
            };
            let (image, data) = fixture(pointer, format, raw);
            let parsed = parse_macho_chained_fixups(
                &image,
                &data,
                &["self", "libSystem.B.dylib"],
                0,
                data.len() as u32,
            )?;
            assert_eq!(
                parsed.binds,
                vec![(0x2000, "libSystem.B.dylib".into(), "_malloc".into())]
            );
            assert!(parsed.rebases.is_empty());
        }
    }
    Ok(())
}

#[test]
fn rebases_remove_chain_and_authentication_bits() -> Result<(), ImageError> {
    for (pointer, raw, target) in [
        (2, 0x2340, 0x2340),
        (6, 0x2340, 0x3340),
        (1, 0x2340, 0x2340),
        (9, 0x2340, 0x3340),
        (12, (1 << 63) | 0x2340, 0x3340),
    ] {
        let (image, data) = fixture(pointer, 1, raw);
        let parsed = parse_macho_chained_fixups(&image, &data, &[], 0, data.len() as u32)?;
        assert_eq!(parsed.rebases, vec![(0x2000, target)]);
    }
    Ok(())
}

#[test]
fn malformed_chains_refuse_cross_page_walks_and_bad_ordinals() {
    for raw in [(1u64 << 63) | 1, (1u64 << 63) | (0xfff << 51)] {
        let (image, data) = fixture(6, 1, raw);
        assert!(parse_macho_chained_fixups(
            &image,
            &data,
            &["self", "libSystem"],
            0,
            data.len() as u32
        )
        .is_err());
    }
    let (image, data) = fixture(13, 1, 0);
    assert!(parse_macho_chained_fixups(&image, &data, &[], 0, data.len() as u32).is_err());
}
