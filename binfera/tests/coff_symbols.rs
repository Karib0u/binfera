//! Hand-built PE32/PE32+ images: no toolchain or sample execution required.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use binfera::extract::recovery::{analyze_with_backend, RecoveryBackend, SeedKind};

const TABLE: usize = 0x600;
const LONG_NAME: &str = "coff_local_helper";

fn symbol(name: &[u8], value: u32, section: i16, typ: u16, class: u8, aux: u8) -> [u8; 18] {
    let mut record = [0; 18];
    record[..name.len()].copy_from_slice(name);
    record[8..12].copy_from_slice(&value.to_le_bytes());
    record[12..14].copy_from_slice(&section.to_le_bytes());
    record[14..16].copy_from_slice(&typ.to_le_bytes());
    record[16] = class;
    record[17] = aux;
    record
}

fn records() -> Vec<[u8; 18]> {
    vec![
        symbol(b"entryfun", 0, 1, 0x20, 2, 1),
        // An auxiliary record deliberately shaped like a function must not be read as one.
        symbol(b"fakefunc", 0x30, 1, 0x20, 2, 0),
        symbol(&[0, 0, 0, 0, 4, 0, 0, 0], 0x10, 1, 0x20, 3, 0),
        symbol(b"orphan", 0x20, 1, 0x20, 2, 0),
        symbol(b"alias", 0x20, 1, 0x20, 2, 0),
        symbol(b"orphan", 0x20, 1, 0x20, 2, 0),
    ]
}

fn fixture(wide: bool, records: &[[u8; 18]]) -> Vec<u8> {
    let mut bytes = vec![0; TABLE];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    let machine: u16 = if wide { 0x8664 } else { 0x14c };
    bytes[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
    bytes[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
    bytes[0x8c..0x90].copy_from_slice(&(TABLE as u32).to_le_bytes());
    bytes[0x90..0x94].copy_from_slice(&(records.len() as u32).to_le_bytes());
    let optional_size: u16 = if wide { 240 } else { 224 };
    bytes[0x94..0x96].copy_from_slice(&optional_size.to_le_bytes());
    bytes[0x96..0x98].copy_from_slice(&0x22u16.to_le_bytes());
    let optional = 0x98;
    let magic: u16 = if wide { 0x20b } else { 0x10b };
    bytes[optional..optional + 2].copy_from_slice(&magic.to_le_bytes());
    for (offset, value) in [
        (4, 0x200u32), // SizeOfCode
        (16, 0x1000),  // AddressOfEntryPoint
        (20, 0x1000),  // BaseOfCode
        (32, 0x1000),  // SectionAlignment
        (36, 0x200),   // FileAlignment
        (56, 0x3000),  // SizeOfImage
        (60, 0x200),   // SizeOfHeaders
    ] {
        bytes[optional + offset..optional + offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    if wide {
        bytes[optional + 24..optional + 32].copy_from_slice(&base(wide).to_le_bytes());
    } else {
        bytes[optional + 28..optional + 32].copy_from_slice(&(base(wide) as u32).to_le_bytes());
    }
    bytes[optional + 68..optional + 70].copy_from_slice(&3u16.to_le_bytes());
    for (index, (name, rva, raw, flags)) in [
        (b".text", 0x1000u32, 0x200u32, 0x60000020u32),
        (b".data", 0x2000, 0x400, 0xc0000040),
    ]
    .into_iter()
    .enumerate()
    {
        let section = optional + usize::from(optional_size) + index * 40;
        bytes[section..section + 5].copy_from_slice(name);
        for (offset, value) in [
            (8, 0x300u32),
            (12, rva),
            (16, 0x200),
            (20, raw),
            (36, flags),
        ] {
            bytes[section + offset..section + offset + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
    // entryfun calls the static helper. The orphan has no callers or prologue.
    bytes[0x200..0x206].copy_from_slice(&[0xe8, 0x0b, 0, 0, 0, 0xc3]);
    bytes[0x210..0x216].copy_from_slice(&[0xb8, 7, 0, 0, 0, 0xc3]);
    bytes[0x220..0x226].copy_from_slice(&[0xb8, 42, 0, 0, 0, 0xc3]);
    for record in records {
        bytes.extend_from_slice(record);
    }
    bytes.extend_from_slice(&(5 + LONG_NAME.len() as u32).to_le_bytes());
    bytes.extend_from_slice(LONG_NAME.as_bytes());
    bytes.push(0);
    bytes
}

fn base(wide: bool) -> u64 {
    if wide {
        0x140000000
    } else {
        0x400000
    }
}

#[test]
fn coff_names_seed_functions_and_keep_aliases_on_both_widths() -> anyhow::Result<()> {
    for wide in [false, true] {
        let bytes = fixture(wide, &records());
        let analysis = analyze_with_backend(&bytes, RecoveryBackend::Native)?;
        let start = base(wide) + 0x1000;
        assert_eq!(analysis.elf_function_symbols.len(), 3);
        assert_eq!(analysis.elf_function_symbols[&start], ["entryfun"]);
        assert_eq!(analysis.elf_function_symbols[&(start + 0x10)], [LONG_NAME]);
        assert_eq!(
            analysis.elf_function_symbols[&(start + 0x20)],
            ["orphan", "alias"]
        );
        for address in [start, start + 0x10, start + 0x20] {
            assert!(analysis.seeds[&address].contains(&SeedKind::Symbol));
            assert!(analysis.functions.contains_key(&address));
        }
        assert!(!analysis.seeds.contains_key(&(start + 0x30)));
        let compat = analyze_with_backend(&bytes, RecoveryBackend::VivisectCompat)?;
        assert!(compat.elf_function_symbols.is_empty());
        assert!(!compat
            .seeds
            .values()
            .any(|kinds| kinds.contains(&SeedKind::Symbol)));
    }
    Ok(())
}

#[test]
fn coff_ignores_data_debug_undefined_and_invalid_names() -> anyhow::Result<()> {
    let mut entries = records();
    for (value, section, typ, class) in [
        (0, 2, 0x20, 2),      // data section
        (0x30, 0, 0x20, 2),   // undefined
        (0x30, -1, 0x20, 2),  // absolute
        (0x30, -2, 0x20, 2),  // debug
        (0x30, 3, 0x20, 2),   // nonexistent section
        (0x30, 1, 0x20, 101), // .bf/.ef debug record
        (0x30, 1, 0, 3),      // section or untyped label
        (0x30, 1, 0x90, 2),   // pointer to function
        (0x200, 1, 0x20, 2),  // virtual zero-fill
        (0x1000, 1, 0x20, 2), // value outside its section
    ] {
        entries.push(symbol(b"invalid", value, section, typ, class, 0));
    }
    for offset in [0u32, 1, 3, u32::MAX] {
        let mut name = [0; 8];
        name[4..].copy_from_slice(&offset.to_le_bytes());
        entries.push(symbol(&name, 0x30, 1, 0x20, 2, 0));
    }
    entries.push(symbol(b"\xff", 0x30, 1, 0x20, 2, 0));
    let analysis = analyze_with_backend(&fixture(true, &entries), RecoveryBackend::Native)?;
    assert_eq!(analysis.elf_function_symbols.len(), 3);
    Ok(())
}

#[test]
fn coff_reads_real_mingw_symbols() -> anyhow::Result<()> {
    for (bytes, address, name) in [
        (
            include_bytes!("../../tests/testfiles/5589857ba6ad8cd0893f4fbba774382222a573d20a2dd71b26b3b4d64f671301.exe_").as_slice(),
            0x40197e,
            "compute_vector_magnitude",
        ),
        (
            include_bytes!("../../tests/testfiles/58adc2e97fbee01b71073ccd7ff1b9a4.exe_").as_slice(),
            0x401350,
            "_main",
        ),
    ] {
        let analysis = analyze_with_backend(bytes, RecoveryBackend::Native)?;
        assert!(analysis.elf_function_symbols.len() > 50);
        assert_eq!(analysis.elf_function_symbols[&address], [name]);
        assert!(analysis.seeds[&address].contains(&SeedKind::Symbol));
        assert!(analysis.functions.contains_key(&address));
        #[cfg(feature = "decompiler")]
        {
            let mut session = binfera::decompiler::DecompilerSession::from_pe(bytes)?;
            let output = session.decompile_function(address)?;
            assert!(output.text.contains(&format!("{name}(")), "{}", output.text);
        }
    }
    Ok(())
}

#[test]
fn missing_coff_table_has_no_diagnostic() -> anyhow::Result<()> {
    for at in [0x8c, 0x90] {
        let mut bytes = fixture(true, &records());
        bytes[at..at + 4].fill(0);
        let analysis = analyze_with_backend(&bytes, RecoveryBackend::Native)?;
        assert!(analysis.elf_function_symbols.is_empty());
        assert!(!analysis
            .diagnostics
            .iter()
            .any(|d| d.message.contains("COFF")));
    }
    Ok(())
}

#[test]
fn malformed_coff_metadata_does_not_prevent_recovery() -> anyhow::Result<()> {
    let original = fixture(true, &records());
    let strings = TABLE + records().len() * 18;
    let mut cases = Vec::new();
    for (at, value) in [
        (0x8c, u32::MAX),
        (0x90, u32::MAX),
        (strings, 3),
        (strings, u32::MAX),
    ] {
        let mut bytes = original.clone();
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        cases.push(bytes);
    }
    for length in [TABLE + 1, strings, strings + 3] {
        cases.push(original[..length].to_vec());
    }
    let mut bytes = original.clone();
    bytes[TABLE + 17] = 255;
    cases.push(bytes);
    for bytes in cases {
        let analysis = analyze_with_backend(&bytes, RecoveryBackend::Native)?;
        assert!(analysis.functions.contains_key(&(base(true) + 0x1000)));
        assert!(analysis.elf_function_symbols.is_empty());
        assert!(analysis
            .diagnostics
            .iter()
            .any(|d| d.message.contains("COFF symbol table")));
    }
    // A string terminator outside the declared string table is not part of the name.
    let mut bytes = original;
    bytes[strings..strings + 4].copy_from_slice(&(4 + LONG_NAME.len() as u32).to_le_bytes());
    let analysis = analyze_with_backend(&bytes, RecoveryBackend::Native)?;
    assert!(!analysis
        .elf_function_symbols
        .contains_key(&(base(true) + 0x1010)));
    assert_eq!(analysis.elf_function_symbols.len(), 2);
    Ok(())
}

#[cfg(feature = "decompiler")]
#[test]
fn coff_names_reach_decompiled_definitions_and_calls() -> anyhow::Result<()> {
    use binfera::decompiler::DecompilerSession;
    for wide in [false, true] {
        let bytes = fixture(wide, &records());
        let mut session = DecompilerSession::from_pe(&bytes)?;
        let entry = session.decompile_function(base(wide) + 0x1000)?;
        assert!(entry.text.contains("entryfun("), "{}", entry.text);
        assert!(
            entry.text.contains(&format!("{LONG_NAME}(")),
            "{}",
            entry.text
        );
        let orphan = session.decompile_function(base(wide) + 0x1020)?;
        assert!(orphan.text.contains("orphan("), "{}", orphan.text);
    }
    Ok(())
}
