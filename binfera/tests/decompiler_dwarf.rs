#![cfg(feature = "decompiler")]
use binfera::decompiler::DecompilerSession;
use binfera::dwarf::DebugInfo;
use binfera::extract::image::LoadedImage;
use binfera::extract::recovery::SeedKind;

const ELF4: &[u8] = include_bytes!("fixtures/dwarf/dwarf4.elf");
const ELF5: &[u8] = include_bytes!("fixtures/dwarf/dwarf5.elf");
const ZLIB: &[u8] = include_bytes!("fixtures/dwarf/compressed.elf");
const GNU_ZLIB: &[u8] = include_bytes!("fixtures/dwarf/gnu-compressed.elf");
const PE64: &[u8] = include_bytes!("fixtures/dwarf/x86_64.exe");
const PE32: &[u8] = include_bytes!("fixtures/dwarf/i686.exe");

fn address(debug: &DebugInfo, name: &str) -> anyhow::Result<u64> {
    debug
        .functions
        .iter()
        .find_map(|(a, f)| (f.name == name).then_some(*a))
        .ok_or_else(|| anyhow::anyhow!("missing {name}: {:?}", debug.diagnostics))
}

#[test]
fn names_signatures_structures_and_stack_locals() -> anyhow::Result<()> {
    for bytes in [ELF4, ELF5, ZLIB, GNU_ZLIB, PE64, PE32] {
        let image = LoadedImage::parse(bytes)?;
        let debug = DebugInfo::read(bytes, &image);
        assert!(debug.diagnostics.is_empty(), "{:?}", debug.diagnostics);
        let update = address(&debug, "update")?;
        let caller = address(&debug, "call_update")?;
        let (mut session, analysis) = DecompilerSession::from_bytes_with_analysis(bytes)?;
        assert!(analysis
            .seeds
            .get(&update)
            .is_some_and(|kinds| kinds.contains(&SeedKind::Dwarf)));
        let output = session.decompile_function(update)?;
        assert_eq!(output.name.as_deref(), Some("update"));
        assert!(
            output.text.contains("Record *record") && output.text.contains("int amount"),
            "{}",
            output.text
        );
        assert!(
            output.text.contains("record->count") && output.text.contains("record->total"),
            "{}",
            output.text
        );
        let caller_output = session.decompile_function(caller)?;
        // The i386 fixture realigns ESP dynamically and expresses this local with breg4;
        // its type still propagates through the call, but fixed-frame local naming is unsafe.
        if image.architecture != binfera::extract::image::Architecture::X86 {
            assert!(
                caller_output.text.contains("Record record")
                    && caller_output.text.contains("update(&record,7)"),
                "{}",
                caller_output.text
            );
        } else {
            assert!(
                caller_output.text.contains("Record "),
                "{}",
                caller_output.text
            );
        }
        assert_eq!(session.decompile_function(update)?.text, output.text);
    }
    Ok(())
}

#[test]
fn absent_and_truncated_debug_info_do_not_reject_code() -> anyhow::Result<()> {
    use object::{Object, ObjectSection};
    let file = object::File::parse(ELF4)?;
    let section = file
        .section_by_name(".debug_info")
        .ok_or_else(|| anyhow::anyhow!("debug section"))?;
    let (offset, size) = section
        .file_range()
        .ok_or_else(|| anyhow::anyhow!("section range"))?;
    let mut bytes = ELF4.to_vec();
    bytes[offset as usize..(offset + size) as usize].fill(0xff);
    let (mut session, analysis) = DecompilerSession::from_bytes_with_analysis(&bytes)?;
    assert!(!analysis
        .dwarf
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("debug"))?
        .diagnostics
        .is_empty());
    session.decompile_function(
        analysis
            .image
            .entry_point
            .ok_or_else(|| anyhow::anyhow!("entry"))?,
    )?;
    Ok(())
}

#[test]
fn go_uses_debug_names_types_and_its_register_abi() -> anyhow::Result<()> {
    let bytes = include_bytes!("fixtures/dwarf/go.elf");
    let (mut session, analysis) = DecompilerSession::from_bytes_with_analysis(bytes)?;
    let debug = analysis
        .dwarf
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("debug"))?;
    assert!(debug.diagnostics.is_empty(), "{:?}", debug.diagnostics);
    let update = session.decompile_function(address(debug, "main.update")?)?;
    assert!(
        update.text.contains("*record") && update.text.contains("amount"),
        "{}",
        update.text
    );
    assert!(
        update.text.contains("record->Count") && update.text.contains("record->Total"),
        "{}",
        update.text
    );
    assert!(!update.text.contains("unaff_"), "{}", update.text);
    let pair = session.decompile_function(address(debug, "main.pair")?)?;
    assert!(
        pair.text.contains("value") && pair.text.contains("dwarf_results_"),
        "{}",
        pair.text
    );
    assert!(!pair.text.contains("unaff_"), "{}", pair.text);
    Ok(())
}

#[test]
fn rust_pointer_parameters_are_typed_but_private_aggregate_abi_stays_inferred() -> anyhow::Result<()>
{
    let bytes = include_bytes!("fixtures/dwarf/rust.elf");
    let (mut session, analysis) = DecompilerSession::from_bytes_with_analysis(bytes)?;
    let debug = analysis
        .dwarf
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("debug"))?;
    assert!(debug.diagnostics.is_empty(), "{:?}", debug.diagnostics);
    let result = session.decompile_function(address(debug, "rust_update")?)?;
    assert!(
        result.text.contains("*record")
            && result.text.contains("amount")
            && result.text.contains("record->count"),
        "{}",
        result.text
    );
    assert!(
        session
            .warnings()
            .iter()
            .any(|w| w.contains("unsupported types or storage")),
        "{:?}",
        session.warnings()
    );
    Ok(())
}

#[test]
fn compressed_size_limits_and_mutated_entries() -> anyhow::Result<()> {
    use object::{Object, ObjectSection};
    let file = object::File::parse(ZLIB)?;
    let (offset, _) = file
        .section_by_name(".debug_info")
        .and_then(|s| s.file_range())
        .ok_or_else(|| anyhow::anyhow!("compressed info"))?;
    let mut bytes = ZLIB.to_vec();
    bytes[offset as usize + 8..offset as usize + 16].copy_from_slice(&u64::MAX.to_le_bytes());
    let image = LoadedImage::parse(&bytes)?;
    let debug = DebugInfo::read(&bytes, &image);
    assert!(debug.functions.is_empty() && !debug.diagnostics.is_empty());

    let file = object::File::parse(ELF4)?;
    let (offset, size) = file
        .section_by_name(".debug_info")
        .and_then(|s| s.file_range())
        .ok_or_else(|| anyhow::anyhow!("info"))?;
    let image = LoadedImage::parse(ELF4)?;
    for index in 0..size as usize {
        let mut bytes = ELF4.to_vec();
        bytes[offset as usize + index] ^= 0xff;
        let debug = DebugInfo::read(&bytes, &image);
        assert!(debug.functions.len() <= 3);
        // Some mutations remain valid; malformed units must be discarded as a whole.
        if !debug.diagnostics.is_empty() {
            assert!(debug.functions.is_empty());
        }
    }
    Ok(())
}

#[test]
fn caller_names_and_explicit_signatures_override_debug_context() -> anyhow::Result<()> {
    use binfera::decompiler::{CallingConvention, ValueType};
    use std::collections::BTreeMap;
    let (_, analysis) = DecompilerSession::from_bytes_with_analysis(ELF4)?;
    let debug = analysis
        .dwarf
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("debug"))?;
    let entry = address(debug, "update")?;
    let mut session = DecompilerSession::from_analysis(
        &analysis,
        &BTreeMap::from([(entry, "renamed".to_owned())]),
        CallingConvention::SystemVX64,
    )?;
    session.set_signature(entry, ValueType::U32, &[ValueType::Pointer, ValueType::I32])?;
    let output = session.decompile_function(entry)?;
    assert_eq!(output.name.as_deref(), Some("renamed"));
    assert!(
        output.text.contains("unsigned int renamed("),
        "{}",
        output.text
    );
    Ok(())
}
