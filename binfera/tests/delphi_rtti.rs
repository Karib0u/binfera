#[path = "common/delphi.rs"]
mod fixture;

use binfera::delphi::Rtti;
use binfera::extract::image::LoadedImage;
use binfera::extract::recovery::{analyze_with_backend, RecoveryBackend, SeedKind};
use fixture::Fixture;

#[test]
fn reads_class_names_and_methods_on_both_pointer_widths() -> anyhow::Result<()> {
    for (wide, modern) in [(false, false), (false, true), (true, true)] {
        let f = Fixture::new(wide, modern);
        let rtti = Rtti::read(&LoadedImage::from_pe(&f.bytes)?);
        assert_eq!(rtti.classes.len(), 2, "{rtti:?}");
        assert_eq!(rtti.classes[0].name, "TBase");
        assert_eq!(rtti.classes[1].parent, Some(rtti.classes[0].vmt));
        assert_eq!(
            rtti.methods.get(&(f.base + 0x1590)).map(String::as_str),
            Some("TBase::OnClick")
        );
        assert_eq!(
            rtti.methods.get(&(f.base + 0x15a0)).map(String::as_str),
            Some("TBase::Dynamic_0123")
        );
        assert_eq!(
            rtti.methods.get(&(f.base + 0x15b0)).map(String::as_str),
            Some("TBase::GetValue")
        );
        assert!(rtti.methods[&(f.base + 0x1580)].starts_with("TBase::FUN_"));
        assert!(rtti.data_ranges.iter().any(|r| r.contains(&f.base)));
    }
    Ok(())
}

#[test]
fn native_recovery_blocks_metadata_seeds_calls_and_instructions() -> anyhow::Result<()> {
    let mut f = Fixture::new(false, false);
    f.number(0xff, 0xb8, 1); // MOV immediate would straddle the VMT boundary.
    let analysis = analyze_with_backend(&f.bytes, RecoveryBackend::Native)?;
    let rtti = Rtti::read(&LoadedImage::from_pe(&f.bytes)?);
    for range in &rtti.data_ranges {
        assert!(
            !analysis.seeds.keys().any(|a| range.contains(a)),
            "seed in {range:?}"
        );
        assert!(
            !analysis.functions.keys().any(|a| range.contains(a)),
            "function in {range:?}"
        );
        assert!(
            !analysis
                .instructions
                .values()
                .any(|i| i.address < range.end && i.next_address > range.start),
            "instruction in {range:?}"
        );
    }
    for address in [0x1580, 0x1590, 0x15a0, 0x15b0] {
        assert!(analysis.functions.contains_key(&(f.base + address)));
        assert!(analysis.seeds[&(f.base + address)].contains(&SeedKind::DelphiMethod));
    }
    assert!(analysis.image.decode_at(f.base).is_err());
    assert!(analysis.image.decode_at(f.base + 0xff).is_err());
    assert!(analysis.image.decode_at(f.base + 0x1400).is_ok());
    assert_eq!(
        analysis.elf_function_symbols[&(f.base + 0x1590)][0],
        "TBase::OnClick"
    );
    Ok(())
}

#[test]
fn unrelated_shared_code_has_no_class_owner() -> anyhow::Result<()> {
    let mut f = Fixture::new(false, false);
    f.class(0xc00, "TOther", None);
    f.pointer(0xc00 + f.words * f.ptr, 0x1580);
    let rtti = Rtti::read(&LoadedImage::from_pe(&f.bytes)?);
    assert_eq!(rtti.classes.len(), 3);
    assert!(!rtti.methods.contains_key(&(f.base + 0x1580)));
    assert!(rtti.function_starts.contains(&(f.base + 0x1580)));
    assert_eq!(rtti.methods[&(f.base + 0x1590)], "TBase::OnClick");
    Ok(())
}

#[test]
fn published_names_win_and_shared_empty_stubs_stay_generic() -> anyhow::Result<()> {
    let mut f = Fixture::new(false, false);
    let vmt = 0x100 + f.words * f.ptr;
    f.pointer(vmt, 0x1590);
    f.pointer(vmt - 2 * f.ptr, 0x15c0);
    f.pointer(vmt - 3 * f.ptr, 0x15c0);
    let rtti = Rtti::read(&LoadedImage::from_pe(&f.bytes)?);
    assert_eq!(rtti.methods[&(f.base + 0x1590)], "TBase::OnClick");
    assert!(rtti.methods[&(f.base + 0x15c0)].starts_with("TBase::FUN_"));
    Ok(())
}

#[test]
fn cyclic_parents_do_not_assign_misleading_method_owners() -> anyhow::Result<()> {
    let mut f = Fixture::new(false, false);
    f.pointer(0x100 + 10 * f.ptr, 0x400);
    let rtti = Rtti::read(&LoadedImage::from_pe(&f.bytes)?);
    assert!(rtti.methods.is_empty());
    assert!(rtti.function_starts.contains(&(f.base + 0x1590)));
    Ok(())
}

#[test]
fn interface_and_field_tables_remain_data() -> anyhow::Result<()> {
    let mut f = Fixture::new(false, false);
    f.pointer(0x100 + f.ptr, 0xb00);
    f.number(0xb00, 1, f.ptr);
    f.bytes[0xd04..0xd20].fill(0);
    f.pointer(0xb14, 0xb40);
    f.pointer(0xb40, 0x15c0);
    f.number(0xb44, 0, f.ptr);
    f.pointer(0x100 + 5 * f.ptr, 0xc00);
    f.number(0xc00, 1, 2);
    f.pointer(0xc02, 0xc40);
    f.number(0xc06, 8, 4);
    f.number(0xc0a, 0, 2);
    let end = f.string(0xc0c, "FValue");
    f.number(0xc40, 1, 2);
    f.pointer(0xc42, 0x100);
    let rtti = Rtti::read(&LoadedImage::from_pe(&f.bytes)?);
    for offset in [0xb00, 0xb1f, 0xb40, 0xc00, end - 1, 0xc40, 0xc45] {
        assert!(
            rtti.data_ranges
                .iter()
                .any(|r| r.contains(&(f.base + offset as u64))),
            "{offset:x}"
        );
    }
    assert!(rtti.function_starts.contains(&(f.base + 0x15c0)));
    Ok(())
}

#[test]
fn ordinary_pe_images_and_shellcode_do_not_acquire_delphi_metadata() -> anyhow::Result<()> {
    use binfera::extract::image::Architecture;
    let image = LoadedImage::from_pe(include_bytes!("fixtures/pe32_delphi/plain.exe"))?;
    assert!(Rtti::read(&image).data_ranges.is_empty());
    let image = LoadedImage::from_shellcode(&Fixture::new(false, false).bytes, Architecture::X86);
    assert!(Rtti::read(&image).classes.is_empty());
    Ok(())
}

#[test]
fn malformed_tables_do_not_hide_adjacent_code() -> anyhow::Result<()> {
    let mut f = Fixture::new(false, false);
    f.number(0x802, 0, 2); // non-advancing published record
    f.number(0x900, 65535, 2); // impossible dynamic count
    let rtti = Rtti::read(&LoadedImage::from_pe(&f.bytes)?);
    assert!(!rtti.methods.contains_key(&(f.base + 0x1590)));
    for offset in [0x800, 0x900, 0x1400, 0x1590] {
        assert!(!rtti
            .data_ranges
            .iter()
            .any(|r| r.contains(&(f.base + offset))));
    }
    // A broken VMT self pointer does not validate a class just because its name is readable.
    f.pointer(0x100, 0x101);
    f.pointer(0x400, 0x401);
    let rtti = Rtti::read(&LoadedImage::from_pe(&f.bytes)?);
    assert!(rtti.classes.is_empty());
    assert!(rtti.data_ranges.is_empty());
    Ok(())
}

#[test]
fn rejects_truncated_and_mutated_metadata_without_panicking() -> anyhow::Result<()> {
    let f = Fixture::new(false, false);
    for length in (0x200..f.bytes.len()).step_by(31) {
        if let Ok(image) = LoadedImage::from_pe(&f.bytes[..length]) {
            Rtti::read(&image);
        }
    }
    for offset in (0x200..0x1000).step_by(3) {
        let mut bytes = f.bytes.clone();
        bytes[offset..offset + 8].fill(0xff);
        Rtti::read(&LoadedImage::from_pe(&bytes)?);
    }
    Ok(())
}

#[cfg(feature = "decompiler")]
#[test]
fn decompiler_uses_method_names_and_refuses_rtti_as_code() -> anyhow::Result<()> {
    use binfera::decompiler::DecompilerSession;
    let f = Fixture::new(false, false);
    let mut session = DecompilerSession::from_pe(&f.bytes)?;
    let output = session.decompile_function(f.base + 0x1590)?;
    assert!(output.text.contains("TBase::OnClick"), "{}", output.text);
    assert!(
        (output.text.contains("42") || output.text.contains("0x2a")),
        "{}",
        output.text
    );
    assert!(session.decompile_function(f.base).is_err());
    assert!(session.decompile_function(f.base + 0x100).is_err());
    Ok(())
}
