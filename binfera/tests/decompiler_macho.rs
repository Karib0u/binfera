#![cfg(feature = "decompiler")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use binfera::decompiler::{CallingConvention, DecompilerSession};
use binfera::extract::image::{select_macho_slice, Architecture};

const FAT: &[u8] = include_bytes!("fixtures/macho/fat-x86_64-arm64-exe");

#[test]
fn universal_slices_recover_and_decompile_their_own_functions() -> anyhow::Result<()> {
    for (arch, cpu, convention) in [
        ("x86_64", Architecture::X64, CallingConvention::DarwinX64),
        (
            "arm64",
            Architecture::AArch64,
            CallingConvention::DarwinAArch64,
        ),
    ] {
        let (slice, _) = select_macho_slice(FAT, Some(arch))?;
        let (mut session, analysis) =
            DecompilerSession::from_bytes_with_arch_and_analysis(FAT, Some(arch))?;
        assert_eq!(analysis.image.architecture, cpu);
        let thin = binfera::extract::recovery::analyze_macho(slice, None)?;
        assert_eq!(analysis.elf_function_symbols, thin.elf_function_symbols);
        assert_eq!(
            analysis.functions.keys().collect::<Vec<_>>(),
            thin.functions.keys().collect::<Vec<_>>()
        );
        let entry = analysis.image.entry_point.unwrap();
        let result = session.decompile_function(entry)?;
        println!("{arch}: {}\n{:?}", result.text, result.warnings);
        assert_eq!(result.calling_convention, convention);
        assert!(result.text.contains("main("), "{}", result.text);
        assert!(result.text.contains("malloc(0x10)"), "{}", result.text);
        assert!(result.text.contains("puts("), "{}", result.text);
        assert!(result.text.contains("free("), "{}", result.text);
        assert!(!result.text.contains("Bad instruction"), "{}", result.text);
        assert!(!result.text.contains("sys_linux"), "{}", result.text);
    }
    Ok(())
}

#[test]
fn automatic_thin_and_stripped_images_open() -> anyhow::Result<()> {
    for bytes in [
        include_bytes!("fixtures/macho/thin-x86_64-exe").as_slice(),
        include_bytes!("fixtures/macho/thin-arm64-exe").as_slice(),
        include_bytes!("fixtures/macho/stripped-x86_64-exe").as_slice(),
    ] {
        let (mut session, analysis) = DecompilerSession::from_bytes_with_analysis(bytes)?;
        assert!(!analysis.functions.is_empty());
        session.decompile_function(analysis.image.entry_point.unwrap())?;
    }
    Ok(())
}

#[test]
fn stripped_objc_methods_categories_and_selectors_are_readable() -> anyhow::Result<()> {
    for bytes in [
        include_bytes!("fixtures/macho_metadata/objc-x86_64").as_slice(),
        include_bytes!("fixtures/macho_metadata/objc-arm64").as_slice(),
        include_bytes!("fixtures/macho_metadata/classic-x86_64").as_slice(),
        include_bytes!("fixtures/macho_metadata/classic-arm64").as_slice(),
    ] {
        let (mut session, analysis) = DecompilerSession::from_bytes_with_analysis(bytes)?;
        assert!(
            analysis.image.load_diagnostics.is_empty(),
            "{:?}",
            analysis.image.load_diagnostics
        );
        for wanted in [
            "-[AuditObject add:]",
            "+[AuditObject new]",
            "-[AuditObject(Extra) extra]",
        ] {
            let address = analysis
                .elf_function_symbols
                .iter()
                .find(|(_, names)| names.iter().any(|name| name == wanted))
                .map(|(address, _)| *address)
                .ok_or_else(|| {
                    anyhow::anyhow!("missing {wanted}: {:?}", analysis.elf_function_symbols)
                })?;
            let result = session.decompile_function(address)?;
            println!("{wanted}: {}", result.text);
            assert!(result.text.contains("return"), "{}", result.text);
            if wanted.contains("add:") {
                assert!(
                    result.text.contains("0x2a") || result.text.contains("42"),
                    "{}",
                    result.text
                );
            }
        }
        let entry = session.decompile_function(analysis.image.entry_point.unwrap())?;
        println!("ObjC caller: {}\n{:?}", entry.text, entry.warnings);
        assert!(entry.text.contains("objc_msgSend"), "{}", entry.text);
        assert!(
            entry.text.contains("sel_")
                || entry.text.contains("objc_msgSend_add_")
                || entry.text.contains("\"new\""),
            "{}",
            entry.text
        );
    }
    Ok(())
}

#[test]
fn swift_type_metadata_names_accessors_without_a_demangler() -> anyhow::Result<()> {
    let bytes = include_bytes!("fixtures/macho_metadata/swift-arm64.dylib");
    let (mut session, analysis) = DecompilerSession::from_bytes_with_analysis(bytes)?;
    let accessor = analysis
        .elf_function_symbols
        .iter()
        .find(|(_, names)| {
            names
                .iter()
                .any(|name| name == "Audit::AuditRecord::metadata_accessor")
        })
        .map(|(address, _)| *address)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "missing Swift metadata accessor: {:?}",
                analysis.elf_function_symbols
            )
        })?;
    let result = session.decompile_function(accessor)?;
    assert!(result.text.contains("AuditRecord"), "{}", result.text);
    assert!(result.text.contains("return"), "{}", result.text);
    Ok(())
}

#[test]
fn go_macho_uses_darwin_names_and_embedded_dwarf() -> anyhow::Result<()> {
    let bytes = include_bytes!("fixtures/macho_metadata/go-x86_64");
    let (mut session, analysis) = DecompilerSession::from_bytes_with_analysis(bytes)?;
    let debug = analysis
        .dwarf
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing DWARF"))?;
    let address = debug
        .functions
        .iter()
        .find(|(_, function)| function.name == "main.combine")
        .map(|(address, _)| *address)
        .ok_or_else(|| anyhow::anyhow!("missing main.combine"))?;
    let output = session.decompile_function(address)?;
    assert_eq!(output.calling_convention, CallingConvention::GoDarwinX64);
    assert!(
        output.text.contains("left") && output.text.contains("right"),
        "{}",
        output.text
    );
    assert!(!output.text.contains("unaff_"), "{}", output.text);
    assert!(output.text.contains("return"), "{}", output.text);
    Ok(())
}
