#![cfg(feature = "decompiler")]
use binfera::decompiler::{CallingConvention, DecompilerSession, ValueType};
use binfera::extract::image::LoadedImage;

const EXEC: &[u8] = include_bytes!("fixtures/aarch64_decompiler/executable.elf");
const PIE: &[u8] = include_bytes!("fixtures/aarch64_decompiler/pie.elf");
const SHARED: &[u8] = include_bytes!("fixtures/aarch64_decompiler/shared.elf");
const PE: &[u8] = include_bytes!("fixtures/aarch64_decompiler/windows.exe");

fn symbol(bytes: &[u8], name: &str) -> anyhow::Result<u64> {
    let image = LoadedImage::parse(bytes)?;
    if bytes.starts_with(b"MZ") {
        let pe = goblin::pe::PE::parse(bytes)?;
        return pe
            .exports
            .iter()
            .find(|s| s.name == Some(name))
            .map(|s| image.image_base + s.rva as u64)
            .ok_or_else(|| anyhow::anyhow!("missing export {name}"));
    }
    let elf = goblin::elf::Elf::parse(bytes)?;
    elf.syms
        .iter()
        .find(|s| elf.strtab.get_at(s.st_name) == Some(name))
        .map(|s| s.st_value + image.load_bias)
        .ok_or_else(|| anyhow::anyhow!("missing symbol {name}"))
}

#[test]
fn integer_float_stack_arguments_and_named_calls() -> anyhow::Result<()> {
    for bytes in [EXEC, PIE, SHARED, PE] {
        let mut session = DecompilerSession::from_bytes(bytes)?;
        // Scalar and vector FP returns share v0. Supply the source signature to
        // test scalar FP storage without guessing an ambiguous return width.
        session.set_signature(
            symbol(bytes, "floating")?,
            ValueType::F64,
            &[ValueType::F64, ValueType::F64],
        )?;
        for name in ["arithmetic", "floating", "ninth", "caller"] {
            let output = session.decompile_function(symbol(bytes, name)?)?;
            println!("{name}: {}\n{:?}", output.text, output.warnings);
            assert!(matches!(
                output.calling_convention,
                CallingConvention::WindowsAArch64 | CallingConvention::SystemVAArch64
            ));
            assert!(output.text.contains("param_1"), "{}", output.text);
            assert!(output.text.contains("return"), "{}", output.text);
            assert!(!output.text.contains("unaff_"), "{}", output.text);
            assert!(!output.text.contains("Bad instruction"), "{}", output.text);
            match name {
                "arithmetic" => assert!(
                    output.text.contains("* 3") && output.text.contains("param_2"),
                    "{}",
                    output.text
                ),
                "floating" => assert!(
                    output.text.contains("float8") && output.text.contains("2.0"),
                    "{}",
                    output.text
                ),
                "ninth" => assert!(output.text.contains("param_9"), "{}", output.text),
                "caller" => assert!(
                    output.text.contains("arithmetic(param_1,7)"),
                    "{}",
                    output.text
                ),
                _ => unreachable!(),
            }
        }
    }
    Ok(())
}

#[test]
fn plt_and_iat_imports_have_platform_prototypes() -> anyhow::Result<()> {
    for bytes in [PIE, SHARED, PE] {
        let mut session = DecompilerSession::from_bytes(bytes)?;
        let output = session.decompile_function(symbol(bytes, "imported")?)?;
        println!("{}\n{:?}", output.text, output.warnings);
        if bytes.starts_with(b"MZ") {
            assert!(output.text.contains("GetTickCount()"), "{}", output.text);
        } else {
            assert!(output.text.contains("puts(__s)"), "{}", output.text);
            assert!(output.text.contains("strlen(__s)"), "{}", output.text);
            assert!(output.text.contains("char *"), "{}", output.text);
        }
        assert!(!output.unknown_callees, "{:?}", output.warnings);
        assert!(!output.incomplete, "{:?}", output.warnings);
        assert!(output.text.contains("return"), "{}", output.text);
        if !bytes.starts_with(b"MZ") {
            // Without caller evidence a tail wrapper's return type can remain void.
            // With its source contract, verify that x0 forwards the imported result.
            session.set_signature(
                symbol(bytes, "imported")?,
                ValueType::U64,
                &[ValueType::CharPointer],
            )?;
            let typed = session.decompile_function(symbol(bytes, "imported")?)?;
            assert!(typed.text.contains("= strlen(param_1)"), "{}", typed.text);
            assert!(!typed.text.contains("void imported"), "{}", typed.text);
        }
    }
    Ok(())
}

#[test]
fn executable_iat_section_keeps_import_prototypes() -> anyhow::Result<()> {
    let mut bytes = PE.to_vec();
    let pe = goblin::pe::PE::parse(PE)?;
    let table = pe.header.dos_header.pe_pointer as usize
        + 24
        + pe.header.coff_header.size_of_optional_header as usize;
    for index in 0..pe.sections.len() {
        let offset = table + index * 40 + 36;
        let flags = u32::from_le_bytes(bytes[offset..offset + 4].try_into()?);
        bytes[offset..offset + 4].copy_from_slice(&(flags | 0x2000_0000).to_le_bytes());
    }
    let mut session = DecompilerSession::from_bytes(&bytes)?;
    let output = session.decompile_function(symbol(&bytes, "imported")?)?;
    assert!(output.text.contains("GetTickCount()"), "{}", output.text);
    assert!(!output.unknown_callees, "{:?}", output.warnings);
    Ok(())
}

#[test]
fn dynamic_relative_and_defined_symbol_relocations_are_applied() -> anyhow::Result<()> {
    for bytes in [PIE, SHARED] {
        let image = LoadedImage::parse(bytes)?;
        let pointer = |name| -> anyhow::Result<u64> {
            let address = symbol(bytes, name)?;
            Ok(u64::from_le_bytes(
                image
                    .bytes_at(address, 8)
                    .ok_or_else(|| anyhow::anyhow!("unmapped {name}"))?
                    .try_into()?,
            ))
        };
        let greeting = symbol(bytes, "greeting")?;
        assert_eq!(pointer("message")?, greeting);
        assert_eq!(pointer("exported_message")?, greeting);
        assert_eq!(
            pointer("message_address")?,
            symbol(bytes, "exported_message")?
        );
        assert!(!image
            .import_locations
            .values()
            .any(|n| n.ends_with("message")));
    }
    Ok(())
}

#[test]
fn raw_arm_syscalls_do_not_use_x86_syscall_overrides() -> anyhow::Result<()> {
    let mut session = DecompilerSession::from_bytes(EXEC)?;
    let output = session.decompile_function(symbol(EXEC, "raw_syscall")?)?;
    println!("{}", output.text);
    assert!(output.text.contains("CallSupervisor"), "{}", output.text);
    Ok(())
}

#[test]
fn mismatched_abi_and_relabelled_executables_are_rejected() -> anyhow::Result<()> {
    let analysis = binfera::extract::recovery::analyze(EXEC)?;
    assert!(DecompilerSession::from_analysis(
        &analysis,
        &Default::default(),
        CallingConvention::SystemVX64
    )
    .is_err());
    let mut object = EXEC.to_vec();
    object[16..18].copy_from_slice(&1u16.to_le_bytes());
    let error = DecompilerSession::from_bytes(&object)
        .err()
        .ok_or_else(|| anyhow::anyhow!("relabelled executable was accepted as an object"))?;
    assert!(error.to_string().contains("load segments"));
    Ok(())
}

#[test]
fn malformed_and_unsupported_dynamic_relocations_report_diagnostics() -> anyhow::Result<()> {
    let elf = goblin::elf::Elf::parse(PIE)?;
    let table = elf
        .section_headers
        .iter()
        .find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".rela.dyn"))
        .ok_or_else(|| anyhow::anyhow!("no relocation table"))?
        .sh_offset as usize;
    for (offset, bytes, diagnostic) in [
        (0, u64::MAX.to_le_bytes(), "overflow"),
        (0, 0x80000000u64.to_le_bytes(), "unmapped"),
        (
            8,
            1032u64.to_le_bytes(),
            "unsupported AArch64 ELF relocation",
        ),
    ] {
        let mut malformed = PIE.to_vec();
        malformed[table + offset..table + offset + 8].copy_from_slice(&bytes);
        let image = LoadedImage::parse(&malformed)?;
        assert!(
            image
                .load_diagnostics
                .iter()
                .any(|s| s.contains(diagnostic)),
            "{:?}",
            image.load_diagnostics
        );
    }
    // Goblin rejects impossible dynamic-symbol indices before relocation application.
    let mut bad_symbol = PIE.to_vec();
    bad_symbol[table + 8..table + 16]
        .copy_from_slice(&((u64::from(u32::MAX) << 32) | 257).to_le_bytes());
    assert!(LoadedImage::parse(&bad_symbol).is_err());
    // RELA uses its signed explicit addend, not the old bytes at the destination.
    let mut negative = PIE.to_vec();
    negative[table + 16..table + 24].copy_from_slice(&(-8i64).to_le_bytes());
    let image = LoadedImage::parse(&negative)?;
    let offset = u64::from_le_bytes(PIE[table..table + 8].try_into()?);
    let value = u64::from_le_bytes(
        image
            .bytes_at(offset + image.load_bias, 8)
            .ok_or_else(|| anyhow::anyhow!("unmapped relocation"))?
            .try_into()?,
    );
    assert_eq!(value, image.load_bias - 8);
    Ok(())
}
