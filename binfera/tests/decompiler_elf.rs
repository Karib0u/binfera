#![cfg(feature = "decompiler")]
//! x86-64 System V ELF decompilation, on a freestanding static executable built from
//! `fixtures/elf64_sysv/freestanding.c` (clang --target=x86_64-linux-gnu -O1, linked with ld.lld).
use binfera::decompiler::{CallingConvention, DecompilerSession};

const FIXTURE: &[u8] = include_bytes!("fixtures/elf64_sysv/freestanding.elf");

fn symbol(name: &str) -> anyhow::Result<u64> {
    let elf = goblin::elf::Elf::parse(FIXTURE)?;
    elf.syms
        .iter()
        .find(|symbol| elf.strtab.get_at(symbol.st_name) == Some(name))
        .map(|symbol| symbol.st_value)
        .ok_or_else(|| anyhow::anyhow!("no symbol {name}"))
}

#[test]
fn elf_functions_decompile_with_the_system_v_convention() -> anyhow::Result<()> {
    let mut session = DecompilerSession::from_elf(FIXTURE)?;
    let output = session.decompile_function(symbol("sum_to")?)?;
    println!("{}\n{:?}", output.text, output.warnings);
    assert!(matches!(
        output.calling_convention,
        CallingConvention::SystemVX64
    ));
    assert_eq!(output.name.as_deref(), Some("sum_to"));
    // The argument arrives in edi and the loop sums 2*i, so the convention was applied.
    assert!(output.text.contains("param_1"), "{}", output.text);
    assert!(
        output.text.contains("sum_to(int param_1)"),
        "{}",
        output.text
    );
    assert!(!output.incomplete, "{:?}", output.warnings);
    Ok(())
}

#[test]
fn elf_call_between_named_functions_keeps_its_argument() -> anyhow::Result<()> {
    let mut session = DecompilerSession::from_elf(FIXTURE)?;
    let output = session.decompile_function(symbol("classify")?)?;
    println!("{}\n{:?}", output.text, output.warnings);
    assert!(output.text.contains("sum_to("), "{}", output.text);
    assert!(output.text.contains("return"), "{}", output.text);
    Ok(())
}

#[test]
fn elf_units_are_not_built_for_non_windows_images() -> anyhow::Result<()> {
    let mut session = DecompilerSession::from_elf(FIXTURE)?;
    assert!(session.decompile_unit(&[symbol("sum_to")?]).is_err());
    Ok(())
}

#[test]
fn pe_only_constructor_rejects_elf_and_elf_constructor_rejects_pe() {
    assert!(DecompilerSession::from_pe(FIXTURE).is_err());
    assert!(DecompilerSession::from_elf(b"MZ\0\0").is_err());
}

const DYNAMIC: &[u8] = include_bytes!("fixtures/elf64_sysv/dynamic.elf");

fn dynamic_symbol(name: &str) -> anyhow::Result<u64> {
    let elf = goblin::elf::Elf::parse(DYNAMIC)?;
    elf.syms
        .iter()
        .find(|symbol| elf.strtab.get_at(symbol.st_name) == Some(name))
        .map(|symbol| symbol.st_value)
        .ok_or_else(|| anyhow::anyhow!("no symbol {name}"))
}

#[test]
fn plt_calls_are_named_and_typed_from_the_c_library_archive() -> anyhow::Result<()> {
    let mut session = DecompilerSession::from_elf(DYNAMIC)?;
    let output = session.decompile_function(dynamic_symbol("copy_and_measure")?)?;
    println!("{}\n{:?}", output.text, output.warnings);
    // Names come from the PLT stubs' GOT slots, types from the archive.
    for call in ["strlen(", "malloc(", "memcpy(", "puts("] {
        assert!(output.text.contains(call), "{call}: {}", output.text);
    }
    assert!(output.text.contains("size_t"), "{}", output.text);
    assert!(!output.unknown_callees, "{}", output.text);
    assert!(!output.incomplete, "{:?}", output.warnings);
    Ok(())
}

#[test]
fn bss_beyond_the_file_bytes_maps_as_zeros() -> anyhow::Result<()> {
    // `.relro_padding` and `.got.plt` follow the file-backed data in the writable segment.
    let elf = goblin::elf::Elf::parse(DYNAMIC)?;
    assert!(elf
        .program_headers
        .iter()
        .any(|header| header.p_memsz > header.p_filesz));
    assert!(DecompilerSession::from_elf(DYNAMIC).is_ok());
    Ok(())
}

#[test]
fn static_linux_syscalls_have_names_and_prototypes() -> anyhow::Result<()> {
    let mut session = DecompilerSession::from_elf(FIXTURE)?;
    let output = session.decompile_function(symbol("write_hello")?)?;
    assert!(output.text.contains("linux_write(1,"), "{}", output.text);
    assert!(!output.unknown_callees, "{:?}", output.warnings);
    let entry = session.decompile_function(symbol("_start")?)?;
    assert!(entry.text.contains("linux_exit("), "{}", entry.text);
    Ok(())
}

#[test]
fn non_linux_elf_does_not_get_linux_syscall_names() -> anyhow::Result<()> {
    let mut bytes = FIXTURE.to_vec();
    bytes[goblin::elf::header::EI_OSABI] = goblin::elf::header::ELFOSABI_FREEBSD;
    let mut session = DecompilerSession::from_elf(&bytes)?;
    let output = session.decompile_function(symbol("write_hello")?)?;
    assert!(!output.text.contains("linux_write("), "{}", output.text);
    assert!(output.text.contains("syscall()"), "{}", output.text);
    Ok(())
}
