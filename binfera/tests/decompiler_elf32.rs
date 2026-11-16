#![cfg(feature = "decompiler")]
//! System V i386 ELF decompilation, on the programs in `fixtures/elf32_sysv` (`build.sh` there:
//! clang --target=i386-linux-gnu -O1, linked with ld.lld). Ghidra 12.1.4 prints the same bodies
//! for `sum_to`, `classify` and `copy_and_measure`, apart from its type names.
use binfera::decompiler::{CallingConvention, Decompilation, DecompilerSession};

const FREESTANDING: &[u8] = include_bytes!("fixtures/elf32_sysv/freestanding.elf");
const DYNAMIC: &[u8] = include_bytes!("fixtures/elf32_sysv/dynamic.elf");
const PIC: &[u8] = include_bytes!("fixtures/elf32_sysv/pic.elf");
const THUNK: &[u8] = include_bytes!("fixtures/elf32_sysv/thunk.elf");
const THUNK_STRIPPED: &[u8] = include_bytes!("fixtures/elf32_sysv/thunk-stripped.elf");

/// The function's symbol, decompiled. A position-independent image is rebased by the loader, so
/// the symbol's value moves by the load bias.
fn decompile(image: &[u8], name: &str) -> anyhow::Result<Decompilation> {
    let elf = goblin::elf::Elf::parse(image)?;
    let symbol = elf
        .syms
        .iter()
        .find(|symbol| elf.strtab.get_at(symbol.st_name) == Some(name))
        .ok_or_else(|| anyhow::anyhow!("no symbol {name}"))?;
    let bias = binfera::extract::recovery::analyze(image)?.image.load_bias;
    let output = DecompilerSession::from_elf(image)?.decompile_function(symbol.st_value + bias)?;
    println!("{}\n{:?}", output.text, output.warnings);
    Ok(output)
}

/// The lowest recovered function of an image, which has no symbols to find it by.
fn first_function(image: &[u8]) -> anyhow::Result<u64> {
    let analysis = binfera::extract::recovery::analyze(image)?;
    analysis
        .functions
        .keys()
        .next()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("no functions"))
}

#[test]
fn i386_functions_take_their_arguments_from_the_stack() -> anyhow::Result<()> {
    let output = decompile(FREESTANDING, "sum_to")?;
    assert_eq!(output.calling_convention, CallingConvention::SystemVX86);
    assert!(
        output.text.contains("sum_to(int param_1)"),
        "{}",
        output.text
    );
    assert!(!output.incomplete, "{:?}", output.warnings);
    let output = decompile(FREESTANDING, "classify")?;
    assert!(output.text.contains("sum_to(param_1)"), "{}", output.text);
    Ok(())
}

#[test]
fn i386_64_bit_values_pair_two_registers() -> anyhow::Result<()> {
    // `long long widen(long long, int)`: the 64-bit argument is two stack words and the result
    // comes back in `edx:eax`.
    let output = decompile(FREESTANDING, "widen")?;
    assert!(output.text.contains("CONCAT44("), "{}", output.text);
    assert!(output.text.contains("param_3"), "{}", output.text);
    Ok(())
}

#[test]
fn absolute_and_ebx_relative_plt_calls_are_named_and_typed() -> anyhow::Result<()> {
    // `dynamic.elf` jumps through absolute GOT slots; `pic.elf` through `[ebx + slot]`.
    for image in [DYNAMIC, PIC] {
        let output = decompile(image, "copy_and_measure")?;
        for call in ["strlen(", "malloc(", "memcpy(", "puts("] {
            assert!(output.text.contains(call), "{call}: {}", output.text);
        }
        assert!(
            output
                .text
                .contains("size_t copy_and_measure(char *param_1)"),
            "{}",
            output.text
        );
        assert!(!output.unknown_callees, "{}", output.text);
        assert!(!output.incomplete, "{:?}", output.warnings);
    }
    Ok(())
}

#[test]
fn get_pc_thunk_is_modeled_named_or_stripped() -> anyhow::Result<()> {
    // Without the compiler spec's fixup the global read is `*(unaff_EBX + n)`.
    let output = decompile(THUNK, "add_counter")?;
    assert!(output.text.contains("return DAT_"), "{}", output.text);
    assert!(!output.text.contains("unaff_EBX"), "{}", output.text);
    let output = DecompilerSession::from_elf(THUNK_STRIPPED)?
        .decompile_function(first_function(THUNK_STRIPPED)?)?;
    println!("{}", output.text);
    assert!(output.text.contains("return DAT_"), "{}", output.text);
    assert!(!output.text.contains("unaff_EBX"), "{}", output.text);
    Ok(())
}

#[test]
fn i386_units_are_not_built() -> anyhow::Result<()> {
    let mut session = DecompilerSession::from_elf(FREESTANDING)?;
    assert!(session
        .decompile_unit(&[first_function(FREESTANDING)?])
        .is_err());
    Ok(())
}

#[test]
fn from_bytes_picks_the_format() -> anyhow::Result<()> {
    assert!(DecompilerSession::from_bytes(FREESTANDING).is_ok());
    assert!(DecompilerSession::from_bytes(b"MZ\0\0").is_err());
    Ok(())
}

#[test]
fn i386_static_linux_syscalls_have_names_and_prototypes() -> anyhow::Result<()> {
    let output = decompile(FREESTANDING, "write_hello")?;
    assert!(output.text.contains("linux_write(1,"), "{}", output.text);
    assert!(!output.text.contains("swi("), "{}", output.text);
    assert!(!output.unknown_callees, "{:?}", output.warnings);
    let entry = decompile(FREESTANDING, "_start")?;
    assert!(entry.text.contains("linux_exit("), "{}", entry.text);
    Ok(())
}
