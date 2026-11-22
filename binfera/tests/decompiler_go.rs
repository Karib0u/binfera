#![cfg(feature = "decompiler")]
//! Go programs: names from the function table, Go's calling conventions, standard library
//! signatures from Ghidra's API snapshots, and the goroutine register.
use binfera::decompiler::DecompilerSession;
use binfera::extract::image::LoadedImage;

/// Go 1.27, Windows x86-64, the register ABI; source and build command beside it.
const REGISTER_ABI: &[u8] = include_bytes!("fixtures/go/register_abi.exe");
/// Go 1.16.2, Windows x86-64: the stack ABI, from before Go 1.17.
const STACK_ABI_X64: &[u8] =
    include_bytes!("../../tests/testfiles/4122acca2f9ea98fc3f3ad040688e4ce.exe_");
/// Go 1.22.1, Linux i386: the stack ABI, which 386 keeps.
const I386_ELF: &[u8] = include_bytes!(
    "../../tests/testfiles/3da7c2c70a2d93ac4643f20339d5c7d61388bddd77a4a5fd732311efad78e535.elf_"
);

/// A function's entry, by its Go name.
fn entry(sample: &[u8], name: &str) -> anyhow::Result<u64> {
    let image = LoadedImage::parse(sample)?;
    let go = binfera::golang::parse(&image).ok_or_else(|| anyhow::anyhow!("not a Go binary"))?;
    go.functions
        .functions
        .iter()
        .find(|function| function.name == name)
        .map(|function| function.entry)
        .ok_or_else(|| anyhow::anyhow!("no function {name}"))
}

#[test]
fn register_abi_names_signatures_and_goroutine() -> anyhow::Result<()> {
    let mut session = DecompilerSession::from_bytes(REGISTER_ABI)?;
    let output = session.decompile_function(entry(REGISTER_ABI, "main.readFirst")?)?;
    println!("{}\n{:?}", output.text, output.warnings);
    assert_eq!(
        serde_json::to_value(output.calling_convention)?,
        serde_json::json!("go_windows_x64")
    );
    assert_eq!(output.name.as_deref(), Some("main.readFirst"));
    // The string argument arrives in RAX and RBX, so the function has two parameters.
    assert!(
        output
            .text
            .contains("main.readFirst(uint8 *param_1,int param_2)"),
        "{}",
        output.text
    );
    // Standard library calls take their snapshot signatures: a string argument, results in a
    // structure laid out like the registers that hold them.
    assert!(
        output.text.contains("= os.OpenFile(name,0,0);"),
        "{}",
        output.text
    );
    assert!(
        output.text.contains(".~r1.tab == NULL") || output.text.contains(".~r1.tab != NULL"),
        "{}",
        output.text
    );
    assert!(output.text.contains("os.(*File).Read("), "{}", output.text);
    // The verified stack-growth check is runtime scaffolding.
    assert!(
        !output.text.contains("CURRENT_G.stackguard0")
            && !output.text.contains("runtime.morestack"),
        "{}",
        output.text
    );
    assert!(!output.text.contains("unaff_R14"), "{}", output.text);
    assert!(!output.text.contains("in_RAX"), "{}", output.text);
    // Go's names for the core types: an eight-byte integer is never `int8`.
    let words: Vec<&str> = output
        .text
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .collect();
    assert!(
        !words.contains(&"int8") && words.contains(&"undefined8"),
        "{}",
        output.text
    );
    // A known no-return runtime function ends its path.
    let main = session.decompile_function(entry(REGISTER_ABI, "main.main")?)?;
    assert!(main.text.contains("os.Exit(2);"), "{}", main.text);
    assert_eq!(
        session
            .decompile_function(entry(REGISTER_ABI, "main.readFirst")?)?
            .text,
        output.text
    );
    Ok(())
}

#[test]
fn stack_abi_before_go_1_17() -> anyhow::Result<()> {
    let mut session = DecompilerSession::from_pe(STACK_ABI_X64)?;
    let output = session.decompile_function(entry(STACK_ABI_X64, "main.appendToFile")?)?;
    println!("{}\n{:?}", output.text, output.warnings);
    assert_eq!(
        serde_json::to_value(output.calling_convention)?,
        serde_json::json!("go_windows_x64")
    );
    // Every function uses the stack ABI; results come back on the stack too.
    assert!(
        output.text.contains("void abi0 main.appendToFile("),
        "{}",
        output.text
    );
    assert!(output.text.contains("= os.Stat(name);"), "{}", output.text);
    assert!(
        output.text.contains("os.OpenFile(name_00,0x401,0x180)"),
        "{}",
        output.text
    );
    // Go 1.16's write barrier takes the value in a named register and the destination in RDI.
    assert!(
        output.text.contains("runtime.gcWriteBarrierCX(value,"),
        "{}",
        output.text
    );
    assert!(!output.text.contains("in_RAX"), "{}", output.text);
    // Before Go 1.17 the stack check reads the goroutine through RCX, loaded from TLS.
    assert!(
        !output.text.contains("runtime.morestack"),
        "{}",
        output.text
    );
    // Go strings are counted, not terminated: each literal is exactly the length passed beside
    // it (`errors.Wrap(err, msg, len)` before the register ABI), never a run into neighbours.
    for (literal, length) in [
        ("\"destination file does not exist\",0x1f", 31),
        ("\"failed opening destination file\",0x1f", 31),
        ("\"failed appending compressed to destination\",0x2a", 42),
    ] {
        assert!(output.text.contains(literal), "{literal}\n{}", output.text);
        assert_eq!(literal.split('"').nth(1).map(str::len), Some(length));
    }
    assert_eq!(output.text.matches('"').count(), 6, "{}", output.text);
    Ok(())
}

#[test]
fn i386_elf_uses_the_stack_abi() -> anyhow::Result<()> {
    let mut session = DecompilerSession::from_bytes(I386_ELF)?;
    let output = session.decompile_function(entry(I386_ELF, "main.main")?)?;
    println!("{}\n{:?}", output.text, output.warnings);
    assert_eq!(
        serde_json::to_value(output.calling_convention)?,
        serde_json::json!("go_system_v_x86")
    );
    assert_eq!(output.name.as_deref(), Some("main.main"));
    assert!(
        output.text.contains("runtime.printstring(s);"),
        "{}",
        output.text
    );
    assert!(
        output.text.contains("runtime.printint((int64)"),
        "{}",
        output.text
    );
    Ok(())
}

#[test]
fn units_are_refused_for_go() -> anyhow::Result<()> {
    let mut session = DecompilerSession::from_bytes(REGISTER_ABI)?;
    let error = session
        .decompile_unit(&[entry(REGISTER_ABI, "main.main")?])
        .err()
        .ok_or_else(|| anyhow::anyhow!("a Go unit was built"))?;
    assert!(error.to_string().contains("Visual C"), "{error}");
    Ok(())
}
