#![cfg(feature = "decompiler")]
//! Delphi's `register` calling convention on x86-32 PE, on `fixtures/pe32_delphi` (`build.sh`
//! there). Both images hold the same MinGW-built program, whose functions take their arguments
//! in `EAX`, `EDX` and `ECX` (gcc's regparm(3)); `delphi.exe` also has Borland's `CODE` section
//! name, which is what makes Ghidra 12.1.4 (and this crate) load it with `x86delphi.cspec`.
//! Ghidra prints the same three bodies for `delphi.exe`, apart from its type names.
use binfera::decompiler::{CallingConvention, DecompilerSession};

const DELPHI: &[u8] = include_bytes!("fixtures/pe32_delphi/delphi.exe");
const PLAIN: &[u8] = include_bytes!("fixtures/pe32_delphi/plain.exe");
const SCALE: u64 = 0x401000;
const PICK: u64 = 0x401006;
const ENTRY: u64 = 0x40103e;

#[test]
fn delphi_layout_selects_the_register_convention() -> anyhow::Result<()> {
    let mut session = DecompilerSession::from_pe(DELPHI)?;
    let output = session.decompile_function(SCALE)?;
    println!("{}\n{:?}", output.text, output.warnings);
    assert_eq!(output.calling_convention, CallingConvention::DelphiX86);
    assert!(
        output.text.contains("return param_1 * param_2 + param_3;"),
        "{}",
        output.text
    );
    assert!(!output.text.contains("in_EAX"), "{}", output.text);
    Ok(())
}

#[test]
fn register_arguments_reach_their_callees_in_order() -> anyhow::Result<()> {
    let mut session = DecompilerSession::from_pe(DELPHI)?;
    let output = session.decompile_function(PICK)?;
    println!("{}\n{:?}", output.text, output.warnings);
    assert!(output.text.contains("if (param_1 < 0)"), "{}", output.text);
    assert!(
        output
            .text
            .contains("FUN_00401000(param_2,param_3,param_1)"),
        "{}",
        output.text
    );
    assert!(
        output.text.contains("FUN_00401000(param_3,param_2,7)"),
        "{}",
        output.text
    );
    Ok(())
}

#[test]
fn a_callee_inferred_as_void_still_returns_in_eax() -> anyhow::Result<()> {
    // `pick`'s own analysis finds no return value (it tail-returns `scale`'s), but its caller
    // passes the result to ExitProcess. Delphi's model does not kill EAX at a call, so a locked
    // void would show the caller's stale `GetTickCount() & 7` instead.
    let mut session = DecompilerSession::from_pe(DELPHI)?;
    let output = session.decompile_function(ENTRY)?;
    println!("{}\n{:?}", output.text, output.warnings);
    assert!(
        output
            .text
            .contains("uExitCode = FUN_00401006(DVar1 & 7,3,4);"),
        "{}",
        output.text
    );
    assert!(output.incomplete, "{:?}", output.warnings);
    Ok(())
}

#[test]
fn the_same_code_without_the_borland_layout_keeps_the_windows_convention() -> anyhow::Result<()> {
    let mut session = DecompilerSession::from_pe(PLAIN)?;
    let output = session.decompile_function(SCALE)?;
    println!("{}", output.text);
    assert_eq!(output.calling_convention, CallingConvention::WindowsX86);
    // What the register convention looks like when it is read as __fastcall.
    assert!(output.text.contains("in_EAX"), "{}", output.text);
    Ok(())
}

#[test]
fn units_are_not_built_for_the_register_convention() -> anyhow::Result<()> {
    let mut session = DecompilerSession::from_pe(DELPHI)?;
    assert!(session.decompile_unit(&[SCALE]).is_err());
    Ok(())
}
