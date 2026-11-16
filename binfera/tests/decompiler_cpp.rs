#![cfg(feature = "decompiler")]
//! C++ programs: demangled names and the prototypes Microsoft decorations encode, and classes read
//! from MSVC RTTI (labeled virtual function tables, methods named for their class, `this` typed,
//! calls through a table naming their target). Source and build script in `fixtures/cpp`.
use binfera::decompiler::DecompilerSession;

const RTTI32: &[u8] = include_bytes!("fixtures/cpp/rtti32.dll");
const RTTI64: &[u8] = include_bytes!("fixtures/cpp/rtti64.dll");
const RTTI_ELF: &[u8] = include_bytes!("fixtures/cpp/rtti64.elf");

/// The text with every run of whitespace as one space, and none where the printer wrapped a long
/// C++ name before its arguments.
fn flat(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace(") ((", ")((")
        .replace(" (", "(")
}

#[test]
fn microsoft_names_and_prototypes() -> anyhow::Result<()> {
    for (sample, add, use_channel, box_user) in [
        (RTTI32, 0x1000_1030, 0x1000_1050, 0x1000_10d0),
        (RTTI64, 0x1_8000_1030, 0x1_8000_1050, 0x1_8000_10e0),
    ] {
        let mut session = DecompilerSession::from_bytes(sample)?;
        // A decorated export: its label, and the `this` and parameters its decoration encodes.
        let output = session.decompile_function(add)?;
        assert_eq!(output.name.as_deref(), Some("Counter::add"));
        assert!(
            output
                .text
                .contains("int __thiscall Counter::add(Counter *this,int param_1)"),
            "{}",
            output.text
        );
        // A decorated import from the C++ runtime is a method too: `this` is the local object.
        let output = session.decompile_function(use_channel)?;
        let text = flat(&output.text);
        assert!(
            text.contains("std::_Lockit::_Lockit((std::_Lockit *)") && text.contains(",2);"),
            "{}",
            output.text
        );
        assert!(
            text.contains("std::_Lockit::~_Lockit((std::_Lockit *)"),
            "{}",
            output.text
        );
        // A virtual function table is labeled for its class.
        let output = session.decompile_function(box_user)?;
        assert!(
            output.text.contains("= &net::Box<int>::vftable;"),
            "{}",
            output.text
        );
    }
    Ok(())
}

#[test]
fn rtti_names_methods_types_this_and_resolves_virtual_calls() -> anyhow::Result<()> {
    for (sample, constructor, send, recv, log) in [
        (
            RTTI32,
            0x1000_1150u64,
            0x1000_11d0u64,
            "FUN_100011a0",
            "FUN_10001210",
        ),
        (
            RTTI64,
            0x1_8000_1160,
            0x1_8000_11e0,
            "FUN_1800011c0",
            "FUN_180001240",
        ),
    ] {
        let mut session = DecompilerSession::from_bytes(sample)?;
        // The constructor stores both of the class's tables, the second for its Logger part.
        let output = session.decompile_function(constructor)?;
        assert!(
            output.text.contains("= &net::LoggingChannel::vftable;")
                && output
                    .text
                    .contains("= &net::LoggingChannel::vftable_for_Logger;"),
            "{}",
            output.text
        );
        // LoggingChannel::send: named for its class, `this` typed, and both virtual calls on
        // `this` go through the tables' fields, which name the functions in their slots.
        let output = session.decompile_function(send)?;
        let name = output.name.clone().unwrap_or_default();
        assert!(
            name.starts_with("net::LoggingChannel::FUN_"),
            "{name}: {}",
            output.text
        );
        let text = flat(&output.text);
        assert!(
            text.contains(&format!("{name}(net::LoggingChannel *this,")),
            "{}",
            output.text
        );
        assert!(
            text.contains(&format!("(*this->vftable->{recv})(this,")),
            "{}",
            output.text
        );
        assert!(
            text.contains(&format!(
                "(*this->vftable_for_Logger->{log})((net::Logger *)&this->vftable_for_Logger,"
            )),
            "{}",
            output.text
        );
        // An access past the table pointers is an offset into the object, not an array index.
        assert!(!text.contains("this[1]"), "{}", output.text);
        // Same text in a fresh session and in another request order.
        let first = output.text.clone();
        let mut fresh = DecompilerSession::from_bytes(sample)?;
        fresh.decompile_function(constructor)?;
        assert_eq!(fresh.decompile_function(send)?.text, first);
        assert_eq!(session.decompile_function(send)?.text, first);
    }
    Ok(())
}

#[test]
fn itanium_names() -> anyhow::Result<()> {
    let mut session = DecompilerSession::from_bytes(RTTI_ELF)?;
    let output = session.decompile_function(0x200_2620)?;
    assert_eq!(output.name.as_deref(), Some("net::TcpChannel::send"));
    // Imports from the C++ runtime are demangled too.
    let output = session.decompile_function(0x200_24f0)?;
    assert!(
        output.text.contains("std::_Lockit::_Lockit(")
            && output.text.contains("std::_Lockit::~_Lockit("),
        "{}",
        output.text
    );
    let output = session.decompile_function(0x200_2550)?;
    assert!(
        output
            .text
            .contains("net::LoggingChannel::LoggingChannel(param_1,9);"),
        "{}",
        output.text
    );
    Ok(())
}

#[test]
fn units_refuse_cpp_names() -> anyhow::Result<()> {
    let mut session = DecompilerSession::from_bytes(RTTI32)?;
    // `use_channel` calls `std::_Lockit::_Lockit`, which C cannot declare.
    let refused = session.decompile_unit(&[0x1000_1050]);
    assert!(
        matches!(&refused, Err(binfera::decompiler::DecompileError::Unsupported(message)) if message.contains("C++")),
        "{refused:?}"
    );
    // A function that names none still makes a unit.
    let unit = session.decompile_unit(&[0x1000_1110])?;
    assert!(unit.text.contains("DllEntryPoint"), "{}", unit.text);
    Ok(())
}

#[test]
fn com_interface_methods_keep_this_on_the_stack() -> anyhow::Result<()> {
    // `Thing` implements a COM-style interface: on x86 its methods are `__stdcall`, `this` on the
    // stack, so they are named for the class but never made `__thiscall`.
    let mut session = DecompilerSession::from_bytes(RTTI32)?;
    let output = session.decompile_function(0x1000_1260)?;
    assert_eq!(output.name.as_deref(), Some("Thing::FUN_10001260"));
    assert!(
        !output.text.contains("__thiscall") && output.text.contains("(int param_1,int param_2)"),
        "{}",
        output.text
    );
    // On x64 every convention passes `this` first in RCX.
    let mut session = DecompilerSession::from_bytes(RTTI64)?;
    let output = session.decompile_function(0x1_8000_1290)?;
    assert!(output.text.contains("(Thing *this,"), "{}", output.text);
    Ok(())
}
