#![cfg(feature = "decompiler")]
use binfera::decompiler::{CallingConvention, DecompilerSession, ValueType};

#[test]
fn narrow_returns_keep_proven_physical_bits_and_unknown_bits_stay_unknown() -> anyhow::Result<()> {
    for convention in [CallingConvention::SystemVX86, CallingConvention::SystemVX64] {
        for (callee, result, known) in [
            (
                vec![0x31, 0xc0, 0x85, 0xd2, 0x0f, 0x95, 0xc0, 0xc3],
                ValueType::Bool,
                true,
            ),
            (
                vec![0x85, 0xd2, 0x0f, 0x95, 0xc0, 0xc3],
                ValueType::Bool,
                false,
            ),
            (
                vec![0x0f, 0xb7, 0x02, 0x23, 0x01, 0xc3],
                ValueType::U16,
                true,
            ),
        ] {
            // CALL, full-EAX test, Boolean result. The callee begins at 0x20.
            let mut bytes = vec![
                0xe8, 0x1b, 0, 0, 0, 0x85, 0xc0, 0x0f, 0x95, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3,
            ];
            bytes.resize(0x20, 0xcc);
            bytes.extend(callee);
            let (mut session, _) =
                DecompilerSession::from_shellcode_with_analysis(&bytes, convention)?;
            session.set_signature(0x20, result, &[])?;
            let output = session.decompile_function(0)?;
            assert_eq!(!output.text.contains("extraout_"), known, "{}", output.text);
            session.decompile_function(0x20)?;
            assert_eq!(session.decompile_function(0)?.text, output.text);
        }
    }
    Ok(())
}

#[test]
fn an_unused_ecx_survives_a_leaf_call_but_a_written_ecx_does_not() -> anyhow::Result<()> {
    for (callee, preserved) in [
        (vec![0x31, 0xc0, 0xc3], true),
        (vec![0x31, 0xc9, 0x31, 0xc0, 0xc3], false),
    ] {
        // Keep a cursor in ECX across the call, then load through it.
        let mut bytes = vec![
            0x8b, 0x4c, 0x24, 4, 0xe8, 0x17, 0, 0, 0, 0x0f, 0xb7, 0x01, 0xc3,
        ];
        bytes.resize(0x20, 0xcc);
        bytes.extend(callee);
        let (mut session, _) =
            DecompilerSession::from_shellcode_with_analysis(&bytes, CallingConvention::SystemVX86)?;
        session.set_signature(0x20, ValueType::U32, &[])?;
        let output = session.decompile_function(0)?;
        assert_eq!(
            !output.text.contains("extraout_ECX"),
            preserved,
            "{}",
            output.text
        );
        assert_eq!(session.decompile_function(0)?.text, output.text);
    }
    Ok(())
}
