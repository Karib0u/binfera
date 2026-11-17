#![cfg(feature = "native")]
use binfera_ghidra::{Language, Session};

#[test]
fn inferred_void_does_not_erase_a_live_call_result() -> Result<(), Box<dyn std::error::Error>> {
    use binfera_ghidra::ValueType;
    for language in [Language::X86Linux64, Language::X86Apple64] {
        let mut session = Session::new(language)?;
        // Save the allocator wrapper's return and pass it to a known consumer.
        let caller = [
            0x48, 0x83, 0xec, 8, 0xe8, 0xf7, 0x0f, 0, 0, 0x48, 0x89, 0xc7, 0xe8, 0xef, 0x2f, 0, 0,
            0x48, 0x83, 0xc4, 8, 0xc3,
        ];
        let wrapper = [
            0x53, 0x6a, 1, 0x5f, 0x6a, 8, 0x5e, 0xe8, 0xf4, 0x0f, 0, 0, 0x48, 0x89, 0xc3, 0x6a, 2,
            0x5f, 0x6a, 8, 0x5e, 0xe8, 0xe6, 0x0f, 0, 0, 0x48, 0x89, 0x18, 0x5b, 0xc3,
        ];
        session.add_section(0x1000, &caller, true, true)?;
        session.add_section(0x2000, &wrapper, true, true)?;
        for (address, name) in [
            (0x1000, "caller"),
            (0x2000, "make_pair"),
            (0x3000, "allocate"),
            (0x4000, "consume"),
        ] {
            session.add_function(address, name, false)?;
        }
        session.set_signature(0x3000, ValueType::Pointer, &[ValueType::U64; 2])?;
        session.set_signature(0x4000, ValueType::I32, &[ValueType::Pointer])?;
        let output = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
        assert!(
            output
                .text
                .lines()
                .any(|line| line.contains('=') && line.contains("make_pair()")),
            "{}",
            output.text
        );
        assert!(!output.text.contains("extraout_"), "{}", output.text);
        assert!(
            output.incomplete && output.unknown_callees,
            "{:?}",
            output.warnings
        );
        assert_eq!(
            output.text,
            session.decompile(0x1000, 5000, 1000, 1_000_000)?.text
        );
        session.set_signature(0x2000, ValueType::Void, &[])?;
        let explicit = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
        assert!(explicit.text.contains("extraout_"), "{}", explicit.text);
        assert!(!explicit.unknown_callees, "{:?}", explicit.warnings);
    }
    Ok(())
}

#[test]
fn c_types_and_api_argument_local_names_are_stable() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new(Language::X86Windows64)?;
    session.add_section(
        0x1000,
        &[
            0x48, 0x81, 0xec, 0x48, 2, 0, 0, // sub rsp,0x248
            0x4c, 0x8d, 0x4c, 0x24, 0x20, // output buffer in R9
            0x45, 0x31, 0xc0, 0x31, 0xd2, 0x31, 0xc9, 0xff, 0x15, 0xe7, 0x0f, 0,
            0, // call [0x2000]
            0x48, 0x81, 0xc4, 0x48, 2, 0, 0, 0xc3,
        ],
        true,
        true,
    )?;
    session.add_section(0x2000, &[0; 8], false, false)?;
    session.add_function(0x1000, "make_temp", false)?;
    session.add_import(0x2000, "kernel32_GetTempFileNameW", false)?;
    assert!(session.apply_prototype(0x2000, "GetTempFileNameW")?);
    let output = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(output.text.contains("lpTempFileName"), "{}", output.text);
    assert!(!output.text.contains("int4 "), "{}", output.text);
    assert!(!output.text.contains("xunknown"), "{}", output.text);
    assert!(output.analysis_passes > 0);
    assert!(output.initial_ms > 0.0);
    assert_eq!(
        session.decompile(0x1000, 5000, 1000, 1_000_000)?.text,
        output.text
    );
    Ok(())
}

#[test]
fn instruction_lookahead_preserves_section_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    // mov eax, 42; ret. Cover contiguous lookahead, end padding, an adjacent
    // section, and a gap followed by another mapped section in the window.
    let code = [0xb8, 42, 0, 0, 0, 0xc3];
    let mut padded = code.to_vec();
    padded.resize(32, 0xcc);
    let layouts: Vec<Vec<(u64, &[u8])>> = vec![
        vec![(0x1000, &padded)],
        vec![(0x1000, &code)],
        vec![(0x1005, &code[5..]), (0x1000, &code[..5])],
        vec![(0x1008, &[0xcc; 8]), (0x1000, &code)],
    ];
    let mut expected = None;
    for sections in layouts {
        let mut session = Session::new(Language::X86Linux64)?;
        for (address, bytes) in sections {
            session.add_section(address, bytes, true, true)?;
        }
        session.add_function(0x1000, "answer", false)?;
        let output = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
        assert!(output.text.contains("return 0x2a;"), "{}", output.text);
        if let Some(expected) = &expected {
            assert_eq!(&output.text, expected);
        } else {
            expected = Some(output.text);
        }
    }
    Ok(())
}

#[test]
fn frame_lists_stack_symbols_with_their_instructions() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new(Language::X86Linux64)?;
    session.add_section(
        0x1000,
        &[
            0x48, 0x83, 0xec, 0x28, // sub rsp, 0x28
            0x48, 0x8d, 0x3c, 0x24, // lea rdi, [rsp]: a buffer whose address escapes
            0xe8, 0xf3, 0x0f, 0, 0, // call 0x2000
            0x48, 0x83, 0xc4, 0x28, // add rsp, 0x28
            0xc3, // ret
        ],
        true,
        true,
    )?;
    session.add_function(0x1000, "caller", false)?;
    session.add_function(0x2000, "fill", false)?;
    let output = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    let buffer = output
        .frame
        .iter()
        .find(|slot| slot.offset == -0x28)
        .ok_or_else(|| format!("{:?}\n{}", output.frame.len(), output.text))?;
    assert!(output.text.contains(&buffer.name), "{}", output.text);
    assert_eq!(buffer.size, 0x28, "{}", output.text);
    assert_eq!(buffer.type_name, "unsigned char[40]", "{}", output.text);
    assert!(!buffer.parameter);
    // Not `sub rsp`, where copy propagation leaves the pointer's definition: the call that uses it.
    assert_eq!(buffer.references, [0x1008], "{}", output.text);
    Ok(())
}

#[test]
fn frame_lists_register_parameters() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new(Language::X86Linux64)?;
    // mov rax, rdi; ret
    session.add_section(0x1000, &[0x48, 0x89, 0xf8, 0xc3], true, true)?;
    session.add_function(0x1000, "identity", false)?;
    let output = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    let parameter = output
        .frame
        .iter()
        .find(|slot| slot.register_name == "RDI")
        .ok_or_else(|| output.text.clone())?;
    assert!(parameter.parameter);
    assert!(output.text.contains(&parameter.name), "{}", output.text);
    assert_eq!(parameter.reads, [0x1000], "{}", output.text);
    Ok(())
}

#[test]
fn frame_reads_exclude_the_pieces_of_a_wide_store() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new(Language::X86Linux64)?;
    session.add_section(
        0x1000,
        &[
            0x48, 0x83, 0xec, 0x28, // sub rsp, 0x28
            0x0f, 0x57, 0xc0, // xorps xmm0, xmm0
            0x0f, 0x29, 0x04, 0x24, // movaps [rsp], xmm0
            0x48, 0x8b, 0x44, 0x24, 0x08, // mov rax, [rsp+8]
            0x48, 0x83, 0xc4, 0x28, // add rsp, 0x28
            0xc3, // ret
        ],
        true,
        true,
    )?;
    session.add_function(0x1000, "wide", false)?;
    let output = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    for slot in &output.frame {
        assert!(
            !slot.reads.contains(&0x1007) || !slot.writes.contains(&0x1007),
            "{}",
            output.text
        );
    }
    Ok(())
}

#[test]
fn low_byte_hint_requires_boolean_partial_returns() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new(Language::X86Linux64)?;
    // The comparison sets AL; the otherwise live pointer in upper RAX is not a
    // result when the caller consumes the Boolean low byte.
    session.add_section(
        0x1000,
        &[
            0x48, 0x85, 0xff, 0x75, 5, 0xe8, 0xf6, 0x1f, 0,
            0, // null pointer calls a noreturn helper
            0x50, 0x48, 0x89, 0xd0, // save stack slot; pointer in RDX
            0x48, 0x39, 0xf7, 0x74, 0x16, 0x48, 0x01, 0xc7, 0x48, 0x01, 0xc6, 0x48, 0x8d, 0x47, 1,
            0x48, 0x39, 0xf0, 0x74, 0x0b, 0xb1, 0x2f, 0x80, 0x3f, 0x2e, 0x74, 9, 0x31, 0xc0, 0x59,
            0xc3, 0xb1, 0x2e, 0x48, 0x89, 0xf8, 0x38, 8, 0x0f, 0x94, 0xc0, 0x59, 0xc3,
        ],
        true,
        true,
    )?;
    // A byte increment is not a Boolean return, even if a caller reads AL.
    session.add_section(0x2000, &[0x48, 0x89, 0xf8, 0xfe, 0xc0, 0xc3], true, true)?;
    for address in [0x1000, 0x2000] {
        session.add_function(address, "predicate", false)?;
    }
    session.add_function(0x3000, "panic", true)?;
    let before = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(before.text.contains("CONCAT71"), "{}", before.text);
    let narrowed = session.decompile_with_hints(0x1000, 5000, 1000, 1_000_000, 1, false)?;
    assert!(
        narrowed.text.contains("bool ") && !narrowed.text.contains("CONCAT71"),
        "{}",
        narrowed.text
    );
    assert_eq!(
        before.text,
        session.decompile(0x1000, 5000, 1000, 1_000_000)?.text
    );
    let integer = session.decompile_with_hints(0x2000, 5000, 1000, 1_000_000, 1, false)?;
    assert!(!integer.text.contains("bool "), "{}", integer.text);
    session.set_signature(
        0x1000,
        binfera_ghidra::ValueType::U64,
        &[binfera_ghidra::ValueType::Pointer],
    )?;
    let locked = session.decompile_with_hints(0x1000, 5000, 1000, 1_000_000, 1, false)?;
    assert!(
        locked.text.contains("unsigned long long ") && locked.text.contains("CONCAT71"),
        "{}",
        locked.text
    );
    Ok(())
}

#[test]
fn wrapped_byte_switch_recovers_low_cases_before_foreign_table(
) -> Result<(), Box<dyn std::error::Error>> {
    use binfera_ghidra::CodeRange;
    let mut session = Session::new(Language::X86Linux64)?;
    let mut code = vec![
        0x0f, 0xb6, 0x07, 0x3c, 6, 0x74, 0x49, 0x48, 0x8d, 0x0d, 0xf2, 0x0f, 0, 0, 0x48, 0x63,
        0x04, 0x81, 0x48, 0x01, 0xc8, 0xff, 0xe0,
    ];
    code.resize(0x30, 0xcc);
    code.extend([0xb8, 1, 0, 0, 0, 0xc3]);
    code.resize(0x40, 0xcc);
    code.extend([0xb8, 2, 0, 0, 0, 0xc3]);
    code.resize(0x50, 0xcc);
    code.extend([0xb8, 3, 0, 0, 0, 0xc3]);
    let mut table = Vec::new();
    for i in 0..256 {
        let target: i32 = if i < 6 {
            if i % 2 == 0 {
                0x1030
            } else {
                0x1040
            }
        } else {
            0x1101
        };
        table.extend((target - 0x2000).to_le_bytes());
    }
    session.add_section(0x1000, &code, true, true)?;
    session.add_section(0x1100, &[0x90, 0xb8, 99, 0, 0, 0, 0xc3], true, true)?;
    session.add_section(0x2000, &table, false, true)?;
    session.add_function(0x1000, "dispatch", false)?;
    session.set_function_ranges(&[
        CodeRange {
            start: 0x1000,
            end: 0x1060,
        },
        CodeRange {
            start: 0x1100,
            end: 0x1110,
        },
    ])?;
    let output = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(
        !output.text.contains("99") && !output.text.contains("UNRECOVERED_JUMPTABLE"),
        "{}",
        output.text
    );
    for i in 0..6 {
        assert!(
            output.text.contains(&format!("case {i}:")),
            "{}",
            output.text
        );
    }
    for i in 1..=3 {
        assert!(
            output.text.contains(&format!("return {i};")),
            "{}",
            output.text
        );
    }
    assert!(
        output
            .warnings
            .iter()
            .any(|w| w.contains("truncation of jumptable")),
        "{:?}",
        output.warnings
    );
    assert!(
        !output
            .warnings
            .iter()
            .any(|w| w.contains("normalized switch variable")),
        "{:?}",
        output.warnings
    );
    // A foreign target in the low segment invalidates the fallback too.
    table[12..16].copy_from_slice(&(0x1101i32 - 0x2000).to_le_bytes());
    let mut invalid = Session::new(Language::X86Linux64)?;
    invalid.add_section(0x1000, &code, true, true)?;
    invalid.add_section(0x1100, &[0x90, 0xb8, 99, 0, 0, 0, 0xc3], true, true)?;
    invalid.add_section(0x2000, &table, false, true)?;
    invalid.add_function(0x1000, "dispatch", false)?;
    invalid.set_function_ranges(&[
        CodeRange {
            start: 0x1000,
            end: 0x1060,
        },
        CodeRange {
            start: 0x1100,
            end: 0x1110,
        },
    ])?;
    let rejected = invalid.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(
        rejected
            .warnings
            .iter()
            .any(|w| w.contains("did not pass sanity check")),
        "{:?}",
        rejected.warnings
    );
    assert!(!rejected.text.contains("return 99;"), "{}", rejected.text);
    Ok(())
}

#[test]
fn variadic_forwarder_keeps_fixed_inputs_and_callee_return(
) -> Result<(), Box<dyn std::error::Error>> {
    use binfera_ghidra::ValueType;
    let mut session = Session::new(Language::X86Linux64)?;
    session.add_section(
        0x1000,
        &[
            0x48, 0x83, 0xec, 8, 0xe8, 0xf7, 0x0f, 0, 0, 0x48, 0x83, 0xc4, 8, 0xc3,
        ],
        true,
        true,
    )?;
    session.add_section(0x2000, &[0xb8, 42, 0, 0, 0, 0xc3], true, true)?;
    session.add_function(0x1000, "wrapper", false)?;
    session.add_function(0x2000, "result", false)?;
    assert!(session.set_variadic_forwarder(0x1000, 1, 0x2000)?);
    let output = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(
        output
            .text
            .contains("wrapper(unsigned long long param_1,...)"),
        "{}",
        output.text
    );
    assert!(
        output.text.contains("= result()") && !output.text.contains("return;"),
        "{}",
        output.text
    );
    assert_eq!(
        output.text,
        session.decompile(0x1000, 5000, 1000, 1_000_000)?.text
    );
    session.set_method_signature(0x1000, "", "", ValueType::Void, &[ValueType::I32], false)?;
    assert!(!session.set_variadic_forwarder(0x1000, 1, 0x2000)?);
    let explicit = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(
        explicit.text.contains("void wrapper(int param_1)"),
        "{}",
        explicit.text
    );
    Ok(())
}

#[test]
fn unwind_ranges_stop_a_table_at_a_foreign_function_interior(
) -> Result<(), Box<dyn std::error::Error>> {
    use binfera_ghidra::CodeRange;
    let mut session = Session::new(Language::X86Linux64)?;
    let mut code = vec![
        0x0f, 0xb6, 0x07, 0x48, 0x8d, 0x0d, 0xf6, 0x0f, 0, 0, 0x48, 0x63, 0x04, 0x81, 0x48, 0x01,
        0xc8, 0xff, 0xe0,
    ];
    code.resize(0x20, 0xcc);
    code.extend([0xb8, 1, 0, 0, 0, 0xc3]);
    code.resize(0x30, 0xcc);
    code.extend([0xb8, 2, 0, 0, 0, 0xc3]);
    let mut table = Vec::new();
    for i in 0..256 {
        let target = match i {
            0 => 0x1020i32,
            1 => 0x1030,
            _ => 0x1101,
        };
        table.extend((target - 0x2000).to_le_bytes());
    }
    session.add_section(0x1000, &code, true, true)?;
    session.add_section(0x1100, &[0x90, 0xb8, 99, 0, 0, 0, 0xc3], true, true)?;
    session.add_section(0x2000, &table, false, true)?;
    session.add_function(0x1000, "dispatch", false)?;
    let original = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(original.text.contains("return 99;"), "{}", original.text);
    session.set_function_ranges(&[
        CodeRange {
            start: 0x1000,
            end: 0x1040,
        },
        CodeRange {
            start: 0x1100,
            end: 0x1110,
        },
    ])?;
    let bounded = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(!bounded.text.contains("return 99;"), "{}", bounded.text);
    assert!(
        bounded.text.contains("case 0:") && bounded.text.contains("case 1:"),
        "{}",
        bounded.text
    );
    assert!(
        bounded
            .warnings
            .iter()
            .any(|w| w.contains("truncation of jumptable")),
        "{:?}",
        bounded.warnings
    );
    assert!(bounded.incomplete);
    assert!(session
        .set_function_ranges(&[
            CodeRange {
                start: 0x1000,
                end: 0x1120
            },
            CodeRange {
                start: 0x1100,
                end: 0x1110
            },
        ])
        .is_err());
    assert_eq!(
        bounded.text,
        session.decompile(0x1000, 5000, 1000, 1_000_000)?.text
    );
    // A distinct entry/cold fragment is permitted; only foreign interiors stop a table.
    session.set_function_ranges(&[
        CodeRange {
            start: 0x1000,
            end: 0x1040,
        },
        CodeRange {
            start: 0x1101,
            end: 0x1110,
        },
    ])?;
    assert_eq!(
        original.text,
        session.decompile(0x1000, 5000, 1000, 1_000_000)?.text
    );
    session.set_function_ranges(&[])?;
    assert_eq!(
        original.text,
        session.decompile(0x1000, 5000, 1000, 1_000_000)?.text
    );
    Ok(())
}

#[test]
fn homed_unused_parameters_do_not_erase_call_arguments() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new(Language::X86Windows64)?;
    let caller = [
        0x48, 0x83, 0xec, 0x28, 0xb9, 1, 0, 0, 0, 0xba, 2, 0, 0, 0, 0x41, 0xb8, 3, 0, 0, 0, 0x41,
        0xb9, 4, 0, 0, 0, 0x48, 0xc7, 0x44, 0x24, 0x20, 5, 0, 0, 0, 0xe8, 0xd8, 0x0f, 0, 0, 0x48,
        0x83, 0xc4, 0x28, 0xc3,
    ];
    let callee = [
        0x4c, 0x89, 0x4c, 0x24, 0x20, 0x4c, 0x89, 0x44, 0x24, 0x18, 0x48, 0x89, 0x54, 0x24, 0x10,
        0x48, 0x89, 0x4c, 0x24, 8, 0x31, 0xc0, 0xc3,
    ];
    session.add_section(0x1000, &caller, true, true)?;
    session.add_section(0x2000, &callee, true, true)?;
    session.add_function(0x1000, "caller", false)?;
    session.add_function(0x2000, "logging", false)?;
    let output = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(
        output.text.contains("logging(1,2,3,4,5)"),
        "{}",
        output.text
    );
    assert!(output.unknown_callees, "{:?}", output.warnings);
    let site = 0x1000
        + caller
            .iter()
            .position(|&b| b == 0xe8)
            .ok_or("missing call")? as u64;
    assert!(session.set_callsite_arguments(0x1000, site, 0x2000, 5)?);
    let hinted = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(hinted.text.contains("logging(1,2,3,4,5)"));
    session.set_signature(
        0x2000,
        binfera_ghidra::ValueType::Void,
        &[binfera_ghidra::ValueType::U64; 4],
    )?;
    let supplied = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(
        supplied.text.contains("logging(1,2,3,4)"),
        "{}",
        supplied.text
    );
    assert!(!session.set_callsite_arguments(0x1000, site, 0x2000, 5)?);
    // The same homes, now actually read by a wrapper with an unknown indirect
    // call. Its four inputs are corroborated; the return must stay uncertain.
    let mut wrapper = callee[..20].to_vec();
    wrapper.extend([
        0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0x4c, 0x24, 0x30, 0x48, 0x03, 0x4c, 0x24, 0x38, 0x4c,
        0x01, 0xc1, 0x4c, 0x01, 0xc9, 0xff, 0x15, 0xd2, 0x0f, 0, 0, 0x48, 0x83, 0xc4, 0x28, 0xc3,
    ]);
    let mut session = Session::new(Language::X86Windows64)?;
    session.add_section(0x1000, &caller, true, true)?;
    session.add_section(0x2000, &wrapper, true, true)?;
    session.add_section(0x3000, &[0; 8], false, false)?;
    session.add_function(0x1000, "caller", false)?;
    session.add_function(0x2000, "wrapper", false)?;
    let output = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(output.text.contains("wrapper(1,2,3,4)"), "{}", output.text);
    assert!(output.unknown_callees, "{:?}", output.warnings);
    assert!(
        output
            .warnings
            .iter()
            .any(|w| w.contains("wrapper (return)")),
        "{:?}",
        output.warnings
    );
    // Four floating-point inputs are not corroborated by four integer homes.
    let mut floating = callee[..20].to_vec();
    floating.extend([
        0x48, 0x83, 0xec, 0x28, 0xf2, 0x0f, 0x58, 0xc1, 0xf2, 0x0f, 0x58, 0xc2, 0xf2, 0x0f, 0x58,
        0xc3, 0x66, 0x48, 0x0f, 0x7e, 0xc1, 0x31, 0xd2, 0x45, 0x31, 0xc0, 0x45, 0x31, 0xc9,
    ]);
    let displacement = 0x1000i32 - floating.len() as i32 - 6;
    floating.extend([0xff, 0x15]);
    floating.extend(displacement.to_le_bytes());
    floating.extend([0x48, 0x83, 0xc4, 0x28, 0xc3]);
    let mut session = Session::new(Language::X86Windows64)?;
    session.add_section(0x1000, &caller, true, true)?;
    session.add_section(0x2000, &floating, true, true)?;
    session.add_section(0x3000, &[0; 8], false, false)?;
    session.add_function(0x1000, "caller", false)?;
    session.add_function(0x2000, "floating", false)?;
    let output = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(
        output
            .warnings
            .iter()
            .any(|w| w.contains("floating (arguments, return)")),
        "{:?}",
        output.warnings
    );
    Ok(())
}

#[test]
fn stack_input_alignment_includes_a_crossing_later_input() -> Result<(), Box<dyn std::error::Error>>
{
    let mut session = Session::new(Language::X86Linux64)?;
    // movzx eax,byte [rsp+9]; mov ecx,[rsp+15]; add eax,ecx; ret.
    // Aligning the byte to [rsp+8,rsp+16) must also include the later dword.
    session.add_section(
        0x1000,
        &[
            0x0f, 0xb6, 0x44, 0x24, 9, 0x8b, 0x4c, 0x24, 15, 1, 0xc8, 0xc3,
        ],
        true,
        true,
    )?;
    session.add_function(0x1000, "packed_inputs", false)?;
    let output = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(
        output.text.contains("return ") && output.text.contains(" + "),
        "{}",
        output.text
    );
    assert!(output.text.contains("._7_4_"), "{}", output.text);
    Ok(())
}

#[test]
fn simd_loop_locals_survive_more_than_eight_hash_collisions(
) -> Result<(), Box<dyn std::error::Error>> {
    use binfera_ghidra::ValueType;
    // Two LD1 paths merge byte comparisons in a loop. The scalarized lanes
    // have identical local data-flow hashes at the same instruction address.
    let words: [u32; 17] = [
        0x4e010c20, 0x4f00e404, 0xf100005f, 0x540000e0, 0x4cdfa001, 0x6e208c23, 0x6e208c44,
        0x4e24bc66, 0x9e6600c6, 0xb50000c6, 0x4cdfa001, 0x6e208c23, 0x4ea41c66, 0x9e6600c6,
        0xb4ffff86, 0xaa0603e0, 0xd65f03c0,
    ];
    let bytes: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
    let mut session = Session::new(Language::AArch64Windows)?;
    session.add_section(0x1000, &bytes, true, true)?;
    session.add_function(0x1000, "scan", false)?;
    session.set_signature(
        0x1000,
        ValueType::U64,
        &[ValueType::Pointer, ValueType::U32, ValueType::U64],
    )?;
    let output = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(output.text.contains("return "), "{}", output.text);
    assert!(output.text.contains("param_2"), "{}", output.text);
    assert_eq!(
        output.text,
        session.decompile(0x1000, 5000, 1000, 1_000_000)?.text
    );
    Ok(())
}

#[test]
fn go_three_part_return_keeps_the_original_join() -> Result<(), Box<dyn std::error::Error>> {
    // Forward a rune, string and error in EAX, RBX:RCX and RDI:RSI. Splitting
    // the 36-byte result must concatenate within the original register join.
    let mut session = Session::new(Language::X86GoLinux64)?;
    session.set_go_target("l", 17, true, 0x1000, 0x2001)?;
    session.add_section(
        0x1000,
        &[
            0x48, 0x83, 0xec, 8, 0xe8, 0xf7, 0x0f, 0, 0, 0x48, 0x83, 0xc4, 8, 0xc3,
        ],
        true,
        true,
    )?;
    session.add_section(0x2000, &[0xc3], true, true)?;
    for (address, name) in [
        (
            0x1000,
            "regexp/syntax.(*regexp/syntax.parser).parseClassChar",
        ),
        (0x2000, "regexp/syntax.(*regexp/syntax.parser).parseEscape"),
    ] {
        session.add_function(address, name, false)?;
        assert!(session.apply_go_prototype(address, name)?);
    }
    let output = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    println!("{}", output.text);
    assert!(output.text.contains("parseEscape("), "{}", output.text);
    for field in ["r", "rest", "err"] {
        assert!(
            output.text.contains(&format!(".{field} = ")),
            "{}",
            output.text
        );
    }
    assert!(output.text.contains("return "), "{}", output.text);
    Ok(())
}

#[test]
fn go_metadata_pointer_is_not_a_string() -> Result<(), Box<dyn std::error::Error>> {
    for descriptor in [b" \0\0\0\0\0\0\0".as_slice(), b"ABCD\0\0\0\0".as_slice()] {
        let mut session = Session::new(Language::X86GoLinux64)?;
        session.set_go_target("l", 17, true, 0x1000, 0x2001)?;
        // runtime.newobject receives a type descriptor whose size happens to spell a space.
        session.add_section(
            0x1000,
            &[
                0x48, 0x83, 0xec, 8, 0xb8, 0, 0x30, 0, 0, 0xe8, 0xf2, 0x0f, 0, 0, 0x48, 0x83, 0xc4,
                8, 0xc3,
            ],
            true,
            true,
        )?;
        session.add_section(0x2000, &[0xc3], true, true)?;
        session.add_section(0x3000, descriptor, false, true)?;
        session.add_function(0x1000, "allocate", false)?;
        session.add_function(0x2000, "runtime.newobject", false)?;
        assert!(session.apply_go_prototype(0x2000, "runtime.newobject")?);
        let output = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
        assert!(
            output.text.contains("runtime.newobject("),
            "{}",
            output.text
        );
        assert!(!output.text.contains('"'), "{}", output.text);
    }
    Ok(())
}

#[test]
fn inferred_return_is_request_local_and_preserves_explicit_signatures(
) -> Result<(), Box<dyn std::error::Error>> {
    use binfera_ghidra::ValueType;
    // A loop computes its result in EAX, but the unlocked analysis drops it.
    let bytes = [
        0x33, 0xc0, 0x83, 0xf9, 1, 0x76, 0x1c, 0x3d, 0xe8, 3, 0, 0, 0x7d, 0x15, 0xf6, 0xc1, 1,
        0x74, 7, 0x8d, 0x0c, 0x49, 0xff, 0xc1, 0xeb, 2, 0xd1, 0xe9, 0xff, 0xc0, 0x83, 0xf9, 1,
        0x77, 0xe4, 0xc3,
    ];
    let mut session = Session::new(Language::X86Windows64)?;
    session.add_section(0x1000, &bytes, true, true)?;
    session.add_function(0x1000, "loop_result", false)?;
    assert!(session
        .decompile_with_hints(0x1000, 5000, 1000, 1_000_000, 2, false)
        .is_err());
    let plain = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    let hinted = session.decompile_with_hints(0x1000, 5000, 1000, 1_000_000, 4, false)?;
    assert!(hinted.text.contains("return iVar"), "{}", hinted.text);
    assert!(
        hinted.incomplete
            && hinted
                .warnings
                .iter()
                .any(|w| w.contains("Return storage inferred"))
    );
    assert_eq!(
        plain.text,
        session.decompile(0x1000, 5000, 1000, 1_000_000)?.text
    );
    assert!(session
        .decompile_with_hints(0x1000, 5000, 1000, 1, 4, false)
        .is_err());
    assert_eq!(
        plain.text,
        session.decompile(0x1000, 5000, 1000, 1_000_000)?.text
    );
    session.set_signature(0x1000, ValueType::Void, &[ValueType::I32])?;
    let explicit = session.decompile_with_hints(0x1000, 5000, 1000, 1_000_000, 4, false)?;
    assert!(
        explicit.text.contains("void loop_result"),
        "{}",
        explicit.text
    );
    assert!(!explicit
        .warnings
        .iter()
        .any(|w| w.contains("Return storage inferred")));
    Ok(())
}

#[test]
fn inferred_cdecl_is_request_local() -> Result<(), Box<dyn std::error::Error>> {
    // Recursive x86 function: one stack argument, caller cleans four bytes.
    let bytes = [
        0x55, 0x8b, 0xec, 0x51, 0x83, 0x7d, 8, 1, 0x7f, 9, 0xc7, 0x45, 0xfc, 1, 0, 0, 0, 0xeb,
        0x16, 0x8b, 0x45, 8, 0x83, 0xe8, 1, 0x50, 0xe8, 0xe1, 0xff, 0xff, 0xff, 0x83, 0xc4, 4,
        0x0f, 0xaf, 0x45, 8, 0x89, 0x45, 0xfc, 0x8b, 0x45, 0xfc, 0x8b, 0xe5, 0x5d, 0xc3,
    ];
    let mut session = Session::new(Language::X86Windows32)?;
    session.add_section(0x1000, &bytes, true, true)?;
    session.add_function(0x1000, "recursive", false)?;
    let plain = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    let hinted = session.decompile_with_hints(0x1000, 5000, 1000, 1_000_000, 0, true)?;
    assert!(
        hinted.text.contains("__cdecl recursive(int param_1)"),
        "{}",
        hinted.text
    );
    assert!(hinted.incomplete && hinted.warnings.iter().any(|w| w.contains("cdecl")));
    assert_eq!(
        plain.text,
        session.decompile(0x1000, 5000, 1000, 1_000_000)?.text
    );
    assert!(session
        .decompile_with_hints(0x1000, 5000, 1000, 1, 0, true)
        .is_err());
    assert_eq!(
        plain.text,
        session.decompile(0x1000, 5000, 1000, 1_000_000)?.text
    );
    session.set_signature(
        0x1000,
        binfera_ghidra::ValueType::I32,
        &[binfera_ghidra::ValueType::I32],
    )?;
    let explicit = session.decompile_with_hints(0x1000, 5000, 1000, 1_000_000, 0, true)?;
    assert!(!explicit
        .warnings
        .iter()
        .any(|w| w.contains("cdecl calling convention")));
    Ok(())
}

#[test]
fn inferred_x86_return_is_request_local() -> Result<(), Box<dyn std::error::Error>> {
    // Increment a global, leaving the new 32-bit value in EAX.
    let bytes = [0xa1, 0, 0x20, 0, 0, 0x40, 0xa3, 0, 0x20, 0, 0, 0xc3];
    let mut session = Session::new(Language::X86Windows32)?;
    session.add_section(0x1000, &bytes, true, true)?;
    session.add_section(0x2000, &[0; 4], false, false)?;
    session.add_function(0x1000, "increment", false)?;
    let plain = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    let hinted = session.decompile_with_hints(0x1000, 5000, 1000, 1_000_000, 4, false)?;
    assert!(hinted.text.contains("return DAT_"), "{}", hinted.text);
    assert!(
        hinted.incomplete
            && hinted
                .warnings
                .iter()
                .any(|w| w.contains("Return storage inferred"))
    );
    assert_eq!(
        plain.text,
        session.decompile(0x1000, 5000, 1000, 1_000_000)?.text
    );
    Ok(())
}

#[test]
fn forwarded_import_return_requires_a_locked_four_byte_prototype(
) -> Result<(), Box<dyn std::error::Error>> {
    // Push four zero arguments, call the import slot, and return its result.
    let bytes = [
        0x6a, 0, 0x6a, 0, 0x6a, 0, 0x6a, 0, 0xff, 0x15, 0, 0x20, 0, 0, 0xc3,
    ];
    let mut session = Session::new(Language::X86Windows32)?;
    session.add_section(0x1000, &bytes, true, true)?;
    session.add_section(0x2000, &[0; 4], false, false)?;
    session.add_function(0x1000, "wrapper", false)?;
    session.add_import(0x2000, "user32_MessageBoxA", false)?;
    let unknown = session.decompile_with_hints(0x1000, 5000, 1000, 1_000_000, 1, false)?;
    assert!(!unknown
        .warnings
        .iter()
        .any(|w| w.contains("Return storage inferred")));
    assert!(session.apply_prototype(0x2000, "MessageBoxA")?);
    let plain = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    let hinted = session.decompile_with_hints(0x1000, 5000, 1000, 1_000_000, 1, false)?;
    assert!(hinted.text.contains("return iVar"), "{}", hinted.text);
    assert!(
        hinted
            .warnings
            .iter()
            .any(|w| w.contains("Return storage inferred")),
        "{:?}",
        hinted.warnings
    );
    assert_eq!(
        plain.text,
        session.decompile(0x1000, 5000, 1000, 1_000_000)?.text
    );
    Ok(())
}

#[test]
fn x86_stdcall_imports_preserve_later_stack_arguments() -> Result<(), Box<dyn std::error::Error>> {
    // LoadLibraryA(first), then GetProcAddress(module, second). Both imports
    // clean their own arguments; the wrapper itself is cdecl.
    let bytes = [
        0xff, 0x74, 0x24, 4, 0xff, 0x15, 0, 0x20, 0, 0, 0x85, 0xc0, 0x75, 1, 0xc3, 0xff, 0x74,
        0x24, 8, 0x50, 0xff, 0x15, 4, 0x20, 0, 0, 0xc3,
    ];
    let mut session = Session::new(Language::X86Windows32)?;
    session.add_section(0x1000, &bytes, true, true)?;
    session.add_section(0x2000, &[0; 8], false, false)?;
    session.add_function(0x1000, "resolve", false)?;
    session.add_import(0x2000, "kernel32_LoadLibraryA", false)?;
    session.add_import(0x2004, "kernel32_GetProcAddress", false)?;
    assert!(session.apply_prototype(0x2000, "LoadLibraryA")?);
    assert!(session.apply_prototype(0x2004, "GetProcAddress")?);
    let result = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(result.text.contains("lpProcName"), "{}", result.text);
    assert!(
        result.text.contains("GetProcAddress(hModule,lpProcName)"),
        "{}",
        result.text
    );
    Ok(())
}

#[test]
fn explicit_register_effect_preserves_return_without_changing_ordinary_calls(
) -> Result<(), Box<dyn std::error::Error>> {
    use binfera_ghidra::ValueType;
    // mov eax,42; call helper; ret; padding; ret
    let mut bytes = vec![0xb8, 42, 0, 0, 0, 0xe8, 6, 0, 0, 0, 0xc3];
    bytes.resize(16, 0x90);
    bytes.push(0xc3);
    let mut session = Session::new(Language::X86Windows64)?;
    session.add_section(0x1000, &bytes, true, true)?;
    session.add_function(0x1000, "caller", false)?;
    session.add_function(0x1010, "helper", false)?;
    session.set_signature(0x1010, ValueType::Void, &[])?;
    let ordinary = session.decompile(0x1000, 5000, 1000, 100_000)?;
    assert!(!ordinary.text.contains("return 0x2a"), "{}", ordinary.text);
    assert!(session.set_preserves_rax(0).is_err());
    session.set_preserves_rax(0x1010)?;
    let preserved = session.decompile(0x1000, 5000, 1000, 100_000)?;
    assert!(preserved.text.contains("return 0x2a"), "{}", preserved.text);
    assert_eq!(
        session.decompile(0x1000, 5000, 1000, 100_000)?.text,
        preserved.text
    );
    Ok(())
}

#[test]
fn call_fixup_models_a_helper_and_is_not_an_analysis_gap() -> Result<(), Box<dyn std::error::Error>>
{
    // mov eax,42; call helper; ret; padding; helper: ret
    let mut bytes = vec![0xb8, 42, 0, 0, 0, 0xe8, 6, 0, 0, 0, 0xc3];
    bytes.resize(16, 0x90);
    bytes.push(0xc3);
    let mut session = Session::new(Language::X86Windows64)?;
    session.add_section(0x1000, &bytes, true, true)?;
    session.add_function(0x1000, "caller", false)?;
    session.add_function(0x1010, "helper", false)?;
    assert!(session.set_call_fixup(0, "security_check_cookie").is_err());
    assert!(session.set_call_fixup(0x1010, "no_such_fixup").is_err());
    session.set_call_fixup(0x1010, "security_check_cookie")?;
    let modeled = session.decompile(0x1000, 5000, 1000, 100_000)?;
    // The injected snippet leaves RAX alone, so the constant survives the call,
    // the call itself disappears, and the notice does not mark the result incomplete.
    assert!(modeled.text.contains("return 0x2a"), "{}", modeled.text);
    assert!(!modeled.text.contains("helper("), "{}", modeled.text);
    assert!(
        modeled
            .notes
            .iter()
            .any(|w| w.contains("replaced with injection")),
        "{:?}",
        modeled.notes
    );
    assert!(modeled.warnings.is_empty(), "{:?}", modeled.warnings);
    assert!(!modeled.incomplete, "{:?}", modeled.warnings);
    assert!(!modeled.unknown_callees);
    Ok(())
}

#[test]
fn supplemental_imports_reconstruct_arguments_and_returns() -> Result<(), Box<dyn std::error::Error>>
{
    use binfera_ghidra::ValueType;
    for (language, bytes) in [
        (
            Language::X86Linux64,
            vec![
                0xbf, 11, 0, 0, 0, 0xbe, 22, 0, 0, 0, 0xe8, 0xf1, 0x0f, 0, 0, 0xc3,
            ],
        ),
        (
            Language::X86Apple64,
            vec![
                0xbf, 11, 0, 0, 0, 0xbe, 22, 0, 0, 0, 0xe8, 0xf1, 0x0f, 0, 0, 0xc3,
            ],
        ),
        (
            Language::X86Linux32,
            vec![
                0x6a, 22, 0x6a, 11, 0xe8, 0xf7, 0x0f, 0, 0, 0x83, 0xc4, 8, 0xc3,
            ],
        ),
        (
            Language::AArch64Linux,
            [
                0xa9bf7bfdu32,
                0xd2800160,
                0xd28002c1,
                0x940003fd,
                0xa8c17bfd,
                0xd65f03c0,
            ]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
        ),
        (
            Language::AArch64Apple,
            [
                0xa9bf7bfdu32,
                0xd2800160,
                0xd28002c1,
                0x940003fd,
                0xa8c17bfd,
                0xd65f03c0,
            ]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
        ),
    ] {
        let mut session = Session::new(language)?;
        session.add_section(0x1000, &bytes, true, true)?;
        session.add_function(0x1000, "lookup", false)?;
        session.set_signature(0x1000, ValueType::Pointer, &[])?;
        session.add_function(0x2000, "dlsym", false)?;
        assert!(session.apply_prototype(0x2000, "dlsym")?);
        let output = session.decompile(0x1000, 5000, 1000, 100_000)?;
        assert!(!output.unknown_callees, "{:?}", output.warnings);
        assert!(
            output.text.contains("dlsym((void *)0xb,(char *)0x16)"),
            "{language:?}: {}",
            output.text
        );
        assert!(output.text.contains("return"), "{}", output.text);
    }
    // Five stdcall arguments are removed by each native API, keeping the second call aligned.
    let bytes = [
        0x6a, 5, 0x6a, 4, 0x6a, 3, 0x6a, 2, 0x6a, 1, 0xe8, 0xf1, 0x0f, 0, 0, 0x6a, 10, 0x6a, 9,
        0x6a, 8, 0x6a, 7, 0x6a, 6, 0xe8, 0xe2, 0x0f, 0, 0, 0xc3,
    ];
    let mut session = Session::new(Language::X86Windows32)?;
    session.add_section(0x1000, &bytes, true, true)?;
    session.add_function(0x1000, "read_twice", false)?;
    session.add_function(0x2000, "ZwReadVirtualMemory", false)?;
    assert!(session.apply_prototype(0x2000, "ZwReadVirtualMemory")?);
    let output = session.decompile(0x1000, 5000, 1000, 100_000)?;
    assert!(!output.unknown_callees, "{:?}", output.warnings);
    assert!(
        output.text.contains(
            "ZwReadVirtualMemory((void *)0x1,(void *)0x2,(void *)0x3,4,(unsigned int *)0x5)"
        ),
        "{}",
        output.text
    );
    assert!(
        output.text.contains(
            "ZwReadVirtualMemory((void *)0x6,(void *)0x7,(void *)0x8,9,(unsigned int *)0xa)"
        ),
        "{}",
        output.text
    );
    Ok(())
}

#[test]
fn go_bounds_panics_use_their_assembly_registers() -> Result<(), Box<dyn std::error::Error>> {
    for language in [
        Language::X86GoWindows32,
        Language::X86GoLinux32,
        Language::X86GoWindows64,
        Language::X86GoLinux64,
        Language::X86GoApple64,
    ] {
        for (kind, arguments) in [
            ("panic_ax_cx", "1,2"),
            ("panic_cx_dx", "2,3"),
            ("panic_dx_bx", "3,4"),
            ("panic_ax_cx_u", "1,2"),
            ("panic_cx_dx_u", "2,3"),
            ("panic_dx_bx_u", "3,4"),
        ] {
            // Set AX, CX, DX and BX to distinct values, then call the runtime stub.
            let bytes = [
                0xb8, 1, 0, 0, 0, 0xb9, 2, 0, 0, 0, 0xba, 3, 0, 0, 0, 0xbb, 4, 0, 0, 0, 0xe8, 0xe7,
                0, 0, 0, 0xc3,
            ];
            let mut session = Session::new(language)?;
            session.add_section(0x1000, &bytes, true, true)?;
            session.add_section(0x1100, &[0xc3], true, true)?;
            session.add_function(0x1000, "caller", false)?;
            session.add_function(0x1100, "bounds_fail", false)?;
            assert!(session.set_go_special(0x1100, kind)?);
            let output = session.decompile(0x1000, 5000, 1000, 100_000)?;
            assert!(
                output.text.contains(&format!("bounds_fail({arguments})")),
                "{language:?} {kind}: {}",
                output.text
            );
            assert!(!output.unknown_callees, "{:?}", output.warnings);
            assert!(!output.text.contains("unaff_"), "{}", output.text);
        }
    }
    Ok(())
}

#[test]
fn modeled_call_effects_do_not_block_wrapper_inference() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new(Language::X86Windows64)?;
    // caller: wrapper(10); wrapper: return ecx+1, with a modeled security-cookie check.
    session.add_section(
        0x800,
        &[0xb9, 10, 0, 0, 0, 0xe8, 0xf6, 7, 0, 0, 0xc3],
        true,
        true,
    )?;
    session.add_section(
        0x1000,
        &[0x8d, 0x41, 1, 0xe8, 0xf8, 0, 0, 0, 0xc3],
        true,
        true,
    )?;
    session.add_section(0x1100, &[0xc3], true, true)?;
    session.add_function(0x800, "caller", false)?;
    session.add_function(0x1000, "wrapper", false)?;
    session.add_function(0x1100, "cookie_check", false)?;
    session.set_call_fixup(0x1100, "security_check_cookie")?;
    let output = session.decompile(0x800, 5000, 1000, 1_000_000)?;
    assert!(
        !output.unknown_callees,
        "{}\n{:?}",
        output.text, output.warnings
    );
    assert!(
        output.text.contains("wrapper(10)") || output.text.contains("wrapper(0xa)"),
        "{}",
        output.text
    );
    assert!(output
        .notes
        .iter()
        .any(|note| note.contains("prototypes inferred")));
    session.add_section(0x900, &[0xe8, 0xfb, 8, 0, 0, 0xc3], true, true)?;
    session.add_section(0x1200, &[0xff, 0xff], true, true)?;
    session.add_function(0x900, "calls_bad_code", false)?;
    session.add_function(0x1200, "bad_code", false)?;
    let bad = session.decompile(0x900, 5000, 1000, 1_000_000)?;
    assert!(bad.unknown_callees, "{}", bad.text);
    assert!(
        bad.warnings
            .iter()
            .any(|warning| warning.contains("0x900 -> bad_code (arguments, return)")),
        "{:?}",
        bad.warnings
    );
    Ok(())
}

#[test]
fn known_calls_do_not_consume_callee_inference_slots() -> Result<(), Box<dyn std::error::Error>> {
    use binfera_ghidra::ValueType;
    fn calls(address: u64, targets: &[u64]) -> Vec<u8> {
        let mut bytes = vec![0x48, 0x83, 0xec, 0x28]; // Win64 shadow space.
        for target in targets {
            let next = address + bytes.len() as u64 + 5;
            bytes.push(0xe8);
            bytes.extend_from_slice(&((*target as i64 - next as i64) as i32).to_le_bytes());
        }
        bytes.extend_from_slice(&[0x48, 0x83, 0xc4, 0x28, 0xc3]);
        bytes
    }
    let mut session = Session::new(Language::X86Windows64)?;
    let known: Vec<u64> = (0..17).map(|i| 0x2000 + i * 0x10).collect();
    for address in &known {
        session.add_section(*address, &[0xc3], true, true)?;
        session.add_function(*address, &format!("known_{address:x}"), false)?;
        session.set_signature(*address, ValueType::Void, &[])?;
    }
    session.add_section(0x3000, &[0xc3], true, true)?;
    session.add_function(0x3000, "unknown_leaf", false)?;
    let mut targets = known.clone();
    targets.push(0x3000);
    session.add_section(0x1000, &calls(0x1000, &targets), true, true)?;
    session.add_function(0x1000, "wrapper", false)?;
    let direct = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(
        !direct.unknown_callees,
        "{}\n{:?}",
        direct.text, direct.warnings
    );
    assert!(direct.text.contains("unknown_leaf()"), "{}", direct.text);

    // The same known calls must not exhaust the recursive analysis-size bound.
    session.add_section(0x800, &calls(0x800, &[0x1000]), true, true)?;
    session.add_function(0x800, "outer", false)?;
    let nested = session.decompile(0x800, 5000, 1000, 1_000_000)?;
    assert!(
        !nested.unknown_callees,
        "{}\n{:?}",
        nested.text, nested.warnings
    );
    assert!(nested.text.contains("wrapper()"), "{}", nested.text);
    Ok(())
}

#[test]
fn image_validation_and_instruction_limits() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new(Language::X86Windows64)?;
    assert!(session.add_section(u64::MAX, &[0xc3], true, true).is_err());
    assert!(session.add_section(0x1000, &[], true, true).is_err());
    session.add_section(0x1000, &[0x90, 0x90, 0x90, 0xc3], true, true)?;
    assert!(session.add_section(0x1001, &[0xc3], true, true).is_err());
    assert!(session
        .add_function(0x1000, &"x".repeat(1025), false)
        .is_err());
    session.add_function(0x1000, "bounded_function", false)?;
    match session.decompile(0x1000, 5000, 1, 100_000) {
        Err(error) => assert!(
            error.to_string().to_lowercase().contains("instruction"),
            "{error}"
        ),
        Ok(output) => assert!(output.incomplete),
    }
    Ok(())
}

#[test]
fn metadata_stays_readable_and_exclusions_are_atomic() -> Result<(), Box<dyn std::error::Error>> {
    use binfera_ghidra::{CodeRange, ValueType};
    let mut bytes = vec![0; 0x104];
    // mov eax,[rip+0xfa]; ret, reading the metadata constant at 0x1100.
    bytes[..7].copy_from_slice(&[0x8b, 0x05, 0xfa, 0, 0, 0, 0xc3]);
    bytes[0x100] = 42;
    let mut session = Session::new(Language::X86Windows64)?;
    session.add_section(0x1000, &bytes, true, true)?;
    session.add_function(0x1000, "read_metadata", false)?;
    session.set_signature(0x1000, ValueType::U32, &[])?;
    let metadata = CodeRange {
        start: 0x1100,
        end: 0x1104,
    };
    session.set_code_exclusions(&[metadata])?;
    let output = session.decompile(0x1000, 5000, 1000, 100_000)?;
    assert!(!output.incomplete, "{:?}", output.warnings);
    assert!(output.text.contains("DAT_00001100"), "{}", output.text);
    assert!(output
        .globals
        .iter()
        .any(|global| global.address == 0x1100 && global.size == 4));
    for invalid in [
        vec![CodeRange { start: 1, end: 1 }],
        vec![
            metadata,
            CodeRange {
                start: 0x1102,
                end: 0x1106,
            },
        ],
        vec![metadata, CodeRange { start: 1, end: 2 }],
        vec![metadata; 100_001],
    ] {
        assert!(session.set_code_exclusions(&invalid).is_err());
        assert!(session.decompile(0x1100, 5000, 1000, 100_000).is_err());
    }
    // Both ends of the instruction are executable, but an interior byte is metadata.
    session.set_code_exclusions(&[CodeRange {
        start: 0x1002,
        end: 0x1003,
    }])?;
    if let Ok(output) = session.decompile(0x1000, 5000, 1000, 100_000) {
        assert!(output.incomplete, "{}", output.text);
    }
    session.set_code_exclusions(&[])?;
    assert!(!session.decompile(0x1000, 5000, 1000, 100_000)?.incomplete);
    Ok(())
}

#[test]
fn malformed_code_is_a_result_not_a_crash() -> Result<(), Box<dyn std::error::Error>> {
    for bytes in [
        &[0x0f][..],
        &[0xff, 0xff][..],
        &[0xe9, 0xff, 0xff, 0xff, 0x7f][..],
    ] {
        let mut session = Session::new(Language::X86Windows64)?;
        session.add_section(0x1000, bytes, true, true)?;
        session.add_function(0x1000, "malformed", false)?;
        if let Ok(output) = session.decompile(0x1000, 100, 1000, 10_000) {
            assert!(output.incomplete, "{}", output.text);
        }
    }
    Ok(())
}

#[test]
fn sessions_created_on_separate_threads_are_serialized() -> Result<(), Box<dyn std::error::Error>> {
    let handles: Vec<_> = (0..4)
        .map(|_| {
            std::thread::spawn(|| -> Result<String, String> {
                let run = || -> Result<String, binfera_ghidra::Error> {
                    let mut session = Session::new(Language::X86Windows64)?;
                    session.add_section(0x1000, &[0x8d, 0x41, 0x01, 0xc3], true, true)?;
                    session.add_function(0x1000, "increment", false)?;
                    Ok(session.decompile(0x1000, 5000, 1000, 100_000)?.text)
                };
                run().map_err(|e| e.to_string())
            })
        })
        .collect();
    let mut outputs = Vec::new();
    for handle in handles {
        outputs.push(handle.join().map_err(|_| "thread panicked")??);
    }
    assert!(outputs.windows(2).all(|pair| pair.first() == pair.get(1)));
    Ok(())
}

#[test]
fn tail_calls_and_recursive_callees_are_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new(Language::X86Windows64)?;
    // jmp 0x1010; padding; lea eax,[rcx+1]; ret
    let mut bytes = vec![0xe9, 0x0b, 0, 0, 0];
    bytes.resize(16, 0x90);
    bytes.extend_from_slice(&[0x8d, 0x41, 1, 0xc3]);
    session.add_section(0x1000, &bytes, true, true)?;
    session.add_function(0x1000, "wrapper", false)?;
    session.add_function(0x1010, "increment", false)?;
    assert!(session.add_tail_call(0, 0x1000, 0x1010).is_err());
    assert!(session.add_tail_call(0x1000, 0x1000, 0).is_err());
    session.add_tail_call(0x1000, 0x1000, 0x1010)?;
    let first = session.decompile(0x1000, 5000, 1000, 100_000)?;
    assert!(first.text.contains("increment(param_1)"), "{}", first.text);
    assert!(!first.text.contains("+ 1"));
    assert_eq!(
        session.decompile(0x1000, 5000, 1000, 100_000)?.text,
        first.text
    );

    let mut recursive = Session::new(Language::X86Windows64)?;
    // caller calls recursive; recursive calls itself.
    let mut bytes = vec![0xe8, 0x0b, 0, 0, 0, 0xc3];
    bytes.resize(16, 0x90);
    bytes.extend_from_slice(&[0xe8, 0xfb, 0xff, 0xff, 0xff, 0xc3]);
    recursive.add_section(0x1000, &bytes, true, true)?;
    recursive.add_function(0x1000, "caller", false)?;
    recursive.add_function(0x1010, "recursive", false)?;
    let output = recursive.decompile(0x1000, 5000, 1000, 100_000)?;
    assert!(output.incomplete);
    assert!(output.warnings.iter().any(|w| w.contains("Unknown callee")));
    Ok(())
}

#[test]
fn import_jump_thunk_preserves_forwarded_argument() -> Result<(), Box<dyn std::error::Error>> {
    use binfera_ghidra::ValueType;
    let mut session = Session::new(Language::X86Windows64)?;
    // jmp qword ptr [rip+0xffa], through the IAT slot at 0x2000.
    session.add_section(0x1000, &[0xff, 0x25, 0xfa, 0x0f, 0, 0], true, true)?;
    session.add_section(0x2000, &[0; 8], false, false)?;
    session.add_function(0x1000, "exit_thunk", false)?;
    session.add_import(0x2000, "ExitProcess", true)?;
    session.set_signature(0x2000, ValueType::Void, &[ValueType::U32])?;
    session.add_tail_call(0x1000, 0x1000, 0x2000)?;
    let output = session.decompile(0x1000, 5000, 1000, 100_000)?;
    assert!(
        output.text.contains("ExitProcess(param_1)"),
        "{}",
        output.text
    );
    assert!(output.text.contains("void exit_thunk("), "{}", output.text);
    assert!(
        !output
            .text
            .lines()
            .any(|line| line.trim_start().starts_with("return")),
        "{}",
        output.text
    );
    assert_eq!(
        output.text,
        session.decompile(0x1000, 5000, 1000, 100_000)?.text
    );
    Ok(())
}

#[test]
fn ordinary_call_with_an_unused_result_stays_void() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new(Language::X86Linux64)?;
    // sub rsp,8; call 0x2000; add rsp,8; ret
    let wrapper = [
        0x48, 0x83, 0xec, 8, 0xe8, 0xf7, 0x0f, 0, 0, 0x48, 0x83, 0xc4, 8, 0xc3,
    ];
    session.add_section(0x1000, &wrapper, true, true)?;
    session.add_section(0x2000, &[0x31, 0xc0, 0xc3], true, true)?;
    session.add_function(0x1000, "discard_result", false)?;
    session.add_function(0x2000, "callee", false)?;
    session.set_signature(0x2000, binfera_ghidra::ValueType::U64, &[])?;
    let output = session.decompile(0x1000, 5000, 1000, 100_000)?;
    assert!(
        output.text.contains("void discard_result("),
        "{}",
        output.text
    );
    assert!(output.text.contains("callee();"), "{}", output.text);
    assert!(output.text.contains("return;"), "{}", output.text);
    Ok(())
}

#[test]
fn packed_archive_types_and_prototypes_decode() {
    for (language, functions, known_failures) in [
        (Language::X86Windows64, 30751, 0),
        (Language::X86Windows32, 30634, 1),
    ] {
        let mut session = Session::new(language).unwrap();
        let report = session.validate_prototype_pack(40).unwrap();
        println!("{language:?}: {report}");
        // One original Win32 RAS callback passes an unsupported aggregate by value.
        // Every new kernel type and signature must decode, including bitfield types.
        let failures: usize = report
            .split("failures=")
            .nth(1)
            .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|digits| digits.parse().ok())
            .unwrap();
        assert_eq!(failures, known_failures, "{report}");
        assert!(
            report
                .lines()
                .skip(1)
                .all(|line| line.contains("F:PMPRADMINCONNECTIONHANGUPNOTIFICATION3:")),
            "{report}"
        );
        assert!(
            report.contains(&format!("functions={functions}")),
            "{report}"
        );
    }
}

#[test]
fn system_v_c_library_archive_decodes() {
    let mut session = Session::new(Language::X86Linux64).unwrap();
    let report = session.validate_prototype_pack(40).unwrap();
    println!("{report}");
    assert!(report.contains("failures=0"), "{report}");
    assert!(report.contains("functions=6633"), "{report}");
}

#[test]
fn system_v_i386_c_library_archive_decodes() {
    let mut session = Session::new(Language::X86Linux32).unwrap();
    let report = session.validate_prototype_pack(40).unwrap();
    println!("{report}");
    assert!(report.contains("failures=0"), "{report}");
    assert!(report.contains("functions=6633"), "{report}");
}

#[test]
fn borland_compilers_start_with_their_specifications() {
    // Both reuse the Win32 archive, so its prototypes decode under their models too.
    for language in [Language::X86Delphi32, Language::X86Borland32] {
        let mut session = Session::new(language).unwrap();
        let report = session.validate_prototype_pack(40).unwrap();
        assert!(report.contains("functions=30634"), "{language:?}: {report}");
    }
}

/// The `N:`, `F:` and `D:` records of a Go pack that apply to one release decode through the engine,
/// and Go's ABI gives nearly every standard library signature its storage.
fn go_pack_decodes(language: Language, os: &str, minor: u32) {
    let mut session = Session::new(language).unwrap();
    let report = session.validate_go_pack(os, minor, 40).unwrap();
    println!("{os} go1.{minor}: {report}");
    let number = |field: &str| -> usize {
        report
            .split(&format!("{field}="))
            .nth(1)
            .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|digits| digits.parse().ok())
            .unwrap()
    };
    assert_eq!(number("failures"), 0, "{report}");
    assert!(number("functions") > 10_000, "{report}");
    assert!(number("types") > 1_000, "{report}");
    // Results split between registers and the stack, and structures whose registers skip padding
    // (about 1.3%): left without a signature rather than given a wrong one.
    assert!(number("unallocated") * 50 < number("functions"), "{report}");
}

#[test]
fn go_pack_decodes_for_each_platform_and_abi() {
    go_pack_decodes(Language::X86GoWindows64, "w", 23);
    go_pack_decodes(Language::X86GoLinux64, "l", 16);
    go_pack_decodes(Language::X86GoWindows32, "w", 25);
    go_pack_decodes(Language::X86GoLinux32, "l", 15);
}

#[test]
fn classes_label_tables_and_type_method_this() -> Result<(), Box<dyn std::error::Error>> {
    use binfera_ghidra::VfTable;
    // 0x1000: `mov eax,[ecx+8]; ret`; 0x1010: `mov eax,[ecx]; call [eax]; ret`.
    let code = [
        0x8b, 0x41, 0x08, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        0xcc, 0x8b, 0x01, 0xff, 0x10, 0xc3,
    ];
    // The table: its two slots.
    let table = [0x00, 0x10, 0, 0, 0x10, 0x10, 0, 0];
    let mut session = Session::new(Language::X86Windows32)?;
    session.add_section(0x1000, &code, true, true)?;
    session.add_section(0x2000, &table, false, true)?;
    session.add_function(0x1000, "Thing::FUN_00001000", false)?;
    session.add_function(0x1010, "Thing::FUN_00001010", false)?;
    let tables = [VfTable {
        offset: 0,
        address: 0x2000,
        label: "Thing::vftable".into(),
        type_name: "Thing_vftable".into(),
        field: "vftable".into(),
        this_class: "Thing".into(),
        model: "__thiscall".into(),
        slots: vec![0x1000, 0x1010],
    }];
    session.add_class("Thing", &tables)?;
    // A second registration of a completed class leaves it as it is.
    session.add_class("Thing", &tables)?;
    assert!(session.set_method(0x1000, "Thing")?);
    assert!(session.set_method(0x1010, "Thing")?);
    let getter = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(
        getter.text.contains("Thing::FUN_00001000(Thing *this)"),
        "{}",
        getter.text
    );
    // Past the table pointer: an offset into the object, not `this[2]`.
    assert!(getter.text.contains("(int)this + 8"), "{}", getter.text);
    let caller = session.decompile(0x1010, 5000, 1000, 1_000_000)?;
    assert!(
        caller.text.contains("(*this->vftable->FUN_00001000)(this)"),
        "{}",
        caller.text
    );
    // Malformed requests are errors; an unmapped label is refused, not an error.
    assert!(session
        .add_class(
            "Empty",
            &[VfTable {
                slots: vec![],
                ..tables[0].clone()
            }]
        )
        .is_err());
    assert!(session.add_label(0x2000, "taken", 0).is_err());
    assert!(!session.add_label(0x9000, "unmapped", 4)?);
    assert!(!session.add_label(0x2000, "Thing::vftable_again", 4)?);
    Ok(())
}

#[test]
fn linux_syscalls_resolve_numbers_and_kernel_arguments() -> Result<(), Box<dyn std::error::Error>> {
    for (language, bytes) in [
        (
            Language::X86Linux64,
            vec![
                0xb8, 1, 0, 0, 0, // write
                0xbf, 1, 0, 0, 0, // fd
                0xbe, 0, 0x20, 0, 0, // buf
                0xba, 5, 0, 0, 0, // count
                0x0f, 0x05, 0xc3,
            ],
        ),
        (
            Language::X86Linux32,
            vec![
                0xb8, 4, 0, 0, 0, // write
                0xbb, 1, 0, 0, 0, 0xb9, 0, 0x20, 0, 0, 0xba, 5, 0, 0, 0, 0xcd, 0x80, 0xc3,
            ],
        ),
    ] {
        let mut session = Session::new(language)?;
        session.add_section(0x1000, &bytes, true, true)?;
        session.add_section(0x2000, b"hello\0", false, true)?;
        session.add_function(0x1000, "write_message", false)?;
        let output = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
        assert!(
            output.text.contains("linux_write(1,"),
            "{} {:?}",
            output.text,
            output.warnings
        );
        assert!(output.text.contains(",5)"), "{}", output.text);
        assert!(!output.unknown_callees, "{:?}", output.warnings);
        assert_eq!(
            output.text,
            session.decompile(0x1000, 5000, 1000, 1_000_000)?.text
        );
    }
    Ok(())
}

fn syscall_output(
    language: Language,
    bytes: &[u8],
) -> Result<binfera_ghidra::NativeOutput, Box<dyn std::error::Error>> {
    let mut session = Session::new(language)?;
    session.add_section(0x1000, bytes, true, true)?;
    session.add_function(0x1000, "entry", false)?;
    Ok(session.decompile(0x1000, 5000, 1000, 1_000_000)?)
}

#[test]
fn linux_syscalls_use_r10_and_all_six_arguments() -> Result<(), Box<dyn std::error::Error>> {
    let output = syscall_output(
        Language::X86Linux64,
        &[
            0xb8, 9, 0, 0, 0, // mmap
            0x31, 0xff, // address
            0xbe, 0, 0x10, 0, 0, // length
            0xba, 3, 0, 0, 0, // protection
            0x41, 0xba, 0x22, 0, 0, 0, // flags in R10
            0xb9, 0x77, 0x77, 0, 0, // decoy in RCX
            0x41, 0xb8, 0xff, 0xff, 0xff, 0xff, // fd
            0x45, 0x31, 0xc9, // offset
            0x0f, 5, 0xc3,
        ],
    )?;
    assert!(output.text.contains("linux_mmap("), "{}", output.text);
    assert!(
        output.text.contains("0x1000,3,0x22,-1,0)"),
        "{}",
        output.text
    );
    assert!(!output.unknown_callees, "{:?}", output.warnings);
    Ok(())
}

#[test]
fn linux_syscalls_resolve_dataflow_without_guessing_at_joins(
) -> Result<(), Box<dyn std::error::Error>> {
    for (other, resolved) in [(1, true), (0, false)] {
        let output = syscall_output(
            Language::X86Linux64,
            &[
                0x85, 0xff, 0x74, 7, // test edi,edi; jz other
                0xb8, 1, 0, 0, 0, 0xeb, 5, 0xb8, other, 0, 0, 0, 0x0f, 5, 0xc3,
            ],
        )?;
        assert_eq!(
            output.text.contains("linux_write("),
            resolved,
            "{}",
            output.text
        );
        if !resolved {
            assert!(output.text.contains("syscall()"), "{}", output.text);
        }
    }
    // A partial-register write after zeroing EAX still yields a known number.
    let output = syscall_output(Language::X86Linux64, &[0x31, 0xc0, 0xb0, 39, 0x0f, 5, 0xc3])?;
    assert!(output.text.contains("linux_getpid()"), "{}", output.text);
    // The result of one syscall is not the number of the next.
    let output = syscall_output(Language::X86Linux64, &[0x31, 0xc0, 0x0f, 5, 0x0f, 5, 0xc3])?;
    assert_eq!(
        output.text.matches("linux_read(").count(),
        1,
        "{}",
        output.text
    );
    assert!(output.text.contains("syscall()"), "{}", output.text);
    Ok(())
}

#[test]
fn linux_syscalls_leave_unknown_and_other_abis_untouched() -> Result<(), Box<dyn std::error::Error>>
{
    for language in [Language::X86Windows64, Language::X86GoWindows64] {
        let output = syscall_output(language, &[0xb8, 1, 0, 0, 0, 0x0f, 5, 0xc3])?;
        assert!(
            output.text.contains("syscall()") && !output.text.contains("linux_"),
            "{}",
            output.text
        );
    }
    for (language, bytes) in [
        (
            Language::X86Linux64,
            vec![0xb8, 0xff, 0xff, 0xff, 0xff, 0x0f, 5, 0xc3],
        ),
        (
            Language::X86Linux64,
            vec![0xb8, 4, 0, 0, 0, 0xcd, 0x80, 0xc3],
        ),
        (
            Language::X86Linux32,
            vec![0xb8, 4, 0, 0, 0, 0xcd, 0x81, 0xc3],
        ),
        (
            Language::X86Windows32,
            vec![0xb8, 4, 0, 0, 0, 0xcd, 0x80, 0xc3],
        ),
    ] {
        let output = syscall_output(language, &bytes)?;
        assert!(!output.text.contains("linux_"), "{}", output.text);
    }
    Ok(())
}

#[test]
fn linux_syscalls_exit_group_is_noreturn_including_go() -> Result<(), Box<dyn std::error::Error>> {
    for language in [
        Language::X86Linux64,
        Language::X86GoLinux64,
        Language::X86Linux32,
        Language::X86GoLinux32,
    ] {
        let wide = matches!(language, Language::X86Linux64 | Language::X86GoLinux64);
        let bytes = if wide {
            vec![0xb8, 231, 0, 0, 0, 0xbf, 7, 0, 0, 0, 0x0f, 5, 0x0f, 0x0b]
        } else {
            vec![0xb8, 252, 0, 0, 0, 0xbb, 7, 0, 0, 0, 0xcd, 0x80, 0x0f, 0x0b]
        };
        let output = syscall_output(language, &bytes)?;
        assert!(
            output.text.contains("linux_exit_group(7)"),
            "{}",
            output.text
        );
        assert!(!output.text.contains("halt"), "{}", output.text);
        assert!(!output.unknown_callees, "{:?}", output.warnings);
    }
    Ok(())
}

#[test]
fn linux_syscall_probe_invalidates_memory_written_by_the_kernel(
) -> Result<(), Box<dyn std::error::Error>> {
    let output = syscall_output(
        Language::X86Linux64,
        &[
            0x48, 0x83, 0xec, 8, // reserve stack buffer
            0xc7, 4, 0x24, 1, 0, 0, 0, // initial value: write's number
            0x31, 0xc0, 0x31, 0xff, // read, fd 0
            0x48, 0x89, 0xe6, // buffer in RSI
            0xba, 4, 0, 0, 0, 0x0f, 5, // read may replace the buffer
            0x8b, 4, 0x24, // number from the now unknown buffer
            0x0f, 5, 0x48, 0x83, 0xc4, 8, 0xc3,
        ],
    )?;
    assert!(output.text.contains("linux_read("), "{}", output.text);
    assert!(!output.text.contains("linux_write("), "{}", output.text);
    assert!(output.text.contains("syscall()"), "{}", output.text);
    Ok(())
}

#[test]
fn linux_syscall_does_not_pop_the_callers_stack() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new(Language::X86Linux64)?;
    session.add_section(
        0x1000,
        &[
            0x48, 0x83, 0xec, 0x10, 0xc7, 0x44, 0x24, 8, 0x55, 0, 0, 0, 0xb8, 39, 0, 0, 0, 0x0f, 5,
            0x8b, 0x44, 0x24, 8, 0x48, 0x83, 0xc4, 0x10, 0xc3,
        ],
        true,
        true,
    )?;
    session.add_function(0x1000, "stack_local", false)?;
    session.set_signature(0x1000, binfera_ghidra::ValueType::I32, &[])?;
    let output = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(output.text.contains("linux_getpid()"), "{}", output.text);
    assert!(output.text.contains("return 0x55;"), "{}", output.text);
    assert!(!output.incomplete, "{:?}", output.warnings);
    Ok(())
}

#[test]
fn aarch64_platform_specs_translate_the_same_leaf() -> Result<(), Box<dyn std::error::Error>> {
    // add w0,w0,w1; ret
    let bytes = [0x00, 0x00, 0x01, 0x0b, 0xc0, 0x03, 0x5f, 0xd6];
    for language in [
        Language::AArch64Linux,
        Language::AArch64Windows,
        Language::AArch64Apple,
    ] {
        let mut session = Session::new(language)?;
        session.add_section(0x1000, &bytes, true, true)?;
        session.add_function(0x1000, "sum", false)?;
        let output = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
        assert!(output.text.contains("param_1 + param_2"), "{}", output.text);
        assert!(!output.incomplete, "{:?}", output.warnings);
    }
    Ok(())
}

#[test]
fn darwin_archive_decodes_for_both_processors() {
    for language in [
        Language::X86Apple64,
        Language::AArch64Apple,
        Language::X86GoApple64,
    ] {
        let mut session = Session::new(language).unwrap();
        let report = session.validate_prototype_pack(20).unwrap();
        assert!(report.contains("functions=14256"), "{language:?}: {report}");
        println!("{language:?}: {report}");
        // hsearch passes ENTRY by value; the x86 compiler model cannot place it.
        let failures = match language {
            Language::AArch64Apple => 0,
            Language::X86GoApple64 => 6,
            _ => 1,
        };
        assert!(
            report.contains(&format!("failures={failures}")),
            "{language:?}: {report}"
        );
        assert!(
            report.lines().skip(1).all(|line| [
                "F:hsearch:",
                "F:bootstrap_create_server:",
                "F:host_get_boot_info:",
                "F:host_kernel_version:",
                "F:mach_vm_read_list:",
                "F:vm_read_list:"
            ]
            .iter()
            .any(|name| line.contains(name))),
            "{report}"
        );
    }
}

#[test]
fn win32_bare_alias_keeps_stdcall_stack_purge() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new(Language::X86Windows32)?;
    session.add_section(0x2000, &[0; 16], false, true)?;
    session.add_import(0x2000, "DeleteUrlCacheEntry", false)?;
    assert!(session.apply_prototype(0x2000, "DeleteUrlCacheEntry")?);
    assert_eq!(session.stack_purge(0x2000)?, 4);
    session.add_import(0x2004, "UnknownApi", false)?;
    assert!(!session.apply_prototype(0x2004, "UnknownApi")?);
    session.set_stack_purge(0x2004, 12)?;
    assert_eq!(session.stack_purge(0x2004)?, 12);
    Ok(())
}

#[test]
fn readonly_ascii_and_utf16_arrays_print_as_literals() -> Result<(), Box<dyn std::error::Error>> {
    use binfera_ghidra::ValueType;
    for (string, result, expected, executable) in [
        (
            b"hello\0".as_slice(),
            ValueType::CharPointer,
            "\"hello\"",
            false,
        ),
        (
            b"h\0e\0l\0l\0o\0\0\0".as_slice(),
            ValueType::WideCharPointer,
            "\"hello\"",
            true,
        ),
        (b".\0".as_slice(), ValueType::CharPointer, "\".\"", true),
    ] {
        let mut session = Session::new(Language::X86Windows32)?;
        session.add_section(0x1000, &[0xb8, 0, 0x20, 0, 0, 0xc3], true, true)?;
        session.add_section(0x2000, string, executable, true)?;
        session.add_function(0x1000, "literal", false)?;
        session.set_signature(0x1000, result, &[])?;
        let result = session.decompile(0x1000, 5000, 1000, 1000000)?;
        assert!(result.text.contains(expected), "{}", result.text);
    }
    Ok(())
}

#[test]
fn counted_strings_are_named_not_printed() -> Result<(), Box<dyn std::error::Error>> {
    // Go and Rust pack strings without terminators: the scan would read "hello" and its
    // neighbour as one literal. The address is passed to a callee without a prototype.
    // push 0x2000; call 0x1010; add esp,4; ret ... 0x1010: mov eax,[esp+4]; movzx eax,byte [eax]; ret
    let mut code = vec![0x68, 0, 0x20, 0, 0, 0xe8, 6, 0, 0, 0, 0x83, 0xc4, 4, 0xc3];
    code.resize(0x10, 0x90);
    code.extend([0x8b, 0x44, 0x24, 0x04, 0x0f, 0xb6, 0x00, 0xc3]);
    for counted in [false, true] {
        let mut session = Session::new(Language::X86Windows32)?;
        session.add_section(0x1000, &code, true, true)?;
        session.add_section(0x2000, b"helloworld\0", false, true)?;
        session.add_function(0x1000, "caller", false)?;
        session.add_function(0x1010, "callee", false)?;
        session.set_counted_strings(counted)?;
        let result = session.decompile(0x1000, 5000, 1000, 1000000)?;
        if counted {
            assert!(!result.text.contains('"'), "{}", result.text);
            assert!(
                result.text.contains("s_helloworld_00002000"),
                "{}",
                result.text
            );
        } else {
            assert!(result.text.contains("\"helloworld\""), "{}", result.text);
        }
    }
    Ok(())
}

#[test]
fn small_utf16_address_in_executable_data_is_a_literal_argument(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new(Language::X86Windows64)?;
    // mov ecx,0xea0; call sink; ret. The callee's argument has no supplied type.
    session.add_section(
        0x1000,
        &[0xb9, 0xa0, 0x0e, 0, 0, 0xe8, 0xf6, 0, 0, 0, 0xc3],
        true,
        true,
    )?;
    session.add_section(
        0x1100,
        &[0x48, 0x89, 0x0d, 0xf9, 0x1e, 0, 0, 0xc3],
        true,
        true,
    )?;
    session.add_section(0xea0, b"L\0a\0n\0g\0\0\0", true, true)?;
    session.add_section(0x3000, &[0; 8], false, false)?;
    session.add_function(0x1000, "caller", false)?;
    session.add_function(0x1100, "sink", false)?;
    let result = session.decompile(0x1000, 5000, 1000, 1000000)?;
    assert!(result.text.contains("\"Lang\""), "{}", result.text);
    Ok(())
}

#[test]
fn writable_string_display_does_not_fold_modified_data() -> Result<(), Box<dyn std::error::Error>> {
    use binfera_ghidra::ValueType;
    let mut session = Session::new(Language::X86Windows32)?;
    session.add_section(
        0x1000,
        &[
            0xc7, 0x05, 0, 0x20, 0, 0, b'b', b'y', b'e', 0, 0xb8, 0, 0x20, 0, 0, 0xc3,
        ],
        true,
        true,
    )?;
    session.add_section(0x2000, b"hello\0", false, false)?;
    session.add_function(0x1000, "change", false)?;
    session.set_signature(0x1000, ValueType::CharPointer, &[])?;
    let result = session.decompile(0x1000, 5000, 1000, 1000000)?;
    assert!(!result.text.contains("return \"hello\""), "{}", result.text);
    assert!(result.text.contains("0x657962"), "{}", result.text);
    Ok(())
}

#[test]
fn opaque_pointer_does_not_turn_a_short_binary_prefix_into_text(
) -> Result<(), Box<dyn std::error::Error>> {
    use binfera_ghidra::ValueType;
    let mut session = Session::new(Language::X86Windows64)?;
    session.add_section(0x1000, &[0xb8, 0, 0x20, 0, 0, 0xc3], true, true)?;
    // An interface table address whose first word happens to contain three ASCII bytes.
    session.add_section(0x2000, b" BT\0\0\0\0\0", false, true)?;
    session.add_function(0x1000, "table", false)?;
    session.set_signature(0x1000, ValueType::Pointer, &[])?;
    let output = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(!output.text.contains('"'), "{}", output.text);
    Ok(())
}

#[test]
fn null_pointer_is_not_a_literal_in_a_zero_based_image() -> Result<(), Box<dyn std::error::Error>> {
    use binfera_ghidra::ValueType;
    let mut session = Session::new(Language::X86Windows64)?;
    session.add_section(0, b"header\0", false, true)?;
    session.add_section(0x1000, &[0x31, 0xc0, 0xc3], true, true)?;
    session.add_function(0x1000, "null_result", false)?;
    session.set_signature(0x1000, ValueType::CharPointer, &[])?;
    let output = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(!output.text.contains('"'), "{}", output.text);
    assert!(output.text.contains("0x0"), "{}", output.text);
    Ok(())
}

#[test]
fn inferred_go_stack_result_reaches_the_callers_result() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new(Language::X86GoWindows32)?;
    session.set_go_target("w", 16, false, 0x1000, 0x2010)?;
    // Caller copies its argument into a call frame, then copies the callee's
    // result into its own result slot. Values are deliberately not in EAX at RET.
    session.add_section(
        0x1000,
        &[
            0x83, 0xec, 8, 0x8b, 0x44, 0x24, 12, 0x89, 0x04, 0x24, 0xe8, 0xf1, 0x0f, 0, 0, 0x8b,
            0x4c, 0x24, 4, 0x89, 0x4c, 0x24, 16, 0x31, 0xc0, 0x83, 0xc4, 8, 0xc3,
        ],
        true,
        true,
    )?;
    session.add_section(
        0x2000,
        &[
            0x8b, 0x44, 0x24, 4, 0x83, 0xc0, 7, 0x89, 0x44, 0x24, 8, 0x31, 0xc0, 0xc3,
        ],
        true,
        true,
    )?;
    session.add_function(0x1000, "forward", false)?;
    session.add_function(0x2000, "compute", false)?;
    assert!(session.set_go_stack_layout(0x1000, 4, 4)?);
    assert!(session.set_go_stack_layout(0x2000, 4, 4)?);
    assert!(!session.set_go_stack_layout(0x2000, 0, 4)?);
    assert!(!session.set_go_stack_layout(0x1000, 4, u32::MAX)?);
    let output = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(output.text.contains("compute(param_1)"), "{}", output.text);
    assert!(
        output.text.contains("return ") && !output.text.contains("return 0;"),
        "{}",
        output.text
    );
    let callee = session.decompile(0x2000, 5000, 1000, 1_000_000)?;
    assert!(callee.text.contains("param_1 + 7"), "{}", callee.text);
    assert_eq!(
        session.decompile(0x1000, 5000, 1000, 1_000_000)?.text,
        output.text
    );
    Ok(())
}

#[test]
fn register_conventions_and_narrow_returns_preserve_explicit_facts(
) -> Result<(), Box<dyn std::error::Error>> {
    use binfera_ghidra::ValueType;
    let mut session = Session::new(Language::X86Windows32)?;
    session.add_section(0x1000, &[0x8d, 0x04, 0x11, 0xc3], true, true)?;
    session.add_function(0x1000, "register_add", false)?;
    assert!(session.set_function_model(0x1000, "__fastcall")?);
    session.set_rust_function(0x1000)?;
    let out = session.decompile_with_hints(0x1000, 5000, 1000, 1_000_000, 4, false)?;
    assert!(
        out.text.contains("param_1") && out.text.contains("param_2"),
        "{}",
        out.text
    );
    assert!(
        !out.text.contains("in_ECX") && !out.text.contains("in_EDX"),
        "{}",
        out.text
    );
    assert!(!out.text.contains("CONCAT44"), "{}", out.text);
    session.set_signature(0x1000, ValueType::U64, &[])?;
    assert!(!session.set_function_model(0x1000, "__fastcall")?);
    let explicit = session.decompile_with_hints(0x1000, 5000, 1000, 1_000_000, 4, false)?;
    assert!(
        explicit.text.contains("unsigned long long "),
        "{}",
        explicit.text
    );
    // The high word is discarded local space, not the helper's result.
    session.add_section(
        0x4000,
        &[
            0x83, 0xec, 4, 0xe8, 2, 0, 0, 0, 0x5a, 0xc3, 0xb8, 1, 0, 0, 0, 0xc3,
        ],
        true,
        true,
    )?;
    session.add_function(0x4000, "scratch_pop", false)?;
    session.add_function(0x400a, "helper", false)?;
    session.set_signature(0x400a, ValueType::U32, &[])?;
    let narrow = session.decompile(0x4000, 5000, 1000, 1_000_000)?;
    assert!(!narrow.text.contains("CONCAT44"), "{}", narrow.text);
    let high_used = session.decompile_with_hints(0x4000, 5000, 1000, 1_000_000, 8, false)?;
    assert!(high_used.text.contains("CONCAT44"), "{}", high_used.text);
    Ok(())
}

#[test]
fn go_arm64_register_parameters_and_c_imports() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new(Language::AArch64GoLinux)?;
    // add x0, x0, x1; ret
    session.add_section(
        0x1000,
        &[0x00, 0x00, 0x01, 0x8b, 0xc0, 0x03, 0x5f, 0xd6],
        true,
        true,
    )?;
    session.set_go_target("l", 24, true, 0x1000, 0x1008)?;
    session.add_function(0x1000, "add", false)?;
    let out = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(
        out.text.contains("param_1") && out.text.contains("param_2"),
        "{}",
        out.text
    );
    assert!(!out.text.contains("unaff_x"), "{}", out.text);
    session.add_import(0x2000, "strlen", false)?;
    assert!(session.apply_prototype(0x2000, "strlen")?);
    Ok(())
}

#[test]
fn go_arm64_write_barrier_keeps_argument_registers() -> Result<(), Box<dyn std::error::Error>> {
    // stp x29,x30,[sp,#-16]!; bl gcWriteBarrier1; str x0,[x25]; ldp x29,x30,[sp],#16; ret
    let caller = [
        0xa9bf_7bfdu32,
        0x9400_03ff,
        0xf900_0320,
        0xa8c1_7bfd,
        0xd65f_03c0,
    ];
    let caller: Vec<u8> = caller.iter().flat_map(|w| w.to_le_bytes()).collect();
    for special in [false, true] {
        let mut session = Session::new(Language::AArch64GoLinux)?;
        session.add_section(0x1000, &caller, true, true)?;
        session.add_section(0x2000, &0xd65f_03c0u32.to_le_bytes(), true, true)?;
        session.set_go_target("l", 26, true, 0x1000, 0x2004)?;
        session.add_function(0x1000, "main.store", false)?;
        session.add_function(0x2000, "runtime.gcWriteBarrier1", false)?;
        if special {
            assert!(session.set_go_special(0x2000, "gcwrite_batch")?);
        }
        let out = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
        // The barrier preserves x0-x15 and returns its buffer in x25.
        assert_eq!(special, out.text.contains("param_1"), "{}", out.text);
        if special {
            assert!(!out.text.contains("extraout_x"), "{}", out.text);
        } else {
            assert!(out.unknown_callees, "{:?}", out.warnings);
        }
    }
    Ok(())
}

#[test]
fn swift_self_and_cpp_parameter_types() -> Result<(), Box<dyn std::error::Error>> {
    use binfera_ghidra::{CppParameter, ValueType};
    let mut session = Session::new(Language::X86Apple64)?;
    session.add_section(0x1000, &[0x49, 0x8b, 0x45, 0, 0xc3], true, true)?;
    session.add_function(0x1000, "swift_method", false)?;
    assert!(session.set_function_model(0x1000, "__swiftself")?);
    let out = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(!out.text.contains("unaff_R13"), "{}", out.text);
    assert!(out.text.contains("param_1"), "{}", out.text);
    session.add_section(0x3000, &[0x0f, 0xb6, 0x07, 0x89, 0x06, 0xc3], true, true)?;
    session.add_function(0x3000, "read_config", false)?;
    assert!(session.set_cpp_parameters(
        0x3000,
        &[
            CppParameter {
                value: ValueType::CharPointer,
                pointee: String::new()
            },
            CppParameter {
                value: ValueType::Pointer,
                pointee: "_XimConfig".into()
            },
        ],
        false
    )?);
    let out = session.decompile(0x3000, 5000, 1000, 1_000_000)?;
    assert!(
        out.text.contains("char *param_1") && out.text.contains("_XimConfig *param_2"),
        "{}",
        out.text
    );
    Ok(())
}
#[test]
fn temporary_prototype_hints_invalidate_callee_inference() -> Result<(), Box<dyn std::error::Error>>
{
    for language in [Language::X86Windows32, Language::X86Windows64] {
        let mut session = Session::new(language)?;
        let caller: &[u8] = if language == Language::X86Windows32 {
            &[0x6a, 5, 0xe8, 0xf9, 0x0f, 0, 0, 0x83, 0xc4, 4, 0xc3]
        } else {
            &[0xb9, 5, 0, 0, 0, 0xe8, 0xf6, 0x0f, 0, 0, 0xc3]
        };
        let callee: &[u8] = if language == Language::X86Windows32 {
            &[0x8b, 0x44, 0x24, 4, 0x40, 0xc3]
        } else {
            &[0x8d, 0x41, 1, 0xc3]
        };
        let loop_result = [
            0x33, 0xc0, 0x83, 0xf9, 1, 0x76, 0x1c, 0x3d, 0xe8, 3, 0, 0, 0x7d, 0x15, 0xf6, 0xc1, 1,
            0x74, 7, 0x8d, 0x0c, 0x49, 0xff, 0xc1, 0xeb, 2, 0xd1, 0xe9, 0xff, 0xc0, 0x83, 0xf9, 1,
            0x77, 0xe4, 0xc3,
        ];
        session.add_section(0x1000, caller, true, true)?;
        session.add_section(0x2000, callee, true, true)?;
        session.add_section(0x3000, &loop_result, true, true)?;
        for (address, name) in [
            (0x1000, "caller"),
            (0x2000, "leaf"),
            (0x3000, "loop_result"),
        ] {
            session.add_function(address, name, false)?;
        }
        let baseline = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
        assert!(baseline.inference_cache_misses > 0);
        let warm = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
        let cdecl = language == Language::X86Windows32;
        assert_eq!(warm.text, baseline.text);
        if cdecl {
            // Only context-independent Windows x64 scalar leaves survive a request.
            assert!(warm.inference_cache_misses > 0);
        } else {
            assert!(warm.inference_cache_hits > 0);
            assert_eq!(warm.inference_cache_misses, 0);
        }
        let hinted = session.decompile_with_hints(0x3000, 5000, 1000, 1_000_000, 4, cdecl)?;
        assert!(hinted
            .warnings
            .iter()
            .any(|w| w.contains("Return storage inferred") || w.contains("cdecl")));
        let after = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
        assert_eq!(after.text, baseline.text);
        assert_eq!(after.warnings, baseline.warnings);
        if cdecl {
            assert!(after.inference_cache_misses > 0);
        } else {
            // A Windows x64 scalar leaf cannot observe another function's temporary hint.
            assert!(after.inference_cache_hits > 0);
            assert_eq!(after.inference_cache_misses, 0);
        }
        if cdecl {
            assert!(session
                .decompile_with_hints(0x3000, 5000, 1000, 1, 0, true)
                .is_err());
            let after_failure = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
            assert_eq!(after_failure.text, baseline.text);
            assert!(after_failure.inference_cache_misses > 0);
        }
    }
    Ok(())
}

#[test]
fn cached_inference_respects_a_smaller_instruction_limit() -> Result<(), Box<dyn std::error::Error>>
{
    let mut session = Session::new(Language::X86Windows64)?;
    session.add_section(0x1000, &[0xe8, 0xfb, 0x0f, 0, 0, 0xc3], true, true)?;
    let mut leaf = vec![0x90; 64];
    leaf.extend_from_slice(&[0x8d, 0x41, 1, 0xc3]);
    session.add_section(0x2000, &leaf, true, true)?;
    session.add_function(0x1000, "caller", false)?;
    session.add_function(0x2000, "long_leaf", false)?;
    let complete = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(!complete.unknown_callees, "{:?}", complete.warnings);
    let limited = session.decompile(0x1000, 5000, 32, 1_000_000)?;
    assert!(limited.unknown_callees, "{}", limited.text);
    assert!(limited.inference_cache_misses > 0);
    assert_eq!(
        session.decompile(0x1000, 5000, 1000, 1_000_000)?.text,
        complete.text
    );
    Ok(())
}

#[test]
fn a_print_stopped_by_a_limit_does_not_change_later_output(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new(Language::X86Windows64)?;
    #[rustfmt::skip]
    let body = [
        0x85, 0xc9, 0x74, 0x06, // test ecx,ecx; je +6
        0xb8, 0x01, 0, 0, 0,    // mov eax,1
        0xc3,                   // ret
        0x85, 0xd2, 0x74, 0x06, // test edx,edx; je +6
        0xb8, 0x02, 0, 0, 0,    // mov eax,2
        0xc3,                   // ret
        0x31, 0xc0,             // xor eax,eax
        0xc3,                   // ret
    ];
    session.add_section(0x1000, &body, true, true)?;
    session.add_function(0x1000, "branches", false)?;
    let expected = session.decompile(0x1000, 5000, 1000, 1_000_000)?.text;
    let mut stopped = 0;
    for work in 1..10_000 {
        session.set_print_work_limit(work)?;
        let result = session.decompile(0x1000, 5000, 1000, 1_000_000);
        session.set_print_work_limit(0)?;
        if result.is_ok() {
            break;
        }
        stopped += 1;
        let text = session.decompile(0x1000, 5000, 1000, 1_000_000)?.text;
        assert_eq!(text, expected, "after stopping the print at {work} writes");
    }
    assert!(stopped > 5, "only {stopped} prints were stopped");
    Ok(())
}

#[test]
fn an_unusable_child_stops_inference_of_its_siblings() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new(Language::X86Windows64)?;
    // caller -> wrapper -> {unusable, leaf}. `unusable` is visited first because direct targets
    // are ordered by address, and its own unknown callee makes it unusable.
    session.add_section(0x1000, &[0xe8, 0xfb, 0x0f, 0, 0, 0xc3], true, true)?;
    session.add_section(
        0x2000,
        &[0xe8, 0xfb, 0x0f, 0, 0, 0xe8, 0xf6, 0x1f, 0, 0, 0xc3],
        true,
        true,
    )?;
    session.add_section(0x3000, &[0xe8, 0xfb, 0x1f, 0, 0, 0xc3], true, true)?;
    session.add_section(0x4000, &[0x8d, 0x41, 1, 0xc3], true, true)?;
    session.add_section(0x5000, &[0xff, 0x11, 0xc3], true, true)?;
    for (address, name) in [
        (0x1000, "caller"),
        (0x2000, "wrapper"),
        (0x3000, "unusable"),
        (0x4000, "leaf"),
        (0x5000, "indirect_through_input"),
    ] {
        session.add_function(address, name, false)?;
    }
    let output = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(output.unknown_callees, "{}", output.text);
    assert!(output.text.contains("wrapper()"), "{}", output.text);
    // caller, wrapper, unusable and its callee: never `leaf`.
    assert_eq!(output.inference_cache_misses, 3, "{:?}", output.warnings);
    assert_eq!(
        session.decompile(0x1000, 5000, 1000, 1_000_000)?.text,
        output.text
    );
    Ok(())
}

#[test]
fn an_unknown_external_call_does_not_trigger_unusable_child_inference(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new(Language::X86Windows64)?;
    session.add_section(0x1000, &[0xe8, 0xfb, 0x0f, 0, 0, 0xc3], true, true)?;
    session.add_section(
        0x2000,
        &[0xe8, 0xfb, 0x0f, 0, 0, 0xe8, 0xf6, 0x1f, 0, 0, 0xc3],
        true,
        true,
    )?;
    session.add_section(0x3000, &[0x8d, 0x41, 1, 0xc3], true, true)?;
    for (address, name) in [
        (0x1000, "caller"),
        (0x2000, "wrapper"),
        (0x3000, "leaf"),
        (0x4000, "unknown_external"),
    ] {
        session.add_function(address, name, false)?;
    }
    let output = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(output.unknown_callees);
    assert!(output.text.contains("wrapper()"), "{}", output.text);
    assert_eq!(output.analysis_passes, 2);
    assert_eq!(output.inference_cache_misses, 1);
    assert_eq!(
        session.decompile(0x1000, 5000, 1000, 1_000_000)?.text,
        output.text
    );
    Ok(())
}

#[test]
fn on_demand_functions_do_not_change_later_address_constants(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new(Language::X86Windows64)?;
    let mut code = vec![0xcc; 64];
    code[..6].copy_from_slice(&[0xb8, 0x20, 0x10, 0, 0, 0xc3]); // return 0x1020
    code[32..36].copy_from_slice(&[0x8d, 0x41, 1, 0xc3]); // unregistered leaf
    session.add_section(0x1000, &code, true, true)?;
    session.add_function(0x1000, "address_constant", false)?;
    let first = session.decompile(0x1000, 5000, 1000, 1_000_000)?;
    assert!(first.text.contains("return 0x1020;"), "{}", first.text);
    for print_work in [0, 1, 0] {
        session.set_print_work_limit(print_work)?;
        let result = session.decompile(0x1020, 5000, 1000, 1_000_000);
        assert_eq!(result.is_err(), print_work != 0);
        session.set_print_work_limit(0)?;
        assert_eq!(
            first.text,
            session.decompile(0x1000, 5000, 1000, 1_000_000)?.text
        );
    }
    // Explicitly registering the same address must still make it a code pointer.
    session.add_function(0x1020, "registered_leaf", false)?;
    assert!(session
        .decompile(0x1000, 5000, 1000, 1_000_000)?
        .text
        .contains("registered_leaf"));
    Ok(())
}

#[test]
fn locked_parameter_names_are_restored_after_printing() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::new(Language::X86Windows64)?;
    // Both functions forward their argument. Only the wrapper calls the named API.
    session.add_section(
        0x1000,
        &[
            0x48, 0x83, 0xec, 0x28, 0xff, 0x15, 0xf6, 0x0f, 0, 0, 0x48, 0x83, 0xc4, 0x28, 0xc3,
        ],
        true,
        true,
    )?;
    session.add_section(
        0x1100,
        &[
            0x48, 0x83, 0xec, 0x28, 0xe8, 0xf7, 0xfe, 0xff, 0xff, 0x48, 0x83, 0xc4, 0x28, 0xc3,
        ],
        true,
        true,
    )?;
    session.add_section(0x2000, &[0; 8], false, false)?;
    session.add_function(0x1000, "wrapper", false)?;
    session.add_function(0x1100, "caller", false)?;
    // The archive locks atexit's parameter type but leaves its name unlocked.
    assert!(session.apply_prototype(0x1000, "atexit")?);
    session.add_import(0x2000, "_onexit", false)?;
    assert!(session.apply_prototype(0x2000, "_onexit")?);
    let first = session.decompile(0x1100, 5000, 1000, 1_000_000)?;
    assert!(!first.text.contains("_Func"), "{}", first.text);
    for print_work in [0, 1, 0] {
        session.set_print_work_limit(print_work)?;
        let wrapper = session.decompile(0x1000, 5000, 1000, 1_000_000);
        if print_work == 0 {
            let wrapper = wrapper?;
            assert!(wrapper.text.contains("_Func"), "{}", wrapper.text);
        } else {
            assert!(wrapper.is_err());
        }
        session.set_print_work_limit(0)?;
        assert_eq!(
            first.text,
            session.decompile(0x1100, 5000, 1000, 1_000_000)?.text
        );
    }
    Ok(())
}
