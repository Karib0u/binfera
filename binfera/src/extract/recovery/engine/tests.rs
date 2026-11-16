#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::extract::image::{ImageFormat, MappedSection, Permissions, SHELLCODE_BASE};

#[test]
fn pointer_runs_recover_entries_but_not_switch_interiors() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let width = architecture.pointer_width();
        for (targets, expected) in [
            ([0x1000u64, 0x1040], vec![0x1000, 0x1040]),
            ([0x1002, 0x1003], vec![]),
            ([0x1002, 0x1040], vec![0x1040]),
        ] {
            let mut bytes = vec![0xcc; 0x80];
            bytes[..5].copy_from_slice(&[0x31, 0xc0, 0x40, 0x40, 0xc3]);
            bytes[0x40..0x46].copy_from_slice(&[0xb8, 1, 0, 0, 0, 0xc3]);
            for target in targets {
                bytes.extend_from_slice(&target.to_le_bytes()[..width]);
            }
            let image = LoadedImage::for_test(
                ImageFormat::Pe,
                architecture,
                0x1000,
                vec![
                    MappedSection {
                        name: ".text".into(),
                        address: 0x1000,
                        virtual_size: 0x80,
                        file_offset: 0,
                        file_size: 0x80,
                        permissions: Permissions {
                            read: true,
                            write: false,
                            execute: true,
                        },
                    },
                    MappedSection {
                        name: ".rdata".into(),
                        address: 0x2000,
                        virtual_size: (2 * width) as u64,
                        file_offset: 0x80,
                        file_size: (2 * width) as u64,
                        permissions: Permissions {
                            read: true,
                            write: false,
                            execute: false,
                        },
                    },
                ],
                BTreeMap::new(),
                bytes,
            );
            let found = vtable_targets(&image);
            assert_eq!(found, expected.into_iter().collect());
        }
    }
}

#[test]
fn seh_scope_records_and_handler_resumes_are_not_tables() {
    // x86 `{try level, filter, handler}` records: the level ends the pointer run before a
    // filter/handler pair. A table whose slot resumes a parent frame is not one either.
    for (prefix, targets, expected) in [
        (0xffff_ffffu32, vec![0x1000u32, 0x1040], vec![]),
        (0xffff_fffe, vec![0x1000, 0x1040], vec![]),
        (2, vec![0x1000, 0x1040], vec![]),
        (0x1234_5678, vec![0x1000, 0x1040], vec![0x1000u64, 0x1040]),
        (0x1234_5678, vec![0x1000, 0x1050, 0x1040], vec![]),
        (
            0x1234_5678,
            vec![0x1000, 0x1040, 0x1050],
            vec![0x1000, 0x1040],
        ),
    ] {
        let mut bytes = vec![0xcc; 0x80];
        bytes[..5].copy_from_slice(&[0x31, 0xc0, 0x40, 0x40, 0xc3]);
        bytes[0x40..0x46].copy_from_slice(&[0xb8, 1, 0, 0, 0, 0xc3]);
        // mov esp,[ebp-18h]: an __except handler continuing in its parent's frame.
        bytes[0x50..0x54].copy_from_slice(&[0x8b, 0x65, 0xe8, 0xc3]);
        bytes.extend_from_slice(&prefix.to_le_bytes());
        for target in &targets {
            bytes.extend_from_slice(&target.to_le_bytes());
        }
        let rdata = 4 + 4 * targets.len() as u64;
        let section = |name: &str, address, size, offset, execute| MappedSection {
            name: name.into(),
            address,
            virtual_size: size,
            file_offset: offset,
            file_size: size,
            permissions: Permissions {
                read: true,
                write: false,
                execute,
            },
        };
        let image = LoadedImage::for_test(
            ImageFormat::Pe,
            Architecture::X86,
            0x1000,
            vec![
                section(".text", 0x1000, 0x80, 0, true),
                section(".rdata", 0x2000, rdata, 0x80, false),
            ],
            BTreeMap::new(),
            bytes,
        );
        assert_eq!(
            vtable_targets(&image),
            expected.into_iter().collect(),
            "level {prefix:#x}, targets {targets:x?}"
        );
    }
}

#[test]
fn seh_scope_blocks_need_a_handler_resuming_its_parent() {
    for (level, handler, expected) in [
        (0xffff_ffffu32, 0x1050u32, vec![0x1040u64, 0x1050]),
        (1, 0x1050, vec![0x1040, 0x1050]),
        (0x1234_5678, 0x1050, vec![]),
        (0xffff_ffff, 0x1000, vec![]),
    ] {
        let mut bytes = vec![0xcc; 0x80];
        bytes[..5].copy_from_slice(&[0x31, 0xc0, 0x40, 0x40, 0xc3]);
        // push 1; pop eax; ret: a filter returning EXCEPTION_EXECUTE_HANDLER.
        bytes[0x40..0x44].copy_from_slice(&[0x6a, 0x01, 0x58, 0xc3]);
        bytes[0x50..0x54].copy_from_slice(&[0x8b, 0x65, 0xe8, 0xc3]);
        for word in [level, 0x1040, handler] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        let section = |name: &str, address, size, offset, execute| MappedSection {
            name: name.into(),
            address,
            virtual_size: size,
            file_offset: offset,
            file_size: size,
            permissions: Permissions {
                read: true,
                write: false,
                execute,
            },
        };
        let image = LoadedImage::for_test(
            ImageFormat::Pe,
            Architecture::X86,
            0x1000,
            vec![
                section(".text", 0x1000, 0x80, 0, true),
                section(".rdata", 0x2000, 12, 0x80, false),
            ],
            BTreeMap::new(),
            bytes,
        );
        assert_eq!(
            seh_scope_blocks(&image),
            expected.into_iter().collect(),
            "level {level:#x}, handler {handler:#x}"
        );
    }
}

fn callback_image(bytes: &[u8], architecture: Architecture, api: &str) -> Analysis {
    let mut image = LoadedImage::for_test(
        ImageFormat::Pe,
        architecture,
        0x1000,
        vec![MappedSection {
            name: ".text".into(),
            address: 0x1000,
            virtual_size: bytes.len() as u64,
            file_offset: 0,
            file_size: bytes.len() as u64,
            permissions: Permissions {
                read: true,
                write: false,
                execute: true,
            },
        }],
        BTreeMap::new(),
        bytes.to_vec(),
    );
    image.import_locations.insert(0x2000, api.into());
    image.external_bindings.insert(0x2000, vec![api.into()]);
    analyze_seeded_image(
        image,
        RecoveryBackend::VivisectCompat,
        SeedMap::from([(0x1000, BTreeSet::from([SeedKind::EntryPoint]))]),
        BTreeMap::new(),
        Vec::new(),
    )
    .expect("synthetic callback recovery succeeds")
}

#[test]
fn flirt_local_code_precedes_fallback_function_entries() {
    let mut bytes = vec![0xe8, 0x1b, 0, 0, 0, 0xc3];
    bytes.resize(0x20, 0xcc);
    bytes.extend_from_slice(&[0x31, 0xc0, 0xc3]);
    bytes.resize(0x40, 0xcc);
    bytes.extend_from_slice(&[0xe9, 0x3b, 0, 0, 0]);
    bytes.resize(0x80, 0xcc);
    bytes.extend_from_slice(&[0x55, 0x8b, 0xec, 0x5d, 0xc3]);
    bytes.resize(0x100, 0xcc);
    let image = noreturn_test_image(&bytes);
    let path = std::env::temp_dir().join(format!("binfera-local-{}.pat", std::process::id()));
    let pattern = format!(
        "31C0C3{} 00 0000 0040 :0000 root :0020@ local\n---",
        "..".repeat(29)
    );
    std::fs::write(&path, pattern).unwrap();
    let signatures = super::super::flirt::Signatures::from_path(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    let analysis = analyze_seeded_image_with_signatures(
        image,
        RecoveryBackend::VivisectCompat,
        SeedMap::from([(0x1000, BTreeSet::from([SeedKind::EntryPoint]))]),
        BTreeMap::new(),
        Vec::new(),
        Some(&signatures),
    )
    .unwrap();
    assert!(analysis.functions.contains_key(&0x1040));
    assert!(analysis.instructions.contains_key(&0x1080));
    assert!(!analysis.functions.contains_key(&0x1080));
    let libraries =
        super::super::flirt::identify_library_functions(&analysis, &signatures).unwrap();
    assert_eq!(libraries.get(&0x1040).map(String::as_str), Some("local"));
}

#[test]
fn flirt_public_names_include_functions_created_by_its_local_symbols() {
    let mut bytes = vec![0xe8, 0x1b, 0, 0, 0, 0xc3];
    bytes.resize(0x20, 0xcc);
    bytes.push(0xc3);
    bytes.resize(0x40, 0xcc);
    bytes.extend_from_slice(&[0xe8, 0x1b, 0, 0, 0, 0xc3]);
    bytes.resize(0x60, 0xcc);
    bytes.extend_from_slice(&[0x90, 0xc3]);
    bytes.resize(0x80, 0xcc);
    bytes.extend_from_slice(&[0x90, 0xc3]);
    bytes.resize(0x100, 0xcc);
    let path = std::env::temp_dir().join(format!("binfera-public-{}.pat", std::process::id()));
    let pattern = format!(
        "C3{} 00 0000 0080 :0000 root :0020@ local :0040 created :0060 later\n---",
        "..".repeat(31)
    );
    std::fs::write(&path, pattern).unwrap();
    let signatures = super::super::flirt::Signatures::from_path(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    let analysis = analyze_seeded_image_with_signatures(
        noreturn_test_image(&bytes),
        RecoveryBackend::VivisectCompat,
        SeedMap::from([
            (0x1000, BTreeSet::from([SeedKind::EntryPoint])),
            (0x1080, BTreeSet::from([SeedKind::Export])),
        ]),
        BTreeMap::new(),
        Vec::new(),
        Some(&signatures),
    )
    .unwrap();
    let libraries =
        super::super::flirt::identify_library_functions(&analysis, &signatures).unwrap();
    assert_eq!(libraries.get(&0x1060).map(String::as_str), Some("created"));
    assert!(analysis.functions.contains_key(&0x1080));
    assert!(!libraries.contains_key(&0x1080));
}

#[test]
fn branch_into_loose_import_root_keeps_its_function_callback_deferred() {
    let mut bytes = vec![0xc3];
    bytes.resize(0x1e, 0xcc);
    bytes.extend_from_slice(&[
        0x75, 0x10, // 0x101e: jnz 0x1030; fallthrough enters loose root
        0xff, 0x15, 0, 0x20, 0, 0, // 0x1020: call [import]
        0xe8, 0x25, 0, 0, 0, 0xc3, // call 0x1050; ret
    ]);
    bytes.resize(0x30, 0xcc);
    bytes.push(0xc3);
    bytes.resize(0x50, 0xcc);
    bytes.extend_from_slice(&[0xe8, 0xc9, 0xff, 0xff, 0xff, 0xc3]); // call 0x101e
    bytes.resize(0x1100, 0);
    let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
    assert!(analysis.instructions.contains_key(&0x101e));
    assert!(analysis.functions.contains_key(&0x1050));
    assert!(!analysis.functions.contains_key(&0x101e));
}

#[test]
fn import_call_functions_keep_the_extent_at_creation() {
    let mut bytes = vec![0xc3];
    bytes.resize(0x10, 0xcc);
    // An unreferenced function, with an exit reachable independently of
    // the import-call fragment that first discovers its recursive call.
    bytes.extend_from_slice(&[0x31, 0xc0, 0x74, 0x2c]);
    bytes.resize(0x20, 0x90);
    bytes.extend_from_slice(&[
        0xff, 0x15, 0, 0x20, 0, 0, // 0x1020: call [import]
        0xe8, 0xe5, 0xff, 0xff, 0xff, // 0x1026: call 0x1010
        0xe8, 0x20, 0, 0, 0, // 0x102b: call 0x1050
        0xc3,
    ]);
    bytes.resize(0x40, 0xcc);
    bytes.push(0xc3);
    bytes.resize(0x50, 0xcc);
    bytes.push(0xc3);
    // Keep the synthetic IAT inside a mapped region for findPointers.
    bytes.resize(0x1100, 0);
    let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
    let function = &analysis.functions[&0x1010];
    let owned: BTreeSet<_> = function
        .blocks
        .iter()
        .flat_map(|block| block.insns.iter().map(|insn| insn.address))
        .collect();
    assert!(owned.contains(&0x1026));
    assert!(owned.contains(&0x1040));
    assert!(!owned.contains(&0x102b));
    assert!(analysis.instructions.contains_key(&0x102b));
    assert!(analysis.functions.contains_key(&0x1050));
    assert!(!analysis.is_noreturn_va(0x1010));

    let native = analyze_seeded_image(
        analysis.image.clone(),
        RecoveryBackend::Native,
        SeedMap::from([(0x1000, BTreeSet::from([SeedKind::EntryPoint]))]),
        BTreeMap::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(native.functions[&0x1010]
        .blocks
        .iter()
        .flat_map(|block| &block.insns)
        .any(|insn| insn.address == 0x102b));

    let mut relocated = analysis.image.clone();
    relocated.relocation_locations.push(0x1022);
    let relocated = analyze_seeded_image(
        relocated,
        RecoveryBackend::VivisectCompat,
        SeedMap::from([(0x1000, BTreeSet::from([SeedKind::EntryPoint]))]),
        BTreeMap::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(
        !relocated.instructions.contains_key(&0x1020),
        "a typed relocation operand is not an undefined import-call candidate"
    );
    assert!(!relocated.functions.contains_key(&0x1010));
}

#[test]
fn api_callbacks_recover_nonreturning_targets_from_computed_arguments() {
    // CreateThread's third argument is an absolute LEA, so it provides
    // no static REF_PTR. The callback never returns, so it cannot pass
    // candidate evaluation either. Only the API type establishes a root.
    let mut bytes = vec![
        0x6a, 0, 0x6a, 0, 0x6a, 0, // last three arguments
        0x8d, 0x05, 0x40, 0x10, 0, 0, // lea eax, [0x1040]
        0x50, 0x6a, 0, 0x6a, 0, // callback, size, attributes
        0x89, 0x43, 8, // mov [ebx+8], eax: unknown destination, not the stack
        0xff, 0x15, 0, 0x20, 0, 0, // call [CreateThread]
        0xc3,
    ];
    bytes.resize(0x40, 0xcc);
    bytes.extend_from_slice(&[0xeb, 0xfe]);
    let analysis = callback_image(&bytes, Architecture::X86, "kernel32.CreateThread");
    assert!(analysis.functions.contains_key(&0x1040));
    assert!(analysis.seeds[&0x1040].contains(&SeedKind::ApiCallback));
    let ordinary = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
    assert!(!ordinary.functions.contains_key(&0x1040));
}

#[test]
fn recursive_callbacks_in_import_fragments_finish_before_finalization() {
    let mut bytes = vec![0xc3];
    bytes.resize(0x10, 0xcc);
    bytes.extend_from_slice(&[
        0xff, 0x15, 0, 0x20, 0, 0, // loose call [import]
        0xe8, 0x25, 0, 0, 0, 0xc3, // call 0x1040; ret
    ]);
    bytes.resize(0x40, 0xcc);
    bytes.extend_from_slice(&[0xb8, 0x80, 0x10, 0, 0, 0xff, 0xd0, 0xc3]);
    bytes.resize(0x80, 0xcc);
    bytes.extend_from_slice(&[0xe8, 0x1b, 0, 0, 0, 0xc3]); // call 0x10a0; ret
    bytes.resize(0xa0, 0xcc);
    bytes.extend_from_slice(&[0xe8, 0xdb, 0xff, 0xff, 0xff, 0xc3]); // call 0x1080; ret
    bytes.resize(0x1100, 0);
    let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
    for start in [0x1080, 0x10a0] {
        assert!(!analysis.is_noreturn_va(start));
        assert!(analysis.functions[&start]
            .blocks
            .iter()
            .flat_map(|block| &block.insns)
            .any(|insn| insn.address == start + 5));
    }
}

#[test]
fn callbacks_discovered_inside_import_fragments_become_functions() {
    let mut bytes = vec![0xc3];
    bytes.resize(0x10, 0xcc);
    bytes.extend_from_slice(&[
        0xff, 0x15, 0, 0x20, 0, 0, // loose call [CreateThread]
        0xe8, 0x25, 0, 0, 0, // call 0x1040
        0xc3,
    ]);
    bytes.resize(0x40, 0xcc);
    bytes.extend_from_slice(&[
        0x6a, 0, 0x6a, 0, 0x6a, 0, 0x8d, 0x05, 0xa0, 0x10, 0, 0, // lea eax,[0x10a0]
        0x50, 0x6a, 0, 0x6a, 0, 0xff, 0x15, 0, 0x20, 0, 0, 0xc3,
    ]);
    bytes.resize(0xa0, 0xcc);
    bytes.extend_from_slice(&[0xeb, 0xfe]);
    bytes.resize(0x1100, 0);
    let analysis = callback_image(&bytes, Architecture::X86, "kernel32.CreateThread");
    assert!(analysis.functions.contains_key(&0x1040));
    assert!(analysis.functions.contains_key(&0x10a0));
    assert!(analysis.seeds[&0x10a0].contains(&SeedKind::ApiCallback));
}

#[test]
fn seh3_scope_tables_contribute_filter_and_handler_candidates() {
    let mut bytes = vec![
        0x6a, 0, // local allocation
        0x68, 0x80, 0x10, 0, 0, // scope table
        0xe8, 0x34, 0, 0, 0, // call seh3_prolog at 0x1040
        0xc3,
    ];
    bytes.resize(0x40, 0xcc);
    bytes.extend_from_slice(&[0x68, 0, 0, 0, 0, 0x64, 0xa1, 0, 0, 0, 0, 0x50, 0xc3]);
    bytes.resize(0x80, 0xcc);
    for value in [u32::MAX, 0x10c0, 0x10d0] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.resize(0xc0, 0xcc);
    bytes.extend_from_slice(&[0x31, 0xc0, 0xc3]);
    bytes.resize(0xd0, 0xcc);
    bytes.extend_from_slice(&[0x49, 0x75, 0xfd, 0xc3]);
    let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
    for address in [0x10c0, 0x10d0] {
        assert!(analysis.functions.contains_key(&address));
        assert!(analysis.seeds[&address].contains(&SeedKind::Emulated));
    }
    assert!(!analysis.instructions.contains_key(&0x1080));
}

#[test]
fn callee_data_references_stop_the_callers_later_code_flow() {
    let mut bytes = vec![0xe8, 0x0b, 0, 0, 0, 0x90, 0x90, 0x90, 0x90, 0xeb, 0xfe];
    bytes.resize(0x10, 0xcc);
    bytes.push(0xa1); // mov eax,[base+5]
    bytes.extend_from_slice(&((SHELLCODE_BASE + 5) as u32).to_le_bytes());
    bytes.push(0xc3);
    let analysis = analyze_shellcode(&bytes, Architecture::X86).unwrap();
    assert!(!analysis.instructions.contains_key(&(SHELLCODE_BASE + 5)));
    assert_eq!(
        function_instruction_addrs(&analysis.functions[&SHELLCODE_BASE]).len(),
        1
    );
    assert!(analysis.functions.contains_key(&(SHELLCODE_BASE + 0x10)));
}

#[test]
fn candidate_traces_follow_previously_resolved_indirect_branches() {
    let mut analysis = analyze_noreturn_test_image(&[0xff, 0xe0, 0xc3]);
    assert_eq!(
        super::super::emucode::evaluate_candidate(&analysis, 0x1000, &BTreeSet::new(), &[]),
        super::super::emucode::Verdict::NotCode
    );
    let target = analysis.image.decode_at_compat(0x1002).unwrap();
    analysis.instructions.insert(0x1002, target);
    analysis.code_xrefs.insert(0x1002, vec![0x1000]);
    assert_eq!(
        super::super::emucode::evaluate_candidate(&analysis, 0x1000, &BTreeSet::new(), &[]),
        super::super::emucode::Verdict::Code
    );
}

#[test]
fn candidate_table_references_require_a_defined_code_block() {
    let mut bytes = vec![0xff, 0x24, 0x85, 0x10, 0x10, 0, 0];
    bytes.resize(0x10, 0xcc);
    bytes.extend_from_slice(&0x1020u32.to_le_bytes());
    bytes.resize(0x20, 0xcc);
    bytes.push(0xc3);
    let mut analysis = analyze_noreturn_test_image(&bytes);
    let target = analysis.image.decode_at_compat(0x1020).unwrap();
    analysis.functions.clear();
    analysis.instructions.insert(0x1020, target.clone());
    analysis.code_xrefs.insert(0x1020, vec![0x1000]);
    assert_eq!(
        super::super::emucode::evaluate_candidate(&analysis, 0x1000, &BTreeSet::new(), &[]),
        super::super::emucode::Verdict::NotCode
    );
    analysis.functions.insert(
        0x1020,
        Function {
            addr: 0x1020,
            blocks: vec![BasicBlock {
                addr: 0x1020,
                insns: vec![target],
                succs: Vec::new(),
            }],
        },
    );
    assert_eq!(
        super::super::emucode::evaluate_candidate(&analysis, 0x1000, &BTreeSet::new(), &[]),
        super::super::emucode::Verdict::Code
    );
}

#[test]
fn rejected_emucode_strings_become_code_barriers() {
    let mut bytes = vec![0xc3];
    bytes.resize(0x40, 0xcc);
    bytes.extend_from_slice(b"hello world\0");
    let mut analysis = analyze_noreturn_test_image(&bytes);
    analysis
        .seeds
        .insert(0x1040, BTreeSet::from([SeedKind::Emulated]));
    let mut discovery = super::super::pointers::Discovery::new(&mut analysis, true);
    assert_eq!(discovery.next(&mut analysis, &BTreeSet::new()), None);
    assert!(super::super::emucode::in_data(
        discovery.code_barriers(),
        0x1045
    ));
}

#[test]
fn compatibility_preserves_jump_table_order_and_deduplicates_arms() {
    let mut bytes = vec![0xff, 0x24, 0x85, 0x20, 0x10, 0, 0];
    bytes.resize(0x20, 0xcc);
    for target in [0x1080u32, 0x1040, 0x1080, 0x1060] {
        bytes.extend_from_slice(&target.to_le_bytes());
    }
    bytes.resize(0x90, 0xcc);
    for offset in [0x40, 0x60, 0x80] {
        bytes[offset] = 0xc3;
    }
    let mut analysis = analyze_noreturn_test_image(&bytes);
    let branch = analysis.instructions[&0x1000].clone();
    assert_eq!(
        jump_table_targets_compat(&mut analysis, &branch, &BTreeSet::new()),
        [0x1080, 0x1040, 0x1060]
    );
    assert_eq!(
        jump_table_targets(&analysis.image, &branch),
        [0x1040, 0x1060, 0x1080]
    );
}

#[test]
fn compatibility_stops_a_table_at_an_unsupported_candidate() {
    let mut bytes = vec![0xff, 0x24, 0x85, 0x20, 0x10, 0, 0];
    bytes.resize(0x20, 0xcc);
    for target in [0x1040u32, 0x1050, 0x1060] {
        bytes.extend_from_slice(&target.to_le_bytes());
    }
    bytes.resize(0x61, 0xcc);
    bytes[0x40] = 0xc3;
    bytes[0x50..0x55].copy_from_slice(&[0xf2, 0x0f, 0x5e, 0xc0, 0xc3]); // divsd; ret
    bytes[0x60] = 0xc3;
    let mut analysis = analyze_noreturn_test_image(&bytes);
    let branch = analysis.instructions[&0x1000].clone();
    assert_eq!(
        jump_table_targets_compat(&mut analysis, &branch, &BTreeSet::new()),
        [0x1040]
    );
    assert!(analysis
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("Divsd")));
}

#[test]
fn compatibility_recovers_switch_arms_beyond_256_entries() {
    let mut bytes = vec![0xff, 0x24, 0x85, 0x20, 0x10, 0, 0];
    bytes.resize(0x20, 0xcc);
    for _ in 0..256 {
        bytes.extend_from_slice(&0x1500u32.to_le_bytes());
    }
    bytes.extend_from_slice(&0x1510u32.to_le_bytes());
    bytes.resize(0x500, 0xcc);
    bytes.push(0xc3);
    bytes.resize(0x510, 0xcc);
    bytes.extend_from_slice(&[0x49, 0x75, 0xfd, 0xc3]);
    let mut analysis = analyze_noreturn_test_image(&bytes);
    let branch = analysis.instructions[&0x1000].clone();
    assert_eq!(
        jump_table_targets_compat(&mut analysis, &branch, &BTreeSet::new()),
        [0x1500, 0x1510]
    );
    assert!(analysis.functions[&0x1000]
        .blocks
        .iter()
        .any(|block| block.addr == 0x1510));
    assert!(!analysis.functions.contains_key(&0x1510));
    assert!(analysis.code_xrefs[&0x1510].contains(&0x1000));
}

#[test]
fn calling_trace_follows_reference_far_pointer_fallthrough() {
    let mut bytes = vec![
        0xff, 0x6a, 0x00, // jmp far [edx]: unsupported six-byte read
        0xe8, 0x18, 0, 0, 0, // call 0x1020 in loose bytes
        0xc3,
    ];
    bytes.resize(0x20, 0xcc);
    bytes.extend_from_slice(&[0x49, 0x75, 0xfd, 0xc3]);
    let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
    assert!(analysis.functions.contains_key(&0x1020));
    assert!(!analysis.instructions.contains_key(&0x1003));
}

#[test]
fn calling_trace_finds_callees_after_a_computed_jump() {
    let mut bytes = vec![
        0xc7, 0x05, 0x40, 0x10, 0, 0, 0x60, 0x10, 0, 0, // mov [0x1040],0x1060
        0x8d, 0x05, 0x40, 0x10, 0, 0, // lea eax,[0x1040]
        0xff, 0x20, // jmp [eax]
    ];
    bytes.resize(0x60, 0);
    bytes.extend_from_slice(&[0xe8, 0x1b, 0, 0, 0, 0xc3]); // call 0x1080; ret
    bytes.resize(0x80, 0xcc);
    bytes.extend_from_slice(&[0xeb, 0xfe]); // a callee that cannot pass candidate evaluation
    let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
    assert!(analysis.functions.contains_key(&0x1080));
    assert!(analysis.seeds[&0x1080].contains(&SeedKind::CallTarget));
}

#[test]
fn calling_trace_continues_past_a_noreturn_call_only_at_its_entry() {
    for prefix in [false, true] {
        let mut bytes = Vec::new();
        if prefix {
            bytes.push(0x90);
        }
        for target in [0x40u32, 0x50] {
            let next = bytes.len() as u32 + 5;
            bytes.push(0xe8);
            bytes.extend_from_slice(&(target - next).to_le_bytes());
        }
        bytes.push(0xc3);
        bytes.resize(0x50, 0xcc);
        bytes.push(0xc3);
        let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
        assert!(analysis.noreturn.contains(&0x1040));
        assert_eq!(analysis.functions.contains_key(&0x1050), !prefix);
        assert!(
            analysis.functions[&0x1000]
                .blocks
                .iter()
                .flat_map(|block| &block.insns)
                .all(|insn| insn.address < 0x1005 + u64::from(prefix)),
            "calling analysis must not expand the captured code scope"
        );
    }
}

#[test]
fn calling_trace_stops_on_the_reference_bad_opcode() {
    let mut bytes = vec![
        0xe8, 0x3b, 0, 0, 0, // call nonreturning function at 0x1040
        0, 0, // bad opcode rejected by the calling monitor
        0xe8, 0x44, 0, 0, 0, // call 0x1050
        0xc3,
    ];
    bytes.resize(0x50, 0xcc);
    bytes.push(0xc3);
    let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
    assert!(analysis.noreturn.contains(&0x1040));
    assert!(!analysis.functions.contains_key(&0x1050));
}

#[test]
fn calling_trace_does_not_treat_import_contents_as_a_callee() {
    let mut bytes = vec![0xff, 0x15, 0, 0x20, 0, 0, 0xc3];
    bytes.resize(0x40, 0xcc);
    bytes.extend_from_slice(&[0xeb, 0xfe]);
    bytes.resize(0x1000, 0);
    bytes.extend_from_slice(&0x1040u32.to_le_bytes());
    let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
    assert!(!analysis.functions.contains_key(&0x1040));
}

#[test]
fn calling_trace_preserves_concrete_nonvolatile_function_pointers_across_calls() {
    let mut bytes = vec![
        0xbd, 0x40, 0x10, 0, 0, // mov ebp,0x1040
        0xff, 0x15, 0, 0x20, 0, 0, // call [OtherApi]
        0xff, 0xd5, 0xc3, // call ebp; ret
    ];
    bytes.resize(0x40, 0xcc);
    bytes.extend_from_slice(&[0xeb, 0xfe]);
    let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
    assert!(analysis.functions.contains_key(&0x1040));
    assert!(analysis.seeds[&0x1040].contains(&SeedKind::CallTarget));
}

#[test]
fn elf_calling_analysis_recovers_concrete_register_calls() {
    let mut bytes = vec![0xb8, 0x20, 0x10, 0, 0, 0xff, 0xd0, 0xc3];
    bytes.resize(0x20, 0xcc);
    bytes.extend_from_slice(&[0x31, 0xc0, 0xc3]);
    let mut image = noreturn_test_image(&bytes);
    image.format = ImageFormat::Elf;
    let analysis = analyze_seeded_image(
        image,
        RecoveryBackend::VivisectCompat,
        SeedMap::from([(0x1000, BTreeSet::from([SeedKind::EntryPoint]))]),
        BTreeMap::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(analysis.seeds[&0x1020].contains(&SeedKind::CallTarget));
    assert!(analysis.functions.contains_key(&0x1020));
}

#[test]
fn referenced_data_strings_do_not_create_embedded_pointer_functions() {
    let mut bytes = vec![0xb8, 0, 0, 0x50, 0, 0xc3];
    bytes.resize(0x41, 0xcc);
    bytes.push(0xc3);
    let data_offset = bytes.len() as u64;
    bytes.extend_from_slice(b"helloAAA\0\0\0\0\0");
    let image = LoadedImage::for_test(
        ImageFormat::Elf,
        Architecture::X86,
        0x414100,
        vec![
            MappedSection {
                name: ".text".into(),
                address: 0x414100,
                virtual_size: data_offset,
                file_offset: 0,
                file_size: data_offset,
                permissions: Permissions {
                    read: true,
                    write: false,
                    execute: true,
                },
            },
            MappedSection {
                name: ".rodata".into(),
                address: 0x500000,
                virtual_size: 13,
                file_offset: data_offset,
                file_size: 13,
                permissions: Permissions {
                    read: true,
                    write: false,
                    execute: false,
                },
            },
        ],
        BTreeMap::new(),
        bytes,
    );
    let analysis = analyze_seeded_image(
        image,
        RecoveryBackend::VivisectCompat,
        SeedMap::from([(0x414100, BTreeSet::from([SeedKind::EntryPoint]))]),
        BTreeMap::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(!analysis.functions.contains_key(&0x414141));
}

#[test]
fn completed_function_padding_stops_later_callback_flow() {
    let mut bytes = vec![
        0xe8, 0x3b, 0, 0, 0, // call 0x1040, which types its preceding pad
        0xe8, 0x16, 0, 0, 0, // call 0x1020
        0xc3,
    ];
    bytes.resize(0x20, 0xcc);
    bytes.extend_from_slice(&[0xff, 0x15, 0, 0x20, 0, 0]);
    bytes.resize(0x40, 0x90);
    bytes.push(0xc3);
    let analysis = analyze_noreturn_test_image(&bytes);
    assert!(!analysis.instructions.contains_key(&0x1026));
    assert!(analysis.functions[&0x1020]
        .blocks
        .iter()
        .all(|block| block.addr < 0x1040));
}

#[test]
fn concrete_callees_finish_in_emulator_encounter_order() {
    let mut bytes = vec![
        0xb8, 0x60, 0x10, 0, 0, 0xff, 0xd0, 0xb8, 0x40, 0x10, 0, 0, 0xff, 0xd0, 0xc3,
    ];
    bytes.resize(0x40, 0xcc);
    bytes.push(0xc3);
    bytes.resize(0x60, 0xcc);
    bytes.push(0xc3);
    let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
    assert!(analysis.function_order[&0x1060] < analysis.function_order[&0x1040]);
}

#[test]
fn callbacks_recheck_locations_after_each_target_finishes() {
    let mut bytes = Vec::new();
    for target in [0x1080u32, 0x1081] {
        bytes.extend_from_slice(&[0x6a, 0, 0x6a, 0, 0x6a, 0, 0x68]);
        bytes.extend_from_slice(&target.to_le_bytes());
        bytes.extend_from_slice(&[0x6a, 0, 0x6a, 0, 0xff, 0x15, 0, 0x20, 0, 0]);
    }
    bytes.push(0xc3);
    bytes.resize(0x80, 0xcc);
    bytes.extend_from_slice(&[0x90, 0xc3]);
    let analysis = callback_image(&bytes, Architecture::X86, "kernel32.CreateThread");
    assert!(analysis.functions.contains_key(&0x1080));
    assert!(!analysis.functions.contains_key(&0x1081));
}

#[test]
fn calling_analysis_follows_data_pointers_before_resuming_its_caller() {
    for opcode in [0x8b, 0x8d] {
        // MOV and the i386 monitor's LEA hook
        let mut bytes = vec![
            0xe8, 0x1b, 0, 0, 0, // call 0x1020
            0xe8, 0x36, 0, 0, 0, // call 0x1040
            0xc3,
        ];
        bytes.resize(0x20, 0xcc);
        bytes.extend_from_slice(&[opcode, 0x05, 0x80, 0x10, 0, 0, 0xc3]);
        bytes.resize(0x40, 0xcc);
        bytes.push(0xc3);
        bytes.resize(0x60, 0xcc);
        bytes.push(0xc3);
        bytes.resize(0x80, 0xcc);
        bytes.extend_from_slice(&0x1060u32.to_le_bytes());
        let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
        if opcode == 0x8b {
            assert!(analysis.function_order[&0x1060] < analysis.function_order[&0x1020]);
        } else {
            assert!(analysis.function_order[&0x1020] < analysis.function_order[&0x1060]);
        }
        assert!(analysis.function_order[&0x1060] < analysis.function_order[&0x1040]);
        assert!(analysis.seeds[&0x1060].contains(&SeedKind::PointerTarget));
    }
}

#[test]
fn calling_trace_follows_resolved_switches_with_unknown_selectors() {
    let mut bytes = vec![0xff, 0x24, 0x8d, 0x80, 0x10, 0, 0];
    bytes.resize(0x20, 0xcc);
    bytes.extend_from_slice(&[0xbf, 0x40, 0x10, 0, 0, 0xff, 0xd7, 0xc3]);
    bytes.resize(0x30, 0xcc);
    bytes.push(0xc3);
    bytes.resize(0x40, 0xcc);
    bytes.extend_from_slice(&[0xeb, 0xfe]);
    bytes.resize(0x80, 0xcc);
    for target in [0x1020u32, 0x1030, 0] {
        bytes.extend_from_slice(&target.to_le_bytes());
    }
    let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
    assert!(analysis.functions.contains_key(&0x1040));
    assert!(analysis.seeds[&0x1040].contains(&SeedKind::CallTarget));
}

#[test]
fn calling_trace_preserves_stack_function_pointers_across_calls() {
    let mut bytes = vec![
        0x68, 0x40, 0x10, 0, 0, // push 0x1040
        0xff, 0x15, 0, 0x20, 0, 0, // call [OtherApi]
        0x5f, 0xff, 0xd7, 0xc3, // pop edi; call edi; ret
    ];
    bytes.resize(0x40, 0xcc);
    bytes.extend_from_slice(&[0xeb, 0xfe]);
    let analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
    assert!(analysis.functions.contains_key(&0x1040));
    assert!(analysis.seeds[&0x1040].contains(&SeedKind::CallTarget));
}

#[test]
fn api_callbacks_preserve_import_registers_but_forget_volatile_values() {
    let mut bytes = vec![
        0x8b, 0x35, 0, 0x20, 0, 0, // mov esi, [CreateThread]
        0xff, 0x15, 0, 0x30, 0, 0, // unknown call
        0x6a, 0, 0x6a, 0, 0x6a, 0, 0x8d, 0x05, 0x40, 0x10, 0, 0, // lea eax, [0x1040]
        0x50, 0x6a, 0, 0x6a, 0, 0xff, 0xd6, // call esi
        0xc3,
    ];
    bytes.resize(0x40, 0xcc);
    bytes.extend_from_slice(&[0xeb, 0xfe]);
    for (load, call) in [(0x35, 0xd6), (0x2d, 0xd5)] {
        // Both ESI and EBP can hold an import across an unknown call.
        bytes[1] = load;
        bytes[30] = call;
        assert!(
            callback_image(&bytes, Architecture::X86, "kernel32.CreateThread")
                .functions
                .contains_key(&0x1040)
        );
    }
    // The same import held in EAX must be invalidated by the unknown call.
    bytes[1] = 0x05;
    bytes[30] = 0xd0;
    let analysis = callback_image(&bytes, Architecture::X86, "kernel32.CreateThread");
    // EAX no longer identifies CreateThread. The later LEA instead
    // makes CALL EAX a concrete call to 0x1040, not an API callback.
    assert!(!analysis.seeds[&0x1040].contains(&SeedKind::ApiCallback));
    assert!(analysis.seeds[&0x1040].contains(&SeedKind::CallTarget));
}

#[test]
fn api_callbacks_use_windows_x64_register_and_stack_arguments() {
    for (api, setup) in [
        (
            "kernel32.CreateThread",
            vec![0x49, 0xc7, 0xc0, 0x40, 0x10, 0, 0],
        ),
        (
            "msvcrt.bsearch",
            vec![0x48, 0xc7, 0x44, 0x24, 0x20, 0x40, 0x10, 0, 0],
        ),
    ] {
        let mut bytes = setup;
        // RIP-relative import call, displacement from the call's end.
        let displacement = 0x2000i32 - (0x1000 + bytes.len() as i32 + 6);
        bytes.extend_from_slice(&[0xff, 0x15]);
        bytes.extend_from_slice(&displacement.to_le_bytes());
        bytes.push(0xc3);
        bytes.resize(0x40, 0xcc);
        bytes.extend_from_slice(&[0xeb, 0xfe]);
        let analysis = callback_image(&bytes, Architecture::X64, api);
        assert!(
            analysis.seeds[&0x1040].contains(&SeedKind::ApiCallback),
            "{api}"
        );
    }
}

#[test]
fn api_callbacks_do_not_promote_unknown_arguments_or_instruction_interiors() {
    for target in [None, Some(0x1001), Some(0x9000)] {
        let mut bytes = vec![0x6a, 0, 0x6a, 0, 0x6a, 0];
        if let Some(target) = target {
            bytes.extend_from_slice(&[0x8d, 0x05]);
            bytes.extend_from_slice(&u32::to_le_bytes(target));
        }
        bytes.extend_from_slice(&[0x50, 0x6a, 0, 0x6a, 0, 0xff, 0x15, 0, 0x20, 0, 0, 0xc3]);
        let analysis = callback_image(&bytes, Architecture::X86, "kernel32.CreateThread");
        assert!(!analysis
            .seeds
            .values()
            .any(|kinds| kinds.contains(&SeedKind::ApiCallback)));
    }
}

#[test]
fn emucode_recovers_instruction_references_without_a_prologue() {
    let target = SHELLCODE_BASE + 32;
    let mut bytes = vec![0xb8]; // mov eax, candidate; ret
    bytes.extend_from_slice(&(target as u32).to_le_bytes());
    bytes.push(0xc3);
    bytes.resize(32, 0xcc);
    bytes.extend_from_slice(&[0x31, 0xc0, 0x40, 0xc3]);
    let image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
    let analysis = analyze_seeded_image(
        image,
        RecoveryBackend::VivisectCompat,
        SeedMap::from([(SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint]))]),
        BTreeMap::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(analysis.functions.contains_key(&target));
    assert!(analysis.seeds[&target].contains(&SeedKind::Emulated));
}

#[test]
fn x86_lea_monitor_follows_a_data_pointer_without_promoting_its_slot() {
    let slot = SHELLCODE_BASE + 32;
    let target = SHELLCODE_BASE + 64;
    let mut bytes = vec![0x8d, 0x05]; // lea eax, [slot]
    bytes.extend_from_slice(&(slot as u32).to_le_bytes());
    bytes.push(0xc3);
    bytes.resize(32, 0xcc);
    bytes.extend_from_slice(&(target as u32).to_le_bytes());
    bytes.resize(64, 0xcc);
    bytes.extend_from_slice(&[0x31, 0xc0, 0x40, 0xc3]);
    let analysis = analyze_seeded_image(
        LoadedImage::from_shellcode(&bytes, Architecture::X86),
        RecoveryBackend::VivisectCompat,
        SeedMap::from([(SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint]))]),
        BTreeMap::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(!analysis.functions.contains_key(&slot));
    assert!(analysis.functions.contains_key(&target));
    assert!(analysis.seeds[&target].contains(&SeedKind::PointerTarget));
}

#[test]
fn pointer_candidates_do_not_split_existing_instructions() {
    let mut bytes = vec![0xb8, 0x31, 0xc0, 0xc3, 0, 0xc3]; // ret bytes inside an immediate
    bytes.resize(32, 0xcc);
    let image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
    let analysis = analyze_seeded_image(
        image,
        RecoveryBackend::VivisectCompat,
        SeedMap::from([
            (SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint])),
            (SHELLCODE_BASE + 1, BTreeSet::from([SeedKind::Relocation])),
        ]),
        BTreeMap::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(!analysis.functions.contains_key(&(SHELLCODE_BASE + 1)));
}

#[test]
fn entry_signatures_skip_instruction_interiors() {
    let bytes = [0xb8, 0x55, 0x8b, 0xec, 0, 0xc3];
    let analysis = analyze_seeded_image(
        LoadedImage::from_shellcode(&bytes, Architecture::X86),
        RecoveryBackend::VivisectCompat,
        SeedMap::from([(SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint]))]),
        BTreeMap::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(!analysis.functions.contains_key(&(SHELLCODE_BASE + 1)));
    assert!(analysis.functions.contains_key(&SHELLCODE_BASE));
}

#[test]
fn only_rip_relative_lea_provides_a_static_candidate_reference() {
    let target = SHELLCODE_BASE + 32;
    for architecture in [Architecture::X86, Architecture::X64] {
        let mut bytes = if architecture == Architecture::X64 {
            vec![0x48, 0x8d, 0x05, 25, 0, 0, 0]
        } else {
            let mut bytes = vec![0x8d, 0x05];
            bytes.extend_from_slice(&(target as u32).to_le_bytes());
            bytes
        };
        bytes.push(0xc3);
        bytes.resize(32, 0xcc);
        bytes.extend_from_slice(&[0x31, 0xc0, 0xc3]);
        let image = LoadedImage::from_shellcode(&bytes, architecture);
        let analysis = analyze_seeded_image(
            image,
            RecoveryBackend::VivisectCompat,
            SeedMap::from([(SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint]))]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            analysis.functions.contains_key(&target),
            architecture == Architecture::X64
        );
    }
}

#[test]
fn relocation_targets_are_followed_before_later_slots_are_typed() {
    let target = SHELLCODE_BASE + 32;
    let mut bytes = vec![0xc3];
    bytes.resize(16, 0xcc);
    bytes.extend_from_slice(&(target as u32).to_le_bytes());
    bytes.resize(32, 0xcc);
    bytes.extend_from_slice(&[0x31, 0xc0, 0x40, 0xc3]);
    let mut image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
    image.format = ImageFormat::Pe;
    image.relocation_locations = vec![SHELLCODE_BASE + 16, target];
    let analysis = analyze_seeded_image(
        image,
        RecoveryBackend::VivisectCompat,
        SeedMap::from([(SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint]))]),
        BTreeMap::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(analysis.functions.contains_key(&target));
    assert!(analysis.seeds[&target].contains(&SeedKind::PointerTarget));
}

#[test]
fn partially_overwritten_pointer_stops_code_flow_at_its_remaining_bytes() {
    for pointer_offset in [0, 1] {
        let mut bytes = vec![0xc3];
        bytes.resize(32, 0xcc);
        bytes.extend_from_slice(&[0x83, 0xc0, 1, 0x60, 0x61, 0xc3]);
        let mut analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
        let start = 0x1020;
        let mut pointers = super::super::pointers::Discovery::new(&mut analysis, true);
        pointers.mark_data(start + pointer_offset, 4);
        let mut graph = DirectFlowGraph {
            compatibility: true,
            ..DirectFlowGraph::default()
        };
        discover_flow(
            &mut analysis,
            &mut graph,
            start,
            &mut pointers,
            Some(&mut BTreeSet::new()),
        )
        .unwrap();
        assert_eq!(
            analysis.instructions.contains_key(&start),
            pointer_offset != 0
        );
        assert!(!analysis.instructions.contains_key(&(start + 3)));
        // An existing pointer stops codeflow. Starting before its prefix
        // creates one opcode, then stops at the surviving pointer suffix.
    }
}

#[test]
fn pointer_retyping_deletes_the_covering_opcode_and_preserves_its_suffix() {
    let mut bytes = vec![0xc3];
    bytes.resize(32, 0xcc);
    bytes.extend_from_slice(&[0x83, 0xc0, 1, 0x60, 0x61, 0xc3]);
    let mut analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
    let mut pointers = super::super::pointers::Discovery::new(&mut analysis, true);
    pointers.mark_data(0x1021, 4);
    let mut graph = DirectFlowGraph {
        compatibility: true,
        ..DirectFlowGraph::default()
    };
    discover_flow(
        &mut analysis,
        &mut graph,
        0x1020,
        &mut pointers,
        Some(&mut BTreeSet::new()),
    )
    .unwrap();
    let mut starts = BTreeSet::new();
    assert_eq!(
        prepare_function_code(&mut analysis, &graph, &mut pointers, 0x1020, &mut starts),
        None
    );
    assert!(!analysis.instructions.contains_key(&0x1020));
    assert!(starts.contains(&0x1020));
    assert!(pointers.orphan_pointer(&analysis, 0x1023));
    assert_eq!(
        prepare_function_code(&mut analysis, &graph, &mut pointers, 0x1023, &mut starts),
        Some(Err(()))
    );
}

#[test]
fn deleted_locations_do_not_hide_later_signature_references() {
    let mut bytes = vec![0xc3];
    bytes.resize(32, 0xcc);
    bytes.extend_from_slice(&[0x31, 0xc0, 0xc3]);
    let mut analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
    analysis.instructions.remove(&0x1000);
    let mut pointers = super::super::pointers::Discovery::new(&mut analysis, true);
    let mut graph = DirectFlowGraph {
        compatibility: true,
        ..DirectFlowGraph::default()
    };
    discover_flow(&mut analysis, &mut graph, 0x1020, &mut pointers, None).unwrap();
    let visible = analysis.function_location_counts[&0x1020];
    assert!(analysis.instruction_order[&0x1022] < visible);
    assert!(analysis.instructions.len() < visible);
}

#[test]
fn elf_register_thunks_require_the_first_callers_add() {
    let mut bytes = vec![0xe8, 27, 0, 0, 0, 0x83, 0xc3, 4, 0xc3];
    bytes.resize(32, 0xcc);
    bytes.extend_from_slice(&[0x8b, 0x1c, 0x24, 0xc3]);
    let mut analysis = callback_image(&bytes, Architecture::X86, "kernel32.OtherApi");
    assert!(!super::super::callbacks::is_register_thunk(
        &analysis, 0x1020
    ));
    analysis.image.format = ImageFormat::Elf;
    assert!(super::super::callbacks::is_register_thunk(
        &analysis, 0x1020
    ));
    analysis.code_xrefs.insert(0x1020, vec![0x1008, 0x1000]);
    assert!(!super::super::callbacks::is_register_thunk(
        &analysis, 0x1020
    ));
}

#[test]
fn calls_complete_previously_decoded_jump_targets_before_the_caller() {
    let mut bytes = vec![0xe8, 27, 0, 0, 0, 0xe8, 38, 0, 0, 0, 0xc3];
    bytes.resize(32, 0xcc);
    bytes.extend_from_slice(&[0xeb, 14]);
    bytes.resize(48, 0xcc);
    bytes.push(0xc3);
    let analysis = analyze_seeded_image(
        LoadedImage::from_shellcode(&bytes, Architecture::X86),
        RecoveryBackend::VivisectCompat,
        SeedMap::from([(SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint]))]),
        BTreeMap::new(),
        Vec::new(),
    )
    .unwrap();
    let order = &analysis.function_order;
    assert!(order[&(SHELLCODE_BASE + 32)] < order[&(SHELLCODE_BASE + 48)]);
    assert!(order[&(SHELLCODE_BASE + 48)] < order[&SHELLCODE_BASE]);
}

#[test]
fn pe_entry_point_precedes_lower_address_export_roots() {
    let mut image = LoadedImage::from_shellcode(&[0xc3, 0xc3], Architecture::X86);
    image.format = ImageFormat::Pe;
    image.entry_point = Some(SHELLCODE_BASE + 1);
    let analysis = analyze_seeded_image(
        image,
        RecoveryBackend::VivisectCompat,
        SeedMap::from([
            (SHELLCODE_BASE, BTreeSet::from([SeedKind::Export])),
            (SHELLCODE_BASE + 1, BTreeSet::from([SeedKind::EntryPoint])),
        ]),
        BTreeMap::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(
        analysis.function_order[&(SHELLCODE_BASE + 1)] < analysis.function_order[&SHELLCODE_BASE]
    );
}

#[test]
fn pe_exports_and_handlers_precede_lower_address_unwind_roots() {
    let mut image = LoadedImage::from_shellcode(&[0xc3; 4], Architecture::X64);
    image.format = ImageFormat::Pe;
    image.entry_point = Some(SHELLCODE_BASE + 3);
    let analysis = analyze_seeded_image(
        image,
        RecoveryBackend::VivisectCompat,
        SeedMap::from([
            (SHELLCODE_BASE, BTreeSet::from([SeedKind::Unwind])),
            (SHELLCODE_BASE + 1, BTreeSet::from([SeedKind::SafeSeh])),
            (
                SHELLCODE_BASE + 2,
                BTreeSet::from([SeedKind::Export, SeedKind::Unwind]),
            ),
            (SHELLCODE_BASE + 3, BTreeSet::from([SeedKind::EntryPoint])),
        ]),
        BTreeMap::new(),
        Vec::new(),
    )
    .unwrap();
    let order = &analysis.function_order;
    assert!(order[&(SHELLCODE_BASE + 3)] < order[&(SHELLCODE_BASE + 2)]);
    assert!(order[&(SHELLCODE_BASE + 2)] < order[&(SHELLCODE_BASE + 1)]);
    assert!(order[&(SHELLCODE_BASE + 1)] < order[&SHELLCODE_BASE]);
}

#[test]
fn pointer_candidates_cannot_branch_into_a_completed_functions_hotpatch_padding() {
    let mut bytes = vec![0xe8, 27, 0, 0, 0, 0xc3];
    bytes.resize(16, 0xcc);
    bytes.extend_from_slice(&[0x31, 0xc0, 0x40, 0x40, 0x40, 0xeb, 4]);
    bytes.resize(32, 0x90);
    bytes.push(0xc3);
    bytes.resize(48, 0xcc);
    bytes.extend_from_slice(&((SHELLCODE_BASE + 16) as u32).to_le_bytes());
    let mut image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
    image.format = ImageFormat::Pe;
    image.relocation_locations = vec![SHELLCODE_BASE + 48];
    let analysis = analyze_seeded_image(
        image,
        RecoveryBackend::VivisectCompat,
        SeedMap::from([(SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint]))]),
        BTreeMap::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(analysis.functions.contains_key(&(SHELLCODE_BASE + 32)));
    assert!(!analysis.functions.contains_key(&(SHELLCODE_BASE + 16)));
}

#[test]
fn static_indirect_callees_complete_before_their_callers() {
    let slot = SHELLCODE_BASE + 16;
    let target = SHELLCODE_BASE + 32;
    let mut bytes = vec![0xff, 0x15];
    bytes.extend_from_slice(&(slot as u32).to_le_bytes());
    bytes.push(0xc3);
    bytes.resize(16, 0xcc);
    bytes.extend_from_slice(&(target as u32).to_le_bytes());
    bytes.resize(32, 0xcc);
    bytes.extend_from_slice(&[0x31, 0xc0, 0xc3]);
    let analysis = analyze_seeded_image(
        LoadedImage::from_shellcode(&bytes, Architecture::X86),
        RecoveryBackend::VivisectCompat,
        SeedMap::from([(SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint]))]),
        BTreeMap::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(analysis.functions.contains_key(&target));
    assert!(analysis.seeds[&target].contains(&SeedKind::CallTarget));
    assert!(analysis.function_order[&target] < analysis.function_order[&SHELLCODE_BASE]);
}

#[test]
fn forwarded_pe_exports_do_not_seed_functions() {
    let bytes = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/testfiles/kernel32.dll_"),
    )
    .unwrap();
    let image = LoadedImage::parse(&bytes).unwrap();
    let mut seeds = SeedMap::new();
    collect_pe_seeds(
        &bytes,
        &image,
        RecoveryBackend::VivisectCompat,
        &mut seeds,
        &mut FunctionSymbolMap::new(),
        &mut Vec::new(),
    )
    .unwrap();
    let pe = PE::parse(&bytes).unwrap();
    let forwarded: Vec<_> = pe.exports.iter().filter(|e| e.reexport.is_some()).collect();
    assert!(!forwarded.is_empty());
    for export in forwarded {
        assert!(!seeds.contains_key(&(image.image_base + export.rva as u64)));
    }
    assert!(seeds
        .values()
        .any(|kinds| kinds.contains(&SeedKind::Export)));
}

#[test]
fn relocated_instruction_operands_do_not_bypass_candidate_evaluation() {
    let target = SHELLCODE_BASE + 32;
    for source_is_code in [true, false] {
        let mut bytes = vec![0xb8];
        bytes.extend_from_slice(&(target as u32).to_le_bytes());
        bytes.push(0xc3);
        bytes.resize(16, 0xcc);
        bytes.extend_from_slice(&(target as u32).to_le_bytes());
        bytes.resize(32, 0xcc);
        bytes.extend_from_slice(&[0x55, 0x8b, 0xec, 0x0f, 0x0b]);
        let mut image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
        image.format = ImageFormat::Pe;
        image.relocation_locations = vec![SHELLCODE_BASE + if source_is_code { 1 } else { 16 }];
        let analysis = analyze_seeded_image(
            image,
            RecoveryBackend::VivisectCompat,
            SeedMap::from([
                (SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint])),
                (target, BTreeSet::from([SeedKind::Relocation])),
            ]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        // A data pointer may use isProbablyCode's signature shortcut.
        // A relocated immediate is a REF_PTR for emucode, which must
        // reject this trace before the later function-signature pass.
        assert_eq!(
            analysis.seeds[&target].contains(&SeedKind::PointerTarget),
            !source_is_code
        );
        assert!(!analysis.seeds[&target].contains(&SeedKind::Emulated));
    }
}

#[test]
fn pe_does_not_scan_arbitrary_data_as_function_pointers() {
    for format in [ImageFormat::Pe, ImageFormat::Elf] {
        let target = SHELLCODE_BASE + 32;
        let mut bytes = vec![0xc3];
        bytes.resize(16, 0xcc);
        bytes.extend_from_slice(&(target as u32).to_le_bytes());
        bytes.resize(32, 0xcc);
        bytes.extend_from_slice(&[0x31, 0xc0, 0x40, 0xc3]);
        let mut image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
        image.format = format;
        let analysis = analyze_seeded_image(
            image,
            RecoveryBackend::VivisectCompat,
            SeedMap::from([(SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint]))]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            analysis.functions.contains_key(&target),
            format == ImageFormat::Elf
        );
    }
}

#[test]
fn late_signatures_do_not_restart_the_emucode_pass() {
    let target = SHELLCODE_BASE + 64;
    let mut bytes = vec![0xc3];
    bytes.resize(16, 0xcc);
    bytes.extend_from_slice(&[0x55, 0x8b, 0xec, 0xb8]);
    bytes.extend_from_slice(&(target as u32).to_le_bytes());
    bytes.extend_from_slice(&[0xc9, 0xc3]);
    bytes.resize(64, 0xcc);
    bytes.extend_from_slice(&[0x31, 0xc0, 0x40, 0xc3]);
    let mut image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
    image.format = ImageFormat::Pe;
    let analysis = analyze_seeded_image(
        image,
        RecoveryBackend::VivisectCompat,
        SeedMap::from([(SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint]))]),
        BTreeMap::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(analysis.functions.contains_key(&(SHELLCODE_BASE + 16)));
    assert!(!analysis.functions.contains_key(&target));
}

#[test]
fn dereferenced_data_is_not_promoted_by_a_relocation() {
    let target = SHELLCODE_BASE + 16;
    let mut bytes = vec![0xa1]; // mov eax, [data]; ret
    bytes.extend_from_slice(&(target as u32).to_le_bytes());
    bytes.push(0xc3);
    bytes.resize(16, 0xcc);
    bytes.extend_from_slice(&[0x31, 0xc0, 0x40, 0xc3]);
    let image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
    let analysis = analyze_seeded_image(
        image,
        RecoveryBackend::VivisectCompat,
        SeedMap::from([
            (SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint])),
            (target, BTreeSet::from([SeedKind::Relocation])),
        ]),
        BTreeMap::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(!analysis.functions.contains_key(&target));
}

#[test]
fn later_noreturn_signatures_cannot_validate_an_earlier_candidate() {
    let target = SHELLCODE_BASE + 16;
    let mut bytes = vec![0xb8];
    bytes.extend_from_slice(&(target as u32).to_le_bytes());
    bytes.push(0xc3);
    bytes.resize(16, 0xcc);
    bytes.extend_from_slice(&[0xeb, 0x0e]); // jmp late signature
    bytes.resize(32, 0xcc);
    bytes.extend_from_slice(&[0x55, 0x8b, 0xec, 0x0f, 0x0b]);
    let image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
    let analysis = analyze_seeded_image(
        image,
        RecoveryBackend::VivisectCompat,
        SeedMap::from([(SHELLCODE_BASE, BTreeSet::from([SeedKind::EntryPoint]))]),
        BTreeMap::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(analysis.functions.contains_key(&(SHELLCODE_BASE + 32)));
    assert!(!analysis.functions.contains_key(&target));
}

/// A walk past `MAX_INSNS_PER_FUNCTION` abandons that walk and records
/// why; it does not fail the image. Upstream Vivisect has no per-walk
/// instruction budget at all, so this limit is a statement about
/// binfera's guard rail, and a guard rail that discards every result
/// the run already produced is worse than the runaway it prevents. This
/// is why mapping `0cd2b334`'s resource-hosted
/// code is the faithful loader behaviour, and it was revertible only
/// because the budget turned one long walk into a hard error.
#[test]
fn a_walk_past_the_instruction_budget_is_abandoned_not_fatal() {
    // Single-byte `nop`s so the walk is one straight line, one past the
    // budget, then `ret`.
    let mut bytes = vec![0x90u8; MAX_INSNS_PER_FUNCTION + 1];
    bytes.push(0xc3);

    let analysis = analyze_shellcode(&bytes, Architecture::X86)
        .expect("a runaway walk must not fail the image");

    let abandoned: Vec<&RecoveryDiagnostic> = analysis
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.message.contains("abandoned code walk"))
        .collect();
    assert_eq!(
        abandoned.len(),
        1,
        "expected exactly one abandoned-walk diagnostic, got {:?}",
        analysis.diagnostics
    );
    assert!(
        abandoned[0].message.contains("exceeds"),
        "the diagnostic must say what budget was exceeded: {}",
        abandoned[0].message
    );
    // The walk is abandoned, not the run: what it decoded before hitting
    // the budget is still there to extract features from.
    assert!(
        analysis.instructions.len() >= MAX_INSNS_PER_FUNCTION,
        "decoded instructions should be kept, got {}",
        analysis.instructions.len()
    );
}

#[test]
fn a_budgeted_walk_keeps_discovered_callees() {
    let mut bytes = vec![0x90; MAX_INSNS_PER_FUNCTION + 16];
    let target = bytes.len() - 1;
    bytes[0] = 0xe8;
    bytes[1..5].copy_from_slice(&((target - 5) as i32).to_le_bytes());
    bytes[target] = 0xc3;
    let analysis = analyze_shellcode(&bytes, Architecture::X86).unwrap();
    assert!(analysis
        .functions
        .contains_key(&(SHELLCODE_BASE + target as u64)));
    assert!(analysis
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("abandoned code walk")));
}

#[test]
fn later_overlapping_opcodes_replace_the_covered_location() {
    let mut analysis = analyze_noreturn_test_image(&[0xe9, 0, 0, 0, 0, 0xc3]);
    let interior = analysis.image.decode_at_compat(0x1002).unwrap();
    analysis.instructions.insert(0x1002, interior);
    analysis.instruction_order.insert(0x1002, 0);
    analysis.instruction_order.insert(0x1000, 1);
    assert_eq!(
        instruction_location(&analysis, 0x1002).unwrap().address,
        0x1000
    );
    assert_eq!(
        instruction_location(&analysis, 0x1004).unwrap().address,
        0x1000
    );
    assert_eq!(
        instruction_location(&analysis, 0x1005).unwrap().address,
        0x1005
    );
}

#[test]
fn compatibility_blocks_decode_inside_existing_instruction_locations() {
    let code = [
        0x68, 0x00, 0x64, 0xff, 0x30, // push immediate
        0x64, 0x89, 0x20, // fs: mov [eax],esp
        0x75, 0xf7, // jnz into the push's immediate
        0xc3, 0x90, 0x90, 0x90, 0x90,
    ];
    let analysis = analyze_seeded_image(
        noreturn_test_image(&code),
        RecoveryBackend::VivisectCompat,
        SeedMap::from([(0x1000, BTreeSet::from([SeedKind::EntryPoint]))]),
        BTreeMap::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(!analysis.instructions.contains_key(&0x1001));
    let block = analysis.functions[&0x1000]
        .blocks
        .iter()
        .find(|block| block.addr == 0x1001)
        .unwrap();
    assert_eq!(block.insns[0].x86_instruction().mnemonic(), Mnemonic::Add);
    assert_eq!(
        block.insns[0].x86_instruction().memory_displacement64(),
        0x30
    );
    assert!(block.insns.iter().any(|insn| insn.address == 0x1005));
}

#[test]
fn compatibility_codeflow_continues_through_string_io() {
    for backend in [RecoveryBackend::VivisectCompat, RecoveryBackend::Native] {
        let analysis = analyze_seeded_image(
            noreturn_test_image(&[0x6c, 0x31, 0xc0, 0xc3]),
            backend,
            SeedMap::from([(0x1000, BTreeSet::from([SeedKind::EntryPoint]))]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            analysis.instructions.contains_key(&0x1003),
            backend == RecoveryBackend::VivisectCompat
        );
    }
}

#[test]
fn compatibility_halt_ends_codeflow_before_later_bytes() {
    let analysis = analyze_seeded_image(
        noreturn_test_image(&[0xf4, 0x60, 0x61, 0xc3]),
        RecoveryBackend::VivisectCompat,
        SeedMap::from([(0x1000, BTreeSet::from([SeedKind::EntryPoint]))]),
        BTreeMap::new(),
        Vec::new(),
    )
    .unwrap();
    assert_eq!(analysis.instructions[&0x1000].flow, Flow::Terminal);
    assert!(!analysis.instructions.contains_key(&0x1001));
    assert_eq!(analysis.functions[&0x1000].blocks[0].insns.len(), 1);
}

#[test]
fn compatibility_unwind_entries_preserve_fallthrough_and_shared_tails() {
    for (code, expected) in [
        (
            vec![0x90, 0x90, 0x90, 0xc3],
            BTreeSet::from([0x1000, 0x1001, 0x1002, 0x1003]),
        ),
        (
            vec![0xeb, 0x00, 0x90, 0xc3],
            BTreeSet::from([0x1000, 0x1002, 0x1003]),
        ),
    ] {
        let analysis = analyze_seeded_image(
            noreturn_test_image(&code),
            RecoveryBackend::VivisectCompat,
            SeedMap::from([
                (0x1000, BTreeSet::from([SeedKind::Unwind])),
                (0x1002, BTreeSet::from([SeedKind::Unwind])),
            ]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            function_instruction_addrs(&analysis.functions[&0x1000]),
            expected
        );
        assert!(!analysis.is_noreturn_va(0x1000));
        assert_eq!(
            function_instruction_addrs(&analysis.functions[&0x1002]),
            BTreeSet::from([0x1002, 0x1003])
        );
    }
}

#[test]
fn plain_memory_jumps_do_not_absorb_adjacent_pointer_targets() {
    for (opcode, expected_offsets) in [
        (vec![0xff, 0x25], vec![]),
        (vec![0xff, 0x24, 0x85], vec![0x20, 0x21]),
    ] {
        let mut bytes = opcode;
        bytes.extend_from_slice(&((SHELLCODE_BASE + 0x10) as u32).to_le_bytes());
        bytes.resize(0x10, 0xcc);
        bytes.extend_from_slice(&((SHELLCODE_BASE + 0x20) as u32).to_le_bytes());
        bytes.extend_from_slice(&((SHELLCODE_BASE + 0x21) as u32).to_le_bytes());
        bytes.resize(0x20, 0xcc);
        bytes.extend_from_slice(&[0xc3, 0xc3]);
        let analysis = analyze_shellcode(&bytes, Architecture::X86).unwrap();
        let mut expected = BTreeSet::from([SHELLCODE_BASE]);
        expected.extend(
            expected_offsets
                .into_iter()
                .map(|offset| SHELLCODE_BASE + offset),
        );
        assert_eq!(
            function_instruction_addrs(&analysis.functions[&SHELLCODE_BASE]),
            expected
        );
        assert!(analysis.instructions.contains_key(&(SHELLCODE_BASE + 0x20)));
        assert_eq!(
            analysis.instructions.contains_key(&(SHELLCODE_BASE + 0x21)),
            analysis.instructions[&SHELLCODE_BASE]
                .x86_instruction()
                .memory_index()
                != iced_x86::Register::None
        );
        assert!(!analysis.is_noreturn_va(SHELLCODE_BASE));
    }
}

#[test]
fn unresolved_pointer_jump_keeps_a_diagnostic() {
    let analysis = analyze_noreturn_test_image(&[0xff, 0x25, 0x00, 0x30, 0x00, 0x00]);
    assert!(!analysis.is_noreturn_va(0x1000));
    assert!(analysis.diagnostics.iter().any(|diagnostic| {
        diagnostic.address == 0x1000 && diagnostic.message == "unresolved indirect branch"
    }));
}

#[test]
fn safe_seh_table_entries_become_authoritative_seeds() {
    let image_base = 0x1000;
    let table = 0x2000;
    let code = 0x1100;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x100u32.to_le_bytes());
    bytes.extend_from_slice(&0x101u32.to_le_bytes());
    bytes.extend_from_slice(&[0xc3, 0xc3]);
    let image = LoadedImage::for_test(
        ImageFormat::Pe,
        Architecture::X86,
        image_base,
        vec![
            MappedSection {
                name: ".sxdata".to_string(),
                address: table,
                virtual_size: 8,
                file_offset: 0,
                file_size: 8,
                permissions: Permissions {
                    read: true,
                    write: false,
                    execute: false,
                },
            },
            MappedSection {
                name: ".text".to_string(),
                address: code,
                virtual_size: 2,
                file_offset: 8,
                file_size: 2,
                permissions: Permissions {
                    read: true,
                    write: false,
                    execute: true,
                },
            },
        ],
        BTreeMap::new(),
        bytes,
    );
    let mut seeds = SeedMap::new();
    let mut diagnostics = Vec::new();

    collect_safe_seh_seeds(64, &image, table, 2, &mut seeds, &mut diagnostics);

    assert!(diagnostics.is_empty());
    assert_eq!(seeds.get(&code), Some(&BTreeSet::from([SeedKind::SafeSeh])));
    assert_eq!(
        seeds.get(&code.saturating_add(1)),
        Some(&BTreeSet::from([SeedKind::SafeSeh]))
    );
}

#[test]
fn compat_uses_only_pinned_x86_function_signatures() {
    let x86 = [0xc3, 0x55, 0x8b, 0xec, 0xc3];
    let x86_image = LoadedImage::from_shellcode(&x86, Architecture::X86);
    let x86_analysis = analyze_image(&x86, x86_image, RecoveryBackend::VivisectCompat)
        .expect("compatibility recovery succeeds");
    assert_eq!(
        x86_analysis.seeds.get(&SHELLCODE_BASE.saturating_add(1)),
        Some(&BTreeSet::from([SeedKind::FunctionSignature]))
    );

    let x64 = [0xc3, 0x40, 0x53, 0x48, 0x83, 0xec, 0x20, 0xc3];
    let x64_image = LoadedImage::from_shellcode(&x64, Architecture::X64);
    let x64_analysis = analyze_image(&x64, x64_image, RecoveryBackend::VivisectCompat)
        .expect("compatibility recovery succeeds");
    assert!(!x64_analysis
        .seeds
        .contains_key(&SHELLCODE_BASE.saturating_add(1)));
}

#[test]
fn raw_call_sweep_is_only_a_native_fallback() {
    let bytes = [
        0xc3, 0xe8, 0x04, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x53, 0xc3,
    ];
    let target = 0x1000u64.saturating_add(10);
    let image = LoadedImage::for_test(
        ImageFormat::Pe,
        Architecture::X86,
        0x1000,
        vec![MappedSection {
            name: ".text".to_string(),
            address: 0x1000,
            virtual_size: bytes.len() as u64,
            file_offset: 0,
            file_size: bytes.len() as u64,
            permissions: Permissions {
                read: true,
                write: false,
                execute: true,
            },
        }],
        BTreeMap::new(),
        bytes.to_vec(),
    );
    let mut compat = SeedMap::new();
    add_backend_fallback_seeds(&image, RecoveryBackend::VivisectCompat, &mut compat);
    assert!(!compat
        .get(&target)
        .is_some_and(|kinds| kinds.contains(&SeedKind::SweepCallTarget)));

    let mut native = SeedMap::new();
    add_backend_fallback_seeds(&image, RecoveryBackend::Native, &mut native);
    assert!(native
        .get(&target)
        .is_some_and(|kinds| kinds.contains(&SeedKind::SweepCallTarget)));
}

#[test]
fn msvc_cookie_reference_block_becomes_its_own_function() {
    // `vivisect/analysis/ms/msvcfunc.py`: a `/GS` cookie check is
    // byte-signature-matched, and every code block whose `mov`
    // references that cookie becomes a function.
    //
    //   0x401000: call 0x401010          (the cookie check)
    //   0x401005: jmp  0x401020          (into the cookie-restoring tail)
    //   0x401010: cmp ecx, [0x403000]    \
    //   0x401016: jne 0x40101a            | signature row 1, 32-bit
    //   0x401018: rep ret                 | VS 2005..2013
    //   0x40101a: jmp 0x40101f           /
    //   0x40101f: ret
    //   0x401020: mov eax, [0x403000]    <- the split point
    //   0x401025: ret
    let base = 0x401000u64;
    let bytes = vec![
        0xe8, 0x0b, 0x00, 0x00, 0x00, // call 0x401010
        0xeb, 0x19, // jmp 0x401020
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // padding
        0x3b, 0x0d, 0x00, 0x30, 0x40, 0x00, // cmp ecx, [0x403000]
        0x75, 0x02, // jne 0x40101a
        0xf3, 0xc3, // rep ret
        0xe9, 0x00, 0x00, 0x00, 0x00, // jmp 0x40101f
        0xc3, // ret
        0xa1, 0x00, 0x30, 0x40, 0x00, // mov eax, [0x403000]
        0xc3, // ret
    ];
    let image = LoadedImage::for_test(
        ImageFormat::Pe,
        Architecture::X86,
        base,
        vec![MappedSection {
            name: ".text".to_string(),
            address: base,
            virtual_size: bytes.len() as u64,
            file_offset: 0,
            file_size: bytes.len() as u64,
            permissions: Permissions {
                read: true,
                write: false,
                execute: true,
            },
        }],
        BTreeMap::new(),
        bytes.clone(),
    );
    let analysis = analyze_seeded_image(
        image,
        RecoveryBackend::VivisectCompat,
        SeedMap::from([(base, BTreeSet::from([SeedKind::EntryPoint]))]),
        FunctionSymbolMap::new(),
        Vec::new(),
    )
    .expect("synthetic recovery succeeds");

    let split = base.saturating_add(0x20);
    assert_eq!(
        analysis.seeds.get(&split),
        Some(&BTreeSet::from([SeedKind::MsvcCookieBlock]))
    );
    assert!(analysis.functions.contains_key(&split));
    // the enclosing function still flows through it, as in vivisect --
    // this splits ownership, it does not cut the edge.
    let entry = analysis
        .functions
        .get(&base)
        .expect("entry function recovered");
    assert!(function_instruction_addrs(entry).contains(&split));
}

#[test]
fn msvc_cookie_wave_ignores_a_non_mov_reference() {
    // Same shape, but the tail reads the cookie with `cmp`, which
    // `msvcfunc.py`'s `op.mnem == 'mov'` rejects.
    let base = 0x401000u64;
    let bytes = vec![
        0xe8, 0x0b, 0x00, 0x00, 0x00, //
        0xeb, 0x19, //
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, //
        0x3b, 0x0d, 0x00, 0x30, 0x40, 0x00, //
        0x75, 0x02, //
        0xf3, 0xc3, //
        0xe9, 0x00, 0x00, 0x00, 0x00, //
        0xc3, //
        0x3b, 0x05, 0x00, 0x30, 0x40, 0x00, // cmp eax, [0x403000]
        0xc3, //
    ];
    let image = LoadedImage::for_test(
        ImageFormat::Pe,
        Architecture::X86,
        base,
        vec![MappedSection {
            name: ".text".to_string(),
            address: base,
            virtual_size: bytes.len() as u64,
            file_offset: 0,
            file_size: bytes.len() as u64,
            permissions: Permissions {
                read: true,
                write: false,
                execute: true,
            },
        }],
        BTreeMap::new(),
        bytes.clone(),
    );
    let analysis = analyze_seeded_image(
        image,
        RecoveryBackend::VivisectCompat,
        SeedMap::from([(base, BTreeSet::from([SeedKind::EntryPoint]))]),
        FunctionSymbolMap::new(),
        Vec::new(),
    )
    .expect("synthetic recovery succeeds");
    assert!(!analysis.functions.contains_key(&base.saturating_add(0x20)));
}

#[test]
fn direct_call_target_inside_recovered_region_gets_function_scope() {
    // call base+0xa; five nops; ret. The entry-point walk reaches and
    // owns base+0xa before the discovered call target is processed.
    let bytes = [
        0xe8, 0x05, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3,
    ];
    let analysis = analyze_shellcode(&bytes, Architecture::X86)
        .expect("synthetic shellcode recovery succeeds");

    assert!(analysis.functions.contains_key(&SHELLCODE_BASE));
    assert!(analysis
        .functions
        .contains_key(&SHELLCODE_BASE.saturating_add(0xa)));
}

#[test]
fn call_plus_five_does_not_create_function_candidate() {
    // Pinned Vivisect's `envi/codeflow.py` explicitly excludes a
    // procedural target equal to the next instruction. The xref remains
    // visible so capa can still extract `characteristic: call $+5`.
    let bytes = [0xe8, 0x00, 0x00, 0x00, 0x00, 0x58, 0xc3];
    let analysis = analyze_shellcode(&bytes, Architecture::X86)
        .expect("synthetic shellcode recovery succeeds");

    let next = SHELLCODE_BASE.saturating_add(0x5);
    assert!(!analysis.seeds.contains_key(&next));
    assert!(!analysis.functions.contains_key(&next));
    assert_eq!(analysis.code_xrefs.get(&next), Some(&vec![SHELLCODE_BASE]));
    assert!(function_instruction_addrs(
        analysis
            .functions
            .get(&SHELLCODE_BASE)
            .expect("entry function recovered")
    )
    .contains(&next));
}

#[test]
fn overlapping_call_targets_get_distinct_shared_graph_views() {
    // Both calls target instructions that entry-point discovery reaches
    // first by fallthrough. Each target must still become a function view
    // over the shared direct-flow graph, without cloning blocks from an
    // already-materialized function.
    //   base+0x0: e8 06 00 00 00  call base+0xb
    //   base+0x5: e8 03 00 00 00  call base+0xd
    //   base+0xa: 90              nop
    //   base+0xb: 90 90           nop; nop
    //   base+0xd: c3              ret
    let bytes = [
        0xe8, 0x06, 0x00, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0xc3,
    ];
    let analysis = analyze_shellcode(&bytes, Architecture::X86)
        .expect("synthetic shellcode recovery succeeds");

    let first_target = SHELLCODE_BASE.saturating_add(0xb);
    let second_target = SHELLCODE_BASE.saturating_add(0xd);
    let entry_addrs = function_instruction_addrs(
        analysis
            .functions
            .get(&SHELLCODE_BASE)
            .expect("entry function recovered"),
    );
    let first_addrs = function_instruction_addrs(
        analysis
            .functions
            .get(&first_target)
            .expect("first overlapping target recovered"),
    );
    let second_addrs = function_instruction_addrs(
        analysis
            .functions
            .get(&second_target)
            .expect("second overlapping target recovered"),
    );

    assert!(entry_addrs.contains(&first_target));
    assert!(entry_addrs.contains(&second_target));
    assert_eq!(
        first_addrs,
        BTreeSet::from([first_target, first_target.saturating_add(1), second_target])
    );
    assert_eq!(second_addrs, BTreeSet::from([second_target]));
}

fn function_instruction_addrs(function: &Function) -> BTreeSet<u64> {
    function
        .blocks
        .iter()
        .flat_map(|block| block.insns.iter().map(|insn| insn.address))
        .collect()
}

#[test]
fn direct_jump_to_call_seeded_target_stays_in_flowing_function() {
    // Phase 2.1: `call base+0xb` (seeds base+0xb as a call target), then
    // `jmp base+0xb`. A seed at the jump target must NOT split the function
    // -- the flowing function keeps flowing through the jump. Pre-2.1 the
    // seed made this a TailCall that ended the entry function short.
    //   base+0x0: e8 06 00 00 00  call base+0xb
    //   base+0x5: eb 04           jmp  base+0xb
    //   base+0x7: 90 90 90 90     nop x4
    //   base+0xb: c3              ret
    let bytes = [
        0xe8, 0x06, 0x00, 0x00, 0x00, 0xeb, 0x04, 0x90, 0x90, 0x90, 0x90, 0xc3,
    ];
    let analysis = analyze_shellcode(&bytes, Architecture::X86)
        .expect("synthetic shellcode recovery succeeds");

    let target = SHELLCODE_BASE.saturating_add(0xb);
    let entry = analysis
        .functions
        .get(&SHELLCODE_BASE)
        .expect("entry function recovered");
    // The jump followed into the seeded target: it belongs to the caller.
    assert!(function_instruction_addrs(entry).contains(&target));
    // ...and the call target still gets its own (overlapping) function.
    assert!(analysis.functions.contains_key(&target));
}

#[test]
fn direct_jump_to_prologue_seeded_target_stays_in_flowing_function() {
    // Phase 2.1: `jmp` to a `push ebp; mov ebp, esp` prologue pattern. The
    // prologue scan seeds that address, but a seed is not proof of a tail
    // call -- the caller must still flow through it.
    //   base+0x0: eb 03        jmp base+0x5
    //   base+0x2: 90 90 90     nop x3
    //   base+0x5: 55           push ebp
    //   base+0x6: 8b ec        mov ebp, esp
    //   base+0x8: c3           ret
    let bytes = [0xeb, 0x03, 0x90, 0x90, 0x90, 0x55, 0x8b, 0xec, 0xc3];
    let analysis = analyze_shellcode(&bytes, Architecture::X86)
        .expect("synthetic shellcode recovery succeeds");

    let target = SHELLCODE_BASE.saturating_add(0x5);
    let entry = analysis
        .functions
        .get(&SHELLCODE_BASE)
        .expect("entry function recovered");
    assert!(function_instruction_addrs(entry).contains(&target));
}

#[test]
fn called_signature_seed_is_walked_before_lower_signature_seeds() {
    // An MSVC hot-patch thunk in miniature: the entry calls the *higher*
    // of two `mov edi, edi; push ebp; mov ebp, esp` prologue hits, and
    // that one jumps down into the *lower* one. Both are signature seeds,
    // so the initial priority sort would walk the lower (body) one first
    // and give it a function of its own -- which vivisect never does,
    // because codeflow from the call has already claimed those bytes by
    // the time `generic/funcentries.py` scans for prologues.
    //   base+0x00: e8 08 00 00 00  call base+0xd
    //   base+0x05: c3              ret
    //   base+0x06: 8b ff           mov edi, edi   <- body
    //   base+0x08: 55              push ebp
    //   base+0x09: 8b ec           mov ebp, esp
    //   base+0x0b: 5d              pop ebp
    //   base+0x0c: c3              ret
    //   base+0x0d: 8b ff           mov edi, edi   <- thunk
    //   base+0x0f: 55              push ebp
    //   base+0x10: 8b ec           mov ebp, esp
    //   base+0x12: 5d              pop ebp
    //   base+0x13: e9 ee ff ff ff  jmp base+0x6
    let bytes = [
        0xe8, 0x08, 0x00, 0x00, 0x00, 0xc3, 0x8b, 0xff, 0x55, 0x8b, 0xec, 0x5d, 0xc3, 0x8b, 0xff,
        0x55, 0x8b, 0xec, 0x5d, 0xe9, 0xee, 0xff, 0xff, 0xff,
    ];
    let analysis = analyze_shellcode(&bytes, Architecture::X86)
        .expect("synthetic shellcode recovery succeeds");

    let body = SHELLCODE_BASE.saturating_add(0x6);
    let thunk = SHELLCODE_BASE.saturating_add(0xd);
    let thunk_view = analysis
        .functions
        .get(&thunk)
        .expect("the called thunk is a function");
    assert!(function_instruction_addrs(thunk_view).contains(&body));
    assert!(
        !analysis.functions.contains_key(&body),
        "the jump target is the thunk's body, not a function of its own"
    );
}

#[test]
fn call_target_view_can_flow_into_authoritative_entry() {
    // The entry calls base+6 and returns. The callee jumps back to the
    // authoritative entry. Discovery must record that jump before function
    // ownership is constructed, so the callee view can include the entry.
    //   base+0x0: e8 01 00 00 00  call base+0x6
    //   base+0x5: c3              ret
    //   base+0x6: eb f8           jmp base+0x0
    let bytes = [0xe8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0xeb, 0xf8];
    let analysis = analyze_shellcode(&bytes, Architecture::X86)
        .expect("synthetic shellcode recovery succeeds");

    let callee_address = SHELLCODE_BASE.saturating_add(0x6);
    let callee = analysis
        .functions
        .get(&callee_address)
        .expect("call target function recovered");
    let owned = function_instruction_addrs(callee);
    assert!(owned.contains(&callee_address));
    assert!(owned.contains(&SHELLCODE_BASE));
    assert!(owned.contains(&SHELLCODE_BASE.saturating_add(0x5)));
}

#[test]
fn overlapping_relocation_candidate_stays_isolated() {
    let address = SHELLCODE_BASE.saturating_add(0x10);
    let mut seeds = SeedMap::new();
    seeds
        .entry(address)
        .or_default()
        .insert(SeedKind::Relocation);
    let mut fallback = SeedMap::new();

    assert!(should_isolate_overlapping_candidate(
        &fallback, &seeds, address, true
    ));
    assert!(!should_isolate_overlapping_candidate(
        &fallback, &seeds, address, false
    ));

    seeds
        .entry(address)
        .or_default()
        .insert(SeedKind::CallTarget);
    assert!(!should_isolate_overlapping_candidate(
        &fallback, &seeds, address, true
    ));
    if let Some(kinds) = seeds.get_mut(&address) {
        kinds.remove(&SeedKind::CallTarget);
    }

    seeds.entry(address).or_default().insert(SeedKind::Export);
    assert!(!should_isolate_overlapping_candidate(
        &fallback, &seeds, address, true
    ));

    if let Some(kinds) = seeds.get_mut(&address) {
        kinds.remove(&SeedKind::Export);
    }
    fallback
        .entry(address)
        .or_default()
        .insert(SeedKind::Prologue);
    assert!(!should_isolate_overlapping_candidate(
        &fallback, &seeds, address, true
    ));
}

/// A hand-built x86 PE-shaped image: `.text` at `TEXT_BASE`, plus a
/// non-executable one-slot import table at `IAT` bound to
/// `kernel32.ExitProcess` -- one of the literal no-return APIs the pinned
/// PE loader registers (`vivisect/parsers/pe.py:417`).
fn noreturn_test_image(code: &[u8]) -> LoadedImage {
    const TEXT_BASE: u64 = 0x1000;
    const IAT: u64 = 0x2000;
    let mut bytes = code.to_vec();
    let iat_offset = bytes.len() as u64;
    // An unbound IAT slot: not an executable address, so an indirect
    // branch through it stays unresolved, exactly as in a real unloaded PE.
    bytes.extend_from_slice(&0u32.to_le_bytes());
    LoadedImage::for_test(
        ImageFormat::Pe,
        Architecture::X86,
        TEXT_BASE,
        vec![
            MappedSection {
                name: ".text".to_string(),
                address: TEXT_BASE,
                virtual_size: code.len() as u64,
                file_offset: 0,
                file_size: code.len() as u64,
                permissions: Permissions {
                    read: true,
                    write: false,
                    execute: true,
                },
            },
            MappedSection {
                name: ".idata".to_string(),
                address: IAT,
                virtual_size: 4,
                file_offset: iat_offset,
                file_size: 4,
                permissions: Permissions {
                    read: true,
                    write: false,
                    execute: false,
                },
            },
        ],
        BTreeMap::new(),
        bytes,
    )
    .with_import_location(IAT, "kernel32.ExitProcess")
}

/// Run the full no-return fixpoint over a hand-built image, seeding only
/// its entry point (a synthetic image has no parseable PE directories for
/// [`collect_seeds`] to walk).
fn analyze_noreturn_test_image(code: &[u8]) -> Analysis {
    let image = noreturn_test_image(code);
    let mut seeds = SeedMap::new();
    if let Some(entry) = image.entry_point {
        add_seed(&image, &mut seeds, entry, SeedKind::EntryPoint);
    }
    analyze_seeded_image(
        image,
        RecoveryBackend::VivisectCompat,
        seeds,
        BTreeMap::new(),
        Vec::new(),
    )
    .expect("synthetic no-return recovery succeeds")
}

#[test]
fn terminated_text_is_not_a_swept_entry() {
    assert!(terminated_text(b"http://example\0"));
    assert!(terminated_text(b"h\0t\0t\0p\0\0\0"));
    // Short runs and unterminated bytes stay candidates: code often starts printable.
    assert!(!terminated_text(b"UVW\0"));
    assert!(!terminated_text(b"\x55\x8b\xec\x83\xec\x10"));
    assert!(!terminated_text(b"VWPQ\x8b"));
    assert!(!terminated_text(b"VWSj\0"));
}

#[test]
fn native_sweeps_unclaimed_i686_entries_after_existing_flow() {
    let mut bytes = vec![0xc3];
    bytes.resize(16, 0xcc);
    bytes.extend_from_slice(&[0x0f, 0xb6, 0x01, 0xc3]);
    bytes.resize(32, 0xcc);
    bytes.extend_from_slice(&[0; 16]);
    let mut image = LoadedImage::from_shellcode_at(&bytes, Architecture::X86, 0x1000);
    image.format = ImageFormat::Pe;
    let analysis = analyze_seeded_image(
        image,
        RecoveryBackend::Native,
        SeedMap::from([(0x1000, BTreeSet::from([SeedKind::EntryPoint]))]),
        BTreeMap::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(analysis.functions.contains_key(&0x1000));
    assert!(analysis.functions.contains_key(&0x1010));
    assert!(analysis.seeds[&0x1010].contains(&SeedKind::Unclaimed));
    assert!(!analysis.functions.contains_key(&0x1020));
}

/// Native recovery of a hand-built x64 PE: `.text` at 0x1000 (also the
/// image base and entry), `.rdata` at 0x2000 and `.pdata` at 0x3000.
fn native_x64(text: &[u8], rdata: &[u8], pdata: &[u8]) -> Analysis {
    let section =
        |name: &str, address: u64, offset: usize, data: &[u8], execute: bool| MappedSection {
            name: name.to_string(),
            address,
            virtual_size: data.len() as u64,
            file_offset: offset as u64,
            file_size: data.len() as u64,
            permissions: Permissions {
                read: true,
                write: false,
                execute,
            },
        };
    let mut bytes = text.to_vec();
    let rdata_offset = bytes.len();
    bytes.extend_from_slice(rdata);
    let pdata_offset = bytes.len();
    bytes.extend_from_slice(pdata);
    let image = LoadedImage::for_test(
        ImageFormat::Pe,
        Architecture::X64,
        0x1000,
        vec![
            section(".text", 0x1000, 0, text, true),
            section(".rdata", 0x2000, rdata_offset, rdata, false),
            section(".pdata", 0x3000, pdata_offset, pdata, false),
        ],
        BTreeMap::new(),
        bytes,
    );
    analyze_seeded_image(
        image,
        RecoveryBackend::Native,
        SeedMap::from([(0x1000, BTreeSet::from([SeedKind::EntryPoint]))]),
        BTreeMap::new(),
        Vec::new(),
    )
    .expect("synthetic native recovery succeeds")
}

/// Entry `ret`, int3 padding, then `0x1010: xor eax, eax; ret`.
fn entry_then_leaf() -> Vec<u8> {
    let mut text = vec![0xc3];
    text.resize(0x10, 0xcc);
    text.extend_from_slice(&[0x33, 0xc0, 0xc3]);
    text
}

#[test]
fn native_admits_data_named_code_that_follows_a_function_end() {
    // A leaf funclet has no unwind entry; only an image-relative value in
    // `.rdata` names it.
    let rva = (0x1010u32 - 0x1000).to_le_bytes();
    let analysis = native_x64(&entry_then_leaf(), &rva, &[]);
    assert!(analysis.functions.contains_key(&0x1010));
    // With unwind data for the first function, nothing names the leaf.
    let mut entry = Vec::new();
    for value in [0u32, 1, 0x4000] {
        entry.extend_from_slice(&value.to_le_bytes());
    }
    let unnamed = native_x64(&entry_then_leaf(), &[], &entry);
    assert!(!unnamed.functions.contains_key(&0x1010));
    // Without any (a UEFI driver), the late sweep finds it after the padding.
    let unwindless = native_x64(&entry_then_leaf(), &[], &[]);
    assert!(unwindless.functions.contains_key(&0x1010));
}

#[test]
fn native_admits_rip_relative_callback_after_function_end() {
    // lea rcx, [rip+9]; ret; padding; xor eax, eax; ret
    let mut text = vec![0x48, 0x8d, 0x0d, 9, 0, 0, 0, 0xc3];
    text.resize(0x10, 0xcc);
    text.extend_from_slice(&[0x33, 0xc0, 0xc3]);
    let analysis = native_x64(&text, &[], &[]);
    assert!(analysis.functions.contains_key(&0x1010));
}

#[test]
fn native_rejects_rip_relative_address_inside_unwind_extent() {
    let mut text = vec![0x48, 0x8d, 0x0d, 9, 0, 0, 0, 0xc3];
    text.resize(0x10, 0xcc);
    text.extend_from_slice(&[0x33, 0xc0, 0xc3]);
    let mut entry = Vec::new();
    for value in [0u32, 0x13, 0x4000] {
        entry.extend_from_slice(&value.to_le_bytes());
    }
    let analysis = native_x64(&text, &[], &entry);
    assert!(!analysis.functions.contains_key(&0x1010));
}

#[test]
fn native_rejects_data_named_code_inside_a_block() {
    // `0x1001` is the second instruction of straight-line code, not a
    // function start, even though a table names it.
    let text = [0xb8, 1, 0, 0, 0, 0xb9, 2, 0, 0, 0, 0xc3];
    let rva = (0x1005u32 - 0x1000).to_le_bytes();
    let analysis = native_x64(&text, &rva, &[]);
    assert!(!analysis.functions.contains_key(&0x1005));
}

#[test]
fn native_rejects_data_named_code_inside_an_unwind_extent() {
    // A catch continuation or switch arm lies inside its function's
    // `.pdata` extent even when it follows a `ret`.
    let rva = (0x1010u32 - 0x1000).to_le_bytes();
    let mut entry = Vec::new();
    for value in [0u32, 0x13, 0x4000] {
        entry.extend_from_slice(&value.to_le_bytes());
    }
    let analysis = native_x64(&entry_then_leaf(), &rva, &entry);
    assert!(!analysis.functions.contains_key(&0x1010));
}

#[test]
fn native_never_admits_padding_named_by_data() {
    let rva = (0x1008u32 - 0x1000).to_le_bytes();
    let analysis = native_x64(&entry_then_leaf(), &rva, &[]);
    assert!(!analysis.functions.contains_key(&0x1008));
}

#[test]
fn native_tail_jump_to_code_after_padding_starts_a_function() {
    // 0x1000: jmp 0x1010; int3 padding; 0x1010: xor eax, eax; ret.
    let mut text = vec![0xe9, 0x0b, 0, 0, 0];
    text.resize(0x10, 0xcc);
    text.extend_from_slice(&[0x33, 0xc0, 0xc3]);
    let analysis = native_x64(&text, &[], &[]);
    assert!(analysis.functions.contains_key(&0x1010));
    // The compatibility backend keeps Vivisect's layout and folds it in.
    let image = native_x64(&text, &[], &[]).image;
    let compat = analyze_seeded_image(
        image,
        RecoveryBackend::VivisectCompat,
        SeedMap::from([(0x1000, BTreeSet::from([SeedKind::EntryPoint]))]),
        BTreeMap::new(),
        Vec::new(),
    )
    .expect("compat recovery succeeds");
    assert!(!compat.functions.contains_key(&0x1010));
}

#[test]
fn native_jump_to_the_middle_of_a_function_is_not_a_tail_call() {
    // 0x1000: cmp eax, 0; jne 0x1008; mov eax, 1 ... a loop back-edge or
    // forward branch target follows a non-terminating instruction.
    let text = [
        0x83, 0xf8, 0x00, // cmp eax, 0
        0xeb, 0x03, // jmp 0x1008
        0x90, 0x90, 0x90, // nop padding inside the function
        0x33, 0xc0, // 0x1008: xor eax, eax
        0xc3,
    ];
    let analysis = native_x64(&text, &[], &[]);
    assert!(!analysis.functions.contains_key(&0x1008));
}

/// `0x1010: jmp [0x2000]` -- a one-instruction import thunk, preceded by
/// `code` and padded out so the thunk always lands at `0x1010`.
fn thunk_at_0x1010(code: &[u8]) -> Vec<u8> {
    let mut bytes = code.to_vec();
    bytes.resize(0x10, 0xcc);
    bytes.extend_from_slice(&[0xff, 0x25, 0x00, 0x20, 0x00, 0x00]);
    bytes
}

#[test]
fn elf_plt_loose_code_finishes_callees_before_image_entry() {
    let mut bytes = vec![0xc3];
    bytes.resize(0x20, 0xcc);
    bytes.extend_from_slice(&[0xe8, 0x1b, 0, 0, 0, 0xc3]);
    bytes.resize(0x40, 0xcc);
    bytes.push(0xc3);
    let mut image = noreturn_test_image(&bytes);
    image.format = ImageFormat::Elf;
    image.elf_plt_ranges.push((0x1020, 0x1026));
    let analysis = analyze_seeded_image(
        image,
        RecoveryBackend::VivisectCompat,
        SeedMap::from([(0x1000, BTreeSet::from([SeedKind::EntryPoint]))]),
        BTreeMap::new(),
        Vec::new(),
    )
    .unwrap();
    assert!(analysis.function_order[&0x1040] < analysis.function_order[&0x1000]);
    assert!(!analysis.functions.contains_key(&0x1020));
}

#[test]
fn cet_plt_thunks_propagate_no_return_only_in_plt_sections() {
    for in_plt in [false, true] {
        let mut code = vec![0xe8, 0x0b, 0, 0, 0, 0x90, 0xc3];
        code.resize(0x10, 0xcc);
        code.extend_from_slice(&[0xf3, 0x0f, 0x1e, 0xfb, 0xff, 0x25, 0, 0x20, 0, 0]);
        let mut image =
            noreturn_test_image(&code).with_import_location(0x2000, "*.__stack_chk_fail");
        image.format = ImageFormat::Elf;
        if in_plt {
            image.elf_plt_ranges.push((0x1010, 0x1020));
        }
        let analysis = analyze_seeded_image(
            image,
            RecoveryBackend::VivisectCompat,
            SeedMap::from([(0x1000, BTreeSet::from([SeedKind::EntryPoint]))]),
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(analysis.is_noreturn_va(0x1010), in_plt);
        assert_eq!(analysis.noreturn_calls.contains(&0x1000), in_plt);
    }
}

#[test]
fn call_through_a_noreturn_import_keeps_its_fallthrough() {
    // Vivisect does *not* stop here, even though the IAT slot is a
    // registered no-return VA: `_cb_opcode` (`vivisect/base.py:820`) drops
    // branches to `LOC_IMPORT` targets before codeflow's `BR_DEREF`
    // no-return check can see them. Verified on `Practical Malware
    // Analysis Lab 17-02.dll_`, where all ten `call [no-return import]`
    // sites keep their fallthrough.
    //   0x1000: ff 15 00 20 00 00   call [0x2000]   ; kernel32.ExitProcess
    //   0x1006: 90                  nop
    //   0x1007: c3                  ret
    let analysis = analyze_noreturn_test_image(&[0xff, 0x15, 0x00, 0x20, 0x00, 0x00, 0x90, 0xc3]);

    assert!(analysis.noreturn.contains(&0x2000));
    assert!(analysis.noreturn_calls.is_empty());
    let entry = analysis
        .functions
        .get(&0x1000)
        .expect("entry function recovered");
    assert_eq!(
        function_instruction_addrs(entry),
        BTreeSet::from([0x1000, 0x1006, 0x1007])
    );
}

#[test]
fn noreturn_status_propagates_through_an_import_thunk() {
    //   0x1000: e8 0b 00 00 00      call 0x1010
    //   0x1005: 90                  nop             ; unreachable
    //   0x1006: c3                  ret             ; unreachable
    //   0x1010: ff 25 00 20 00 00   jmp [0x2000]    ; ExitProcess thunk
    let analysis =
        analyze_noreturn_test_image(&thunk_at_0x1010(&[0xe8, 0x0b, 0, 0, 0, 0x90, 0xc3]));

    // The thunk inherits the import's no-return status
    // (`VivWorkspace.checkNoRetApi`), which then truncates its caller --
    // reached only by re-running discovery with the enlarged set.
    assert!(analysis.noreturn.contains(&0x1010));
    assert!(analysis.noreturn_calls.contains(&0x1000));
    // addEntryPoint completes even a known no-return callee before the
    // caller's fallthrough is suppressed on subsequent recovery sweeps.
    assert!(analysis.function_order[&0x1010] < analysis.function_order[&0x1000]);
    let entry = analysis
        .functions
        .get(&0x1000)
        .expect("entry function recovered");
    assert_eq!(function_instruction_addrs(entry), BTreeSet::from([0x1000]));
    // The bytes after the call were never even decoded.
    assert!(!analysis.instructions.contains_key(&0x1005));
    // ...and a function whose only leaf ends in a no-return call is itself
    // no-return (`vivisect/analysis/generic/noret.py`).
    assert!(analysis.is_noreturn_va(0x1000));
}

#[test]
fn noreturn_call_mid_function_keeps_the_rest_of_the_function() {
    // The no-return call is *not* the last instruction: its own
    // fallthrough disappears, but the branch target block is still part of
    // the same function, and the function still returns.
    //   0x1000: 85 c0               test eax, eax
    //   0x1002: 74 0b               je 0x100f
    //   0x1004: e8 07 00 00 00      call 0x1010     ; ExitProcess thunk
    //   0x1009: 90 x6                               ; unreachable
    //   0x100f: c3                  ret
    //   0x1010: ff 25 00 20 00 00   jmp [0x2000]
    let analysis = analyze_noreturn_test_image(&thunk_at_0x1010(&[
        0x85, 0xc0, 0x74, 0x0b, 0xe8, 0x07, 0, 0, 0, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3,
    ]));

    assert!(analysis.noreturn_calls.contains(&0x1004));
    let entry = analysis
        .functions
        .get(&0x1000)
        .expect("entry function recovered");
    assert_eq!(
        function_instruction_addrs(entry),
        BTreeSet::from([0x1000, 0x1002, 0x1004, 0x100f])
    );
    assert!(!analysis.instructions.contains_key(&0x1009));
    // A leaf ending in `ret` means the function itself still returns.
    assert!(!analysis.is_noreturn_va(0x1000));
}

#[test]
fn a_callee_whose_only_leaf_stops_on_undecodable_bytes_is_noreturn() {
    // `noret.py` sets `hasret` only for a leaf ending in `IF_RET` or an
    // unresolved `IF_BRANCH`. A block that simply stops -- here because
    // the bytes after `xor edx, edx` do not decode -- is neither, so the
    // function is no-return and its caller's fallthrough disappears. This
    // is the shape behind `0596c4ea`'s `inject thread`: three functions
    // deep, the reference ends the chain's first block on an invalid
    // `0f c7 c8` and every caller inherits it.
    //   0x1000: e8 03 00 00 00      call 0x1008
    //   0x1005: 90 90               nop, nop        ; unreachable
    //   0x1007: c3                  ret             ; unreachable
    //   0x1008: 31 d2               xor edx, edx
    //   0x100a: 0f c7 c8            (invalid)
    let analysis = analyze_noreturn_test_image(&[
        0xe8, 0x03, 0, 0, 0, 0x90, 0x90, 0xc3, 0x31, 0xd2, 0x0f, 0xc7, 0xc8,
    ]);

    assert!(analysis.is_noreturn_va(0x1008));
    assert!(analysis.noreturn_calls.contains(&0x1000));
    let entry = analysis
        .functions
        .get(&0x1000)
        .expect("entry function recovered");
    assert_eq!(function_instruction_addrs(entry), BTreeSet::from([0x1000]));
    // The caller's own leaf is now a suppressed call, so it too is
    // no-return -- the propagation that used to stop at the decode gap.
    assert!(analysis.is_noreturn_va(0x1000));
}

#[test]
fn unresolved_jump_does_not_truncate_its_caller() {
    // call 0x1008; nop; nop; ret; jmp 0x1100 (outside the image).
    let analysis =
        analyze_noreturn_test_image(&[0xe8, 0x03, 0, 0, 0, 0x90, 0x90, 0xc3, 0xe9, 0xf3, 0, 0, 0]);
    assert!(!analysis.is_noreturn_va(0x1008));
    assert!(analysis.noreturn_calls.is_empty());
    assert_eq!(
        function_instruction_addrs(&analysis.functions[&0x1000]),
        BTreeSet::from([0x1000, 0x1005, 0x1006, 0x1007])
    );
}

#[test]
fn conflicting_instruction_stream_does_not_truncate_its_caller() {
    // An unresolved ELF relocation can point a call into its own operand:
    // call 0x1001; nop; ret. The alternate stream is cld; invalid ff.
    // Its decode gap cannot establish that this call never returns.
    let analysis = analyze_noreturn_test_image(&[0xe8, 0xfc, 0xff, 0xff, 0xff, 0x90, 0xc3]);
    assert!(!analysis.is_noreturn_va(0x1001));
    assert!(analysis.noreturn_calls.is_empty());
    assert_eq!(
        function_instruction_addrs(&analysis.functions[&0x1000]),
        BTreeSet::from([0x1000, 0x1005, 0x1006])
    );
}

#[test]
fn call_to_an_ordinary_import_thunk_keeps_its_fallthrough() {
    // The same shape as `noreturn_status_propagates_through_an_import_thunk`
    // but through an import that is *not* on the pinned no-return list:
    // suppression must be name-driven, not "any thunk".
    let image = noreturn_test_image(&thunk_at_0x1010(&[0xe8, 0x0b, 0, 0, 0, 0x90, 0xc3]))
        .with_import_location(0x2000, "kernel32.CreateFileA");
    let mut seeds = SeedMap::new();
    if let Some(entry) = image.entry_point {
        add_seed(&image, &mut seeds, entry, SeedKind::EntryPoint);
    }
    let analysis = analyze_seeded_image(
        image,
        RecoveryBackend::VivisectCompat,
        seeds,
        BTreeMap::new(),
        Vec::new(),
    )
    .expect("synthetic recovery succeeds");

    assert!(analysis.noreturn.is_empty());
    assert!(analysis.noreturn_calls.is_empty());
    let entry = analysis
        .functions
        .get(&0x1000)
        .expect("entry function recovered");
    assert_eq!(
        function_instruction_addrs(entry),
        BTreeSet::from([0x1000, 0x1005, 0x1006])
    );
}

#[test]
fn recognizes_vivisect_x86_seh_entry_signature() {
    assert!(matches_x86_seh_entry_signature(&[
        0x6a, 0x38, 0x68, 0x10, 0x23, 0x4b, 0x00, 0xe8,
    ]));
    assert!(!matches_x86_seh_entry_signature(&[
        0x6a, 0x38, 0x68, 0x10, 0x23, 0x4b, 0x00, 0x90,
    ]));
}

/// A hand-built AArch64 image: `bl <stub>` at the entry point, and at
/// `stub` the AAPCS64 lazy-PLT shape (`adrp x16, page(got); ldr x17,
/// [x16, #off]; br x17`) whose `adrp`+`ldr` pair resolves to `got` --
/// bound, via `with_import_location`/`external_bindings`, to `exit`, one
/// of the pinned ELF no-return APIs (`ELF_NORETURN_APIS`). Encodings
/// independently verified in Python against `aarch64_plt_got_target`'s
/// own formulas before being hand-transcribed here.
#[test]
fn aarch64_plt_stub_resolves_to_its_got_import_and_propagates_noreturn() {
    const ENTRY: u64 = 0x400000;
    const STUB: u64 = 0x400100;
    const GOT: u64 = 0x500000;

    let mut code = vec![0x90u8; (STUB - ENTRY) as usize];
    code[0..4].copy_from_slice(&0x9400_0040u32.to_le_bytes()); // bl STUB
    let stub_offset = code.len();
    code.extend_from_slice(&0x9000_0810u32.to_le_bytes()); // adrp x16, page(GOT)
    code.extend_from_slice(&0xf940_0211u32.to_le_bytes()); // ldr x17, [x16, #off]
    code.extend_from_slice(&0xd61f_0220u32.to_le_bytes()); // br x17
    assert_eq!(ENTRY + stub_offset as u64, STUB);

    let image = LoadedImage::for_test(
        ImageFormat::Elf,
        Architecture::AArch64,
        ENTRY,
        vec![MappedSection {
            name: ".text".to_string(),
            address: ENTRY,
            virtual_size: code.len() as u64,
            file_offset: 0,
            file_size: code.len() as u64,
            permissions: Permissions {
                read: true,
                write: false,
                execute: true,
            },
        }],
        BTreeMap::from([(GOT, vec!["exit".to_string()])]),
        code,
    )
    .with_import_location(GOT, "*.exit");

    let mut seeds = SeedMap::new();
    add_seed(&image, &mut seeds, ENTRY, SeedKind::EntryPoint);
    let analysis = analyze_seeded_image(
        image,
        RecoveryBackend::VivisectCompat,
        seeds,
        BTreeMap::new(),
        Vec::new(),
    )
    .expect("synthetic AArch64 recovery succeeds");

    assert_eq!(
        analysis
            .image
            .import_locations
            .get(&STUB)
            .map(String::as_str),
        Some("*.exit"),
        "the stub's own start address should alias the GOT slot's import name"
    );
    assert!(
        analysis
            .image
            .external_bindings
            .get(&STUB)
            .is_some_and(|names| names.iter().any(|name| name == "exit")),
        "external_bindings should carry the same alias"
    );
    // `exit` is a pinned ELF no-return API (`ELF_NORETURN_APIS`); once
    // the stub's address is a known import location, the no-return
    // fixpoint (which re-seeds from `import_locations` each pass) should
    // propagate that status to the stub itself.
    assert!(
        analysis.noreturn.contains(&STUB),
        "a stub resolving to a no-return API should itself be no-return"
    );
}

#[test]
fn aarch64_leaf_sweep_respects_unwind_bodies_and_compatibility() {
    let code: Vec<u8> = [
        0xd65f03c0u32, // entry: ret
        0x528000e0,
        0xd65f03c0, // uncalled leaf: mov w0,7; ret
        0xd65f03c0, // authoritative body begins here
        0x52800100,
        0xd65f03c0, // an internal block after a ret
    ]
    .into_iter()
    .flat_map(u32::to_le_bytes)
    .collect();
    let mut image = LoadedImage::for_test(
        ImageFormat::Elf,
        Architecture::AArch64,
        0x1000,
        vec![MappedSection {
            name: ".text".into(),
            address: 0x1000,
            virtual_size: code.len() as u64,
            file_offset: 0,
            file_size: code.len() as u64,
            permissions: Permissions {
                read: true,
                write: false,
                execute: true,
            },
        }],
        BTreeMap::new(),
        code,
    );
    image.function_ranges = vec![(0x100c, 0x1018)];
    let seeds = BTreeMap::from([
        (0x1000, BTreeSet::from([SeedKind::EntryPoint])),
        (0x100c, BTreeSet::from([SeedKind::EhFrame])),
    ]);
    for backend in [RecoveryBackend::Native, RecoveryBackend::VivisectCompat] {
        let analysis = analyze_seeded_image(
            image.clone(),
            backend,
            seeds.clone(),
            BTreeMap::new(),
            Vec::new(),
        )
        .expect("synthetic arm64 recovery");
        assert_eq!(
            analysis.functions.contains_key(&0x1004),
            backend == RecoveryBackend::Native
        );
        assert!(!analysis.functions.contains_key(&0x1010));
    }
}
