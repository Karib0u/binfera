#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::pe::{carved_pe_size, resolve_pe_ordinal};
use super::*;

#[test]
fn compatibility_rejects_new_vex_mask_register_encodings() {
    let image = synthetic_image(
        vec![0xc5, 0xf9, 0x92, 0xf8],
        Permissions {
            read: true,
            write: false,
            execute: true,
        },
    );
    assert!(image.decode_at(0x1000).is_ok());
    assert!(image.decode_at_compat(0x1000).is_err());
}

#[test]
fn amd64_traps_preserve_reference_codeflow_fallthrough() {
    for bytes in [vec![0xf1], vec![0xcd, 0], vec![0xcd, 0x80]] {
        let image = synthetic_image(
            bytes,
            Permissions {
                read: true,
                write: false,
                execute: true,
            },
        );
        assert_eq!(
            image.decode_at_compat(0x1000).unwrap().flow,
            super::super::decoder::Flow::Next
        );
        assert_eq!(
            image.decode_at(0x1000).unwrap().flow,
            super::super::decoder::Flow::Terminal
        );
    }
    let image = synthetic_image(
        vec![0xcc],
        Permissions {
            read: true,
            write: false,
            execute: true,
        },
    );
    assert_eq!(
        image.decode_at_compat(0x1000).unwrap().flow,
        super::super::decoder::Flow::Terminal
    );
}

#[test]
fn carved_pe_headers_handle_xor_and_truncated_section_tables() {
    let mut bytes = vec![0; 0x200];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    bytes[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes());
    // No directories: the section table begins at 0x98 + 96.
    bytes[0x108..0x10c].copy_from_slice(&0x600u32.to_le_bytes());
    bytes[0x10c..0x110].copy_from_slice(&0x200u32.to_le_bytes());
    for key in [0, 0x5a, 0xff] {
        let encoded: Vec<_> = bytes.iter().map(|byte| byte ^ key).collect();
        assert_eq!(carved_pe_size(&encoded, 0x80, key), Some(0x800));
        assert_eq!(carved_pe_size(&encoded[..0x110], 0x80, key), None);
    }
}

fn synthetic_image(bytes: Vec<u8>, permissions: Permissions) -> LoadedImage {
    LoadedImage {
        format: ImageFormat::Pe,
        architecture: Architecture::X64,
        image_base: 0x1000,
        load_bias: 0,
        entry_point: Some(0x1000),
        arm_context: BTreeMap::new(),
        global_pointer: None,
        sections: vec![MappedSection {
            name: ".text".to_string(),
            address: 0x1000,
            virtual_size: bytes.len() as u64,
            file_offset: 0,
            file_size: bytes.len() as u64,
            permissions,
        }],
        external_bindings: BTreeMap::new(),
        import_locations: BTreeMap::new(),
        load_diagnostics: Vec::new(),
        imports_skipped: false,
        relocation_locations: Vec::new(),
        elf_plt_ranges: Vec::new(),
        dead_data: Vec::new(),
        pe_exception_directory: None,
        code_exclusions: Vec::new(),
        function_ranges: Vec::new(),
        uninitialized: Vec::new(),
        primary_code: vec![(0x1000, 0x1000u64.saturating_add(bytes.len() as u64))],
        mapped_bytes: vec![bytes],
    }
}

#[test]
fn compatibility_rejects_undefined_amd64_variable_vector_shift() {
    let image = LoadedImage::from_shellcode(&[0xc4, 0xe2, 0x6d, 0x47, 0xd0], Architecture::X64);
    assert!(image.decode_at(image.image_base).is_ok());
    assert!(image.decode_at_compat(image.image_base).is_err());
}

#[test]
fn compatibility_i386_far_loads_do_not_consume_vex_payloads() {
    for (bytes, mnemonic) in [
        (&[0xc4, 0xfc, 0x89, 0x34, 0x24][..], iced_x86::Mnemonic::Les),
        (&[0xc5, 0xf8, 0x58, 0xc0][..], iced_x86::Mnemonic::Lds),
    ] {
        let image = LoadedImage::from_shellcode(bytes, Architecture::X86);
        let insn = image.decode_at_compat(image.image_base).unwrap();
        assert_eq!(insn.bytes.len(), 2);
        assert_eq!(insn.x86_instruction().mnemonic(), mnemonic);
        assert_eq!(
            insn.x86_instruction().op1_kind(),
            iced_x86::OpKind::Register
        );
    }
}

#[test]
fn compatibility_decodes_legacy_bound_and_modrm_aliases() {
    let image = LoadedImage::from_shellcode(
        &[0x62, 0xf1, 0x7f, 0x48, 0x6f, 0x2d, 0x4a, 0x42, 1, 0],
        Architecture::X64,
    );
    let native = image.decode_at(image.image_base).unwrap();
    let compat = image.decode_at_compat(image.image_base).unwrap();
    assert_eq!(
        native.x86_instruction().mnemonic(),
        iced_x86::Mnemonic::Vmovdqu8
    );
    assert_eq!(
        compat.x86_instruction().mnemonic(),
        iced_x86::Mnemonic::Bound
    );
    assert_eq!(compat.bytes, [0x62, 0xf1]);
    assert_eq!(compat.next_address, image.image_base + 2);

    for (bytes, mnemonic) in [
        (vec![0xc6, 0x64, 0xfd, 0xdd, 0xf3], iced_x86::Mnemonic::Mov),
        (vec![0x8f, 0xdc], iced_x86::Mnemonic::Pop),
    ] {
        let image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
        assert!(image.decode_at(image.image_base).is_err());
        let compat = image.decode_at_compat(image.image_base).unwrap();
        assert_eq!(compat.x86_instruction().mnemonic(), mnemonic);
        assert_eq!(compat.bytes, bytes);
    }
    for bytes in [&[0x62][..], &[0xc6, 0x64, 0xfd], &[0x8f]] {
        let image = LoadedImage::from_shellcode(bytes, Architecture::X86);
        assert!(matches!(
            image.decode_at_compat(image.image_base),
            Err(ImageError::InvalidInstruction { .. })
        ));
    }
}

#[test]
fn compatibility_rejects_undefined_i386_three_byte_simd_encodings() {
    for bytes in [
        vec![0x66, 0x0f, 0x38, 0x40, 0xc1],    // pmulld
        vec![0x66, 0x0f, 0x38, 0x41, 0xc1],    // phminposuw
        vec![0x66, 0x0f, 0x3a, 0x08, 0xc1, 0], // roundps
        vec![0x66, 0x0f, 0x3a, 0x15, 0xc1, 0], // pextrw
    ] {
        let image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
        assert!(image.decode_at(image.image_base).is_ok());
        assert!(matches!(
            image.decode_at_compat(image.image_base),
            Err(ImageError::InvalidInstruction { .. })
        ));
    }
    // opcode64 has a separate, newer SIMD table. PMULLD is valid there.
    let image = LoadedImage::from_shellcode(&[0x66, 0x0f, 0x38, 0x40, 0xc1], Architecture::X64);
    assert_eq!(
        image
            .decode_at_compat(image.image_base)
            .unwrap()
            .x86_instruction()
            .mnemonic(),
        iced_x86::Mnemonic::Pmulld
    );
    let image = LoadedImage::from_shellcode(&[0x66, 0x0f, 0x38, 0xdc, 0xc1], Architecture::X86);
    assert_eq!(
        image
            .decode_at_compat(image.image_base)
            .unwrap()
            .x86_instruction()
            .mnemonic(),
        iced_x86::Mnemonic::Aesenc
    );
}

#[test]
fn compatibility_preserves_the_i386_platform_int1_decode_failure() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let mut image = LoadedImage::from_shellcode(&[0xf1], architecture);
        image.format = ImageFormat::Pe;
        assert!(image.decode_at(image.image_base).is_ok());
        assert_eq!(
            image.decode_at_compat(image.image_base).is_err(),
            architecture == Architecture::X86
        );
    }
}

#[test]
fn compatibility_decodes_legacy_nop_aliases() {
    for bytes in [
        &[0xf3, 0x90][..],
        &[0x0f, 0x1f, 0x54, 0x54, 0x68],
        &[0x0f, 0x1c, 0x00],
        &[0xf3, 0x0f, 0x1e, 0xfb],
    ] {
        let image = LoadedImage::from_shellcode(bytes, Architecture::X86);
        let decoded = image.decode_at_compat(image.image_base).unwrap();
        assert_eq!(
            decoded.x86_instruction().mnemonic(),
            iced_x86::Mnemonic::Nop
        );
        assert_eq!(decoded.bytes, bytes);
        assert_eq!(decoded.next_address, image.image_base + bytes.len() as u64);
    }
}

#[test]
fn compatibility_preserves_legacy_vector_decode_boundaries() {
    let image = LoadedImage::from_shellcode(&[0xf2, 0x0f, 0xd6, 0xeb, 0xc3], Architecture::X86);
    let instruction = image.decode_at_compat(image.image_base).unwrap();
    assert_eq!(instruction.bytes, [0xf2, 0x0f, 0xd6]);
    assert_eq!(instruction.next_address, image.image_base + 3);
    assert_eq!(
        instruction.x86_instruction().op0_register(),
        iced_x86::Register::MM5
    );
    assert_eq!(
        instruction.x86_instruction().op1_register(),
        iced_x86::Register::XMM5
    );
    for bytes in [
        &[0xc5, 0xf8, 0x62, 0xc0][..],
        &[0x48, 0xc5, 0xf8, 0x10, 0xc0],
    ] {
        let image = LoadedImage::from_shellcode(bytes, Architecture::X64);
        assert!(image.decode_at(image.image_base).is_err());
        let instruction = image.decode_at_compat(image.image_base).unwrap();
        assert_eq!(instruction.bytes, bytes);
        assert_eq!(
            instruction.next_address,
            image.image_base + bytes.len() as u64
        );
    }
}

#[test]
fn compatibility_rejects_undefined_x87_register_aliases() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let image = LoadedImage::from_shellcode(&[0xdf, 0xdb, 0xc3], architecture);
        assert!(image.decode_at(image.image_base).is_ok());
        assert!(image.decode_at_compat(image.image_base).is_err());
        let image = LoadedImage::from_shellcode(&[0xdd, 0xdb, 0xc3], architecture);
        assert!(image.decode_at_compat(image.image_base).is_ok());
    }
}

#[test]
fn compatibility_accepts_lock_on_non_lockable_instructions() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let image = LoadedImage::from_shellcode(&[0xf0, 0x89, 0x5d, 0xf4], architecture);
        assert!(image.decode_at(image.image_base).is_err());
        let instruction = image.decode_at_compat(image.image_base).unwrap();
        assert_eq!(
            instruction.x86_instruction().mnemonic(),
            iced_x86::Mnemonic::Mov
        );
        assert_eq!(instruction.next_address, image.image_base + 4);
        assert!(instruction.x86_instruction().has_lock_prefix());
    }
}

#[test]
fn compatibility_rejects_undefined_padlock_opcodes() {
    for bytes in [&[0x0f, 0xa7, 0xc0][..], &[0xf3, 0x0f, 0xa7, 0xc8]] {
        let image = LoadedImage::from_shellcode(bytes, Architecture::X86);
        assert!(image.decode_at(image.image_base).is_ok());
        assert!(matches!(
            image.decode_at_compat(image.image_base),
            Err(ImageError::InvalidInstruction { .. })
        ));
    }
}

#[test]
fn compatibility_moffs_uses_pointer_width_despite_address_size_prefix() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for opcode in 0xa0..=0xa3 {
            let mut bytes = vec![0x64, 0x67, opcode];
            bytes.extend_from_slice(&0x44332211u32.to_le_bytes());
            if architecture == Architecture::X64 {
                bytes.extend_from_slice(&0x88776655u32.to_le_bytes());
            }
            let image = LoadedImage::from_shellcode(&bytes, architecture);
            let decoded = image.decode_at_compat(image.image_base).unwrap();
            assert_eq!(decoded.bytes, bytes);
            assert_eq!(decoded.next_address, image.image_base + bytes.len() as u64);
            assert_eq!(
                decoded.x86_instruction().segment_prefix(),
                iced_x86::Register::FS
            );
            assert_eq!(
                decoded.x86_instruction().memory_displacement64(),
                if architecture == Architecture::X86 {
                    0x44332211
                } else {
                    0x8877665544332211
                }
            );
            assert!(image.decode_at(image.image_base).unwrap().bytes.len() < bytes.len());
        }
    }
}

#[test]
fn compatibility_keeps_full_addresses_for_operand_size_prefixed_branches() {
    for bytes in [
        &[0x66, 0xe0, 0xfd][..], // loopne back to the instruction
        &[0x66, 0xe1, 0xfd],
        &[0x66, 0xe2, 0xfd],
        &[0x66, 0xe8, 0xfc, 0xff],
        &[0x66, 0xe9, 0xfc, 0xff],
        &[0x66, 0x0f, 0x85, 0xfb, 0xff],
    ] {
        let image = LoadedImage::from_shellcode(bytes, Architecture::X86);
        let decoded = image.decode_at_compat(image.image_base).unwrap();
        assert_eq!(decoded.direct_target, Some(image.image_base));
        assert_eq!(
            decoded.x86_instruction().near_branch_target(),
            image.image_base
        );
        assert_ne!(
            image.decode_at(image.image_base).unwrap().direct_target,
            Some(image.image_base)
        );
    }
}

#[test]
fn truncated_instruction_is_a_contextual_error() {
    let image = synthetic_image(
        vec![0x48, 0x8b],
        Permissions {
            read: true,
            write: false,
            execute: true,
        },
    );
    let error = image
        .decode_at(0x1000)
        .expect_err("instruction is truncated");
    assert!(matches!(
        error,
        ImageError::InvalidInstruction {
            address: 0x1000,
            ..
        }
    ));
    assert!(error.to_string().contains("truncated instruction"));
}

/// envi's own fixture (`envi/tests/test_arch_i386.py:222`):
/// `0F3F070B` -> `vpcext 7,11`, four bytes, two immediate operands.
/// `PE/ordlookup/__init__.py` maps `wsock32.dll` at `ws2_32.ord_names`;
/// pefile keeps a separate `wsock32` table that shifts 10/11/12. Getting
/// this wrong named `wsock32` ordinal 10 `inet_addr`, and cost
/// `set socket configuration` on `74fa32d2b277f583010b692a3f91b627.exe_`.
#[test]
fn wsock32_ordinals_resolve_against_the_ws2_32_table() {
    assert_eq!(resolve_pe_ordinal("WSOCK32.dll", 10), Some("ioctlsocket"));
    assert_eq!(resolve_pe_ordinal("ws2_32.dll", 10), Some("ioctlsocket"));
    assert_eq!(resolve_pe_ordinal("WSOCK32.dll", 11), Some("inet_addr"));
    assert_eq!(resolve_pe_ordinal("wsock32", 116), Some("WSACleanup"));
    assert_eq!(resolve_pe_ordinal("wsock32.dll", 9999), None);
    assert_eq!(resolve_pe_ordinal("kernel32.dll", 10), None);
}

#[test]
fn automation_ordinals_resolve_with_case_insensitive_library_names() {
    assert_eq!(
        resolve_pe_ordinal("OLEAUT32.DLL", 2),
        Some("SysAllocString")
    );
    assert_eq!(resolve_pe_ordinal("oleaut32", 8), Some("VariantInit"));
    assert_eq!(resolve_pe_ordinal("oleaut32.dll", 65535), None);
    assert_eq!(resolve_pe_ordinal("WS2_32.DLL", 115), Some("WSAStartup"));
}

#[test]
fn decodes_vpcext_the_way_envi_does() {
    let image = synthetic_image(
        vec![0x0f, 0x3f, 0x07, 0x0b, 0x90],
        Permissions {
            read: true,
            write: false,
            execute: true,
        },
    );
    let insn = image.decode_at(0x1000).expect("vpcext decodes");
    assert_eq!(insn.mnemonic_override, Some("vpcext"));
    assert_eq!(insn.bytes, vec![0x0f, 0x3f, 0x07, 0x0b]);
    assert_eq!(insn.x86_instruction().len(), 4);
    assert_eq!(insn.flow, super::super::decoder::Flow::Next);
    assert_eq!(insn.x86_instruction().op_count(), 2);
    assert_eq!(
        super::super::operand::classify_operand(insn.x86_instruction(), 0),
        super::super::operand::Operand::Imm(7)
    );
    assert_eq!(
        super::super::operand::classify_operand(insn.x86_instruction(), 1),
        super::super::operand::Operand::Imm(11)
    );
    // and the following instruction is still reachable, which is the
    // point: an undecodable `0F 3F` truncates the whole function.
    assert!(image.decode_at(0x1004).is_ok());
}

/// A `0F 3F` with fewer than two trailing immediate bytes in the mapping
/// is still an error -- envi would not decode it either.
#[test]
fn truncated_vpcext_stays_an_error() {
    let image = synthetic_image(
        vec![0x0f, 0x3f, 0x07],
        Permissions {
            read: true,
            write: false,
            execute: true,
        },
    );
    assert!(matches!(
        image.decode_at(0x1000),
        Err(ImageError::InvalidInstruction {
            address: 0x1000,
            ..
        })
    ));
}

#[test]
fn decoder_rejects_non_executable_mapping() {
    let image = synthetic_image(
        vec![0x90],
        Permissions {
            read: true,
            write: true,
            execute: false,
        },
    );
    assert!(matches!(
        image.decode_at(0x1000),
        Err(ImageError::AddressNotExecutable { address: 0x1000 })
    ));
}

#[test]
fn sparse_test_mapping_does_not_invent_zero_fill() {
    let mut image = synthetic_image(
        vec![0x90],
        Permissions {
            read: true,
            write: false,
            execute: true,
        },
    );
    image.sections[0].virtual_size = 4;
    assert!(image.section_containing(0x1002).is_some());
    assert_eq!(image.va_to_file_offset(0x1002), None);
    assert!(matches!(
        image.decode_at(0x1002),
        Err(ImageError::AddressNotMapped { address: 0x1002 })
    ));
}
