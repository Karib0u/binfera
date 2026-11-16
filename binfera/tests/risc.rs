#![allow(clippy::unwrap_used, clippy::expect_used)]
use binfera::extract::{
    image::{Architecture, LoadedImage},
    recovery,
};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/risc/{name}.elf",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn symbol(bytes: &[u8], name: &str) -> u64 {
    let elf = goblin::elf::Elf::parse(bytes).unwrap();
    elf.syms
        .iter()
        .find(|s| elf.strtab.get_at(s.st_name) == Some(name))
        .unwrap()
        .st_value
        & !1
}

#[test]
fn arm_thumb_and_both_mips_byte_orders_recover_real_compiler_output() {
    for (name, architecture) in [
        ("arm", Architecture::Arm),
        ("thumb", Architecture::Arm),
        ("mips", Architecture::MipsBe),
        ("mipsel", Architecture::Mips),
    ] {
        let bytes = fixture(name);
        let image = LoadedImage::parse(&bytes).unwrap();
        assert_eq!(image.architecture, architecture, "{name}");
        assert_eq!(image.is_thumb(symbol(&bytes, "mix")), name == "thumb");
        let analysis = recovery::analyze(&bytes).unwrap();
        for function in ["mix", "invoke", "_start"] {
            let address = symbol(&bytes, function);
            assert!(
                analysis.functions.contains_key(&address),
                "{name}/{function}: {:?}",
                analysis.diagnostics
            );
            assert!(!analysis.functions[&address].blocks.is_empty());
        }
        assert!(analysis
            .instructions
            .values()
            .all(|i| i.disassembly().is_some()));
    }
}

#[test]
fn arm_thumb_interworking_keeps_canonical_addresses_and_instruction_modes() {
    let bytes = fixture("interwork");
    let analysis = recovery::analyze(&bytes).unwrap();
    let arm = symbol(&bytes, "arm_callee");
    let thumb = symbol(&bytes, "thumb_callee");
    assert!(!analysis.image.is_thumb(arm));
    assert!(analysis.image.is_thumb(thumb));
    assert!(analysis.functions.contains_key(&arm));
    assert!(analysis.functions.contains_key(&thumb));
    assert!(analysis
        .instructions
        .values()
        .any(|i| i.direct_target == Some(thumb)));
    assert!(analysis
        .instructions
        .values()
        .any(|i| i.direct_target == Some(arm)));
}

#[cfg(feature = "decompiler")]
#[test]
fn ghidra_decompiles_each_architecture_and_interworking() {
    for name in ["arm", "thumb", "mips", "mipsel", "interwork"] {
        let bytes = fixture(name);
        let function = if name == "interwork" {
            "thumb_callee"
        } else {
            "mix"
        };
        let mut session = binfera::decompiler::DecompilerSession::from_elf(&bytes).unwrap();
        let result = session
            .decompile_function(symbol(&bytes, function))
            .unwrap();
        assert!(!result.text.is_empty(), "{name}");
        assert!(!result.text.contains("BADSPACE"), "{name}: {}", result.text);
        assert!(result.text.contains("param_1"), "{name}: {}", result.text);
        assert!(result.text.contains("return"), "{name}: {}", result.text);
        if name != "interwork" {
            assert!(
                result.text.contains("param_2")
                    && result.text.contains("0xb")
                    && result.text.contains('^'),
                "{name}: {}",
                result.text
            );
        } else {
            assert!(
                result.text.contains("arm_callee(param_1)"),
                "{}",
                result.text
            );
        }
        assert!(!result.incomplete, "{name}: {:?}", result.warnings);
        eprintln!("{name}: {}", result.text);
    }
}

#[cfg(feature = "decompiler")]
#[test]
fn arm_float_abi_and_stack_arguments_use_the_pinned_compiler_models() {
    use binfera::decompiler::{CallingConvention, DecompilerSession, ValueType};
    for (name, convention) in [
        ("arm-softfp", CallingConvention::SystemVArmSoft),
        ("arm-hard", CallingConvention::SystemVArm),
    ] {
        let bytes = fixture(name);
        let mut session = DecompilerSession::from_elf(&bytes).unwrap();
        let floating = symbol(&bytes, "floating");
        session
            .set_signature(floating, ValueType::F64, &[ValueType::F64, ValueType::F64])
            .unwrap();
        let output = session.decompile_function(floating).unwrap();
        assert_eq!(output.calling_convention, convention);
        assert!(
            output.text.contains("param_1")
                && output.text.contains("param_2")
                && output.text.contains('+'),
            "{}",
            output.text
        );
        assert!(!output.incomplete, "{:?}", output.warnings);
        let address = symbol(&bytes, "stack_args");
        session
            .set_signature(address, ValueType::U32, &[ValueType::U32; 6])
            .unwrap();
        let output = session.decompile_function(address).unwrap();
        assert!(
            output.text.contains("param_5") && output.text.contains("param_6"),
            "{}",
            output.text
        );
        // Execute emitted C only for our own freestanding source fixture. This
        // catches numeric casts accidentally replacing float bit reinterpretation.
        let expression = session.decompile_function(floating).unwrap().text;
        // Independent reference helpers use byte copies rather than the union
        // helpers emitted by the production C prelude.
        let prelude = "typedef double float8; typedef float float4; typedef unsigned long long uint8; typedef unsigned int uint4;\nstatic double BITCAST_F64(uint8 v) { double r; __builtin_memcpy(&r,&v,8); return r; }\nstatic uint8 BITCAST_U64(double v) { uint8 r; __builtin_memcpy(&r,&v,8); return r; }\nstatic float BITCAST_F32(uint4 v) { float r; __builtin_memcpy(&r,&v,4); return r; }\nstatic uint4 BITCAST_U32(float v) { uint4 r; __builtin_memcpy(&r,&v,4); return r; }\n";
        // Not the clock: on Windows two parallel tests can read the same time.
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let nonce = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let directory =
            std::env::temp_dir().join(format!("binfera-risc-float-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let source = directory.join("fixture.c");
        let binary = directory.join("fixture");
        let harness = "\nint main(void) { double inputs[][2] = {{1.5,2.25},{-4.25,1.0},{0.0,0.0},{99.0,-0.125}}; for (unsigned i=0;i<4;i++) { double a=inputs[i][0],b=inputs[i][1]; if (floating(a,b) != a+b*2.0) return 1; } return 0; }\n";
        std::fs::write(&source, format!("{prelude}{expression}{harness}")).unwrap();
        let compiled = std::process::Command::new("cc")
            .args(["-std=c11", "-O0"])
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        assert!(
            std::process::Command::new(&binary)
                .status()
                .unwrap()
                .success(),
            "{name}: emitted C differs from source"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[cfg(feature = "decompiler")]
#[test]
fn windows_arm_thumb_pe_uses_the_windows_compiler_model() {
    use binfera::decompiler::{CallingConvention, DecompilerSession};
    let bytes = std::fs::read(format!(
        "{}/tests/fixtures/risc/windows.exe",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let image = LoadedImage::parse(&bytes).unwrap();
    let pe = goblin::pe::PE::parse(&bytes).unwrap();
    let address = image.image_base
        + pe.exports
            .iter()
            .find(|e| e.name == Some("mix"))
            .unwrap()
            .rva as u64;
    let mut session = DecompilerSession::from_pe(&bytes).unwrap();
    let output = session.decompile_function(address & !1).unwrap();
    assert_eq!(output.calling_convention, CallingConvention::WindowsArm);
    assert!(
        output.text.contains("param_1") && output.text.contains("param_2"),
        "{}",
        output.text
    );
    assert!(!output.incomplete, "{:?}", output.warnings);
}

#[test]
fn mips_branch_likely_annuls_the_delay_slot_on_the_false_path() {
    use binfera::extract::recovery::EdgeKind;
    let words = [
        0x5080_0002u32,
        0x2402_0005,
        0x2402_0001,
        0x03e0_0008,
        0x2442_0002,
    ];
    for architecture in [Architecture::Mips, Architecture::MipsBe] {
        let bytes: Vec<u8> = words
            .iter()
            .flat_map(|w| {
                if architecture.little_endian() {
                    w.to_le_bytes()
                } else {
                    w.to_be_bytes()
                }
            })
            .collect();
        let analysis = recovery::analyze_shellcode(&bytes, architecture).unwrap();
        let base = analysis.image.entry_point.unwrap();
        let function = &analysis.functions[&base];
        let branch = function.blocks.iter().find(|b| b.addr == base).unwrap();
        assert!(branch
            .succs
            .iter()
            .any(|e| e.kind == EdgeKind::Fallthrough && e.target == base + 8));
        assert!(branch
            .succs
            .iter()
            .any(|e| e.kind == EdgeKind::Branch && e.target == base + 4));
        let slot = function.blocks.iter().find(|b| b.addr == base + 4).unwrap();
        assert_eq!(slot.succs.len(), 1);
        assert_eq!(slot.succs[0].target, base + 12);
        assert!(function
            .blocks
            .iter()
            .any(|b| b.insns.iter().any(|i| i.address == base + 16)));
    }
}

#[test]
fn capability_extraction_produces_code_features_for_each_architecture() {
    use binfera::{api, features::Feature, freeze::Freeze, parallel::AnalysisOptions};
    for name in ["arm", "thumb", "mips", "mipsel"] {
        let bytes = fixture(name);
        let (loaded, format) =
            api::load_input(&bytes, &AnalysisOptions::default(), &mut Default::default()).unwrap();
        assert_eq!(format, "elf");
        let Freeze::Static(features) = loaded.freeze else {
            panic!("expected static features")
        };
        assert!(features
            .functions
            .contains_key(&binfera::address::Address::Absolute(symbol(&bytes, "mix"))));
        assert!(
            features
                .functions
                .values()
                .flat_map(|f| f.basic_blocks.values())
                .flat_map(|b| b.instructions.values())
                .flat_map(|i| &i.features)
                .any(|(_, f)| matches!(f, Feature::Mnemonic(_))),
            "{name}"
        );
    }
}

#[test]
fn shared_library_imports_and_strings_are_code_features() {
    use binfera::{api, features::Feature, freeze::Freeze, parallel::AnalysisOptions};
    for name in [
        "arm-dynamic",
        "thumb-dynamic",
        "mips-dynamic",
        "mipsel-dynamic",
    ] {
        let bytes = fixture(name);
        let (loaded, _) =
            api::load_input(&bytes, &AnalysisOptions::default(), &mut Default::default()).unwrap();
        let Freeze::Static(features) = loaded.freeze else {
            panic!("static features")
        };
        let code: Vec<_> = features
            .functions
            .values()
            .flat_map(|f| f.basic_blocks.values())
            .flat_map(|b| b.instructions.values())
            .flat_map(|i| i.features.iter().map(|(_, f)| f))
            .collect();
        assert!(
            code.iter()
                .any(|f| matches!(f, Feature::Api(n) if n == "imported")),
            "{name}: no imported API: {code:?}"
        );
        assert!(code.iter().any(|f| matches!(f, Feature::String(s) if format!("{s:?}").contains("risc fixture string"))), "{name}: no referenced string");
    }
}

#[test]
fn arm_pc_reads_are_not_branches_and_it_returns_keep_fallthrough() {
    use binfera::extract::decoder::Flow;
    // mov r0, pc; bx lr
    let image = LoadedImage::from_shellcode(
        &[0x0f, 0x00, 0xa0, 0xe1, 0x1e, 0xff, 0x2f, 0xe1],
        Architecture::Arm,
    );
    assert_eq!(
        image.decode_at(image.entry_point.unwrap()).unwrap().flow,
        Flow::Next
    );
    // Thumb: it eq; bxeq lr; movs r0, #1; bx lr
    let mut bytes = fixture("thumb");
    let elf = goblin::elf::Elf::parse(&bytes).unwrap();
    let address = symbol(&bytes, "mix");
    let section = elf
        .section_headers
        .iter()
        .find(|s| address >= s.sh_addr && address < s.sh_addr + s.sh_size)
        .unwrap();
    let offset = (section.sh_offset + address - section.sh_addr) as usize;
    bytes[offset..offset + 8].copy_from_slice(&[0x08, 0xbf, 0x70, 0x47, 0x01, 0x20, 0x70, 0x47]);
    let analysis = recovery::analyze(&bytes).unwrap();
    assert_eq!(
        analysis.instructions[&(address + 2)].flow,
        Flow::ConditionalBranch
    );
    assert!(analysis.instructions.contains_key(&(address + 4)));
}

#[test]
fn unsupported_mips_profiles_keep_inspection_but_reject_code_analysis() {
    for flags in [
        0x9000_1000u32,
        0x8000_1000,
        0x7400_1000,
        0x7200_1000,
        0x7000_0020,
        0x7000_3000,
    ] {
        let mut bytes = fixture("mipsel");
        bytes[36..40].copy_from_slice(&flags.to_le_bytes());
        assert!(LoadedImage::parse(&bytes).is_err(), "{flags:x}");
        assert!(
            binfera::image_info::inspect(&bytes, None).is_ok(),
            "{flags:x}"
        );
    }
}

#[test]
fn malformed_risc_instructions_return_results_without_panicking() {
    let mut random = 0x7135_ae29u32;
    for architecture in [Architecture::Arm, Architecture::Mips, Architecture::MipsBe] {
        for _ in 0..256 {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            let bytes = random.to_le_bytes();
            for length in 0..=4 {
                let image = LoadedImage::from_shellcode(&bytes[..length], architecture);
                let _ = image.decode_at(image.entry_point.unwrap());
            }
        }
    }
}

#[test]
fn stripped_interworking_and_literal_pc_loads_preserve_thumb_mode() {
    let original = fixture("interwork");
    let thumb = symbol(&original, "thumb_callee");
    let arm = symbol(&original, "arm_callee");
    let mut bytes = original.clone();
    let elf = goblin::elf::Elf::parse(&original).unwrap();
    for (index, section) in elf.section_headers.iter().enumerate() {
        if section.sh_type == goblin::elf::section_header::SHT_SYMTAB {
            let offset = elf.header.e_shoff as usize + index * elf.header.e_shentsize as usize + 4;
            bytes[offset..offset + 4].fill(0);
        }
    }
    let analysis = recovery::analyze(&bytes).unwrap();
    assert!(analysis.image.is_thumb(thumb));
    assert!(!analysis.image.is_thumb(arm));
    assert!(analysis.functions.contains_key(&thumb));
    assert!(analysis.functions.contains_key(&arm));
    // ARM: ldr pc, [pc, #-4]; literal Thumb pointer; Thumb: bx lr.
    let base = binfera::extract::image::SHELLCODE_BASE;
    let mut code = vec![0x04, 0xf0, 0x1f, 0xe5];
    code.extend_from_slice(&((base + 9) as u32).to_le_bytes());
    code.extend_from_slice(&[0x70, 0x47]);
    let analysis = recovery::analyze_shellcode(&code, Architecture::Arm).unwrap();
    assert!(analysis.image.is_thumb(base + 8));
    assert!(analysis.instructions.contains_key(&(base + 8)));
}

#[test]
fn arm_pe_capabilities_include_the_architecture_global() {
    use binfera::{api, features::Feature, freeze::Freeze, parallel::AnalysisOptions};
    let bytes = include_bytes!("fixtures/risc/windows.exe");
    let (loaded, _) =
        api::load_input(bytes, &AnalysisOptions::default(), &mut Default::default()).unwrap();
    let Freeze::Static(features) = loaded.freeze else {
        panic!("static features")
    };
    assert!(features
        .global_features
        .contains(&Feature::Arch("arm".into())));
    assert!(!features.functions.is_empty());
}

#[cfg(feature = "decompiler")]
#[test]
fn ghidra_names_calls_through_arm_plt_and_mips_got() {
    for name in [
        "arm-dynamic",
        "thumb-dynamic",
        "mips-dynamic",
        "mipsel-dynamic",
    ] {
        let bytes = fixture(name);
        let image = LoadedImage::parse(&bytes).unwrap();
        let address = symbol(&bytes, "call_import") + image.load_bias;
        let (mut session, analysis) =
            binfera::decompiler::DecompilerSession::from_bytes_with_analysis(&bytes).unwrap();
        // This custom fixture import has no standard-library prototype. Supply
        // its known signature at the GOT slot and any wrapper entry.
        for slot in image.import_locations.keys() {
            session
                .set_signature(
                    *slot,
                    binfera::decompiler::ValueType::I32,
                    &[binfera::decompiler::ValueType::I32],
                )
                .unwrap();
        }
        let entries: std::collections::BTreeSet<_> = analysis
            .functions
            .keys()
            .copied()
            .chain(
                analysis
                    .instructions
                    .values()
                    .filter_map(|i| i.direct_target),
            )
            .collect();
        for entry in entries {
            if session.is_import_thunk(entry) {
                session
                    .set_signature(
                        entry,
                        binfera::decompiler::ValueType::I32,
                        &[binfera::decompiler::ValueType::I32],
                    )
                    .unwrap();
            }
        }
        let output = session.decompile_function(address).unwrap();
        assert!(output.text.contains("imported("), "{name}: {}", output.text);
        assert!(output.text.contains("param_1"), "{name}: {}", output.text);
        assert!(!output.incomplete, "{name}: {:?}", output.warnings);
    }
}
