#![cfg(feature = "decompiler")]
use binfera::decompiler::{BatchOptions, CallingConvention as C};
use binfera::emulate::{Emulator, MemoryInput, MemoryRange, Request};
use binfera::extract::{image::Architecture, recovery};

fn raw(code: &[u8], convention: C) -> anyhow::Result<Emulator> {
    let arch = if matches!(convention, C::WindowsX86 | C::SystemVX86) {
        Architecture::X86
    } else {
        Architecture::X64
    };
    Ok(Emulator::from_analysis(
        recovery::analyze_shellcode_native(code, arch)?,
        convention,
    )?)
}
fn raw_import(code: &[u8], convention: C, name: &str) -> anyhow::Result<Emulator> {
    let mut bytes = code.to_vec();
    bytes.resize(0x88, 0xcc);
    let arch = if convention == C::WindowsX86 {
        Architecture::X86
    } else {
        Architecture::X64
    };
    let mut analysis = recovery::analyze_shellcode_native(&bytes, arch)?;
    analysis
        .image
        .import_locations
        .insert(0x80, format!("kernel32.{name}"));
    analysis
        .image
        .external_bindings
        .insert(0x80, vec![name.into()]);
    Ok(Emulator::from_analysis(analysis, convention)?)
}
fn req(args: &[u64]) -> Request {
    Request {
        args: args.into(),
        ..Request::default()
    }
}

#[test]
fn abi_register_and_stack_arguments() -> anyhow::Result<()> {
    // mov rax,rcx; add rax,[rsp+0x28]; ret
    let mut win = raw(
        &[0x48, 0x89, 0xc8, 0x48, 0x03, 0x44, 0x24, 0x28, 0xc3],
        C::WindowsX64,
    )?;
    let result = win.run(&req(&[11, 22, 33, 44, 55]))?;
    assert_eq!(result.stop.kind, "returned");
    assert_eq!(result.return_value, 66);
    // mov rax,rdi; add rax,[rsp+8]; ret
    let mut sysv = raw(
        &[0x48, 0x89, 0xf8, 0x48, 0x03, 0x44, 0x24, 8, 0xc3],
        C::SystemVX64,
    )?;
    assert_eq!(sysv.run(&req(&[1, 2, 3, 4, 5, 6, 7]))?.return_value, 8);
    // mov eax,[esp+4]; add eax,[esp+8]; ret
    let mut x86 = raw(
        &[0x8b, 0x44, 0x24, 4, 0x03, 0x44, 0x24, 8, 0xc3],
        C::SystemVX86,
    )?;
    assert_eq!(x86.run(&req(&[123, 456]))?.return_value, 579);
    Ok(())
}

#[test]
fn captures_writes_and_resets_each_run() -> anyhow::Result<()> {
    // inc byte ptr [rcx]; movzx eax,byte ptr [rcx]; ret
    let mut emu = raw(&[0xfe, 1, 0x0f, 0xb6, 1, 0xc3], C::WindowsX64)?;
    let mut request = req(&[0x100000]);
    request.memory.push(MemoryInput {
        address: 0x100000,
        data: vec![41],
    });
    request.capture.push(MemoryRange {
        address: 0x100000,
        size: 1,
    });
    let a = emu.run(&request)?;
    let b = emu.run(&request)?;
    assert_eq!(a.return_value, 42);
    assert_eq!(b.return_value, 42);
    assert_eq!(a.writes.len(), 1);
    assert_eq!(a.writes[0].address, 0x100000);
    assert_eq!(a.writes[0].data, vec![42]);
    assert_eq!(a.memory[0].data, vec![42]);
    request.max_write_bytes = 0;
    let limited = emu.run(&request)?;
    assert!(limited.writes[0].truncated);
    assert!(limited.writes[0].data.is_empty());
    Ok(())
}

#[test]
fn faults_traps_limits_and_modified_code_are_explicit() -> anyhow::Result<()> {
    let mut emu = raw(&[0x48, 0x8b, 1, 0xc3], C::WindowsX64)?;
    assert_eq!(emu.run(&req(&[0x100000]))?.stop.kind, "read_fault");
    let mut emu = raw(&[0x48, 0x89, 1, 0xc3], C::WindowsX64)?;
    assert_eq!(emu.run(&req(&[0x100000]))?.stop.kind, "write_fault");
    let mut emu = raw(&[0x0f, 5, 0xc3], C::SystemVX64)?;
    assert_eq!(emu.run(&req(&[]))?.stop.kind, "trap");
    let mut emu = raw(&[0xeb, 0xfe], C::WindowsX64)?;
    let mut request = req(&[]);
    request.max_steps = 12;
    let out = emu.run(&request)?;
    assert_eq!(out.stop.kind, "step_limit");
    assert_eq!(out.steps, 12);
    request.max_steps = 10_000_000;
    request.timeout_ms = 1;
    assert_eq!(emu.run(&request)?.stop.kind, "timeout");
    // mov byte ptr [rip],0xc3; nop; ret. The next instruction changed in emulated RAM.
    let mut emu = raw(&[0xc6, 5, 0, 0, 0, 0, 0xc3, 0x90, 0xc3], C::WindowsX64)?;
    let out = emu.run(&req(&[]))?;
    assert_eq!(out.stop.kind, "unsupported");
    assert!(out.stop.detail.contains("modified image code"));
    Ok(())
}

#[test]
fn wide_mul_div_sse_and_segment_bases() -> anyhow::Result<()> {
    // mov rax,rcx; mul rdx; ret
    let mut emu = raw(&[0x48, 0x89, 0xc8, 0x48, 0xf7, 0xe2, 0xc3], C::WindowsX64)?;
    let out = emu.run(&req(&[0x12345678, 0x87654321]))?;
    assert_eq!(out.stop.kind, "returned");
    assert_eq!(out.return_value, 0x12345678u64 * 0x87654321u64);
    // mov rax,rcx; xor edx,edx; div r8; ret
    let mut emu = raw(
        &[0x48, 0x89, 0xc8, 0x31, 0xd2, 0x49, 0xf7, 0xf0, 0xc3],
        C::WindowsX64,
    )?;
    assert_eq!(emu.run(&req(&[12345, 0, 17]))?.return_value, 726);
    // movdqu xmm0,[rcx]; pxor xmm0,xmm0; movdqu [rdx],xmm0; ret
    let mut emu = raw(
        &[
            0xf3, 0x0f, 0x6f, 1, 0x66, 0x0f, 0xef, 0xc0, 0xf3, 0x0f, 0x7f, 2, 0xc3,
        ],
        C::WindowsX64,
    )?;
    let mut request = req(&[0x100000, 0x100010]);
    request.memory.push(MemoryInput {
        address: 0x100000,
        data: vec![255; 32],
    });
    request.capture.push(MemoryRange {
        address: 0x100010,
        size: 16,
    });
    let out = emu.run(&request)?;
    assert_eq!(out.stop.kind, "returned");
    assert_eq!(out.memory[0].data, vec![0; 16]);
    // mov rax,gs:[0x10]; ret
    let mut emu = raw(
        &[0x65, 0x48, 0x8b, 4, 0x25, 0x10, 0, 0, 0, 0xc3],
        C::WindowsX64,
    )?;
    let mut request = req(&[]);
    request.registers.insert("GS_OFFSET".into(), 0x100000);
    request.memory.push(MemoryInput {
        address: 0x100010,
        data: 12345u64.to_le_bytes().to_vec(),
    });
    assert_eq!(emu.run(&request)?.return_value, 12345);
    Ok(())
}

#[test]
fn import_calls_use_configured_returns_and_stdcall_purge() -> anyhow::Result<()> {
    // call [rip+0x7a]; add rax,5; ret
    let mut emu = raw_import(
        &[0xff, 0x15, 0x7a, 0, 0, 0, 0x48, 0x83, 0xc0, 5, 0xc3],
        C::WindowsX64,
        "GetTickCount",
    )?;
    let mut request = req(&[]);
    request.import_returns.insert("GetTickCount".into(), 123);
    let out = emu.run(&request)?;
    assert_eq!(out.stop.kind, "returned");
    assert_eq!(out.return_value, 128);
    assert_eq!(out.calls.len(), 1);
    assert_eq!(out.calls[0].name, "kernel32.GetTickCount");
    assert!(out.calls[0].args.is_empty());
    request.max_calls = 0;
    assert_eq!(emu.run(&request)?.stop.kind, "call_limit");
    request.max_calls = 256;
    request.max_steps = 1;
    let bounded = emu.run(&request)?;
    assert_eq!(bounded.stop.kind, "step_limit");
    assert_eq!(bounded.steps, 1);
    // push 42; call [0x80]; mov eax,99; ret
    let mut emu = raw_import(
        &[0x6a, 42, 0xff, 0x15, 0x80, 0, 0, 0, 0xb8, 99, 0, 0, 0, 0xc3],
        C::WindowsX86,
        "Sleep",
    )?;
    let out = emu.run(&req(&[]))?;
    assert_eq!(
        out.stop.kind,
        "returned",
        "{:?}, calls: {:?}, regs: {:?}",
        out.stop,
        out.calls.iter().take(3).collect::<Vec<_>>(),
        out.registers
    );
    assert_eq!(out.return_value, 99);
    assert_eq!(out.calls[0].args, vec![42]);
    // A 64-bit by-value argument makes SetFilePointerEx pop 20 bytes, not count * 4.
    let mut emu = raw_import(
        &[
            0x6a, 5, 0x6a, 4, 0x6a, 3, 0x6a, 2, 0x6a, 1, 0xff, 0x15, 0x80, 0, 0, 0, 0xc3,
        ],
        C::WindowsX86,
        "SetFilePointerEx",
    )?;
    let out = emu.run(&req(&[]))?;
    assert_eq!(
        out.stop.kind,
        "returned",
        "{:?}, calls: {:?}, regs: {:?}",
        out.stop,
        out.calls.iter().take(3).collect::<Vec<_>>(),
        out.registers
    );
    let mut unknown = raw_import(
        &[0xff, 0x15, 0x80, 0, 0, 0, 0xc3],
        C::WindowsX86,
        "UnknownAPI",
    )?;
    assert_eq!(unknown.run(&req(&[]))?.stop.kind, "unknown_import_abi");
    let mut request = req(&[]);
    request.import_stack_pops.insert("UnknownAPI".into(), 0);
    assert_eq!(unknown.run(&request)?.stop.kind, "returned");
    Ok(())
}

#[test]
fn direct_call_sites_report_reached_and_unreached_paths() -> anyhow::Result<()> {
    // test ecx,ecx; jz done; call target; done:ret; target:lea eax,[rcx+7];ret
    let mut emu = raw(
        &[
            0x85, 0xc9, 0x74, 5, 0xe8, 1, 0, 0, 0, 0xc3, 0x8d, 0x41, 7, 0xc3,
        ],
        C::WindowsX64,
    )?;
    let mut request = req(&[5]);
    request.address = 10;
    let out = emu.call_sites(&request, 10)?;
    assert_eq!(out.total_sites, 1);
    assert!(out.sites[0].reached);
    assert_eq!(out.sites[0].result.stop.kind, "returned");
    assert_eq!(out.sites[0].result.return_value, 12);
    request.args = vec![0];
    let out = emu.call_sites(&request, 10)?;
    assert!(!out.sites[0].reached);
    Ok(())
}

/// main decrypts two XOR-0x5a strings in place through `decrypt(buffer, length)` at 0x2f, which
/// the web UI's Emulate tab runs (web/scripts/check-emulate.mjs uses the same bytes).
pub const XOR_STRINGS: &[u8] = &[
    0x48, 0x83, 0xec, 0x28, 0x48, 0x8d, 0x0d, 0x39, 0, 0, 0, 0xba, 5, 0, 0, 0, 0xe8, 0x1a, 0, 0, 0,
    0x48, 0x8d, 0x0d, 0x2e, 0, 0, 0, 0xba, 7, 0, 0, 0, 0xe8, 9, 0, 0, 0, 0x48, 0x83, 0xc4, 0x28,
    0x31, 0xc0, 0xc3, 0xcc, 0xcc, 0x48, 0x89, 0xc8, 0x85, 0xd2, 0x74, 0x0a, 0x80, 0x31, 0x5a, 0x48,
    0xff, 0xc1, 0xff, 0xca, 0x75, 0xf6, 0xc3, 0xcc, 0xcc, 0xcc, 0x32, 0x3f, 0x36, 0x36, 0x35, 0,
    0x3f, 0x22, 0x3b, 0x37, 0x2a, 0x36, 0x3f, 0,
];

#[test]
fn string_decryption_helper_runs_directly_and_at_each_call_site() -> anyhow::Result<()> {
    let mut emu = raw(XOR_STRINGS, C::WindowsX64)?;
    // Direct run: an input buffer the caller supplies.
    let mut request = req(&[0x100000, 3]);
    request.address = 0x2f;
    request.memory.push(MemoryInput {
        address: 0x100000,
        data: vec![0x32, 0x3f, 0x36],
    });
    let out = emu.run(&request)?;
    assert_eq!(out.stop.kind, "returned");
    assert_eq!(out.return_value, 0x100000);
    assert_eq!(out.writes.len(), 1);
    assert_eq!(out.writes[0].data, b"hel");

    // Call sites: each caller passes its own encrypted string. `call_writes` holds only what
    // the call wrote, while `writes` still has what the caller wrote before the second site.
    let mut request = req(&[]);
    request.address = 0x2f;
    let out = emu.call_sites(&request, 8)?;
    assert_eq!(out.total_sites, 2);
    let sites: Vec<_> = out.sites.iter().map(|s| (s.caller, s.site)).collect();
    assert_eq!(sites, [(0, 0x10), (0, 0x21)]);
    let decoded: Vec<_> = out
        .sites
        .iter()
        .map(|s| {
            assert!(s.reached);
            assert_eq!(s.result.stop.kind, "returned");
            // The call's own return address lands on the synthetic stack; the strings do not.
            let sp = s.result.registers["RSP"];
            assert!(s
                .call_writes
                .iter()
                .any(|w| w.address.abs_diff(sp) < 0x100 && w.size == 8));
            s.call_writes
                .iter()
                .filter(|w| w.address.abs_diff(sp) >= 1 << 20)
                .map(|w| (w.address, w.data.clone()))
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(decoded[0], [(0x44, b"hello".to_vec())]);
    assert_eq!(decoded[1], [(0x4a, b"example".to_vec())]);
    let second = &out.sites[1].result.writes;
    assert!(second
        .iter()
        .any(|w| w.address == 0x44 && w.data == b"hello"));
    assert!(second
        .iter()
        .any(|w| w.address == 0x4a && w.data == b"example"));
    Ok(())
}

#[test]
fn recursive_call_site_returns_from_its_own_frame() -> anyhow::Result<()> {
    // f: test ecx,ecx; jz done; sub rsp,0x28; dec ecx; call f; inc eax; add rsp,0x28; ret;
    // done: xor eax,eax; ret. Nested frames reach the fallthrough before the site's own frame.
    let mut emu = raw(
        &[
            0x85, 0xc9, 0x74, 0x12, 0x48, 0x83, 0xec, 0x28, 0xff, 0xc9, 0xe8, 0xf1, 0xff, 0xff,
            0xff, 0xff, 0xc0, 0x48, 0x83, 0xc4, 0x28, 0xc3, 0x31, 0xc0, 0xc3,
        ],
        C::WindowsX64,
    )?;
    let out = emu.call_sites(&req(&[3]), 10)?;
    assert_eq!(out.total_sites, 1);
    assert!(out.sites[0].reached);
    assert_eq!(out.sites[0].result.stop.kind, "returned");
    assert_eq!(out.sites[0].result.return_value, 2);
    Ok(())
}

#[test]
fn invalid_opcode_traps_and_oversized_registers_are_rejected() -> anyhow::Result<()> {
    let mut emu = raw(&[0x0f, 0x0b, 0xc3], C::WindowsX64)?;
    assert_eq!(emu.run(&req(&[]))?.stop.kind, "trap");
    let mut emu = raw(&[0xc3], C::WindowsX86)?;
    let mut request = req(&[]);
    request.registers.insert("EBX".into(), 0x1_0000_1000);
    assert!(emu.run(&request).is_err());
    Ok(())
}

#[test]
fn bytewise_writes_to_code_merge_into_one_range() -> anyhow::Result<()> {
    // xor eax,eax; l: mov byte ptr [rcx+rax],0; inc eax; cmp eax,0x2100; jne l; ret
    let mut code = vec![
        0x31, 0xc0, 0xc6, 0x04, 0x01, 0x00, 0xff, 0xc0, 0x3d, 0x00, 0x21, 0x00, 0x00, 0x75, 0xf3,
        0xc3,
    ];
    code.resize(0x4000, 0xcc);
    let mut emu = raw(&code, C::WindowsX64)?;
    let mut request = req(&[0x100]);
    request.timeout_ms = 60_000;
    let out = emu.run(&request)?;
    assert_eq!(out.stop.kind, "returned");
    assert_eq!(out.writes.len(), 1);
    assert_eq!(out.writes[0].size, 0x2100);
    Ok(())
}

fn symbol(bytes: &[u8], name: &str) -> anyhow::Result<u64> {
    let image = binfera::extract::image::LoadedImage::parse(bytes)?;
    if bytes.starts_with(b"MZ") {
        goblin::pe::PE::parse(bytes)?
            .exports
            .iter()
            .find(|s| s.name == Some(name))
            .map(|s| image.image_base + s.rva as u64)
    } else {
        let elf = goblin::elf::Elf::parse(bytes)?;
        elf.syms
            .iter()
            .find(|s| elf.strtab.get_at(s.st_name) == Some(name))
            .map(|s| s.st_value + image.load_bias)
    }
    .ok_or_else(|| anyhow::anyhow!("missing symbol {name}"))
}
#[test]
fn aarch64_real_images_arguments_imports_and_call_sites() -> anyhow::Result<()> {
    for bytes in [
        include_bytes!("fixtures/aarch64_decompiler/executable.elf").as_slice(),
        include_bytes!("fixtures/aarch64_decompiler/pie.elf").as_slice(),
        include_bytes!("fixtures/aarch64_decompiler/windows.exe").as_slice(),
    ] {
        let mut emu = Emulator::open(bytes, &BatchOptions::default())?;
        let mut request = req(&[10, 20]);
        request.address = symbol(bytes, "arithmetic")?;
        let out = emu.run(&request)?;
        assert_eq!(
            out.stop.kind,
            "returned",
            "{:?}, calls: {:?}, regs: {:?}",
            out.stop,
            out.calls.iter().take(3).collect::<Vec<_>>(),
            out.registers
        );
        assert_eq!(out.return_value, 50);
        request.args = (1..=9).collect();
        request.address = symbol(bytes, "ninth")?;
        assert_eq!(emu.run(&request)?.return_value, 45);
        request.address = symbol(bytes, "arithmetic")?;
        request.args = vec![4];
        let out = emu.call_sites(&request, 8)?;
        assert!(out
            .sites
            .iter()
            .any(|s| s.reached && s.result.return_value == 19));
        if bytes.starts_with(b"MZ") {
            request.address = symbol(bytes, "imported")?;
            request.args.clear();
            request.import_returns.insert("GetTickCount".into(), 987);
            let out = emu.run(&request)?;
            assert_eq!(
                out.stop.kind,
                "returned",
                "{:?}, calls: {:?}, regs: {:?}",
                out.stop,
                out.calls.iter().take(3).collect::<Vec<_>>(),
                out.registers
            );
            assert_eq!(out.return_value, 987);
            assert_eq!(out.calls.len(), 1);
        } else if bytes.starts_with(b"\x7fELF") && bytes[16] == 3 {
            request.address = symbol(bytes, "imported")?;
            request.args = vec![0x100000];
            request.memory.push(MemoryInput {
                address: 0x100000,
                data: b"hello\0".to_vec(),
            });
            request.import_returns.insert("strlen".into(), 5);
            let out = emu.run(&request)?;
            assert_eq!(
                out.stop.kind,
                "returned",
                "{:?}, calls: {:?}, regs: {:?}",
                out.stop,
                out.calls.iter().take(3).collect::<Vec<_>>(),
                out.registers
            );
            assert_eq!(out.return_value, 5);
            assert_eq!(out.calls.len(), 2);
        }
    }
    Ok(())
}
#[test]
fn rejects_invalid_requests() -> anyhow::Result<()> {
    let mut emu = raw(&[0xc3], C::WindowsX64)?;
    let mut request = req(&[]);
    request.max_steps = 0;
    assert!(emu.run(&request).is_err());
    request = Request::default();
    request.memory.push(MemoryInput {
        address: u64::MAX,
        data: vec![1, 2],
    });
    assert!(emu.run(&request).is_err());
    assert!(serde_json::from_str::<Request>(r#"{"unknown":1}"#).is_err());
    Ok(())
}

#[test]
fn risc32_integer_arguments_and_endianness() -> anyhow::Result<()> {
    for bytes in [
        include_bytes!("fixtures/risc/arm.elf").as_slice(),
        include_bytes!("fixtures/risc/thumb.elf").as_slice(),
        include_bytes!("fixtures/risc/mipsel.elf").as_slice(),
        include_bytes!("fixtures/risc/mips.elf").as_slice(),
    ] {
        let mut emulator = Emulator::open(bytes, &BatchOptions::default())?;
        let mut request = req(&[9, 3]);
        request.address = symbol(bytes, "mix")?;
        let out = emulator.run(&request)?;
        assert_eq!(out.stop.kind, "returned", "{:?}", out.stop);
        assert_eq!(out.return_value, (9 ^ 3) + 11);
        request.address = symbol(bytes, "invoke")? & !1;
        request.args = vec![9];
        let out = emulator.run(&request)?;
        assert_eq!(out.stop.kind, "returned", "{:?}", out.stop);
        assert_eq!(out.return_value, (9 ^ 3) + 11 + 5);
    }
    Ok(())
}
