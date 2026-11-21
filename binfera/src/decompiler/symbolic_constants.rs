//! Tests of the symbolic-constants pass: constant API arguments print as the names of the Win32
//! metadata's enumeration or flag set for that parameter (`MEM_COMMIT | MEM_RESERVE`).
//!
//! The pass is in the native bridge (`symbolicParameters` and `SymbolicSet` in
//! `binfera-ghidra/native/bridge.cc`): applying a Windows pack prototype gives each parameter named
//! by the function's `P:` record an enum type, so Ghidra types the constant arguments with it, and
//! the printer spells a value only when it is a member, or for a flag set an OR of members that
//! covers every bit. Anything else prints as before.
use super::{CallingConvention, DecompilerSession};
use crate::extract::image::{Architecture, SHELLCODE_BASE};
use crate::extract::recovery::analyze_shellcode;
use std::collections::BTreeMap;

const VIRTUAL_ALLOC: usize = 0xc0;
const SET_FILE_POINTER: usize = 0xc8;
const REG_OPEN_KEY: usize = 0xd0;
const CREATE_THREAD: usize = 0xd8;
const SUBKEY: usize = 0xe0;

/// `call [rip+slot]` at the end of `code`.
fn call(code: &mut Vec<u8>, slot: usize) {
    let next = code.len() + 6;
    code.extend([0xff, 0x15]);
    code.extend((slot as i32 - next as i32).to_le_bytes());
}

fn mov_r8d(code: &mut Vec<u8>, value: u32) {
    code.extend([0x41, 0xb8]);
    code.extend(value.to_le_bytes());
}

fn mov_r9d(code: &mut Vec<u8>, value: u32) {
    code.extend([0x41, 0xb9]);
    code.extend(value.to_le_bytes());
}

/// One x64 function calling VirtualAlloc, SetFilePointer, RegOpenKeyExA and CreateThread with
/// constant arguments, decompiled with the Windows x64 pack.
fn decompile() -> anyhow::Result<String> {
    let mut code = vec![0x48, 0x83, 0xec, 0x48]; // sub rsp,0x48
    let alloc = |code: &mut Vec<u8>, kind: u32, protect: u32| {
        code.extend([0x31, 0xc9]); // xor ecx,ecx
        code.extend([0xba, 0x00, 0x10, 0x00, 0x00]); // mov edx,0x1000
        mov_r8d(code, kind);
        mov_r9d(code, protect);
        call(code, VIRTUAL_ALLOC);
    };
    // A flag OR and a single flag.
    alloc(&mut code, 0x3000, 0x40);
    code.extend([0x48, 0x89, 0xc3]); // mov rbx,rax
                                     // Bit 0 belongs to no member of VIRTUAL_ALLOCATION_TYPE.
    alloc(&mut code, 0x3001, 0x04);
    let seek = |code: &mut Vec<u8>, method: u32| {
        code.extend([0x48, 0x89, 0xd9]); // mov rcx,rbx
        code.extend([0x31, 0xd2]); // xor edx,edx
        code.extend([0x45, 0x31, 0xc0]); // xor r8d,r8d
        mov_r9d(code, method);
        call(code, SET_FILE_POINTER);
    };
    // A plain enumeration: 2 is FILE_END; 3 is no member and is not FILE_CURRENT | FILE_END.
    seek(&mut code, 2);
    seek(&mut code, 3);
    // RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software", 0, KEY_READ, &key)
    code.extend([0x48, 0xc7, 0xc1, 0x02, 0x00, 0x00, 0x80]); // mov rcx,0xffffffff80000002
    let next = code.len() + 7;
    code.extend([0x48, 0x8d, 0x15]); // lea rdx,[rip+subkey]
    code.extend((SUBKEY as i32 - next as i32).to_le_bytes());
    code.extend([0x45, 0x31, 0xc0]); // xor r8d,r8d
    mov_r9d(&mut code, 0x20019);
    code.extend([0x48, 0x8d, 0x44, 0x24, 0x38]); // lea rax,[rsp+0x38]
    code.extend([0x48, 0x89, 0x44, 0x24, 0x20]); // mov [rsp+0x20],rax
    call(&mut code, REG_OPEN_KEY);
    // CreateThread(NULL, 0, rbx, NULL, 0, NULL): no flags is 0, not THREAD_CREATE_RUN_IMMEDIATELY.
    code.extend([0x31, 0xc9]); // xor ecx,ecx
    code.extend([0x31, 0xd2]); // xor edx,edx
    code.extend([0x49, 0x89, 0xd8]); // mov r8,rbx
    code.extend([0x45, 0x31, 0xc9]); // xor r9d,r9d
    code.extend([0x48, 0xc7, 0x44, 0x24, 0x20, 0, 0, 0, 0]); // mov qword [rsp+0x20],0
    code.extend([0x48, 0xc7, 0x44, 0x24, 0x28, 0, 0, 0, 0]); // mov qword [rsp+0x28],0
    call(&mut code, CREATE_THREAD);
    code.extend([0x48, 0x83, 0xc4, 0x48, 0xc3]); // add rsp,0x48; ret
    assert!(
        code.len() <= VIRTUAL_ALLOC,
        "code overlaps the import slots"
    );
    code.resize(SUBKEY, 0);
    code.extend(b"Software\0");
    code.resize(0x100, 0);

    let mut analysis = analyze_shellcode(&code, Architecture::X64)?;
    for (slot, name) in [
        (VIRTUAL_ALLOC, "kernel32.VirtualAlloc"),
        (SET_FILE_POINTER, "kernel32.SetFilePointer"),
        (REG_OPEN_KEY, "advapi32.RegOpenKeyExA"),
        (CREATE_THREAD, "kernel32.CreateThread"),
    ] {
        analysis
            .image
            .import_locations
            .insert(SHELLCODE_BASE + slot as u64, name.into());
    }
    let mut session = DecompilerSession::from_analysis(
        &analysis,
        &BTreeMap::new(),
        CallingConvention::WindowsX64,
    )?;
    Ok(session.decompile_function(SHELLCODE_BASE)?.text)
}

/// The arguments of each call to `api` in `text`, whitespace collapsed.
fn calls(text: &str, api: &str) -> Vec<String> {
    let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    flat.match_indices(&format!("{api}("))
        .map(|(at, found)| {
            let rest = &flat[at + found.len()..];
            let mut depth = 1;
            let end = rest
                .char_indices()
                .find(|&(_, c)| {
                    match c {
                        '(' => depth += 1,
                        ')' => depth -= 1,
                        _ => {}
                    }
                    depth == 0
                })
                .map_or(rest.len(), |(i, _)| i);
            rest[..end].to_string()
        })
        .collect()
}

#[test]
fn constant_api_arguments_print_by_name() -> anyhow::Result<()> {
    let text = decompile()?;
    let alloc = calls(&text, "VirtualAlloc");
    assert_eq!(alloc.len(), 2, "{text}");
    // A flag OR, in the metadata's declaration order, and a single flag.
    assert!(
        alloc[0].ends_with(",MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE"),
        "{text}"
    );
    // A value with a bit outside the set stays numeric; the other argument is still named.
    assert!(alloc[1].ends_with(",0x3001,PAGE_READWRITE"), "{text}");

    let seek = calls(&text, "SetFilePointer");
    assert_eq!(seek.len(), 2, "{text}");
    assert!(seek[0].ends_with(",FILE_END"), "{text}");
    // An enumeration names members only: Ghidra's own enum printing would OR FILE_CURRENT and
    // FILE_END into 3.
    assert!(seek[1].ends_with(",3"), "{text}");

    let key = calls(&text, "RegOpenKeyExA");
    assert_eq!(key.len(), 1, "{text}");
    assert!(key[0].starts_with("HKEY_LOCAL_MACHINE,"), "{text}");
    assert!(key[0].contains(",0,KEY_READ,"), "{text}");

    let thread = calls(&text, "CreateThread");
    assert_eq!(thread.len(), 1, "{text}");
    assert!(
        !thread[0].contains("THREAD_CREATE_RUN_IMMEDIATELY"),
        "{text}"
    );
    Ok(())
}
