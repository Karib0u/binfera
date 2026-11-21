//! APIs a program loads at run time: `slot = GetProcAddress(module, "ReadFile")`.
//!
//! Malware and packers often keep the APIs they use out of the import table, resolve them with
//! `GetProcAddress` and call them through a global pointer. Registered as imports, those globals
//! print and type like any import (`ReadFile(hFile, lpBuffer, ...)`) instead of
//! `(*DAT_0040f880)(...)`.
//!
//! Recognized in the machine code, before any function is decompiled, so the result does not
//! depend on which function is decompiled first: a call to `GetProcAddress` whose name argument is
//! the address of a literal string, followed by a store of its result to a fixed address. The name
//! argument is a push on x86 and RDX on x64; the store must come before the result register is
//! overwritten or another call is made. A slot that receives two different names is left out.
use crate::extract::decoder::{DecodedInstruction, Flow};
use crate::extract::image::Architecture;
use crate::extract::recovery::Analysis;
use iced_x86::{Mnemonic, OpKind, Register};
use std::collections::{BTreeMap, BTreeSet};

/// Instructions to look past a `GetProcAddress` call for the store of its result.
const STORE_WINDOW: usize = 12;
/// The longest API name accepted; Win32 names are far shorter.
const MAX_NAME: usize = 128;

/// Pointer slots and the API each holds, from `GetProcAddress` calls with literal names.
/// `thunks` maps import stubs (`jmp [slot]`) to the import they jump to.
pub(super) fn find(analysis: &Analysis, thunks: &BTreeMap<u64, String>) -> BTreeMap<u64, String> {
    let image = &analysis.image;
    let wide = match image.architecture {
        Architecture::X86 => false,
        Architecture::X64 => true,
        _ => return BTreeMap::new(),
    };
    let is_resolver = |import: &str| import.rsplit('.').next() == Some("GetProcAddress");
    let slots: BTreeSet<u64> = image
        .import_locations
        .iter()
        .filter(|(_, name)| is_resolver(name))
        .map(|(address, _)| *address)
        .collect();
    let stubs: BTreeSet<u64> = thunks
        .iter()
        .filter(|(_, name)| is_resolver(name))
        .map(|(address, _)| *address)
        .collect();
    if slots.is_empty() && stubs.is_empty() {
        return BTreeMap::new();
    }
    let name_at = |address: u64| -> Option<String> {
        // An ordinal is a small integer, not a string address.
        if address < 0x10000 {
            return None;
        }
        let bytes = image.bytes_at(address, MAX_NAME + 1)?;
        let end = bytes.iter().position(|b| *b == 0)?;
        let name = std::str::from_utf8(&bytes[..end]).ok()?;
        (!name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'@' || b == b'?')
            && !name.as_bytes()[0].is_ascii_digit())
        .then(|| name.to_owned())
    };

    let mut found: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    for function in analysis.functions.values() {
        // Address order across blocks: a store often follows a null check in the next block.
        let mut insns: Vec<&DecodedInstruction> = function
            .blocks
            .iter()
            .flat_map(|block| &block.insns)
            .collect();
        insns.sort_by_key(|insn| insn.address);
        insns.dedup_by_key(|insn| insn.address);
        // Constant register values (`mov edi, offset aReadFile`), and the values pushed since the
        // last call, newest last.
        let mut registers: BTreeMap<Register, u64> = BTreeMap::new();
        let mut pushes: Vec<Option<u64>> = Vec::new();
        for (index, insn) in insns.iter().enumerate() {
            let op = insn.x86_instruction();
            if matches!(insn.flow, Flow::Call | Flow::IndirectCall) {
                let calls_resolver = insn.memory_target.is_some_and(|t| slots.contains(&t))
                    || insn.direct_target.is_some_and(|t| stubs.contains(&t))
                    || (op.op0_kind() == OpKind::Register
                        && registers
                            .get(&op.op0_register().full_register())
                            .is_some_and(|v| slots.contains(v) || stubs.contains(v)));
                if calls_resolver {
                    let name = if wide {
                        registers.get(&Register::RDX).copied()
                    } else {
                        // stdcall pushes right to left: the module, then the name before it.
                        pushes.len().checked_sub(2).and_then(|i| pushes[i])
                    };
                    if let Some(name) = name.and_then(name_at) {
                        if let Some(slot) = result_store(&insns[index + 1..], wide) {
                            found.entry(slot).or_default().insert(name);
                        }
                    }
                }
                pushes.clear();
                // Volatile registers do not survive a call; the callee-saved ones keep their value.
                for volatile in [
                    Register::RAX,
                    Register::RCX,
                    Register::RDX,
                    Register::R8,
                    Register::R9,
                    Register::R10,
                    Register::R11,
                ] {
                    registers.remove(&volatile);
                }
                continue;
            }
            if !matches!(insn.flow, Flow::Next | Flow::ConditionalBranch) {
                registers.clear();
                pushes.clear();
                continue;
            }
            match op.mnemonic() {
                Mnemonic::Push => {
                    pushes.push(match op.op0_kind() {
                        OpKind::Immediate32 => Some(u64::from(op.immediate32())),
                        OpKind::Immediate8to32 => Some(op.immediate8to32() as u32 as u64),
                        OpKind::Register => {
                            registers.get(&op.op0_register().full_register()).copied()
                        }
                        _ => None,
                    });
                    continue;
                }
                Mnemonic::Mov | Mnemonic::Lea if op.op0_kind() == OpKind::Register => {
                    let target = op.op0_register().full_register();
                    let value = match op.op1_kind() {
                        OpKind::Immediate32 => Some(u64::from(op.immediate32())),
                        OpKind::Immediate32to64 => Some(op.immediate32to64() as u64),
                        OpKind::Immediate64 => Some(op.immediate64()),
                        // `lea rdx, [rip+aReadFile]`, or `mov esi, [GetProcAddress slot]` (held for `call esi`).
                        OpKind::Memory if op.mnemonic() == Mnemonic::Lea => insn.memory_target,
                        OpKind::Memory => insn.memory_target.filter(|t| slots.contains(t)),
                        OpKind::Register => {
                            registers.get(&op.op1_register().full_register()).copied()
                        }
                        _ => None,
                    };
                    match value {
                        Some(value) => registers.insert(target, value),
                        None => registers.remove(&target),
                    };
                }
                _ => {
                    // Any other write to a register forgets its value; any other stack change, the pushes.
                    if op.op0_kind() == OpKind::Register {
                        registers.remove(&op.op0_register().full_register());
                    }
                }
            }
            if op.is_stack_instruction()
                || (op.op0_kind() == OpKind::Register
                    && op.op0_register().full_register() == Register::RSP)
            {
                pushes.clear();
            }
        }
    }
    found
        .into_iter()
        .filter(|(slot, names)| names.len() == 1 && !image.import_locations.contains_key(slot))
        .filter_map(|(slot, names)| names.into_iter().next().map(|name| (slot, name)))
        .collect()
}

/// The fixed address the result of a call is stored to (`mov ds:[slot], eax`), if it is stored
/// before the result register is overwritten or control leaves the straight line.
fn result_store(after: &[&DecodedInstruction], wide: bool) -> Option<u64> {
    let result = if wide { Register::RAX } else { Register::EAX };
    for insn in after.iter().take(STORE_WINDOW) {
        let op = insn.x86_instruction();
        if matches!(
            insn.flow,
            Flow::Call
                | Flow::IndirectCall
                | Flow::Return
                | Flow::UnconditionalBranch
                | Flow::IndirectBranch
        ) {
            return None;
        }
        let fixed = matches!(op.memory_base(), Register::None | Register::RIP)
            && op.memory_index() == Register::None;
        if op.mnemonic() == Mnemonic::Mov
            && op.op0_kind() == OpKind::Memory
            && op.op1_kind() == OpKind::Register
            && op.op1_register() == result
            && fixed
        {
            return insn.memory_target;
        }
        // The result moved to another register first (`mov ebx, eax; ...; mov ds:[slot], ebx`) is
        // not followed; overwriting it ends the search.
        let reads_only = matches!(
            op.mnemonic(),
            Mnemonic::Test | Mnemonic::Cmp | Mnemonic::Push | Mnemonic::Bt
        );
        if !reads_only
            && op.op0_kind() == OpKind::Register
            && op.op0_register().full_register() == result.full_register()
        {
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::image::SHELLCODE_BASE;
    use crate::extract::recovery::analyze_shellcode;

    const NAME: &[u8] = b"ReadFile\0";

    #[test]
    fn x86_push_name_then_store_result() -> anyhow::Result<()> {
        let base = SHELLCODE_BASE;
        let name = base as u32 + 0x40;
        let slot = base as u32 + 0x80;
        let resolver = base as u32 + 0x90;
        let mut bytes = vec![0x68];
        bytes.extend(name.to_le_bytes()); // push offset aReadFile
        bytes.push(0x53); // push ebx
        bytes.extend([0xff, 0x15]);
        bytes.extend(resolver.to_le_bytes()); // call [GetProcAddress]
        bytes.extend([0x85, 0xc0]); // test eax,eax
        bytes.push(0xa3);
        bytes.extend(slot.to_le_bytes()); // mov ds:[slot],eax
        bytes.push(0xc3);
        bytes.resize(0x40, 0x90);
        bytes.extend(NAME);
        bytes.resize(0xa0, 0);
        let mut analysis = analyze_shellcode(&bytes, Architecture::X86)?;
        analysis
            .image
            .import_locations
            .insert(u64::from(resolver), "kernel32.GetProcAddress".into());
        let found = find(&analysis, &BTreeMap::new());
        assert_eq!(
            found.get(&u64::from(slot)).map(String::as_str),
            Some("ReadFile")
        );
        Ok(())
    }

    /// `lea rdx,[rip+name]; mov rcx,rbx; call [rip+resolver]; test rax,rax; mov [rip+slot],rax`
    /// for each name, then `ret`, with the names, the resolver slot and the result slot after it.
    fn x64_resolver(names: &[&[u8]]) -> anyhow::Result<(Analysis, u64)> {
        let (text, resolver, slot) = (0x80usize, 0xc0usize, 0xd0usize);
        let rel =
            |at: usize, len: usize, target: usize| ((target as i64) - ((at + len) as i64)) as i32;
        let mut code = Vec::new();
        let mut at_name = text;
        for _ in names {
            let at = code.len();
            code.extend([0x48, 0x8d, 0x15]);
            code.extend(rel(at, 7, at_name).to_le_bytes());
            code.extend([0x48, 0x89, 0xd9]);
            let at = code.len();
            code.extend([0xff, 0x15]);
            code.extend(rel(at, 6, resolver).to_le_bytes());
            code.extend([0x48, 0x85, 0xc0]);
            let at = code.len();
            code.extend([0x48, 0x89, 0x05]);
            code.extend(rel(at, 7, slot).to_le_bytes());
            at_name += 0x10;
        }
        code.push(0xc3);
        for (i, name) in names.iter().enumerate() {
            code.resize(text + i * 0x10, 0x90);
            code.extend(*name);
        }
        code.resize(0xe0, 0);
        let mut analysis = analyze_shellcode(&code, Architecture::X64)?;
        analysis.image.import_locations.insert(
            SHELLCODE_BASE + resolver as u64,
            "kernel32.GetProcAddress".into(),
        );
        Ok((analysis, SHELLCODE_BASE + slot as u64))
    }

    #[test]
    fn x64_name_in_rdx_then_store_result() -> anyhow::Result<()> {
        let (analysis, slot) = x64_resolver(&[NAME])?;
        let found = find(&analysis, &BTreeMap::new());
        assert_eq!(found.get(&slot).map(String::as_str), Some("ReadFile"));
        Ok(())
    }

    #[test]
    fn a_slot_given_two_names_is_left_out() -> anyhow::Result<()> {
        let (analysis, _) = x64_resolver(&[NAME, b"WriteFile\0"])?;
        assert!(find(&analysis, &BTreeMap::new()).is_empty());
        Ok(())
    }
}
