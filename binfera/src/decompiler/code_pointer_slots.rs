//! Globals that only ever hold the address of one function of the program.
//!
//! A program often keeps a function pointer in a global, sets it once, and calls through it
//! (`DAT_x = FUN_00401234;` ... `(*DAT_x)(a, b)`): a hook installed at start-up, or a pointer
//! chosen by a compile-time switch. Told that the global is that function, Ghidra turns the
//! indirect call into a direct one and prints it with the callee's prototype.
//!
//! Found in the machine code of the whole image, before any function is decompiled, so the result
//! does not depend on which function is decompiled first. A global qualifies only when every
//! way it can get its value is known and the same:
//!
//! * each instruction that writes the fixed address stores the same function entry, as an
//!   immediate (`mov dword ptr ds:[slot], offset f`, `mov qword ptr [rip+slot], rax` after
//!   `lea rax, [rip+f]`), and the file's own bytes at the slot are zero or that entry too. A global
//!   that is never written and starts as that entry qualifies as well;
//! * no write is of another value, of an unknown register, or by an instruction that only
//!   modifies it (`xchg`, `inc`, `rep stos`);
//! * its address is never taken: no `lea`, no `push offset slot`, no `[slot + index]`, and no
//!   pointer to it in the image's data, since a write through such a pointer cannot be seen.
//!
//! A write through a pointer to an enclosing object or one computed at run time is not detected.
//! Only PE images are scanned: an ELF or Mach-O GOT slot is written by the dynamic loader.
use crate::extract::decoder::{DecodedInstruction, Flow};
use crate::extract::image::{Architecture, ImageFormat};
use crate::extract::recovery::Analysis;
use iced_x86::{InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use std::collections::{BTreeMap, BTreeSet};

/// Everything the instructions do to one fixed address.
#[derive(Default)]
struct Writes {
    /// The values stored, when known.
    values: BTreeSet<u64>,
    /// Some write whose value is unknown, or that is not a plain store.
    unknown: bool,
}

#[derive(Default)]
struct Facts {
    /// Fixed addresses an instruction refers to (`mov eax, ds:[a]`, `call dword ptr ds:[a]`).
    referenced: BTreeSet<u64>,
    writes: BTreeMap<u64, Writes>,
    /// Addresses the program computes: `lea`, an immediate, a displacement added to a register.
    taken: BTreeSet<u64>,
}

/// Pointer slots and the entry of the function each one holds.
pub(super) fn find(analysis: &Analysis) -> BTreeMap<u64, u64> {
    let image = &analysis.image;
    let (ptr, wide) = match image.architecture {
        Architecture::X86 => (4u64, false),
        Architecture::X64 => (8, true),
        _ => return BTreeMap::new(),
    };
    if !matches!(image.format, ImageFormat::Pe | ImageFormat::Sc) {
        return BTreeMap::new();
    }
    let is_data = |address: u64| {
        image
            .section_containing(address)
            .is_some_and(|section| section.permissions.write)
    };
    let mut facts = Facts::default();
    let mut info = InstructionInfoFactory::new();
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    for function in analysis.functions.values() {
        let block_starts: BTreeSet<u64> = function.blocks.iter().map(|block| block.addr).collect();
        let mut insns: Vec<&DecodedInstruction> = function
            .blocks
            .iter()
            .flat_map(|block| &block.insns)
            .collect();
        insns.sort_by_key(|insn| insn.address);
        insns.dedup_by_key(|insn| insn.address);
        // Constant register values along the straight line: only what a block itself loaded.
        let mut registers: BTreeMap<Register, u64> = BTreeMap::new();
        for insn in insns {
            if block_starts.contains(&insn.address) {
                registers.clear();
            }
            seen.insert(insn.address);
            let op = insn.x86_instruction();
            let stored = if op.mnemonic() == Mnemonic::Mov
                && op.op0_kind() == OpKind::Memory
                && op.memory_size().size() as u64 == ptr
            {
                match op.op1_kind() {
                    OpKind::Immediate32 => Some(u64::from(op.immediate32())),
                    OpKind::Immediate32to64 => Some(op.immediate32to64() as u64),
                    OpKind::Immediate64 => Some(op.immediate64()),
                    OpKind::Register => registers.get(&op.op1_register().full_register()).copied(),
                    _ => None,
                }
            } else {
                None
            };
            observe(insn, stored, wide, &is_data, &mut info, &mut facts);
            // Registers: forget what the instruction writes, then learn constants.
            let flow = insn.flow;
            for used in info.info(op).used_registers() {
                if matches!(
                    used.access(),
                    OpAccess::Write
                        | OpAccess::CondWrite
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                ) {
                    registers.remove(&used.register().full_register());
                }
            }
            if matches!(flow, Flow::Call | Flow::IndirectCall) {
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
            } else if !matches!(flow, Flow::Next | Flow::ConditionalBranch) {
                registers.clear();
            }
            if matches!(op.mnemonic(), Mnemonic::Mov | Mnemonic::Lea)
                && op.op0_kind() == OpKind::Register
                && matches!(flow, Flow::Next)
            {
                let target = op.op0_register().full_register();
                let value = match op.op1_kind() {
                    OpKind::Immediate32 => Some(u64::from(op.immediate32())),
                    OpKind::Immediate32to64 => Some(op.immediate32to64() as u64),
                    OpKind::Immediate64 => Some(op.immediate64()),
                    OpKind::Memory if op.mnemonic() == Mnemonic::Lea => {
                        fixed(op).then_some(insn.memory_target).flatten()
                    }
                    OpKind::Register if op.mnemonic() == Mnemonic::Mov => {
                        registers.get(&op.op1_register().full_register()).copied()
                    }
                    _ => None,
                };
                if let Some(value) = value {
                    registers.insert(target, value);
                }
            }
        }
    }
    // Instructions recovery found outside any function: they can write a slot too.
    for insn in analysis.instructions.values() {
        if !seen.contains(&insn.address) {
            observe(insn, None, wide, &is_data, &mut info, &mut facts);
        }
    }

    let entries = &analysis.functions;
    let read_ptr = |address: u64| -> Option<u64> {
        let bytes = image.bytes_at(address, ptr as usize)?;
        if bytes.len() < ptr as usize {
            return None;
        }
        let mut word = [0u8; 8];
        word[..bytes.len()].copy_from_slice(bytes);
        Some(u64::from_le_bytes(word))
    };
    let mut found: BTreeMap<u64, u64> = BTreeMap::new();
    for &slot in &facts.referenced {
        let Some(section) = image.section_containing(slot) else {
            continue;
        };
        let inside = slot
            .checked_add(ptr)
            .zip(section.end_address())
            .is_some_and(|(end, limit)| end <= limit);
        if !section.permissions.write
            || !inside
            || slot % ptr != 0
            || image.import_locations.contains_key(&slot)
            || image.external_bindings.contains_key(&slot)
            || facts.taken.contains(&slot)
        {
            continue;
        }
        // A write that overlaps the slot without being at it (a byte store into it).
        if facts
            .writes
            .range(slot.saturating_sub(ptr - 1)..slot.saturating_add(ptr))
            .any(|(at, _)| *at != slot)
        {
            continue;
        }
        let mut values: BTreeSet<u64> = BTreeSet::new();
        if let Some(writes) = facts.writes.get(&slot) {
            if writes.unknown {
                continue;
            }
            values.extend(&writes.values);
        }
        // The file's own contents: zero is no value; anything else is one.
        match read_ptr(slot) {
            Some(0) => {}
            Some(initial) => {
                values.insert(initial);
            }
            None => continue,
        }
        let mut values = values.into_iter();
        if let (Some(target), None) = (values.next(), values.next()) {
            if entries.contains_key(&target) {
                found.insert(slot, target);
            }
        }
    }
    if found.is_empty() {
        return found;
    }
    // A pointer to a slot anywhere in the image's data: whoever holds it can write the slot.
    for (index, section) in image.sections.iter().enumerate() {
        if section.permissions.execute {
            continue;
        }
        let Some(data) = image.section_bytes(index) else {
            continue;
        };
        let step = ptr as usize;
        let mut offset = 0;
        while offset + step <= data.len() {
            let mut word = [0u8; 8];
            word[..step].copy_from_slice(&data[offset..offset + step]);
            let value = u64::from_le_bytes(word);
            let at = section.address + offset as u64;
            if value != 0 && at != value {
                found.remove(&value);
            }
            offset += step;
        }
        if found.is_empty() {
            break;
        }
    }
    found
}

/// A memory operand at a fixed address: no base or index register (or only `rip`), no
/// `fs`/`gs` override.
fn fixed(op: &iced_x86::Instruction) -> bool {
    matches!(op.memory_base(), Register::None | Register::RIP)
        && op.memory_index() == Register::None
        && !matches!(op.segment_prefix(), Register::FS | Register::GS)
}

/// Record what one instruction does to fixed addresses, and which addresses it computes.
/// `stored` is the known value of a pointer-sized `mov` to memory.
fn observe(
    insn: &DecodedInstruction,
    stored: Option<u64>,
    wide: bool,
    is_data: &impl Fn(u64) -> bool,
    info: &mut InstructionInfoFactory,
    facts: &mut Facts,
) {
    let op = insn.x86_instruction();
    let mask = |value: u64| if wide { value } else { value & 0xffff_ffff };
    for operand in 0..op.op_count() {
        let value = match op.op_kind(operand) {
            OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
            | OpKind::Immediate32
            | OpKind::Immediate64 => Some(mask(op.immediate(operand))),
            _ => None,
        };
        // Storing an address is the same as taking it, but `mov [slot], offset f` is the write
        // being looked for and its value is not a slot.
        if let Some(value) = value.filter(|value| is_data(*value)) {
            facts.taken.insert(value);
        }
    }
    if op.mnemonic() == Mnemonic::Lea || !fixed(op) {
        // `lea reg, [rip+slot]`, `[slot + eax*4]`, `[ebx + slot]`: the address is computed.
        let computed = insn
            .memory_target
            .unwrap_or_else(|| mask(op.memory_displacement64()));
        if (op.memory_displ_size() > 0 || insn.memory_target.is_some()) && is_data(computed) {
            facts.taken.insert(computed);
        }
        return;
    }
    let Some(target) = insn.memory_target else {
        return;
    };
    facts.referenced.insert(target);
    let info = info.info(op);
    // Only the operand at the fixed address: a call's push of the return address, or a string
    // instruction's store through `edi`, is a write elsewhere.
    let writes = info.used_memory().iter().any(|used| {
        matches!(used.base(), Register::None | Register::RIP)
            && used.index() == Register::None
            && matches!(
                used.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            )
    });
    if !writes {
        return;
    }
    let entry = facts.writes.entry(target).or_default();
    match stored {
        Some(value) => {
            entry.values.insert(value);
        }
        None => entry.unknown = true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::image::SHELLCODE_BASE;
    use crate::extract::recovery::analyze_shellcode;

    fn rel(at: usize, len: usize, target: usize) -> [u8; 4] {
        (((target as i64) - ((at + len) as i64)) as i32).to_le_bytes()
    }

    /// x64 code. The entry routine runs `sets` (each `lea rax,[rip+f]; mov [rip+slot],rax`), then
    /// whatever `extra` returns for its position, then calls the routine at `caller` (which calls
    /// through the slot) and the functions at 0x80 and 0x90. The slot is at 0xc0 and starts as
    /// `initial`.
    fn image(
        sets: &[usize],
        extra: &dyn Fn(usize) -> Vec<u8>,
        initial: u64,
    ) -> anyhow::Result<(Analysis, u64, u64)> {
        let slot = 0xc0usize;
        let mut code = Vec::new();
        for target in sets {
            let at = code.len();
            code.extend([0x48, 0x8d, 0x05]); // lea rax,[rip+f]
            code.extend(rel(at, 7, *target));
            let at = code.len();
            code.extend([0x48, 0x89, 0x05]); // mov [rip+slot],rax
            code.extend(rel(at, 7, slot));
        }
        code.extend(extra(code.len()));
        let calls = code.len();
        let caller = 0x40usize;
        for target in [caller, 0x80, 0x90] {
            let at = code.len();
            code.push(0xe8); // call target
            code.extend(rel(at, 5, target));
        }
        code.push(0xc3);
        assert!(code.len() <= caller, "{calls}");
        code.resize(caller, 0xcc);
        code.extend([0x48, 0x83, 0xec, 0x28]); // sub rsp,0x28
        let at = code.len();
        code.extend([0xff, 0x15]); // call [rip+slot]
        code.extend(rel(at, 6, slot));
        code.extend([0x48, 0x83, 0xc4, 0x28, 0xc3]); // add rsp,0x28; ret
        code.resize(0x80, 0xcc);
        code.push(0xc3); // f1 at 0x80
        code.resize(0x90, 0xcc);
        code.extend([0x31, 0xc0, 0xc3]); // f2 at 0x90: xor eax,eax; ret
        code.resize(slot, 0xcc);
        code.extend(initial.to_le_bytes());
        code.resize(0xe0, 0);
        let analysis = analyze_shellcode(&code, Architecture::X64)?;
        for entry in [0, caller as u64, 0x80, 0x90] {
            assert!(
                analysis.functions.contains_key(&(SHELLCODE_BASE + entry)),
                "function {entry:#x} missing: {:x?}",
                analysis.functions.keys().collect::<Vec<_>>()
            );
        }
        Ok((analysis, SHELLCODE_BASE + slot as u64, SHELLCODE_BASE))
    }

    const NONE: &dyn Fn(usize) -> Vec<u8> = &|_| Vec::new();

    #[test]
    fn a_global_set_to_one_function_is_that_function() -> anyhow::Result<()> {
        let (analysis, slot, base) = image(&[0x80], NONE, 0)?;
        assert_eq!(find(&analysis).get(&slot), Some(&(base + 0x80)));
        Ok(())
    }

    #[test]
    fn the_same_function_stored_twice_is_still_one() -> anyhow::Result<()> {
        let (analysis, slot, base) = image(&[0x80, 0x80], NONE, 0)?;
        assert_eq!(find(&analysis).get(&slot), Some(&(base + 0x80)));
        Ok(())
    }

    #[test]
    fn two_different_functions_leave_the_global_alone() -> anyhow::Result<()> {
        let (analysis, _, _) = image(&[0x80, 0x90], NONE, 0)?;
        assert!(find(&analysis).is_empty());
        Ok(())
    }

    #[test]
    fn a_conflicting_initial_value_leaves_the_global_alone() -> anyhow::Result<()> {
        let (analysis, _, _) = image(&[0x80], NONE, SHELLCODE_BASE + 0x90)?;
        assert!(find(&analysis).is_empty());
        Ok(())
    }

    #[test]
    fn an_initial_value_alone_is_enough_when_nothing_writes_the_global() -> anyhow::Result<()> {
        let (analysis, slot, base) = image(&[], NONE, SHELLCODE_BASE + 0x90)?;
        assert_eq!(find(&analysis).get(&slot), Some(&(base + 0x90)));
        Ok(())
    }

    #[test]
    fn a_store_of_an_unknown_register_leaves_the_global_alone() -> anyhow::Result<()> {
        let (analysis, _, _) = image(
            &[0x80],
            &|at| {
                // mov rax,rbx; mov [rip+slot],rax
                let mut code = vec![0x48, 0x89, 0xd8, 0x48, 0x89, 0x05];
                code.extend(rel(at + 3, 7, 0xc0));
                code
            },
            0,
        )?;
        assert!(find(&analysis).is_empty());
        Ok(())
    }

    #[test]
    fn a_taken_address_leaves_the_global_alone() -> anyhow::Result<()> {
        let (analysis, _, _) = image(
            &[0x80],
            &|at| {
                // lea rcx,[rip+slot]
                let mut code = vec![0x48, 0x8d, 0x0d];
                code.extend(rel(at, 7, 0xc0));
                code
            },
            0,
        )?;
        assert!(find(&analysis).is_empty());
        Ok(())
    }

    #[test]
    fn a_reset_to_zero_leaves_the_global_alone() -> anyhow::Result<()> {
        let (analysis, _, _) = image(
            &[0x80],
            &|at| {
                // mov qword ptr [rip+slot],0
                let mut code = vec![0x48, 0xc7, 0x05];
                code.extend(rel(at, 11, 0xc0));
                code.extend(0u32.to_le_bytes());
                code
            },
            0,
        )?;
        assert!(find(&analysis).is_empty());
        Ok(())
    }

    #[test]
    fn a_value_that_is_not_a_function_entry_is_ignored() -> anyhow::Result<()> {
        let (analysis, _, _) = image(&[0x88], NONE, 0)?;
        assert!(find(&analysis).is_empty());
        Ok(())
    }

    #[test]
    fn x86_immediate_store_of_a_function_address() -> anyhow::Result<()> {
        let base = SHELLCODE_BASE as u32;
        let (slot, target) = (base + 0x80, base + 0x60);
        let mut code = Vec::new();
        code.extend([0xc7, 0x05]); // mov dword ptr ds:[slot], offset f
        code.extend(slot.to_le_bytes());
        code.extend(target.to_le_bytes());
        code.extend([0xe8]); // call caller
        code.extend((0x40i32 - (code.len() as i32 + 4)).to_le_bytes());
        code.extend([0xe8]); // call f
        code.extend((0x60i32 - (code.len() as i32 + 4)).to_le_bytes());
        code.push(0xc3);
        code.resize(0x40, 0xcc);
        code.extend([0xff, 0x15]); // call dword ptr ds:[slot]
        code.extend(slot.to_le_bytes());
        code.push(0xc3);
        code.resize(0x60, 0xcc);
        code.push(0xc3); // f
        code.resize(0x80, 0xcc);
        code.extend([0; 4]); // the slot
        let analysis = analyze_shellcode(&code, Architecture::X86)?;
        assert!(analysis.functions.contains_key(&u64::from(target)));
        assert_eq!(
            find(&analysis).get(&u64::from(slot)),
            Some(&u64::from(target))
        );
        Ok(())
    }
}
