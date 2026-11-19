//! Win64 call sites with a contiguous argument area explicitly populated in one block.
use crate::extract::{
    decoder::Flow,
    image::{Architecture, ImageFormat},
    recovery::{Analysis, Function},
};
use iced_x86::{InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub(super) struct Calls {
    pub variadic: Vec<(u64, u64, u64, u32)>,
    pub fifth_argument: Vec<u64>,
}

pub(super) fn calls(analysis: &Analysis) -> Calls {
    let image = &analysis.image;
    if image.format != ImageFormat::Pe || image.architecture != Architecture::X64 {
        return Calls::default();
    }
    let regs = [Register::RCX, Register::RDX, Register::R8, Register::R9];
    let candidates: BTreeSet<_> = analysis
        .functions
        .keys()
        .copied()
        .filter(|&entry| candidate(image, entry))
        .collect();
    let mut found = Calls::default();
    let mut fifth_argument = BTreeMap::new();
    let mut info = InstructionInfoFactory::new();
    for function in analysis.functions.values() {
        for block in &function.blocks {
            let mut written = BTreeSet::new();
            let mut stack = BTreeMap::new();
            for decoded in &block.insns {
                let i = decoded.x86_instruction();
                if matches!(decoded.flow, Flow::Call | Flow::IndirectCall) {
                    if let Some(target) = decoded.direct_target {
                        let all_registers = regs.iter().all(|r| written.contains(r));
                        let explicit_fifth = all_registers && stack.contains_key(&32);
                        fifth_argument
                            .entry(target)
                            .and_modify(|all| *all &= explicit_fifth)
                            .or_insert(explicit_fifth);
                        if explicit_fifth && candidates.contains(&target) {
                            let count = (0..28)
                                .take_while(|slot| stack.contains_key(&(32 + slot * 8)))
                                .count();
                            found.variadic.push((
                                function.addr,
                                decoded.address,
                                target,
                                4 + count as u32,
                            ));
                        }
                    }
                    written.clear();
                    stack.clear();
                    continue;
                }
                let facts = info.info(i);
                for reg in facts.used_registers() {
                    if matches!(reg.access(), OpAccess::Write | OpAccess::ReadWrite) {
                        let r = reg.register().full_register();
                        if r == Register::RSP {
                            written.clear();
                            stack.clear();
                        }
                        if regs.contains(&r) && reg.register().size() >= 4 {
                            written.insert(r);
                        }
                    }
                }
                if i.mnemonic() == Mnemonic::Mov
                    && i.op0_kind() == OpKind::Memory
                    && i.memory_base() == Register::RSP
                    && i.memory_index() == Register::None
                    && i.memory_size().size() == 8
                {
                    let offset = i.memory_displacement64();
                    if (32..256).contains(&offset) && offset % 8 == 0 {
                        stack.insert(offset, ());
                    }
                }
            }
        }
    }
    found.fifth_argument = fifth_argument
        .into_iter()
        .filter(|(target, all_sites_write)| {
            *all_sites_write
                && !candidates.contains(target)
                && analysis
                    .functions
                    .get(target)
                    .is_some_and(|function| reads_fifth_argument(function, &mut info))
        })
        .map(|(target, _)| target)
        .collect();
    found
}

// Follow the entry prologue until its first branch or call. RBP may hold an
// offset frame pointer, so both tracked bases are relative to incoming RSP.
fn reads_fifth_argument(function: &Function, info: &mut InstructionInfoFactory) -> bool {
    let Some(entry) = function
        .blocks
        .iter()
        .find(|block| block.addr == function.addr)
    else {
        return false;
    };
    let mut rsp = 0i64;
    let mut rbp = None;
    for decoded in entry.insns.iter().take(48) {
        if decoded.flow != Flow::Next {
            break;
        }
        let instruction = decoded.x86_instruction();
        let facts = info.info(instruction);
        for memory in facts.used_memory() {
            let base = match memory.base() {
                Register::RSP => Some(rsp),
                Register::RBP => rbp,
                _ => None,
            };
            if memory.index() == Register::None
                && base
                    .is_some_and(|offset| offset.wrapping_add(memory.displacement() as i64) == 0x28)
            {
                return memory.access() == OpAccess::Read
                    && matches!(memory.memory_size().size(), 4 | 8);
            }
        }
        let writes = |register| {
            facts.used_registers().iter().any(|used| {
                used.register().full_register() == register
                    && matches!(
                        used.access(),
                        OpAccess::Write
                            | OpAccess::CondWrite
                            | OpAccess::ReadWrite
                            | OpAccess::ReadCondWrite
                    )
            })
        };
        if writes(Register::RBP) {
            rbp = match instruction.mnemonic() {
                Mnemonic::Mov
                    if instruction.op0_register() == Register::RBP
                        && instruction.op1_register() == Register::RSP =>
                {
                    Some(rsp)
                }
                Mnemonic::Lea
                    if instruction.op0_register() == Register::RBP
                        && instruction.memory_base() == Register::RSP
                        && instruction.memory_index() == Register::None =>
                {
                    rsp.checked_add(instruction.memory_displacement64() as i64)
                }
                _ => None,
            };
        }
        if writes(Register::RSP) {
            let delta = match instruction.mnemonic() {
                Mnemonic::Push | Mnemonic::Pop => i64::from(instruction.stack_pointer_increment()),
                Mnemonic::Add | Mnemonic::Sub
                    if instruction.op0_register() == Register::RSP
                        && matches!(
                            instruction.op1_kind(),
                            OpKind::Immediate8to64 | OpKind::Immediate32to64
                        ) =>
                {
                    let amount = instruction.immediate(1) as i64;
                    if instruction.mnemonic() == Mnemonic::Add {
                        amount
                    } else {
                        -amount
                    }
                }
                _ => return false,
            };
            rsp += delta;
        }
    }
    false
}

fn candidate(image: &crate::extract::image::LoadedImage, entry: u64) -> bool {
    let regs = [Register::RCX, Register::RDX, Register::R8, Register::R9];
    let mut mask = 0;
    let mut address = entry;
    for _ in 0..4 {
        let Ok(decoded) = image.decode_at(address) else {
            return false;
        };
        let i = decoded.x86_instruction();
        if i.mnemonic() != Mnemonic::Mov
            || i.op0_kind() != OpKind::Memory
            || i.op1_kind() != OpKind::Register
            || i.memory_base() != Register::RSP
            || i.memory_index() != Register::None
            || !matches!(i.memory_size().size(), 4 | 8)
        {
            return false;
        }
        let Some(slot) = regs
            .iter()
            .position(|&r| r == i.op1_register().full_register())
        else {
            return false;
        };
        if i.memory_displacement64() != (slot as u64 + 1) * 8 || mask & (1 << slot) != 0 {
            return false;
        }
        mask |= 1 << slot;
        address = decoded.next_address;
    }
    mask == 15 && va_list_or_unused_homes(image, address)
}

// A normal fixed-argument callee also homes registers. Require a pointer into
// its argument area, or a straight-line stub that never reads those arguments.
fn va_list_or_unused_homes(image: &crate::extract::image::LoadedImage, mut address: u64) -> bool {
    let mut delta = 0i64;
    let mut live = BTreeSet::from([Register::RCX, Register::RDX, Register::R8, Register::R9]);
    let mut info = InstructionInfoFactory::new();
    for _ in 0..128 {
        let Ok(decoded) = image.decode_at(address) else {
            return false;
        };
        let i = decoded.x86_instruction();
        if i.mnemonic() == Mnemonic::Lea
            && i.memory_base() == Register::RSP
            && i.memory_index() == Register::None
        {
            let offset = delta + i.memory_displacement64() as i64;
            if (8..=256).contains(&offset) {
                return true;
            }
        }
        if decoded.flow == Flow::Return {
            return delta == 0;
        }
        if decoded.flow != Flow::Next {
            return false;
        }
        let facts = info.info(i);
        for memory in facts.used_memory() {
            if memory.base() == Register::RSP && memory.index() == Register::None {
                let offset = delta + memory.displacement() as i64;
                if offset >= 8
                    && matches!(
                        memory.access(),
                        OpAccess::Read
                            | OpAccess::CondRead
                            | OpAccess::ReadWrite
                            | OpAccess::ReadCondWrite
                    )
                {
                    return false;
                }
            }
        }
        for reg in facts.used_registers() {
            let register = reg.register().full_register();
            if live.contains(&register)
                && matches!(
                    reg.access(),
                    OpAccess::Read
                        | OpAccess::CondRead
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                )
            {
                return false;
            }
            if matches!(reg.access(), OpAccess::Write) {
                live.remove(&register);
            }
        }
        if i.op0_register() == Register::RSP {
            if !matches!(i.mnemonic(), Mnemonic::Sub | Mnemonic::Add)
                || matches!(i.op1_kind(), OpKind::Register | OpKind::Memory)
            {
                return false;
            }
            let amount = i.immediate(1) as i64;
            delta += if i.mnemonic() == Mnemonic::Sub {
                -amount
            } else {
                amount
            };
        } else if facts.used_registers().iter().any(|r| {
            r.register() == Register::RSP
                && matches!(r.access(), OpAccess::Write | OpAccess::ReadWrite)
        }) {
            return false;
        }
        address = decoded.next_address;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::image::LoadedImage;

    #[test]
    fn fifth_argument_follows_the_entry_frame_pointer() -> anyhow::Result<()> {
        fn detects(bytes: &[u8]) -> anyhow::Result<bool> {
            let analysis = crate::extract::recovery::analyze_shellcode(bytes, Architecture::X64)?;
            let entry = analysis
                .image
                .entry_point
                .ok_or_else(|| anyhow::anyhow!("missing entry"))?;
            let function = &analysis.functions[&entry];
            Ok(reads_fifth_argument(
                function,
                &mut InstructionInfoFactory::new(),
            ))
        }

        let mut bytes = [
            0x55, // push rbp
            0x48, 0x8d, 0x6c, 0x24, 0xe9, // lea rbp, [rsp-0x17]
            0x48, 0x83, 0xec, 0x30, // sub rsp, 0x30
            0x48, 0x8b, 0x75, 0x47, // mov rsi, [rbp+0x47], incoming RSP+0x28
            0x48, 0x83, 0xc4, 0x30, // add rsp, 0x30
            0x5d, 0xc3, // pop rbp; ret
        ];
        assert!(detects(&bytes)?);
        bytes[13] = 0x3f; // RSP+0x20 is a register home slot
        assert!(!detects(&bytes)?);
        bytes[13] = 0x47;
        bytes[11] = 0x89; // unconditionally overwriting the slot does not read the input
        assert!(!detects(&bytes)?);
        Ok(())
    }

    #[test]
    fn mixed_width_homes_preserve_integer_arguments() {
        let mut bytes = vec![
            0x44, 0x89, 0x4c, 0x24, 0x20, 0x44, 0x89, 0x44, 0x24, 0x18, 0x48, 0x89, 0x54, 0x24,
            0x10, 0x48, 0x89, 0x4c, 0x24, 0x08, 0xc3,
        ];
        let image = LoadedImage::from_shellcode_at(&bytes, Architecture::X64, 0);
        assert!(candidate(&image, 0));
        bytes.pop();
        bytes.extend_from_slice(&[0x8b, 0x44, 0x24, 0x18, 0xc3]);
        let image = LoadedImage::from_shellcode_at(&bytes, Architecture::X64, 0);
        assert!(!candidate(&image, 0));
    }
    #[test]
    fn homing_registers_alone_does_not_prove_variadic_arguments() {
        for (bytes, expected) in [
            (
                vec![
                    0x48, 0x83, 0xec, 0x18, 0x8b, 0x44, 0x24, 8, 0x48, 0x83, 0xc4, 0x18, 0xc3,
                ],
                true,
            ),
            (vec![0x8b, 0x44, 0x24, 8, 0xc3], false),
            (vec![0x48, 0x8d, 0x44, 0x24, 0x28, 0xc3], true),
            (vec![0x48, 0x89, 0xc8, 0xc3], false),
            (vec![0xe8, 0, 0, 0, 0, 0xc3], false),
        ] {
            let image = LoadedImage::from_shellcode_at(&bytes, Architecture::X64, 0);
            assert_eq!(va_list_or_unused_homes(&image, 0), expected);
        }
    }
}
