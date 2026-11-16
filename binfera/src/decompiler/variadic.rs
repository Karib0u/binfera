//! Win64 callees homing all argument registers can consume an untyped va_list.
//! Recover only a contiguous argument area explicitly populated in one block.
use crate::extract::{
    decoder::Flow,
    image::{Architecture, ImageFormat},
    recovery::Analysis,
};
use iced_x86::{InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn calls(analysis: &Analysis) -> Vec<(u64, u64, u64, u32)> {
    let image = &analysis.image;
    if image.format != ImageFormat::Pe || image.architecture != Architecture::X64 {
        return Vec::new();
    }
    let regs = [Register::RCX, Register::RDX, Register::R8, Register::R9];
    let candidates: BTreeSet<_> = analysis
        .functions
        .keys()
        .copied()
        .filter(|&entry| candidate(image, entry))
        .collect();
    let mut found = Vec::new();
    let mut info = InstructionInfoFactory::new();
    for function in analysis.functions.values() {
        for block in &function.blocks {
            let mut written = BTreeSet::new();
            let mut stack = BTreeMap::new();
            for decoded in &block.insns {
                let i = decoded.x86_instruction();
                if matches!(decoded.flow, Flow::Call | Flow::IndirectCall) {
                    if let Some(target) = decoded.direct_target.filter(|t| candidates.contains(t)) {
                        if regs.iter().all(|r| written.contains(r)) {
                            let count = (0..28)
                                .take_while(|slot| stack.contains_key(&(32 + slot * 8)))
                                .count();
                            if count > 0 {
                                found.push((
                                    function.addr,
                                    decoded.address,
                                    target,
                                    4 + count as u32,
                                ));
                            }
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
    found
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
