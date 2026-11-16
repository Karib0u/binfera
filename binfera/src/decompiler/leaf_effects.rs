//! Physical register facts from bounded, fully decoded x86 leaf bodies.
use super::{Analysis, Architecture, Flow};
use iced_x86::{InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use std::collections::{BTreeMap, VecDeque};

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Effects {
    /// Bytes above this offset in EAX/RAX are zero on every return; 0 means unknown.
    pub zero_from: u32,
    pub preserves_ecx: bool,
}

pub(super) fn infer(analysis: &Analysis, entry: u64) -> Option<Effects> {
    if !matches!(
        analysis.image.architecture,
        Architecture::X86 | Architecture::X64
    ) {
        return None;
    }
    let function = analysis.functions.get(&entry)?;
    // Local policy: do not turn whole-image setup into another decompiler pass.
    if function
        .blocks
        .iter()
        .flat_map(|b| &b.insns)
        .take(257)
        .count()
        > 256
    {
        return None;
    }
    let instructions: BTreeMap<_, _> = function
        .blocks
        .iter()
        .flat_map(|b| &b.insns)
        .map(|i| (i.address, i))
        .collect();
    let wide = analysis.image.architecture == Architecture::X64;
    let mut states = BTreeMap::from([(entry, 0u64)]);
    let mut queue = VecDeque::from([entry]);
    let mut returns = BTreeMap::new();
    let mut preserves_ecx = true;
    let mut info = InstructionInfoFactory::new();
    let mut work = 0;
    while let Some(at) = queue.pop_front() {
        work += 1;
        if work > 2048 || (at != entry && analysis.functions.contains_key(&at)) {
            return None;
        }
        let decoded = instructions.get(&at)?;
        let insn = decoded.x86_instruction();
        let facts = info.info(insn);
        let mut zero = *states.get(&at)?;
        let before = zero;
        for used in facts.used_registers() {
            // Ghidra excludes unaffected storage from parameter recovery. Only
            // install that effect for a register the leaf does not use at all.
            preserves_ecx &= used.register().full_register() != Register::RCX;
            if !matches!(
                used.access(),
                OpAccess::Write
                    | OpAccess::ReadWrite
                    | OpAccess::CondWrite
                    | OpAccess::ReadCondWrite
            ) {
                continue;
            }
            let reg = used.register();
            if reg.full_register() == Register::RAX {
                let shift = if reg == Register::AH { 8 } else { 0 };
                zero &= !(mask(reg.size()) << shift);
                if wide
                    && reg == Register::EAX
                    && matches!(used.access(), OpAccess::Write | OpAccess::ReadWrite)
                {
                    zero |= !mask(4);
                }
            }
        }
        let dest = insn.op0_register();
        if dest.full_register() == Register::RAX {
            let width = dest.size();
            let shift = if dest == Register::AH { 8 } else { 0 };
            if wide
                && dest == Register::EAX
                && matches!(facts.op0_access(), OpAccess::Write | OpAccess::ReadWrite)
            {
                zero |= !mask(4);
            }
            let known = match insn.mnemonic() {
                Mnemonic::Xor | Mnemonic::Sub
                    if insn.op1_kind() == OpKind::Register && insn.op1_register() == dest =>
                {
                    mask(width)
                }
                Mnemonic::Mov if immediate(insn.op1_kind()) => !insn.immediate(1) & mask(width),
                Mnemonic::Movzx => {
                    let source = if insn.op1_kind() == OpKind::Register {
                        insn.op1_register().size()
                    } else {
                        insn.memory_size().size()
                    };
                    mask(width) & !mask(source)
                }
                Mnemonic::And => {
                    let operand = if immediate(insn.op1_kind()) {
                        !insn.immediate(1)
                    } else {
                        0
                    };
                    ((before >> shift) | operand) & mask(width)
                }
                Mnemonic::Seta
                | Mnemonic::Setae
                | Mnemonic::Setb
                | Mnemonic::Setbe
                | Mnemonic::Sete
                | Mnemonic::Setg
                | Mnemonic::Setge
                | Mnemonic::Setl
                | Mnemonic::Setle
                | Mnemonic::Setne
                | Mnemonic::Setno
                | Mnemonic::Setnp
                | Mnemonic::Setns
                | Mnemonic::Seto
                | Mnemonic::Setp
                | Mnemonic::Sets => 0xfe,
                _ => 0,
            };
            zero |= known << shift;
        }
        let successors = match decoded.flow {
            Flow::Return => {
                returns.insert(at, zero);
                continue;
            }
            Flow::Terminal => continue,
            Flow::Next => vec![decoded.next_address],
            Flow::ConditionalBranch => vec![decoded.direct_target?, decoded.next_address],
            Flow::UnconditionalBranch => vec![decoded.direct_target?],
            // Calls and unresolved jumps cannot establish a complete leaf's effects.
            _ => return None,
        };
        for next in successors {
            match states.get_mut(&next) {
                Some(old) => {
                    let merged = *old & zero;
                    if merged != *old {
                        *old = merged;
                        queue.push_back(next);
                    }
                }
                None => {
                    states.insert(next, zero);
                    queue.push_back(next);
                }
            }
        }
    }
    if returns.is_empty() {
        return None;
    }
    let width = if wide { 8 } else { 4 };
    let zero = returns.values().fold(mask(width), |all, &path| all & path);
    let zero_from = (1..width)
        .find(|&at| zero & (mask(width) & !mask(at)) == (mask(width) & !mask(at)))
        .unwrap_or(0) as u32;
    Some(Effects {
        zero_from,
        preserves_ecx,
    })
}

fn mask(bytes: usize) -> u64 {
    u64::MAX
        .checked_shr((8usize.saturating_sub(bytes) * 8) as u32)
        .unwrap_or(0)
}

fn immediate(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::recovery::analyze_shellcode;

    #[test]
    fn physical_return_bits_and_preservation_require_complete_paths() -> anyhow::Result<()> {
        for (bytes, expected) in [
            (
                vec![0x31, 0xc0, 0x85, 0xc9, 0x0f, 0x95, 0xc0, 0xc3],
                Some((1, false)),
            ),
            (vec![0x85, 0xc9, 0x0f, 0x95, 0xc0, 0xc3], Some((0, false))),
            (
                vec![0x0f, 0xb7, 0x00, 0x23, 0x44, 0x24, 4, 0xc3],
                Some((2, true)),
            ),
            (vec![0x85, 0xd2, 0x74, 2, 0x31, 0xc0, 0xc3], Some((0, true))),
            (vec![0x31, 0xc9, 0x31, 0xc0, 0xc3], Some((1, false))),
            (vec![0x31, 0xc0, 0xb4, 1, 0xc3], Some((2, true))),
            (vec![0xe8, 1, 0, 0, 0, 0xc3, 0xc3], None),
            (vec![0xff, 0xe0], None),
        ] {
            let analysis = analyze_shellcode(&bytes, Architecture::X86)?;
            let entry = analysis
                .image
                .entry_point
                .ok_or_else(|| anyhow::anyhow!("entry"))?;
            assert_eq!(
                infer(&analysis, entry).map(|e| (e.zero_from, e.preserves_ecx)),
                expected,
                "{bytes:x?}"
            );
        }
        Ok(())
    }
}
