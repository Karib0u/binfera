//! Infer ABI0 result storage from `_func.args` and bounded control-flow analysis.
//! Reads before writes are inputs; a result suffix must be written on every return.
use crate::extract::decoder::Flow;
use crate::extract::image::{Architecture, LoadedImage};
use crate::golang::GoFunction;
use iced_x86::{InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, PartialEq, Eq)]
struct State {
    delta: i64,
    written: Vec<bool>,
}

pub(super) fn layout(
    image: &LoadedImage,
    function: &GoFunction,
    noreturn: &BTreeSet<u64>,
) -> Option<(u32, u32)> {
    if image.architecture != Architecture::X86 || function.assembly {
        return None;
    }
    let size = usize::try_from(function.args_size?).ok()?;
    if size == 0 || size > 512 || size % 4 != 0 {
        return None;
    }
    let mut states = BTreeMap::new();
    states.insert(
        function.entry,
        State {
            delta: 0,
            written: vec![false; size],
        },
    );
    let mut queue = VecDeque::from([function.entry]);
    let mut inputs = vec![false; size];
    let mut returns = BTreeMap::new();
    let mut info = InstructionInfoFactory::new();
    let mut work = 0;
    while let Some(address) = queue.pop_front() {
        work += 1;
        if work > 20000 {
            return None;
        }
        let mut state = states.get(&address)?.clone();
        let decoded = image.decode_at(address).ok()?;
        if decoded.flow == Flow::Call
            && decoded
                .direct_target
                .is_some_and(|target| noreturn.contains(&target))
        {
            continue;
        }
        let insn = decoded.x86_instruction();
        let facts = info.info(insn);
        for mem in facts.used_memory() {
            if mem.base() != Register::ESP {
                continue;
            }
            if mem.index() != Register::None {
                return None;
            }
            let at = state
                .delta
                .checked_add(mem.displacement() as i32 as i64)?
                .checked_sub(4)?;
            let width = mem.memory_size().size();
            if at < 0 || at >= size as i64 {
                continue;
            }
            let end = (at as usize).checked_add(width)?;
            if width == 0 || end > size {
                return None;
            }
            for (input, written) in inputs[at as usize..end]
                .iter_mut()
                .zip(&mut state.written[at as usize..end])
            {
                if matches!(
                    mem.access(),
                    OpAccess::Read
                        | OpAccess::CondRead
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                ) && !*written
                {
                    *input = true;
                }
                if matches!(mem.access(), OpAccess::Write | OpAccess::ReadWrite) {
                    *written = true;
                }
            }
        }
        if insn.mnemonic() == Mnemonic::Lea && insn.memory_base() == Register::ESP {
            let at = state.delta + insn.memory_displacement64() as i32 as i64 - 4;
            if (0..size as i64).contains(&at) {
                return None;
            }
        }
        if decoded.flow == Flow::Return {
            if state.delta != 0 {
                return None;
            }
            returns.insert(address, state.written);
            continue;
        }
        if matches!(insn.mnemonic(), Mnemonic::Add | Mnemonic::Sub)
            && insn.op0_register() == Register::ESP
        {
            if insn.op1_kind() == OpKind::Register || insn.op1_kind() == OpKind::Memory {
                return None;
            }
            let amount = insn.immediate(1) as i32 as i64;
            state.delta += if insn.mnemonic() == Mnemonic::Sub {
                -amount
            } else {
                amount
            };
        } else if !matches!(decoded.flow, Flow::Call | Flow::IndirectCall)
            && facts.used_registers().iter().any(|r| {
                r.register().full_register() == Register::RSP
                    && matches!(
                        r.access(),
                        OpAccess::Write
                            | OpAccess::ReadWrite
                            | OpAccess::CondWrite
                            | OpAccess::ReadCondWrite
                    )
            })
        {
            return None;
        }
        let mut successors = Vec::new();
        match decoded.flow {
            Flow::UnconditionalBranch => successors.push(decoded.direct_target?),
            Flow::ConditionalBranch => {
                successors.push(decoded.direct_target?);
                successors.push(decoded.next_address);
            }
            Flow::IndirectBranch => return None,
            Flow::Terminal => continue,
            _ => successors.push(decoded.next_address),
        }
        for next in successors {
            if next < function.entry || next >= function.end {
                if noreturn.contains(&next) {
                    continue;
                }
                return None;
            }
            if let Some(previous) = states.get_mut(&next) {
                if previous.delta != state.delta {
                    return None;
                }
                let mut changed = false;
                for (old, new) in previous.written.iter_mut().zip(&state.written) {
                    if *old && !new {
                        *old = false;
                        changed = true;
                    }
                }
                if changed {
                    queue.push_back(next);
                }
            } else {
                states.insert(next, state.clone());
                queue.push_back(next);
            }
        }
    }
    if returns.is_empty() {
        return None;
    }
    let input_end = inputs
        .iter()
        .rposition(|&read| read)
        .map_or(0, |i| (i + 4) / 4 * 4);
    // Padding can be unwritten; every result word must have an actual store.
    let first = (input_end..size)
        .step_by(4)
        .find(|&at| returns.values().all(|w| w[at..at + 4].iter().any(|&b| b)))?;
    if !(first..size)
        .step_by(4)
        .all(|at| returns.values().all(|w| w[at..at + 4].iter().any(|&b| b)))
    {
        return None;
    }
    Some((first as u32, (size - first) as u32))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn check(bytes: &[u8], size: u32) -> Option<(u32, u32)> {
        let image = LoadedImage::from_shellcode_at(bytes, Architecture::X86, 0);
        let function = GoFunction {
            entry: 0,
            end: bytes.len() as u64,
            name: "main.f".into(),
            assembly: false,
            args_size: Some(size),
        };
        layout(&image, &function, &BTreeSet::new())
    }
    #[test]
    fn inputs_and_result_stores_respect_stack_adjustments() {
        // sub esp,16; mov eax,[esp+20]; inc eax; mov [esp+24],eax; add esp,16; ret
        assert_eq!(
            check(
                &[
                    0x83, 0xec, 16, 0x8b, 0x44, 0x24, 20, 0x40, 0x89, 0x44, 0x24, 24, 0x83, 0xc4,
                    16, 0xc3
                ],
                8
            ),
            Some((4, 4))
        );
        assert_eq!(
            check(&[0x8b, 0x44, 0x24, 4, 0x89, 0x44, 0x24, 4, 0xc3], 4),
            None
        );
    }
    #[test]
    fn conditional_result_and_unknown_metadata_are_not_locked() {
        // One return path skips the store to the result area.
        assert_eq!(
            check(&[0x85, 0xc0, 0x74, 4, 0x89, 0x44, 0x24, 4, 0xc3], 4),
            None
        );
        assert_eq!(check(&[0xc3], u32::MAX), None);
        assert_eq!(check(&[0xc3], 0), None);
    }
}
