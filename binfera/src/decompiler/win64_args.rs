//! Win64 stack arguments seen from both sides of a call. A callee homing every
//! argument register can consume an untyped va_list, so its call sites keep the
//! explicitly populated argument area. A fixed callee gets its stack arguments
//! only when every caller writes them and its body reads them.
use crate::extract::{
    decoder::Flow,
    image::{Architecture, ImageFormat},
    recovery::{Analysis, BasicBlock, EdgeKind, Function},
};
use iced_x86::{Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use std::collections::{BTreeMap, BTreeSet};

const INTEGER_ARGUMENTS: [Register; 4] = [Register::RCX, Register::RDX, Register::R8, Register::R9];
// `full_register` widens XMMn to ZMMn.
const FLOAT_ARGUMENTS: [Register; 4] = [
    Register::ZMM0,
    Register::ZMM1,
    Register::ZMM2,
    Register::ZMM3,
];
const MAX_STACK_SLOTS: u32 = 28;
// Caller view: the first stack argument is at RSP+0x20 when the call executes.
const OUTGOING_STACK: i64 = 0x20;
// Callee view: the return address moves it to RSP+0x28 at entry.
const INCOMING_STACK: i64 = 0x28;

#[derive(Default)]
pub(super) struct Calls {
    pub variadic: Vec<(u64, u64, u64, u32)>,
    /// Fixed callees and how many stack arguments follow their four register arguments.
    pub stack_arguments: BTreeMap<u64, u32>,
}

/// What one straight-line path has written for the next call.
#[derive(Clone, Default)]
struct Outgoing {
    /// Argument positions written through RCX, RDX, R8 and R9.
    integers: u8,
    /// Argument positions written through either register class.
    positions: u8,
    slots: BTreeSet<u32>,
}

impl Outgoing {
    fn stack_count(&self) -> u32 {
        (0..MAX_STACK_SLOTS)
            .take_while(|slot| self.slots.contains(slot))
            .count() as u32
    }

    fn step(&mut self, instruction: &Instruction, info: &mut InstructionInfoFactory) {
        let facts = info.info(instruction);
        for used in facts.used_registers() {
            if !writes(used.access()) {
                continue;
            }
            let register = used.register().full_register();
            if register == Register::RSP {
                *self = Self::default();
            } else if let Some(position) = INTEGER_ARGUMENTS.iter().position(|&r| r == register) {
                if used.register().size() >= 4 {
                    self.integers |= 1 << position;
                    self.positions |= 1 << position;
                }
            } else if let Some(position) = FLOAT_ARGUMENTS.iter().position(|&r| r == register) {
                self.positions |= 1 << position;
            }
        }
        for memory in facts.used_memory() {
            if memory.base() != Register::RSP
                || memory.index() != Register::None
                || !matches!(memory.access(), OpAccess::Write)
            {
                continue;
            }
            let offset = memory.displacement() as i64 - OUTGOING_STACK;
            if offset < 0 || offset % 8 != 0 {
                continue;
            }
            let size = memory.memory_size().size().max(1) as i64;
            for slot in (offset..offset + size).step_by(8) {
                if slot / 8 < i64::from(MAX_STACK_SLOTS) {
                    self.slots.insert((slot / 8) as u32);
                }
            }
        }
    }
}

fn writes(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

fn reads(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

pub(super) fn calls(analysis: &Analysis) -> Calls {
    let image = &analysis.image;
    if image.format != ImageFormat::Pe || image.architecture != Architecture::X64 {
        return Calls::default();
    }
    let candidates: BTreeSet<_> = analysis
        .functions
        .keys()
        .copied()
        .filter(|&entry| candidate(image, entry))
        .collect();
    let mut found = Calls::default();
    // The fewest stack arguments any call site writes for each target.
    let mut written = BTreeMap::new();
    let mut info = InstructionInfoFactory::new();
    for function in analysis.functions.values() {
        let mut paths = Paths::new(function);
        for block in &function.blocks {
            let mut outgoing = paths.incoming(block.addr, &mut info);
            for decoded in &block.insns {
                if matches!(decoded.flow, Flow::Call | Flow::IndirectCall) {
                    if let Some(target) = decoded.direct_target {
                        let count = if outgoing.positions == 15 {
                            outgoing.stack_count()
                        } else {
                            0
                        };
                        written
                            .entry(target)
                            .and_modify(|fewest: &mut u32| *fewest = (*fewest).min(count))
                            .or_insert(count);
                        if outgoing.integers == 15 && candidates.contains(&target) {
                            let count = outgoing.stack_count();
                            if count > 0 {
                                found.variadic.push((
                                    function.addr,
                                    decoded.address,
                                    target,
                                    4 + count,
                                ));
                            }
                        }
                    }
                    outgoing = Outgoing::default();
                    continue;
                }
                outgoing.step(decoded.x86_instruction(), &mut info);
            }
        }
    }
    found.stack_arguments = written
        .into_iter()
        .filter(|(target, written)| *written > 0 && !candidates.contains(target))
        .filter_map(|(target, written)| {
            let read = incoming_stack_reads(analysis.functions.get(&target)?, &mut info)?;
            (read <= written).then_some((target, read))
        })
        .collect();
    found
}

/// Outgoing state carried into blocks that have one predecessor in their function.
struct Paths<'a> {
    function: &'a Function,
    blocks: BTreeMap<u64, &'a BasicBlock>,
    predecessors: BTreeMap<u64, Vec<u64>>,
    finished: BTreeMap<u64, Outgoing>,
}

impl<'a> Paths<'a> {
    fn new(function: &'a Function) -> Self {
        let mut predecessors: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        for block in &function.blocks {
            for edge in &block.succs {
                let sources = predecessors.entry(edge.target).or_default();
                if edge.kind != EdgeKind::TailCall && !sources.contains(&block.addr) {
                    sources.push(block.addr);
                }
            }
        }
        Self {
            function,
            blocks: function.blocks.iter().map(|b| (b.addr, b)).collect(),
            predecessors,
            finished: BTreeMap::new(),
        }
    }

    fn incoming(&mut self, address: u64, info: &mut InstructionInfoFactory) -> Outgoing {
        // Walk back along single-predecessor edges, then replay forward.
        let mut chain = Vec::new();
        let mut current = address;
        let mut state = loop {
            if current == self.function.addr || chain.len() >= 64 || chain.contains(&current) {
                break Outgoing::default();
            }
            let Some(&[predecessor]) = self.predecessors.get(&current).map(Vec::as_slice) else {
                break Outgoing::default();
            };
            if let Some(state) = self.finished.get(&predecessor) {
                break state.clone();
            }
            if !self.blocks.contains_key(&predecessor) {
                break Outgoing::default();
            }
            chain.push(current);
            current = predecessor;
        };
        // `chain` holds successors of each block to replay; replay from the oldest.
        for &successor in chain.iter().rev() {
            let predecessor = self.predecessors[&successor][0];
            if let Some(known) = self.finished.get(&predecessor) {
                state = known.clone();
                continue;
            }
            for decoded in &self.blocks[&predecessor].insns {
                if matches!(decoded.flow, Flow::Call | Flow::IndirectCall) {
                    state = Outgoing::default();
                } else {
                    state.step(decoded.x86_instruction(), info);
                }
            }
            self.finished.insert(predecessor, state.clone());
        }
        state
    }
}

/// How many incoming stack arguments the body reads: one past the highest
/// slot whose first access is a read. RBP may hold an offset frame pointer, so
/// both tracked bases are relative to incoming RSP. MSVC keeps RSP fixed after
/// the prologue, and any other adjustment leaves the frame unknown.
fn incoming_stack_reads(function: &Function, info: &mut InstructionInfoFactory) -> Option<u32> {
    let entry = function
        .blocks
        .iter()
        .find(|block| block.addr == function.addr)?;
    let mut frame = Frame {
        rsp: Some(0),
        rbp: None,
    };
    let mut entry_first = BTreeMap::new();
    for decoded in &entry.insns {
        frame.step(decoded, info, true, &mut |slot, access| {
            entry_first.entry(slot).or_insert(access);
        })?;
    }
    // Blocks after the entry start from the post-prologue frame. An epilogue
    // or a ret leaves the final state meaningless for the next block.
    let body = Frame {
        rsp: frame.rsp.filter(|_| {
            entry
                .insns
                .last()
                .is_some_and(|last| !matches!(last.flow, Flow::Return | Flow::Terminal))
        }),
        rbp: frame.rbp,
    };
    let mut later_reads = BTreeSet::new();
    let mut later_writes = BTreeSet::new();
    for block in function.blocks.iter().filter(|b| b.addr != function.addr) {
        let mut frame = body.clone();
        for decoded in &block.insns {
            frame.step(decoded, info, false, &mut |slot, access| {
                if access {
                    later_reads.insert(slot);
                } else {
                    later_writes.insert(slot);
                }
            })?;
        }
    }
    let read = |slot: &u32| match entry_first.get(slot) {
        Some(&first) => first,
        None => later_reads.contains(slot) && !later_writes.contains(slot),
    };
    let highest = entry_first
        .keys()
        .chain(later_reads.iter())
        .copied()
        .filter(read)
        .max()?;
    Some(highest + 1)
}

#[derive(Clone)]
struct Frame {
    rsp: Option<i64>,
    rbp: Option<i64>,
}

impl Frame {
    /// Report incoming-slot accesses (true for a read) and follow the frame.
    /// `None` gives up on the whole function.
    fn step(
        &mut self,
        decoded: &crate::extract::decoder::DecodedInstruction,
        info: &mut InstructionInfoFactory,
        entry: bool,
        access: &mut impl FnMut(u32, bool),
    ) -> Option<()> {
        let instruction = decoded.x86_instruction();
        let facts = info.info(instruction);
        for memory in facts.used_memory() {
            let base = match memory.base() {
                Register::RSP => self.rsp,
                Register::RBP => self.rbp,
                _ => None,
            };
            let Some(offset) = base
                .filter(|_| memory.index() == Register::None)
                .map(|base| base.wrapping_add(memory.displacement() as i64) - INCOMING_STACK)
            else {
                continue;
            };
            if offset < 0 || offset / 8 >= i64::from(MAX_STACK_SLOTS) {
                continue;
            }
            let slot = (offset / 8) as u32;
            if reads(memory.access()) {
                access(slot, true);
            } else if writes(memory.access()) {
                access(slot, false);
            }
        }
        // A call returns with RSP restored; a branch or ret ends the block.
        if decoded.flow != Flow::Next {
            return Some(());
        }
        let written = |register| {
            facts
                .used_registers()
                .iter()
                .any(|used| used.register().full_register() == register && writes(used.access()))
        };
        if written(Register::RBP) {
            let from_rsp = match instruction.mnemonic() {
                Mnemonic::Mov
                    if instruction.op0_register() == Register::RBP
                        && instruction.op1_register() == Register::RSP =>
                {
                    self.rsp
                }
                Mnemonic::Lea
                    if instruction.op0_register() == Register::RBP
                        && instruction.memory_base() == Register::RSP
                        && instruction.memory_index() == Register::None =>
                {
                    self.rsp
                        .and_then(|rsp| rsp.checked_add(instruction.memory_displacement64() as i64))
                }
                // The epilogue restores the caller's RBP.
                Mnemonic::Pop => None,
                // Elsewhere RBP is either not the frame pointer or is being clobbered.
                _ if entry || self.rbp.is_none() => None,
                _ => return None,
            };
            self.rbp = from_rsp;
        }
        if written(Register::RSP) {
            self.rsp = match instruction.mnemonic() {
                Mnemonic::Push | Mnemonic::Pop => self
                    .rsp
                    .map(|rsp| rsp + i64::from(instruction.stack_pointer_increment())),
                Mnemonic::Add | Mnemonic::Sub
                    if instruction.op0_register() == Register::RSP
                        && matches!(
                            instruction.op1_kind(),
                            OpKind::Immediate8to64 | OpKind::Immediate32to64
                        ) =>
                {
                    let amount = instruction.immediate(1) as i64;
                    self.rsp.map(|rsp| {
                        if instruction.mnemonic() == Mnemonic::Add {
                            rsp + amount
                        } else {
                            rsp - amount
                        }
                    })
                }
                // Frame-pointer epilogues.
                Mnemonic::Mov
                    if instruction.op0_register() == Register::RSP
                        && instruction.op1_register() == Register::RBP =>
                {
                    self.rbp
                }
                Mnemonic::Lea
                    if instruction.op0_register() == Register::RSP
                        && instruction.memory_base() == Register::RBP
                        && instruction.memory_index() == Register::None =>
                {
                    self.rbp
                        .and_then(|rbp| rbp.checked_add(instruction.memory_displacement64() as i64))
                }
                // Dynamic allocation or realignment: RSP-relative offsets are unknown.
                _ => return None,
            };
        }
        Some(())
    }
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

    fn reads_of(bytes: &[u8]) -> anyhow::Result<Option<u32>> {
        let analysis = crate::extract::recovery::analyze_shellcode(bytes, Architecture::X64)?;
        let entry = analysis
            .image
            .entry_point
            .ok_or_else(|| anyhow::anyhow!("missing entry"))?;
        Ok(incoming_stack_reads(
            &analysis.functions[&entry],
            &mut InstructionInfoFactory::new(),
        ))
    }

    #[test]
    fn stack_reads_follow_the_entry_frame_pointer() -> anyhow::Result<()> {
        let mut bytes = [
            0x55, // push rbp
            0x48, 0x8d, 0x6c, 0x24, 0xe9, // lea rbp, [rsp-0x17]
            0x48, 0x83, 0xec, 0x30, // sub rsp, 0x30
            0x48, 0x8b, 0x75, 0x47, // mov rsi, [rbp+0x47], incoming RSP+0x28
            0x48, 0x83, 0xc4, 0x30, // add rsp, 0x30
            0x5d, 0xc3, // pop rbp; ret
        ];
        assert_eq!(reads_of(&bytes)?, Some(1));
        bytes[13] = 0x4f; // incoming RSP+0x30, the sixth argument
        assert_eq!(reads_of(&bytes)?, Some(2));
        bytes[13] = 0x3f; // RSP+0x20 is a register home slot
        assert_eq!(reads_of(&bytes)?, None);
        bytes[13] = 0x47;
        bytes[11] = 0x89; // unconditionally overwriting the slot does not read the input
        assert_eq!(reads_of(&bytes)?, None);
        bytes[11] = 0x01; // add [rbp+0x47], rsi reads the input before writing it
        assert_eq!(reads_of(&bytes)?, Some(1));
        Ok(())
    }

    #[test]
    fn stack_reads_continue_past_branches_and_calls() -> anyhow::Result<()> {
        let mut bytes = vec![
            0x48, 0x83, 0xec, 0x28, // sub rsp, 0x28
            0xe8, 0x0e, 0, 0, 0, // call 0x17
            0x48, 0x85, 0xc9, // test rcx, rcx
            0x74, 0x05, // je ret
            0x48, 0x8b, 0x44, 0x24, 0x50, // mov rax, [rsp+0x50], the fifth argument
            0x48, 0x83, 0xc4, 0x28, // add rsp, 0x28
            0xc3, // ret
        ];
        assert_eq!(reads_of(&bytes)?, Some(1));
        // A later write before any entry access means a scratch slot.
        bytes.splice(
            14..19,
            [0x48, 0x89, 0x44, 0x24, 0x50], // mov [rsp+0x50], rax
        );
        assert_eq!(reads_of(&bytes)?, None);
        // Dynamic allocation leaves RSP-relative offsets unknown.
        let alloca = [
            0x48, 0x83, 0xec, 0x28, // sub rsp, 0x28
            0x48, 0x29, 0xc4, // sub rsp, rax
            0x48, 0x8b, 0x44, 0x24, 0x50, // mov rax, [rsp+0x50]
            0x48, 0x83, 0xc4, 0x28, 0xc3,
        ];
        assert_eq!(reads_of(&alloca)?, None);
        Ok(())
    }

    #[test]
    fn call_sites_accept_narrow_stores_float_registers_and_earlier_blocks() -> anyhow::Result<()> {
        use crate::extract::image::SHELLCODE_BASE;
        let callee = 0x80usize;
        let call = |at: usize| -> [u8; 5] {
            let relative = (callee as i32 - (at as i32 + 5)).to_le_bytes();
            [0xe8, relative[0], relative[1], relative[2], relative[3]]
        };
        let analyze = |sites: &[&[u8]]| -> anyhow::Result<Calls> {
            let mut bytes = vec![0xcc; 0xa0];
            let mut at = 0;
            for site in sites {
                bytes[at..at + site.len()].copy_from_slice(site);
                at += site.len();
                bytes[at..at + 5].copy_from_slice(&call(at));
                at += 5;
            }
            bytes[at] = 0xc3;
            let body = [
                0x48, 0x83, 0xec, 0x28, // sub rsp, 0x28
                0x48, 0x8b, 0x44, 0x24, 0x50, // mov rax, [rsp+0x50]
                0x48, 0x83, 0xc4, 0x28, 0xc3,
            ];
            bytes[callee..callee + body.len()].copy_from_slice(&body);
            let mut analysis =
                crate::extract::recovery::analyze_shellcode(&bytes, Architecture::X64)?;
            analysis.image.format = ImageFormat::Pe;
            Ok(calls(&analysis))
        };
        let target = SHELLCODE_BASE + callee as u64;
        let registers: &[u8] = &[
            0x31, 0xc9, // xor ecx, ecx
            0x0f, 0x57, 0xc9, // xorps xmm1, xmm1
            0x45, 0x31, 0xc0, // xor r8d, r8d
            0x4d, 0x0f, 0x44, 0xc8, // cmove r9, r8
        ];
        let dword: &[u8] = &[0xc7, 0x44, 0x24, 0x20, 5, 0, 0, 0]; // mov dword [rsp+0x20], 5
        let site = [registers, dword].concat();
        assert_eq!(
            analyze(&[&site])?.stack_arguments,
            BTreeMap::from([(target, 1)])
        );
        // Arguments written before a branch reach the call in its only successor.
        let branched = [registers, dword, &[0x74, 0x00][..]].concat(); // je next
        assert_eq!(
            analyze(&[&branched])?.stack_arguments,
            BTreeMap::from([(target, 1)])
        );
        // One call site without the stack argument leaves the callee alone.
        assert!(analyze(&[&site, registers])?.stack_arguments.is_empty());
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
