//! Register-input evidence for conventions absent from executable metadata.
use super::{Analysis, Architecture, Flow, InstructionInfoFactory, OpAccess, Register};
use std::collections::BTreeSet;

pub(super) fn inputs(
    analysis: &Analysis,
    address: u64,
    registers: &[Register],
) -> BTreeSet<Register> {
    inputs_with_callees(analysis, address, registers, &BTreeSet::new())
}

pub(super) fn inputs_with_callees(
    analysis: &Analysis,
    address: u64,
    registers: &[Register],
    callees: &BTreeSet<u64>,
) -> BTreeSet<Register> {
    let mut read = BTreeSet::new();
    let mut written = BTreeSet::new();
    let mut info = InstructionInfoFactory::new();
    let mut at = address;
    let preserved = registers == [Register::R13];
    for _ in 0..256 {
        let Some(insn) = analysis.instructions.get(&at) else {
            break;
        };
        if !(matches!(
            insn.flow,
            Flow::Next | Flow::Return | Flow::ConditionalBranch
        ) || (preserved && matches!(insn.flow, Flow::Call | Flow::IndirectCall)))
        {
            break;
        }
        if preserved
            && insn
                .direct_target
                .is_some_and(|target| callees.contains(&target))
            && !written.contains(&Register::R13)
        {
            read.insert(Register::R13);
        }
        let op = insn.x86_instruction();
        // Saving a nonvolatile register on the stack is not an input argument.
        let spill = op.mnemonic() == iced_x86::Mnemonic::Mov
            && op.op0_kind() == iced_x86::OpKind::Memory
            && matches!(
                op.memory_base().full_register(),
                Register::RSP | Register::RBP
            )
            && op.op1_kind() == iced_x86::OpKind::Register
            && op.op1_register().full_register() == Register::R13;
        if op.mnemonic() != iced_x86::Mnemonic::Push && !spill {
            for used in info.info(op).used_registers() {
                let reg = used.register().full_register();
                if !registers.contains(&reg) {
                    continue;
                }
                if matches!(
                    used.access(),
                    OpAccess::Read
                        | OpAccess::CondRead
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                ) && !written.contains(&reg)
                {
                    read.insert(reg);
                }
                if matches!(used.access(), OpAccess::Write | OpAccess::ReadWrite) {
                    written.insert(reg);
                }
            }
        }
        if insn.flow != Flow::Next
            && !(preserved && matches!(insn.flow, Flow::Call | Flow::IndirectCall))
        {
            break;
        }
        at = insn.next_address;
    }
    read
}

pub(super) fn fastcall(analysis: &Analysis, rust: bool) -> Vec<u64> {
    if analysis.image.architecture != Architecture::X86 {
        return Vec::new();
    }
    analysis
        .functions
        .keys()
        .copied()
        .filter(|address| {
            let regs = inputs(analysis, *address, &[Register::RCX, Register::RDX]);
            // ECX alone may be thiscall. Require both register arguments here.
            (rust && !regs.is_empty())
                || (regs.contains(&Register::RCX) && regs.contains(&Register::RDX))
        })
        .collect()
}
