//! Bounded compiler idioms shared by recovery and native translation.
use crate::extract::{
    decoder::{DecodedInstruction, Flow},
    image::{Architecture, LoadedImage},
};
#[cfg(any(feature = "decompiler", test))]
use iced_x86::{InstructionInfoFactory, OpAccess};
use iced_x86::{Mnemonic, OpKind, Register};
#[cfg(any(feature = "decompiler", test))]
use std::collections::BTreeMap;

/// The handler operand of Delphi's linked SEH frame is a label, not a callee.
pub(crate) fn delphi_handler(image: &LoadedImage, insn: &DecodedInstruction) -> bool {
    if image.architecture != Architecture::X86 {
        return false;
    }
    let op = insn.x86_instruction();
    if op.mnemonic() != Mnemonic::Push || op.op0_kind() != OpKind::Immediate32 {
        return false;
    }
    image.bytes_at(insn.address.saturating_sub(1), 1) == Some(&[0x55][..])
        && image.bytes_at(insn.next_address, 6) == Some(&[0x64, 0xff, 0x30, 0x64, 0x89, 0x20][..])
}

/// After unlinking SEH, Delphi pushes a local continuation and executes a finally body.
/// Only accept the straight-line, stack-balanced template; arbitrary push/ret code stays intact.
pub(crate) fn delphi_finally(image: &LoadedImage, push: &DecodedInstruction) -> Option<(u64, u64)> {
    if image.architecture != Architecture::X86 {
        return None;
    }
    let op = push.x86_instruction();
    if op.mnemonic() != Mnemonic::Push || op.op0_kind() != OpKind::Immediate32 {
        return None;
    }
    // mov fs:[eax],edx after the saved frame has been popped.
    if image.bytes_at(push.address.checked_sub(3)?, 3)? != [0x64, 0x89, 0x10] {
        return None;
    }
    let target = u64::from(op.immediate32());
    if target <= push.next_address
        || target > push.address.checked_add(256)?
        || !image.is_executable_address(target)
    {
        return None;
    }
    let mut address = push.next_address;
    let mut pending_args = 0;
    for _ in 0..32 {
        let insn = image.decode_at(address).ok()?;
        let op = insn.x86_instruction();
        if insn.flow == Flow::Return {
            return (op.op_count() == 0
                && pending_args == 0
                && address < target
                && target - address <= 32)
                .then_some((address, target));
        }
        match insn.flow {
            Flow::Call | Flow::IndirectCall => {
                pending_args = 0;
            }
            Flow::Next => match op.mnemonic() {
                Mnemonic::Push => pending_args += 1,
                Mnemonic::Mov | Mnemonic::Lea | Mnemonic::Xor => {
                    if op.op0_kind() != OpKind::Register
                        || matches!(op.op0_register(), Register::ESP | Register::EBP)
                    {
                        return None;
                    }
                }
                _ => return None,
            },
            _ => return None,
        }
        address = insn.next_address;
        if address >= target {
            return None;
        }
    }
    None
}

/// GCC's old SysV variadic entry jumps into eight four-byte XMM saves.
/// Saving the unused registers too has no observable effect outside this stack frame.
pub(crate) fn gcc_variadic(
    image: &LoadedImage,
    jump: &DecodedInstruction,
    preceding: &[&DecodedInstruction],
) -> Option<u64> {
    if image.architecture != Architecture::X64
        || jump.flow != Flow::IndirectBranch
        || jump.x86_instruction().op0_kind() != OpKind::Register
    {
        return None;
    }
    let mut end = jump.next_address;
    for register in (0..8).rev() {
        let insn = image.decode_at(end).ok()?;
        let op = insn.x86_instruction();
        if op.mnemonic() != Mnemonic::Movaps
            || insn.bytes.len() != 4
            || op.op0_kind() != OpKind::Memory
            || op.op1_register() as u32 != Register::XMM0 as u32 + register
            || op.memory_base() != Register::RAX
            || op.memory_index() != Register::None
            || op.memory_displacement64() as i64 != -127 + 16 * i64::from(register)
        {
            return None;
        }
        end = insn.next_address;
    }
    let reg = jump.x86_instruction().op0_register().full_register();
    let count = preceding.iter().any(|insn| {
        let op = insn.x86_instruction();
        op.mnemonic() == Mnemonic::Movzx
            && op.op0_register().full_register() == reg
            && op.op1_register() == Register::AL
    });
    let base = preceding.iter().any(|insn| {
        let op = insn.x86_instruction();
        op.mnemonic() == Mnemonic::Mov
            && op.op0_register().full_register() == reg
            && op.op1_kind() == OpKind::Immediate32
            && u64::from(op.immediate32()) == end
    });
    let subtract = preceding.iter().any(|insn| {
        let op = insn.x86_instruction();
        op.mnemonic() == Mnemonic::Sub
            && op.op0_register().full_register() == reg
            && op.op1_kind() == OpKind::Register
            && op.op1_register() == Register::RAX
    });
    let scaled_count = preceding.iter().any(|insn| {
        let op = insn.x86_instruction();
        op.mnemonic() == Mnemonic::Lea
            && op.op0_register() == Register::RAX
            && op.memory_base() == Register::None
            && op.memory_index() == reg
            && op.memory_index_scale() == 4
            && op.memory_displacement64() == 0
    });
    let stack_base = preceding
        .iter()
        .rev()
        .find(|insn| insn.x86_instruction().op0_register().full_register() == Register::RAX)
        .is_some_and(|insn| {
            let op = insn.x86_instruction();
            op.mnemonic() == Mnemonic::Lea
                && op.memory_base() == Register::RSP
                && op.memory_index() == Register::None
                && (127..=4096).contains(&op.memory_displacement64())
        });
    (count && base && subtract && scaled_count && stack_base).then_some(jump.next_address)
}

/// A SysV va_list initialized after the validated GCC register-save entry.
/// Require all unused integer registers to be saved before they are overwritten,
/// both va_list offsets, and a balanced call/return tail. This establishes the
/// fixed integer argument count, but leaves the forwarded result type unknown.
#[cfg(any(feature = "decompiler", test))]
pub(crate) fn gcc_variadic_forwarder(
    image: &LoadedImage,
    jump: &DecodedInstruction,
    preceding: &[&DecodedInstruction],
) -> Option<(u64, u32, u64)> {
    let body = gcc_variadic(image, jump, preceding)?.checked_add(32)?;
    let start = preceding.iter().rposition(|insn| {
        let op = insn.x86_instruction();
        op.mnemonic() == Mnemonic::Sub && op.op0_register() == Register::RSP
    })?;
    let prefix = &preceding[start..];
    if !matches!(
        prefix[0].x86_instruction().op1_kind(),
        OpKind::Immediate8to64 | OpKind::Immediate32to64
    ) {
        return None;
    }
    let frame = prefix[0].x86_instruction().immediate(1);
    if !(176..=4096).contains(&frame) {
        return None;
    }
    let gprs = [
        Register::RDI,
        Register::RSI,
        Register::RDX,
        Register::RCX,
        Register::R8,
        Register::R9,
    ];
    let mut intact = [true; 6];
    let mut saves = [None; 6];
    let mut info = InstructionInfoFactory::new();
    let mut next = prefix[0].address;
    let mut xmm_base = None;
    for (index, insn) in prefix.iter().enumerate() {
        if insn.address != next || insn.flow != Flow::Next {
            return None;
        }
        next = insn.next_address;
        let op = insn.x86_instruction();
        if op.op0_kind() == OpKind::Memory {
            let i = gprs.iter().position(|reg| *reg == op.op1_register())?;
            let offset = op.memory_displacement64();
            if op.mnemonic() != Mnemonic::Mov
                || op.memory_base() != Register::RSP
                || op.memory_index() != Register::None
                || !intact[i]
                || offset.checked_add(8)? > frame
                || saves
                    .iter()
                    .flatten()
                    .any(|saved| *saved < offset + 8 && offset < *saved + 8)
            {
                return None;
            }
            saves[i] = Some(offset);
        }
        if op.op0_register() == Register::RAX {
            xmm_base = (op.mnemonic() == Mnemonic::Lea
                && op.memory_base() == Register::RSP
                && op.memory_index() == Register::None)
                .then(|| op.memory_displacement64().checked_sub(127))
                .flatten();
        }
        for used in info.info(op).used_registers() {
            if matches!(
                used.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            ) {
                if index != 0 && used.register().full_register() == Register::RSP {
                    return None;
                }
                if let Some(i) = gprs
                    .iter()
                    .position(|reg| *reg == used.register().full_register())
                {
                    intact[i] = false;
                }
            }
        }
    }
    if next != jump.address {
        return None;
    }
    // Track only constants and addresses relative to the unchanged RSP.
    #[derive(Clone, Copy, PartialEq)]
    enum Value {
        Constant(u64),
        Stack(u64),
    }
    let mut registers = BTreeMap::new();
    let mut stores = BTreeMap::new();
    let mut address = body;
    for _ in 0..16 {
        let insn = image.decode_at(address).ok()?;
        let op = insn.x86_instruction();
        if insn.flow == Flow::Call {
            let target = insn.direct_target?;
            let list = gprs.iter().find_map(|reg| match registers.get(reg) {
                Some(Value::Stack(offset))
                    if stores
                        .get(offset)
                        .is_some_and(|(v, size)| matches!(v, Value::Constant(_)) && *size == 4) =>
                {
                    Some(*offset)
                }
                _ => None,
            })?;
            let (Value::Constant(gp), 4) = *stores.get(&list)? else {
                return None;
            };
            let (Value::Stack(save), 8) = *stores.get(&(list + 16))? else {
                return None;
            };
            if gp == 0
                || gp > 48
                || gp % 8 != 0
                || list.checked_add(24)? > frame
                || stores.get(&(list + 4)) != Some(&(Value::Constant(48), 4))
                || stores.get(&(list + 8)) != Some(&(Value::Stack(frame + 8), 8))
                || xmm_base != Some(save + 48)
                || save + 176 > frame
                || (gp as usize / 8..6).any(|i| saves[i] != Some(save + 8 * i as u64))
            {
                return None;
            }
            let restore = image.decode_at(insn.next_address).ok()?;
            let add = restore.x86_instruction();
            if add.mnemonic() != Mnemonic::Add
                || add.op0_register() != Register::RSP
                || !matches!(
                    add.op1_kind(),
                    OpKind::Immediate8to64 | OpKind::Immediate32to64
                )
                || add.immediate(1) != frame
            {
                return None;
            }
            let ret = image.decode_at(restore.next_address).ok()?;
            return (ret.flow == Flow::Return && ret.x86_instruction().op_count() == 0)
                .then_some((prefix[0].address, gp as u32 / 8, target));
        }
        if insn.flow != Flow::Next
            || !matches!(op.mnemonic(), Mnemonic::Mov | Mnemonic::Lea)
            || op.op0_register().full_register() == Register::RSP
        {
            return None;
        }
        let value = if op.mnemonic() == Mnemonic::Lea
            && op.memory_base() == Register::RSP
            && op.memory_index() == Register::None
        {
            Some(Value::Stack(op.memory_displacement64()))
        } else if op.mnemonic() == Mnemonic::Mov {
            match op.op1_kind() {
                OpKind::Immediate32 | OpKind::Immediate32to64 => {
                    Some(Value::Constant(op.immediate(1)))
                }
                OpKind::Register if op.op1_register() == Register::RSP => Some(Value::Stack(0)),
                OpKind::Register => registers.get(&op.op1_register().full_register()).copied(),
                _ => None,
            }
        } else {
            None
        };
        if op.op0_kind() == OpKind::Register {
            registers.remove(&op.op0_register().full_register());
            if let Some(value) = value {
                registers.insert(op.op0_register().full_register(), value);
            }
        } else if op.op0_kind() == OpKind::Memory
            && op.memory_base() == Register::RSP
            && op.memory_index() == Register::None
        {
            let offset = op.memory_displacement64();
            let size = op.memory_size().size();
            if !matches!(size, 4 | 8)
                || offset.checked_add(size as u64)? > frame
                || stores.iter().any(|(start, (_, width))| {
                    *start < offset + size as u64 && offset < *start + *width as u64
                })
            {
                return None;
            }
            stores.insert(offset, (value?, size));
        } else {
            return None;
        }
        address = insn.next_address;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::image::SHELLCODE_BASE;

    #[test]
    fn variadic_forwarder_requires_a_complete_va_list_and_balanced_tail() -> anyhow::Result<()> {
        let mut bytes = vec![
            0x48, 0x81, 0xec, 0xd8, 0, 0, 0, 0x48, 0x89, 0x54, 0x24, 0x30, 0x0f, 0xb6, 0xd0, 0x48,
            0x89, 0x74, 0x24, 0x28, 0x48, 0x8d, 0x04, 0x95, 0, 0, 0, 0, 0xba,
        ];
        bytes.extend(((SHELLCODE_BASE + 96) as u32).to_le_bytes());
        bytes.extend([
            0x48, 0x89, 0x4c, 0x24, 0x38, 0x4c, 0x89, 0x44, 0x24, 0x40, 0x4c, 0x89, 0x4c, 0x24,
            0x48, 0x48, 0x89, 0xfe, 0x48, 0x29, 0xc2, 0x48, 0x8d, 0x84, 0x24, 0xcf, 0, 0, 0, 0xff,
            0xe2,
        ]);
        assert_eq!(bytes.len(), 64);
        for register in (0..8).rev() {
            bytes.extend([
                0x0f,
                0x29,
                0x40 + 8 * register,
                (129 + 16 * u16::from(register)) as u8,
            ]);
        }
        bytes.extend([
            0x48, 0x8d, 0x84, 0x24, 0xe0, 0, 0, 0, // overflow_arg_area
            0x48, 0x89, 0xe2, // va_list passed in RDX
            0xc7, 0x04, 0x24, 8, 0, 0, 0, // gp_offset
            0xc7, 0x44, 0x24, 4, 0x30, 0, 0, 0, // fp_offset
            0x48, 0x89, 0x44, 0x24, 8, 0x48, 0x8d, 0x44, 0x24, 0x20, 0x48, 0x89, 0x44, 0x24, 0x10,
            0xe8, 0, 0, 0, 0, // call target is next instruction for this layout test
            0x48, 0x81, 0xc4, 0xd8, 0, 0, 0, 0xc3,
        ]);
        let expected_target = SHELLCODE_BASE + bytes.len() as u64 - 8;
        for mutation in [
            None,
            Some((110, 7)),
            Some((118, 0x40)),
            Some((11, 0x38)),
            Some((bytes.len() - 5, 0xc8)),
        ] {
            let mut candidate = bytes.clone();
            if let Some((offset, value)) = mutation {
                candidate[offset] = value;
            }
            let image = LoadedImage::from_shellcode(&candidate, Architecture::X64);
            let mut preceding = Vec::new();
            let mut address = SHELLCODE_BASE;
            while address < SHELLCODE_BASE + 62 {
                let insn = image.decode_at(address)?;
                address = insn.next_address;
                preceding.push(insn);
            }
            let result = gcc_variadic_forwarder(
                &image,
                &image.decode_at(SHELLCODE_BASE + 62)?,
                &preceding.iter().collect::<Vec<_>>(),
            );
            assert_eq!(
                result,
                mutation
                    .is_none()
                    .then_some((SHELLCODE_BASE, 1, expected_target)),
                "mutation {mutation:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn gcc_variadic_jump_requires_the_count_and_a_stack_save_area() -> anyhow::Result<()> {
        let mut bytes = vec![0x0f, 0xb6, 0xd0, 0x48, 0x8d, 0x04, 0x95, 0, 0, 0, 0, 0xba];
        let end = SHELLCODE_BASE + 29 + 32;
        bytes.extend((end as u32).to_le_bytes());
        bytes.extend([
            0x48, 0x29, 0xc2, 0x48, 0x8d, 0x84, 0x24, 0xcf, 0, 0, 0, 0xff, 0xe2,
        ]);
        for register in (0..8).rev() {
            bytes.extend([
                0x0f,
                0x29,
                0x40 + 8 * register,
                (129 + 16 * u16::from(register)) as u8,
            ]);
        }
        bytes.push(0xc3);
        for (stack, expected) in [(0x24, Some(SHELLCODE_BASE + 29)), (0x27, None)] {
            bytes[22] = stack; // RSP versus a non-stack base in the LEA.
            let image = LoadedImage::from_shellcode(&bytes, Architecture::X64);
            let mut preceding = Vec::new();
            let mut address = SHELLCODE_BASE;
            while address < SHELLCODE_BASE + 27 {
                let insn = image.decode_at(address)?;
                address = insn.next_address;
                preceding.push(insn);
            }
            let jump = image.decode_at(SHELLCODE_BASE + 27)?;
            assert_eq!(
                gcc_variadic(&image, &jump, &preceding.iter().collect::<Vec<_>>()),
                expected
            );
        }
        Ok(())
    }

    #[test]
    fn delphi_handler_and_finally_are_labels_but_ordinary_pushes_are_not() -> anyhow::Result<()> {
        let base = SHELLCODE_BASE;
        let target = (base + 32) as u32;
        let mut bytes = vec![0x55, 0x68];
        bytes.extend(target.to_le_bytes());
        bytes.extend([0x64, 0xff, 0x30, 0x64, 0x89, 0x20, 0x64, 0x89, 0x10, 0x68]);
        bytes.extend(target.to_le_bytes());
        bytes.push(0xc3);
        bytes.resize(32, 0x90);
        bytes.push(0xc3);
        let image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
        assert!(delphi_handler(&image, &image.decode_at(base + 1)?));
        assert_eq!(
            delphi_finally(&image, &image.decode_at(base + 15)?),
            Some((base + 20, base + 32))
        );
        bytes[12] = 0x90;
        let image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
        assert!(delphi_finally(&image, &image.decode_at(base + 15)?).is_none());
        Ok(())
    }
}
