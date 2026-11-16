//! ARM/Thumb and classic MIPS32 decoding through Capstone. Ghidra's pinned SLEIGH
//! specifications provide the independent instruction semantics used by decompilation.
use super::{
    decoder::{DecodedInstruction, Flow},
    image::{Architecture, ImageError, LoadedImage},
};
use capstone::{
    arch::{
        arm::{ArmCC, ArmOperandType, ArmShift},
        mips::MipsOperand,
    },
    prelude::*,
    Endian,
};
use std::{
    cell::RefCell,
    collections::{btree_map::Entry, BTreeMap},
};

#[derive(Clone, Debug)]
#[cfg_attr(feature = "decompiler", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct RiscInsn {
    pub mnemonic: String,
    pub operands: String,
    pub numbers: Vec<(usize, u64)>,
    pub offsets: Vec<(usize, i64)>,
    pub registers: Vec<String>,
    pub target_thumb: Option<bool>,
    pub delay: bool,
    pub likely: bool,
    pub it_slots: u8,
    pub simple_operands: bool,
}

thread_local! {
    static DECODERS: RefCell<BTreeMap<u8, Capstone>> = const { RefCell::new(BTreeMap::new()) };
}

fn error(address: u64, reason: impl ToString) -> ImageError {
    ImageError::InvalidInstruction {
        address,
        reason: reason.to_string(),
    }
}

pub(crate) fn decode(image: &LoadedImage, address: u64) -> Result<DecodedInstruction, ImageError> {
    let thumb = image.is_thumb(address);
    let key = match image.architecture {
        Architecture::Arm => u8::from(thumb),
        Architecture::Mips => 2,
        Architecture::MipsBe => 3,
        _ => return Err(error(address, "not an ARM32/MIPS32 image")),
    };
    if !address.is_multiple_of(if thumb { 2 } else { 4 }) {
        return Err(error(address, "unaligned instruction"));
    }
    let bytes = image
        .bytes_at(address, 4)
        .ok_or_else(|| error(address, "unmapped instruction"))?;
    DECODERS.with(|cache| {
        let mut cache = cache.try_borrow_mut().map_err(|e| error(address, e))?;
        let cs = match cache.entry(key) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                let result = match key {
                    0 => Capstone::new()
                        .arm()
                        .mode(arch::arm::ArchMode::Arm)
                        .detail(true)
                        .build(),
                    1 => Capstone::new()
                        .arm()
                        .mode(arch::arm::ArchMode::Thumb)
                        .detail(true)
                        .build(),
                    _ => Capstone::new()
                        .mips()
                        .mode(arch::mips::ArchMode::Mips32)
                        .endian(if key == 3 {
                            Endian::Big
                        } else {
                            Endian::Little
                        })
                        .detail(true)
                        .build(),
                };
                e.insert(result.map_err(|e| error(address, e))?)
            }
        };
        let instructions = cs
            .disasm_count(bytes, address, 1)
            .map_err(|e| error(address, e))?;
        let insn = instructions
            .iter()
            .next()
            .ok_or_else(|| error(address, "invalid encoding"))?;
        let detail = cs.insn_detail(insn).map_err(|e| error(address, e))?;
        let ad = detail.arch_detail();
        let mnemonic = insn.mnemonic().unwrap_or_default().to_owned();
        let mut info = RiscInsn {
            mnemonic: mnemonic.clone(),
            operands: insn.op_str().unwrap_or_default().into(),
            numbers: Vec::new(),
            offsets: Vec::new(),
            registers: Vec::new(),
            target_thumb: None,
            delay: false,
            likely: false,
            it_slots: 0,
            simple_operands: true,
        };
        let group = |id: u32| detail.groups().iter().any(|g| u32::from(g.0) == id);
        let jump = group(capstone::InsnGroupType::CS_GRP_JUMP);
        let call = group(capstone::InsnGroupType::CS_GRP_CALL);
        let mut flow = Flow::Next;
        let mut direct = None;
        let mut memory = None;
        if let Some(arm) = ad.arm() {
            let mut pc = false;
            let mut lr = false;
            for (i, op) in arm.operands().enumerate() {
                info.simple_operands &= op.shift == ArmShift::Invalid;
                match op.op_type {
                    ArmOperandType::Reg(r) => {
                        let name = cs.reg_name(r).unwrap_or_default();
                        pc |= name == "pc";
                        lr |= name == "lr";
                        info.registers.push(name);
                    }
                    ArmOperandType::Imm(v) => {
                        info.numbers.push((i, v as u32 as u64));
                    }
                    ArmOperandType::Mem(m) => {
                        info.simple_operands &= m.index().0 == 0;
                        let base = cs.reg_name(m.base()).unwrap_or_default();
                        info.offsets.push((i, i64::from(m.disp())));
                        if base == "pc" && m.index().0 == 0 {
                            let pc = if thumb {
                                (address + 4) & !3
                            } else {
                                address + 8
                            };
                            memory = Some(pc.wrapping_add_signed(i64::from(m.disp())));
                        }
                        info.registers.push(base);
                    }
                    _ => {}
                }
            }
            let writes_pc = info.registers.first().is_some_and(|r| r == "pc");
            let immediate_target = if (mnemonic.starts_with('b') && !mnemonic.starts_with("bkpt"))
                || mnemonic.starts_with("cb")
                || (writes_pc && mnemonic.starts_with("mov"))
            {
                info.numbers.last().map(|(_, value)| *value)
            } else {
                None
            };
            let returns = (mnemonic.starts_with("bx") && lr)
                || (pc && (mnemonic.starts_with("pop") || mnemonic.starts_with("ldm")))
                || (writes_pc && lr && mnemonic.starts_with("mov"));
            if call || mnemonic.starts_with("blx") || mnemonic == "bl" {
                flow = if immediate_target.is_none() {
                    Flow::IndirectCall
                } else {
                    Flow::Call
                };
            } else if returns {
                flow = Flow::Return;
            } else if jump
                || (writes_pc && (mnemonic.starts_with("ldr") || mnemonic.starts_with("mov")))
            {
                flow = if immediate_target.is_none() {
                    Flow::IndirectBranch
                } else {
                    Flow::UnconditionalBranch
                };
            } else if matches!(mnemonic.as_str(), "udf" | "bkpt") {
                flow = Flow::Terminal;
            }
            if matches!(
                flow,
                Flow::Call | Flow::IndirectBranch | Flow::UnconditionalBranch
            ) {
                direct = immediate_target.map(|value| value & !1);
                if direct.is_some() {
                    info.target_thumb = Some(if mnemonic.starts_with("blx") {
                        !thumb
                    } else {
                        thumb
                    });
                } else if writes_pc && mnemonic.starts_with("ldr") {
                    if let Some(target) = memory
                        .filter(|slot| !image.external_bindings.contains_key(slot))
                        .and_then(|slot| image.read_pointer(slot))
                        .filter(|target| image.is_executable_address(*target & !1))
                    {
                        direct = Some(target & !1);
                        info.target_thumb = Some(target & 1 != 0);
                        flow = Flow::UnconditionalBranch;
                    }
                }
            }
            let conditional = !matches!(arm.cc(), ArmCC::ARM_CC_AL | ArmCC::ARM_CC_INVALID)
                || image.arm_context.get(&address).is_some_and(|v| v & 2 != 0)
                || matches!(mnemonic.as_str(), "cbz" | "cbnz");
            info.simple_operands &= !conditional;
            if conditional
                && matches!(
                    flow,
                    Flow::Return | Flow::IndirectBranch | Flow::UnconditionalBranch
                )
            {
                flow = Flow::ConditionalBranch;
            }
            if thumb
                && bytes.len() >= 2
                && bytes[1] == 0xbf
                && bytes[0] & 15 != 0
                && bytes[0] >> 4 < 14
            {
                info.it_slots = 4 - (bytes[0] & 15).trailing_zeros() as u8;
            }
        } else if let Some(mips) = ad.mips() {
            for (i, op) in mips.operands().enumerate() {
                match op {
                    MipsOperand::Imm(v) => info.numbers.push((i, v as u32 as u64)),
                    MipsOperand::Reg(r) => info.registers.push(cs.reg_name(r).unwrap_or_default()),
                    MipsOperand::Mem(m) => {
                        info.offsets.push((i, m.disp()));
                        info.registers
                            .push(cs.reg_name(m.base()).unwrap_or_default());
                    }
                    _ => {}
                }
            }
            let is_call = call
                || matches!(
                    mnemonic.as_str(),
                    "jal" | "jalr" | "bal" | "bgezal" | "bltzal" | "bgezall" | "bltzall"
                );
            if is_call {
                flow = if info.numbers.is_empty() {
                    Flow::IndirectCall
                } else {
                    Flow::Call
                };
            } else if mnemonic == "jr" && info.registers.iter().any(|r| r == "ra") {
                flow = Flow::Return;
            } else if matches!(mnemonic.as_str(), "jr" | "jalr") {
                flow = Flow::IndirectBranch;
            } else if matches!(mnemonic.as_str(), "j" | "b") {
                flow = Flow::UnconditionalBranch;
            } else if jump {
                flow = Flow::ConditionalBranch;
            } else if mnemonic == "break" {
                flow = Flow::Terminal;
            }
            if matches!(
                flow,
                Flow::Call | Flow::ConditionalBranch | Flow::UnconditionalBranch
            ) {
                direct = info.numbers.last().map(|(_, value)| *value);
            }
            info.delay = !matches!(flow, Flow::Next | Flow::Terminal);
            info.likely = matches!(
                mnemonic.as_str(),
                "beql"
                    | "bnel"
                    | "bgezl"
                    | "bgtzl"
                    | "blezl"
                    | "bltzl"
                    | "bc1fl"
                    | "bc1tl"
                    | "bgezall"
                    | "bltzall"
            );
        }
        if direct.is_some() {
            info.operands = info.operands.replace("#0x", "0x");
        }
        Ok(DecodedInstruction::from_risc(
            address,
            insn.bytes(),
            flow,
            direct,
            memory,
            info,
        ))
    })
}

pub(crate) fn record_arm_context(image: &mut LoadedImage, insn: &DecodedInstruction) {
    let Some(detail) = insn.risc() else {
        return;
    };
    if let (Some(target), Some(thumb)) = (insn.direct_target, detail.target_thumb) {
        image.set_thumb(target, thumb);
    }
    let mut address = insn.next_address;
    for _ in 0..detail.it_slots {
        image.arm_context.insert(address, 3);
        let Ok(slot) = decode(image, address) else {
            break;
        };
        address = slot.next_address;
    }
    if detail.it_slots != 0 {
        image.arm_context.insert(address, 1);
    }
}

pub(crate) fn add_prologue_seeds(
    image: &LoadedImage,
    seeds: &mut BTreeMap<u64, std::collections::BTreeSet<super::recovery::SeedKind>>,
) {
    for section in image.sections.iter().filter(|s| s.permissions.execute) {
        let Some(bytes) =
            image.bytes_at(section.address, (section.file_size as usize).min(4 << 20))
        else {
            continue;
        };
        let mut found = 0usize;
        for offset in (0..bytes.len().saturating_sub(3)).step_by(2) {
            let address = section.address + offset as u64;
            if image.is_code_excluded(address) {
                continue;
            }
            let raw: [u8; 4] = match bytes[offset..offset + 4].try_into() {
                Ok(raw) => raw,
                Err(_) => continue,
            };
            let word = if image.architecture.little_endian() {
                u32::from_le_bytes(raw)
            } else {
                u32::from_be_bytes(raw)
            };
            let matched = match image.architecture {
                Architecture::Arm if image.is_thumb(address) => {
                    u16::from_le_bytes([raw[0], raw[1]]) & 0xff00 == 0xb500
                }
                Architecture::Arm => address.is_multiple_of(4) && word & 0x0fff_4000 == 0x092d_4000,
                Architecture::Mips | Architecture::MipsBe => {
                    address.is_multiple_of(4) && word & 0xffff_8000 == 0x27bd_8000
                }
                _ => false,
            };
            if matched {
                seeds
                    .entry(address)
                    .or_default()
                    .insert(super::recovery::SeedKind::Prologue);
                found += 1;
                if found >= 8_192 {
                    break;
                }
            }
        }
    }
}

/// Linked-image pointer relocations, following the pinned Ghidra ARM/MIPS ELF handlers.
/// Instruction relocations and object linking are not approximated as pointer writes.
pub(crate) fn relocate(
    image: &mut LoadedImage,
    elf: &goblin::elf::Elf<'_>,
    relocation: goblin::elf::reloc::Reloc,
) {
    let kind = relocation.r_type;
    if kind == 0 {
        return;
    }
    let arm = image.architecture == Architecture::Arm;
    let relative = (arm && kind == 23) || (!arm && kind == 3);
    let absolute = kind == 2;
    let jump_slot = if arm {
        kind == goblin::elf::reloc::R_ARM_JUMP_SLOT
    } else {
        kind == goblin::elf::reloc::R_MIPS_JUMP_SLOT
    };
    let import = if arm {
        matches!(kind, 21 | 22)
    } else {
        matches!(kind, 51 | 127)
    };
    let Some(address) = relocation.r_offset.checked_add(image.load_bias) else {
        return;
    };
    if !relative && !absolute && !import {
        image.load_diagnostics.push(format!(
            "unsupported {} relocation {kind} at {address:#x}",
            image.architecture.name()
        ));
        return;
    }
    let symbol = elf.dynsyms.get(relocation.r_sym);
    let name = symbol
        .and_then(|s| elf.dynstrtab.get_at(s.st_name))
        .unwrap_or_default();
    let stored = image.read_pointer(address);
    let Some(addend) = relocation.r_addend.map(|a| a as u64).or(stored) else {
        return;
    };
    if symbol.is_some_and(|s| s.st_shndx == 0) && relocation.r_sym != 0 {
        if !name.is_empty() && (jump_slot || addend == 0) {
            image.add_external_binding(address, vec![name.into()]);
            image.import_locations.insert(address, format!("*.{name}"));
        } else if !name.is_empty() {
            image
                .load_diagnostics
                .push(format!("unresolved offset import {name} at {address:#x}"));
        }
        return;
    }
    let base = if relative && (arm || relocation.r_sym == 0) {
        image.load_bias
    } else {
        symbol.map_or(0, |s| s.st_value.wrapping_add(image.load_bias))
    };
    image.write_pointer(
        address,
        base.wrapping_add(if jump_slot { 0 } else { addend }),
    );
}

pub(crate) fn mips_got(image: &mut LoadedImage, elf: &goblin::elf::Elf<'_>) {
    if !matches!(
        image.architecture,
        Architecture::Mips | Architecture::MipsBe
    ) {
        return;
    }
    let Some(dynamic) = &elf.dynamic else {
        return;
    };
    let tag = |kind| {
        dynamic
            .dyns
            .iter()
            .find(|d| d.d_tag == kind)
            .map(|d| d.d_val)
    };
    let (Some(got), Some(local), Some(first)) = (tag(3), tag(0x7000000a), tag(0x70000013)) else {
        return;
    };
    if local > 1_000_000 || first as usize > elf.dynsyms.len() {
        return;
    }
    let Some(got) = got.checked_add(image.load_bias) else {
        return;
    };
    if image.global_pointer.is_none() {
        image.global_pointer = got.checked_add(0x7ff0);
    }
    for i in 2..local {
        let Some(address) = got.checked_add(i * 4) else {
            break;
        };
        if let Some(value) = image.read_pointer(address) {
            image.write_pointer(address, value.wrapping_add(image.load_bias));
        }
    }
    for (i, symbol) in elf.dynsyms.iter().enumerate().skip(first as usize) {
        let Some(address) = got.checked_add((local + i as u64 - first) * 4) else {
            break;
        };
        let name = elf.dynstrtab.get_at(symbol.st_name).unwrap_or_default();
        if symbol.st_shndx == 0 && !name.is_empty() {
            image.add_external_binding(address, vec![name.into()]);
            image.import_locations.insert(address, format!("*.{name}"));
        } else {
            image.write_pointer(address, symbol.st_value.wrapping_add(image.load_bias));
        }
    }
}

/// Instruction features use Capstone's structured operands, never text parsing of
/// attacker-controlled bytes. Only resolved memory references become strings/APIs.
pub(crate) fn features(
    analysis: &super::recovery::Analysis,
    function: &super::recovery::Function,
    block: &super::recovery::BasicBlock,
    thunks: &BTreeMap<u64, String>,
) -> BTreeMap<crate::address::Address, Vec<(crate::address::Address, crate::features::Feature)>> {
    use crate::{
        address::Address,
        features::{Feature, StringFeature},
    };
    let references = block_references(analysis, &block.insns, function.addr);
    block
        .insns
        .iter()
        .map(|insn| {
            let at = Address::Absolute(insn.address);
            let mut out = Vec::new();
            if let Some(r) = insn.risc() {
                out.push((at, Feature::Mnemonic(r.mnemonic.clone())));
                if insn.flow == Flow::Next {
                    for (index, value) in &r.numbers {
                        out.push((
                            at,
                            Feature::Number(crate::features::NumberValue::Int(i128::from(*value))),
                        ));
                        if let Ok(index) = u8::try_from(*index) {
                            out.push((
                                at,
                                Feature::OperandNumber(
                                    index,
                                    crate::features::NumberValue::Int(i128::from(*value)),
                                ),
                            ));
                        }
                    }
                }
                if !r.registers.iter().any(|v| v == "sp") {
                    for (index, value) in &r.offsets {
                        out.push((at, Feature::Offset(*value)));
                        if let Ok(index) = u8::try_from(*index) {
                            out.push((at, Feature::OperandOffset(index, *value)));
                        }
                    }
                }
                if let Some(memory) = insn
                    .memory_target
                    .or_else(|| references.get(&insn.address).copied())
                {
                    for target in [Some(memory), analysis.image.read_pointer(memory)]
                        .into_iter()
                        .flatten()
                    {
                        if let Some(text) = analysis
                            .image
                            .bytes_at(target, 256)
                            .and_then(super::strings::string_at)
                        {
                            out.push((at, Feature::String(StringFeature::Plain(text))));
                        }
                        if matches!(
                            insn.flow,
                            Flow::Call | Flow::IndirectCall | Flow::IndirectBranch
                        ) {
                            if let Some(names) = analysis.image.external_bindings.get(&target) {
                                out.extend(names.iter().map(|n| (at, Feature::Api(n.clone()))));
                            }
                        }
                    }
                }
                if matches!(insn.flow, Flow::Call | Flow::IndirectCall) {
                    out.push((at, Feature::Characteristic("calls from".into())));
                    if insn.flow == Flow::IndirectCall {
                        out.push((at, Feature::Characteristic("indirect call".into())));
                    }
                    if insn.direct_target == Some(function.addr) {
                        out.push((at, Feature::Characteristic("recursive call".into())));
                    }
                    if let Some(name) = insn.direct_target.and_then(|t| thunks.get(&t)) {
                        let (library, symbol) = name.rsplit_once('.').unwrap_or(("", name));
                        out.extend(
                            super::helpers::generate_symbols(library, symbol, false)
                                .into_iter()
                                .map(|name| (at, Feature::Api(name))),
                        );
                    }
                    if let Some(names) = insn
                        .direct_target
                        .and_then(|t| analysis.image.external_bindings.get(&t))
                    {
                        out.extend(names.iter().map(|n| (at, Feature::Api(n.clone()))));
                    }
                }
                if r.mnemonic.starts_with("eor") || r.mnemonic == "xor" || r.mnemonic == "xori" {
                    let registers = &r.registers;
                    if registers.len() >= 2
                        && registers[registers.len() - 1] != registers[registers.len() - 2]
                    {
                        out.push((at, Feature::Characteristic("nzxor".into())));
                    }
                }
            }
            (at, out)
        })
        .collect()
}

fn block_references(
    analysis: &super::recovery::Analysis,
    instructions: &[DecodedInstruction],
    entry: u64,
) -> BTreeMap<u64, u64> {
    let mut values = BTreeMap::<String, u64>::from([("zero".into(), 0)]);
    if let Some(gp) = analysis.image.global_pointer {
        values.insert("gp".into(), gp);
        values.insert("t9".into(), entry);
    }
    let mut refs = BTreeMap::new();
    let mut pending_call_slot = None;
    for insn in instructions {
        let Some(r) = insn.risc() else {
            continue;
        };
        if matches!(insn.flow, Flow::IndirectCall | Flow::IndirectBranch) {
            if let Some(value) = r.registers.last().and_then(|n| values.get(n)) {
                refs.insert(insn.address, *value);
            }
        }
        (|| {
            let Some(destination) = r.registers.first() else {
                return;
            };
            if analysis.image.architecture == Architecture::Arm {
                let pc = if analysis.image.is_thumb(insn.address) {
                    insn.address + 4
                } else {
                    insn.address + 8
                };
                values.insert("pc".into(), pc);
            }
            if !r.simple_operands {
                values.remove(destination);
                return;
            }
            // Capstone preserves ARM's optional rotated immediate as two operands.
            let immediate = match r.numbers.as_slice() {
                [(2, value), (3, rotation)]
                    if analysis.image.architecture == Architecture::Arm
                        && !analysis.image.is_thumb(insn.address) =>
                {
                    Some((*value as u32).rotate_right(*rotation as u32) as u64)
                }
                numbers => numbers.last().map(|(_, v)| *v),
            };
            let source = r.registers.get(1).and_then(|n| values.get(n)).copied();
            let old = values.get(destination).copied();
            let name = r.mnemonic.as_str();
            let computed = if name == "lui" {
                immediate.map(|v| v << 16)
            } else if name.starts_with("movt") {
                old.zip(immediate).map(|(a, b)| (a & 0xffff) | (b << 16))
            } else if name.starts_with("mov") {
                immediate.or(source)
            } else if name == "adr" {
                immediate
            } else if name == "addiu" {
                source
                    .zip(immediate)
                    .map(|(a, b)| a.wrapping_add_signed(i64::from(b as u32 as i32)))
            } else if name == "ori" {
                source.zip(immediate).map(|(a, b)| a | b)
            } else if name.starts_with("add") {
                if analysis.image.architecture == Architecture::Arm
                    && r.registers.len() == 2
                    && immediate.is_none()
                {
                    old.zip(source).map(|(a, b)| a.wrapping_add(b))
                } else {
                    let right = immediate
                        .or_else(|| r.registers.get(2).and_then(|n| values.get(n)).copied());
                    source.zip(right).map(|(a, b)| a.wrapping_add(b))
                }
            } else if name.starts_with("sub") {
                source.zip(immediate).map(|(a, b)| a.wrapping_sub(b))
            } else if name.starts_with("ldr") || name == "lw" {
                let slot = insn.memory_target.or_else(|| {
                    r.registers
                        .last()
                        .and_then(|n| values.get(n))
                        .copied()
                        .zip(r.offsets.last())
                        .map(|(base, (_, disp))| base.wrapping_add_signed(*disp))
                });
                slot.and_then(|slot| {
                    refs.insert(insn.address, slot);
                    if analysis.image.external_bindings.contains_key(&slot) {
                        Some(slot)
                    } else {
                        analysis.image.read_pointer(slot)
                    }
                })
            } else {
                None
            };
            if let Some(value) = computed {
                values.insert(destination.clone(), value & 0xffff_ffff);
                refs.entry(insn.address).or_insert(value & 0xffff_ffff);
            } else if insn.flow == Flow::Next
                && !matches!(name, "sw" | "sb" | "sh" | "cmp" | "tst" | "push" | "nop")
                && !name.starts_with("str")
            {
                values.remove(destination);
            }
        })();
        if matches!(insn.flow, Flow::Call | Flow::IndirectCall) {
            if r.delay {
                pending_call_slot = Some(insn.next_address);
            } else {
                values.retain(|name, _| name == "gp" || name == "zero");
            }
        }
        if pending_call_slot == Some(insn.address) {
            values.retain(|name, _| name == "gp" || name == "zero");
            pending_call_slot = None;
        }
    }
    refs
}

/// Resolve a bounded import stub to its final transfer and named GOT/IAT slot.
pub(crate) fn import_thunk(analysis: &super::recovery::Analysis, entry: u64) -> Option<(u64, u64)> {
    let mut instructions = Vec::new();
    let mut address = entry;
    // Native recovery can omit PLT entries outside exception-frame ranges.
    // Validate a short complete stub using the decoder instead of guessing
    // its size or matching compiler-specific instruction bytes.
    for _ in 0..8 {
        let insn = analysis.image.decode_at(address).ok()?;
        address = insn.next_address;
        let flow = insn.flow;
        instructions.push(insn);
        if flow == Flow::IndirectBranch {
            break;
        }
        if flow != Flow::Next {
            return None;
        }
    }
    let branch = instructions
        .last()
        .filter(|i| i.flow == Flow::IndirectBranch)?;
    let refs = block_references(analysis, &instructions, entry);
    let slot = branch
        .memory_target
        .or_else(|| refs.get(&branch.address).copied())?;
    analysis
        .image
        .import_locations
        .contains_key(&slot)
        .then_some((branch.address, slot))
}

pub(crate) fn import_thunks(analysis: &super::recovery::Analysis) -> BTreeMap<u64, String> {
    let entries: std::collections::BTreeSet<_> = analysis
        .functions
        .keys()
        .copied()
        .chain(
            analysis
                .instructions
                .values()
                .filter(|i| i.flow == Flow::Call)
                .filter_map(|i| i.direct_target),
        )
        .collect();
    entries
        .into_iter()
        .filter_map(|entry| {
            let (_, slot) = import_thunk(analysis, entry)?;
            Some((entry, analysis.image.import_locations.get(&slot)?.clone()))
        })
        .collect()
}

/// The vendored language is classic MIPS32 with the o32 compiler model.
pub(crate) fn supported_mips_flags(flags: u32) -> bool {
    flags & 0x0600_0020 == 0
        && matches!(
            flags & 0xf000_0000,
            0 | 0x1000_0000 | 0x5000_0000 | 0x7000_0000
        )
        && matches!(flags & 0x0000_f000, 0 | 0x1000)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn pointer_relocations_preserve_glob_dat_addends_and_replace_jump_slots() {
        let bytes = include_bytes!("../../tests/fixtures/risc/arm-dynamic.elf");
        let elf = goblin::elf::Elf::parse(bytes).unwrap();
        let (index, symbol) = elf
            .dynsyms
            .iter()
            .enumerate()
            .find(|(_, s)| elf.dynstrtab.get_at(s.st_name) == Some("call_import"))
            .unwrap();
        for (kind, addend) in [(21, 7), (22, 0)] {
            let mut image = LoadedImage::from_shellcode(&[0; 4], Architecture::Arm);
            let address = image.entry_point.unwrap();
            relocate(
                &mut image,
                &elf,
                goblin::elf::reloc::Reloc {
                    r_offset: address,
                    r_addend: Some(7),
                    r_sym: index,
                    r_type: kind,
                },
            );
            assert_eq!(image.read_pointer(address), Some(symbol.st_value + addend));
        }
        for architecture in [Architecture::Mips, Architecture::MipsBe] {
            let mut image = LoadedImage::from_shellcode(&[0; 4], architecture);
            let address = image.entry_point.unwrap();
            image.load_bias = 0x1000;
            relocate(
                &mut image,
                &elf,
                goblin::elf::reloc::Reloc {
                    r_offset: address - 0x1000,
                    r_addend: Some(7),
                    r_sym: 0,
                    r_type: 3,
                },
            );
            assert_eq!(image.read_pointer(address), Some(0x1007));
        }
    }
}

#[cfg(test)]
#[test]
#[allow(clippy::unwrap_used)]
fn mips_call_arguments_survive_the_slot_but_not_the_callee() {
    for architecture in [Architecture::Mips, Architecture::MipsBe] {
        let words = [
            0x3c04_0000u32,
            0x0c00_0020,
            0x2484_0020,
            0x8c82_0000,
            0x03e0_0008,
            0,
        ];
        let mut bytes: Vec<_> = words
            .into_iter()
            .flat_map(|word| {
                if architecture.little_endian() {
                    word.to_le_bytes()
                } else {
                    word.to_be_bytes()
                }
            })
            .collect();
        bytes.resize(32, 0);
        bytes.extend_from_slice(b"delay string\0");
        let analysis = super::recovery::analyze_shellcode_native(&bytes, architecture).unwrap();
        let block = &analysis.functions[&0].blocks[0];
        let refs = block_references(&analysis, &block.insns, 0);
        assert_eq!(refs.get(&8), Some(&32));
        assert!(!refs.contains_key(&12));
    }
}
