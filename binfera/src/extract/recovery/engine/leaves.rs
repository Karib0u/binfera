//! Frameless leaf functions in the code gaps of an x64 PE image with unwind data.
//!
//! The x64 Windows ABI requires a `.pdata` row for every function that allocates stack, saves
//! a nonvolatile register or calls another function. Code outside every unwind extent that no
//! flow reached is therefore either data, padding, a linker stub or a leaf function: one that
//! never touches the stack pointer and ends in `ret` or a tail jump. Unreferenced leaves
//! (accessors, copy constructors, forwarders an image kept without `/OPT:REF`) are found here.
use super::*;
use iced_x86::{InstructionInfoFactory, OpAccess};

/// Largest leaf body accepted, in instructions and in bytes from its entry.
const MAX_LEAF_INSNS: usize = 256;
const MAX_LEAF_BYTES: u64 = 4096;

/// Whether `image` is an x64 PE whose unwind data rules out every non-leaf function in its gaps.
pub(super) fn sweeps_x64_leaves(image: &LoadedImage) -> bool {
    image.format == ImageFormat::Pe
        && image.architecture == Architecture::X64
        && image
            .pe_exception_directory
            .is_some_and(|(_, size)| size > 0)
        && !unwind_extents(image).is_empty()
}

/// Entries of the leaf functions that fill the unclaimed gaps of an x64 PE's code sections.
///
/// Candidates start a gap: after an unwind extent, after `int3`/`nop` padding, or after a
/// recovered function. Each accepted leaf's end is a boundary for the next one, since the
/// linker places such functions back to back. Bytes that fail validation end the candidate
/// run until the next padding, so the inside of a jump table never starts a function.
pub(super) fn unclaimed_x64_leaf_entries(
    analysis: &Analysis,
    function_starts: &BTreeSet<u64>,
    unwound: &[(u64, u64)],
) -> Vec<u64> {
    let image = &analysis.image;
    let mut found = Vec::new();
    let mut info = InstructionInfoFactory::new();
    for section in image
        .sections
        .iter()
        .filter(|s| s.permissions.execute && image.is_primary_code_address(s.address))
    {
        let Some(bytes) = image.bytes_at(section.address, MAX_PROLOGUE_SCAN_BYTES) else {
            continue;
        };
        let end = section.address.saturating_add(bytes.len() as u64);
        let mut address = section.address;
        let mut boundary = true;
        // Recovered code makes a boundary only when its run began at a function entry and
        // holds no unresolved `jmp reg`: after such a dispatch, adjacent code is as likely its
        // switch cases as a new function. Padding and unwind extents clear that doubt.
        let mut covered_run: Option<bool> = None;
        let mut dispatch = false;
        while address < end {
            if let Some(insn) = instruction_location(analysis, address) {
                let from_entry =
                    *covered_run.get_or_insert_with(|| function_starts.contains(&insn.address));
                dispatch |= register_jump(image, insn);
                boundary = import_thunk(image, insn.address)
                    || (from_entry
                        && !dispatch
                        && matches!(insn.flow, Flow::Return | Flow::UnconditionalBranch));
                address = insn.next_address.max(address + 1);
                continue;
            }
            covered_run = None;
            if let Some(extent_end) = unwind_extent_end(unwound, address) {
                address = extent_end.max(address + 1);
                boundary = true;
                dispatch = false;
                continue;
            }
            let offset = usize::try_from(address - section.address).unwrap_or(usize::MAX);
            if image.is_code_excluded(address) || analysis.data_xrefs.contains_key(&address) {
                // Data named by code (a jump table, a constant): nothing starts inside it.
                boundary = false;
                address += 1;
                continue;
            }
            if matches!(bytes.get(offset), Some(0xcc | 0x90)) {
                boundary = true;
                dispatch = false;
                address += 1;
                continue;
            }
            // Multi-byte `nop` alignment filler.
            if let Some(filler) = image
                .decode_at(address)
                .ok()
                .filter(|insn| insn.x86_instruction().mnemonic() == Mnemonic::Nop)
            {
                boundary = true;
                dispatch = false;
                address = filler.next_address.max(address + 1);
                continue;
            }
            // Compilers align function entries to at least four bytes; switch cases packed
            // after a missed dispatch often are not. An import thunk validates itself, wherever
            // the linker packed it.
            if (boundary && address % 4 == 0) || import_thunk(image, address) {
                if let Some((leaf_end, dispatches)) =
                    leaf_end(analysis, function_starts, unwound, address, &mut info)
                {
                    found.push(address);
                    address = leaf_end;
                    dispatch |= dispatches;
                    boundary = !dispatch;
                    continue;
                }
            }
            // Step over whole instructions, so that an operand byte is never read as padding.
            boundary = false;
            address = image
                .decode_at(address)
                .map_or(address + 1, |insn| insn.next_address.max(address + 1));
        }
    }
    found
}

/// End of the unwind extent that holds `address`, if any.
fn unwind_extent_end(unwound: &[(u64, u64)], address: u64) -> Option<u64> {
    let index = unwound.partition_point(|&(begin, _)| begin <= address);
    index
        .checked_sub(1)
        .and_then(|index| unwound.get(index))
        .map(|&(_, end)| end)
        .filter(|&end| address < end)
}

/// `jmp [slot]` through an import slot.
fn import_thunk(image: &LoadedImage, address: u64) -> bool {
    image.decode_at(address).is_ok_and(|insn| {
        insn.flow == Flow::IndirectBranch
            && insn
                .memory_target
                .is_some_and(|slot| image.import_locations.contains_key(&slot))
    })
}

/// A `jmp` through a register, or through memory other than an import slot.
fn register_jump(image: &LoadedImage, insn: &DecodedInstruction) -> bool {
    insn.flow == Flow::IndirectBranch
        && !insn
            .memory_target
            .is_some_and(|slot| image.import_locations.contains_key(&slot))
}

/// The end of the leaf function at `start`, when every path from it stays in unclaimed
/// bytes, leaves the stack pointer alone and ends in `ret` or a jump to a known entry, and
/// whether it ends in a `jmp reg`.
fn leaf_end(
    analysis: &Analysis,
    function_starts: &BTreeSet<u64>,
    unwound: &[(u64, u64)],
    start: u64,
    info: &mut InstructionInfoFactory,
) -> Option<(u64, bool)> {
    let image = &analysis.image;
    let limit = start.saturating_add(MAX_LEAF_BYTES);
    let known_entry =
        |target: u64| function_starts.contains(&target) || analysis.seeds.contains_key(&target);
    let mut pending = vec![start];
    let mut seen = BTreeSet::new();
    let mut end = start;
    let mut indexed = false;
    let mut dispatches = false;
    while let Some(mut address) = pending.pop() {
        loop {
            if seen.contains(&address) {
                break;
            }
            if !(start..limit).contains(&address)
                || (address != start && known_entry(address))
                || instruction_location(analysis, address).is_some()
                || inside_unwind_extent(unwound, address)
                || image.is_code_excluded(address)
                || seen.len() >= MAX_LEAF_INSNS
            {
                return None;
            }
            let insn = image.decode_at(address).ok()?;
            image.va_to_file_offset(insn.next_address.checked_sub(1)?)?;
            if !leaf_instruction(image, &insn, address == start, info) {
                return None;
            }
            seen.insert(address);
            end = end.max(insn.next_address);
            let x86 = insn.x86_instruction();
            indexed |= (0..x86.op_count()).any(|operand| x86.op_kind(operand) == OpKind::Memory)
                && x86.memory_index() != Register::None;
            match insn.flow {
                Flow::Next => address = insn.next_address,
                Flow::ConditionalBranch => {
                    pending.push(insn.direct_target?);
                    address = insn.next_address;
                }
                Flow::UnconditionalBranch => {
                    let target = insn.direct_target?;
                    if !known_entry(target) {
                        // A jump inside the body; anything else is a tail call.
                        pending.push(target);
                    }
                    break;
                }
                Flow::IndirectBranch => {
                    // A jump through an import slot, or `jmp reg` as a tail call. A memory jump
                    // elsewhere, or a register loaded from an indexed table, is a switch
                    // dispatch whose cases this walk cannot see.
                    if register_jump(image, &insn) {
                        if x86.op0_kind() == OpKind::Memory || indexed {
                            return None;
                        }
                        dispatches = true;
                    }
                    break;
                }
                Flow::Return => break,
                Flow::Call | Flow::IndirectCall | Flow::Terminal => return None,
            }
        }
    }
    // Branch targets must land on instruction boundaries of the same body.
    let overlaps = seen
        .iter()
        .zip(seen.iter().skip(1))
        .any(|(&first, &second)| {
            image
                .decode_at(first)
                .is_ok_and(|insn| insn.next_address > second)
        });
    (!overlaps).then_some((end, dispatches))
}

/// An instruction a frameless leaf can hold: no stack traffic, no write to the stack pointer,
/// nothing privileged, and memory operands that stay inside the image.
fn leaf_instruction(
    image: &LoadedImage,
    insn: &DecodedInstruction,
    entry: bool,
    info: &mut InstructionInfoFactory,
) -> bool {
    if insn.mnemonic_override.is_some() {
        return false;
    }
    let x86 = insn.x86_instruction();
    // `add [rax], al` is how zero bytes decode; no compiled function starts that way.
    if entry && insn.bytes.as_slice().starts_with(&[0, 0]) {
        return false;
    }
    if insn.flow != Flow::Return && x86.is_stack_instruction() {
        return false;
    }
    if insn.flow == Flow::Return && x86.immediate16() != 0 {
        // The x64 convention has the caller clean the stack.
        return false;
    }
    if matches!(
        x86.mnemonic(),
        Mnemonic::In
            | Mnemonic::Out
            | Mnemonic::Insb
            | Mnemonic::Insw
            | Mnemonic::Insd
            | Mnemonic::Outsb
            | Mnemonic::Outsw
            | Mnemonic::Outsd
            | Mnemonic::Hlt
            | Mnemonic::Cli
            | Mnemonic::Sti
            | Mnemonic::Int
            | Mnemonic::Into
            | Mnemonic::Iret
            | Mnemonic::Iretd
            | Mnemonic::Iretq
            | Mnemonic::Sysret
            | Mnemonic::Sysexit
            | Mnemonic::Wait
            | Mnemonic::Lahf
            | Mnemonic::Sahf
            | Mnemonic::Cmc
            | Mnemonic::Std
            | Mnemonic::Xlatb
            | Mnemonic::Retf
    ) || x86.is_jmp_far_indirect()
        || x86.is_call_far_indirect()
    {
        return false;
    }
    let segment = x86.segment_prefix();
    if segment != Register::None && !matches!(segment, Register::FS | Register::GS) {
        return false;
    }
    if (0..x86.op_count()).any(|operand| x86.op_kind(operand) == OpKind::Memory) {
        if x86.is_ip_rel_memory_operand() {
            if image.bytes_at(x86.ip_rel_memory_address(), 1).is_none() {
                return false;
            }
        } else if x86.memory_base() == Register::None
            && x86.memory_index() == Register::None
            && !matches!(segment, Register::FS | Register::GS)
        {
            // An absolute address: position-independent x64 code does not use one.
            return false;
        }
    }
    insn.flow == Flow::Return
        || !info.info(x86).used_registers().iter().any(|used| {
            matches!(
                used.register().full_register(),
                Register::RSP | Register::ES | Register::CS | Register::SS | Register::DS
            ) && matches!(
                used.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            )
        })
}
