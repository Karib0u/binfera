//! Reconcile compatibility and native function discovery for batch decompilation.
use super::*;

pub(in crate::decompiler) fn needs_compatibility(analysis: &Analysis) -> bool {
    analysis.instructions.len() <= 1_000_000
        && !matches!(
            analysis.image.format,
            crate::extract::image::ImageFormat::Macho | crate::extract::image::ImageFormat::Sc
        )
}

pub(super) fn select_analysis(
    bytes: &[u8],
    mut native: Analysis,
    session: &mut DecompilerSession,
) -> Result<(Analysis, BTreeSet<u64>), DecompileError> {
    let mut rejected = BTreeSet::new();
    // The functions listed come from the capability-matching recovery, which finds functions the
    // decompiler's own misses; decompiling them first also tells the decompiler they are code. A
    // large image skips that second recovery and lists the decompiler's: each holds gigabytes
    // there, and the browser has 4 GB per worker.
    let analysis = if needs_compatibility(&native) {
        let mut listed = match crate::extract::recovery::analyze(bytes) {
            Ok(listed) => listed,
            Err(error) => {
                session.warnings.push(format!(
                    "Optional compatibility recovery failed; using native function discovery: {error}"
                ));
                return Ok((native, rejected));
            }
        };
        rejected = crate::decompiler::rejected_compatibility_entries(&native, &listed);
        // Include callees newly reached through validated virtual tables.
        // A conditional branch target is a block of the function that branches to it (a cold
        // panic path, a switch arm), even when a pointer names it too.
        let branched: std::collections::BTreeSet<u64> = native
            .instructions
            .values()
            .filter(|insn| insn.flow == crate::extract::decoder::Flow::ConditionalBranch)
            .filter_map(|insn| insn.direct_target)
            .collect();
        // An instruction that runs straight into a start (`push esi; push edi` before a cold
        // `push 0; push msg; call panic`) makes it a block of the same function; padding does
        // not.
        let falls_into = |address: &u64| {
            use crate::extract::decoder::Flow;
            // Every instruction, in either recovery, that ends where the start begins; an
            // overlapping decode can run into it while the real one ends in a `ret`.
            let ending: Vec<_> = [&native.instructions, &listed.instructions]
                .iter()
                .flat_map(|instructions| instructions.range(address.saturating_sub(15)..*address))
                .map(|(_, insn)| insn)
                .filter(|insn| insn.next_address == *address)
                .collect();
            ending
                .iter()
                .any(|insn| insn.flow == Flow::Next && !insn.is_alignment_filler())
                && !ending.iter().any(|insn| {
                    matches!(
                        insn.flow,
                        Flow::Return
                            | Flow::UnconditionalBranch
                            | Flow::IndirectBranch
                            | Flow::Terminal
                    )
                })
        };
        // Vivisect's late entry signatures (`push 0; push imm32; call`, an SEH prologue) also match
        // such cold paths; with nothing else naming them a start, they are not listed.
        let seh_shaped = |address: &u64| {
            native.image.bytes_at(*address, 8).is_some_and(|bytes| {
                bytes.len() == 8 && bytes[0] == 0x6a && bytes[2] == 0x68 && bytes[7] == 0xe8
            })
        };
        let weak: Vec<u64> = listed
            .functions
            .keys()
            .copied()
            .filter(|address| {
                listed.seeds.get(address).is_some_and(|kinds| {
                    kinds.iter().all(|kind| {
                        matches!(
                            kind,
                            crate::extract::recovery::SeedKind::FunctionSignature
                                | crate::extract::recovery::SeedKind::PointerTarget
                        )
                    })
                }) && seh_shaped(address)
                    && falls_into(address)
            })
            .collect();
        for address in weak {
            listed.functions.remove(&address);
        }
        let mut table_reachable: std::collections::BTreeSet<_> = native
            .seeds
            .iter()
            .filter(|(address, kinds)| {
                kinds.contains(&crate::extract::recovery::SeedKind::Vtable)
                    || kinds.contains(&crate::extract::recovery::SeedKind::Unclaimed)
                    || (native.image.format == crate::extract::image::ImageFormat::Pe
                        && matches!(
                            native.image.architecture,
                            crate::extract::image::Architecture::X86
                                | crate::extract::image::Architecture::X64
                        )
                        && kinds.contains(&crate::extract::recovery::SeedKind::PointerTarget)
                        && !branched.contains(address)
                        && !(seh_shaped(address) && falls_into(address)))
            })
            .map(|(address, _)| *address)
            .collect();
        // Follow `call`s only: native callees also record tail jumps, and a conditional jump to
        // a cold block (a panic path, say) would otherwise become a function of its own.
        let called: std::collections::BTreeSet<u64> = native
            .instructions
            .values()
            .filter(|insn| insn.flow == crate::extract::decoder::Flow::Call)
            .filter_map(|insn| insn.direct_target)
            .collect();
        let mut pending: Vec<_> = table_reachable.iter().copied().collect();
        while let Some(address) = pending.pop() {
            for target in native.callees.get(&address).into_iter().flatten() {
                if called.contains(target) && table_reachable.insert(*target) {
                    pending.push(*target);
                }
            }
        }
        let seeds = &native.seeds;
        let keep_native = |address: &u64, function: &crate::extract::recovery::Function| {
            table_reachable.contains(address)
                || session.is_named_function(*address)
                || seeds.get(address).is_some_and(|kinds| {
                    // Include unwind entries even if compatibility recovery stops at a bad row.
                    kinds.contains(&SeedKind::EhFrame)
                        || kinds.contains(&SeedKind::Vtable)
                        || kinds.contains(&SeedKind::Unwind)
                        || (kinds.contains(&SeedKind::Relocation) && straight_line_leaf(function))
                })
        };
        // Callers can come from either recovery pass. Count only entries the
        // ordinary inventory rules would keep, so stubs cannot seed each other.
        let callers = native.functions.iter().filter_map(|(address, function)| {
            ((listed.functions.contains_key(address) || keep_native(address, function))
                && !rejected.contains(address)
                && session.is_code_address(*address)
                && !session.is_local_label(*address))
            .then_some(*address)
        });
        let called_stubs = called_win64_stubs(&native, callers);
        // Keep compatibility coverage, but use the native graph for shared functions:
        // it includes validated compiler continuations and corrected block boundaries.
        for (address, function) in std::mem::take(&mut native.functions) {
            let kinds = seeds.get(&address);
            // Compatibility can stop before this unwind row, even when it found the function.
            if kinds.is_some_and(|kinds| kinds.contains(&SeedKind::Unwind)) {
                listed
                    .seeds
                    .entry(address)
                    .or_default()
                    .insert(SeedKind::Unwind);
            }
            if let Some(existing) = listed.functions.get_mut(&address) {
                *existing = function;
            } else if keep_native(&address, &function) || called_stubs.contains(&address) {
                listed.functions.insert(address, function);
            }
        }
        // Zero-filled executable memory (a packer's section that is empty on disk) decodes as an
        // endless run of `add [rax], al`. No function begins with sixteen zero bytes, and
        // decompiling one only burns its whole deadline.
        let zero_filled: Vec<u64> = listed
            .functions
            .keys()
            .copied()
            .filter(|&address| {
                listed
                    .image
                    .bytes_at(address, 16)
                    .is_some_and(|bytes| bytes.len() == 16 && bytes.iter().all(|&byte| byte == 0))
            })
            .collect();
        for address in zero_filled {
            listed.functions.remove(&address);
        }
        drop(native);
        listed
    } else {
        native
    };
    Ok((analysis, rejected))
}

/// Show recovered Win64 jump stubs with a direct call from a listed function.
/// This keeps linker stubs reachable without listing every unused IAT entry.
pub(super) fn called_win64_stubs(
    analysis: &Analysis,
    callers: impl Iterator<Item = u64>,
) -> BTreeSet<u64> {
    use crate::extract::{decoder::Flow, image::Architecture};

    if analysis.image.format != ImageFormat::Pe || analysis.image.architecture != Architecture::X64
    {
        return BTreeSet::new();
    }
    let mut called = BTreeSet::new();
    for caller in callers.filter_map(|entry| analysis.functions.get(&entry)) {
        for insn in caller.blocks.iter().flat_map(|block| &block.insns) {
            if insn.flow == Flow::Call {
                if let Some(target) = insn
                    .direct_target
                    .filter(|&target| target != caller.addr && target != insn.next_address)
                {
                    called.insert(target);
                }
            }
        }
    }
    called.retain(|address| {
        let Some(entry) = analysis
            .functions
            .get(address)
            .and_then(|function| function.blocks.iter().find(|block| block.addr == *address))
        else {
            return false;
        };
        let [jump] = entry.insns.as_slice() else {
            return false;
        };
        jump.address == *address
            && match jump.flow {
                Flow::UnconditionalBranch => jump.direct_target.is_some_and(|target| {
                    target != *address && analysis.functions.contains_key(&target)
                }),
                Flow::IndirectBranch => jump
                    .memory_target
                    .is_some_and(|slot| analysis.image.import_locations.contains_key(&slot)),
                _ => false,
            }
    });
    called
}

// Promote relocation entries only when they have a bounded leaf body.
fn straight_line_leaf(function: &crate::extract::recovery::Function) -> bool {
    use crate::extract::decoder::Flow;
    let [block] = function.blocks.as_slice() else {
        return false;
    };
    let Some((last, body)) = block.insns.split_last() else {
        return false;
    };
    block.addr == function.addr
        && block.insns.len() <= 32
        && last.flow == Flow::Return
        && body.iter().all(|insn| insn.flow == Flow::Next)
        && block
            .insns
            .windows(2)
            .all(|pair| pair[0].next_address == pair[1].address)
}

#[cfg(test)]
mod tests {
    #[test]
    fn win64_stubs_need_a_direct_call_from_a_listed_body() -> anyhow::Result<()> {
        use crate::extract::{
            image::{Architecture, ImageFormat},
            recovery::{analyze_shellcode_native, BasicBlock, Function},
        };

        let mut bytes = vec![0xcc; 0x68];
        bytes[..15].copy_from_slice(&[
            0xe8, 0x1b, 0, 0, 0, // call 0x20
            0xe8, 0x26, 0, 0, 0, // call 0x30
            0xe9, 0x31, 0, 0, 0, // jump to 0x40
        ]);
        bytes[0x20..0x25].copy_from_slice(&[0xe9, 0x2b, 0, 0, 0]); // jump to 0x50
        bytes[0x30..0x36].copy_from_slice(&[0xff, 0x25, 0x2a, 0, 0, 0]); // jump via 0x60
        bytes[0x40..0x45].copy_from_slice(&[0xe9, 0x0b, 0, 0, 0]); // jump to 0x50
        bytes[0x50] = 0xc3;

        let mut analysis = analyze_shellcode_native(&bytes, Architecture::X64)?;
        analysis.image.format = ImageFormat::Pe;
        let base = analysis
            .image
            .entry_point
            .ok_or_else(|| anyhow::anyhow!("missing entry"))?;
        analysis
            .image
            .import_locations
            .insert(base + 0x60, "test.Import".into());
        // Supply separate recovered entries to model a PE linker stub table.
        for (offset, instructions) in [
            (0, &[0, 5, 10][..]),
            (0x20, &[0x20][..]),
            (0x30, &[0x30][..]),
            (0x40, &[0x40][..]),
            (0x50, &[0x50][..]),
        ] {
            let addr = base + offset;
            let insns = instructions
                .iter()
                .map(|offset| analysis.image.decode_at(base + offset))
                .collect::<Result<Vec<_>, _>>()?;
            analysis.functions.insert(
                addr,
                Function {
                    addr,
                    blocks: vec![BasicBlock {
                        addr,
                        insns,
                        succs: Vec::new(),
                    }],
                },
            );
        }
        let stubs = super::called_win64_stubs(&analysis, std::iter::once(base));
        assert_eq!(stubs, [base + 0x20, base + 0x30].into());
        assert!(super::called_win64_stubs(&analysis, std::iter::empty()).is_empty());
        analysis.image.import_locations.clear();
        assert_eq!(
            super::called_win64_stubs(&analysis, std::iter::once(base)),
            [base + 0x20].into()
        );
        Ok(())
    }

    #[test]
    fn relocated_callbacks_require_a_straight_line_leaf() -> Result<(), Box<dyn std::error::Error>>
    {
        use crate::extract::{image::Architecture, recovery::analyze_shellcode};
        for (bytes, expected) in [
            (vec![0x8b, 8, 0x89, 0x0a, 0xc3], true),
            (vec![0xdf, 0x28, 0xdf, 0x3a, 0xc3], true),
            (vec![0x85, 0xc0, 0x74, 1, 0x90, 0xc3], false),
            (vec![0xe8, 0, 0, 0, 0, 0xc3], false),
        ] {
            let analysis = analyze_shellcode(&bytes, Architecture::X86)?;
            let function = analysis
                .functions
                .get(&analysis.image.entry_point.ok_or("entry")?)
                .ok_or("function")?;
            assert_eq!(super::straight_line_leaf(function), expected, "{bytes:x?}");
        }
        Ok(())
    }
}
