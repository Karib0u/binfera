//! Reconcile compatibility and native function discovery for batch decompilation.
use super::*;

pub(super) fn needs_compatibility(analysis: &Analysis) -> bool {
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
        // Keep compatibility coverage, but use the native graph for shared functions:
        // it includes validated compiler continuations and corrected block boundaries.
        for (address, function) in std::mem::take(&mut native.functions) {
            let kinds = native.seeds.get(&address);
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
            } else if table_reachable.contains(&address)
                || session.is_named_function(address)
                || kinds.is_some_and(|kinds| {
                    // `.pdata` entries too: compatibility recovery, like Vivisect, gives up on
                    // the whole directory at the first entry it cannot read (Delphi x64).
                    kinds.contains(&SeedKind::EhFrame)
                        || kinds.contains(&SeedKind::Vtable)
                        || kinds.contains(&SeedKind::Unwind)
                        || (kinds.contains(&SeedKind::Relocation) && straight_line_leaf(&function))
                })
            {
                // Declared ELF entries must not depend on speculative callee
                // discovery from another function's decompilation.
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
