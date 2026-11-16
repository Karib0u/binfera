//! Managed IL and data-only files use the same event stream as native code.
use super::*;
use crate::extract::decoder::DecodedInstruction;
use crate::extract::recovery::{BasicBlock, EdgeKind, Function};
use std::collections::BTreeMap;

/// The blocks of a recovered function to list. Its extent can swallow code the decompiler treats as
/// a tail call (a `jmp` into a shared routine), so when the line mapping is known only blocks it
/// touches and the `pinned` ones are certain to belong. Blocks on a path between those belong too: a
/// block that only sets a return value and rejoins the function can have no printed line of its own.
/// Such a path does not pass through the entry of `another_function`.
pub(super) fn shown_blocks<'a>(
    function: &'a Function,
    used: &BTreeSet<u64>,
    pinned: impl Fn(u64) -> bool,
    another_function: impl Fn(u64) -> bool,
) -> Vec<&'a BasicBlock> {
    if used.is_empty() {
        return function.blocks.iter().collect();
    }
    let certain: BTreeSet<u64> = function
        .blocks
        .iter()
        .filter(|b| pinned(b.addr) || b.insns.iter().any(|insn| used.contains(&insn.address)))
        .map(|b| b.addr)
        .collect();
    let mut next = BTreeMap::<u64, Vec<u64>>::new();
    let mut previous = BTreeMap::<u64, Vec<u64>>::new();
    for block in &function.blocks {
        for edge in block
            .succs
            .iter()
            .filter(|e| e.kind != EdgeKind::TailCall && !another_function(e.target))
        {
            next.entry(block.addr).or_default().push(edge.target);
            previous.entry(edge.target).or_default().push(block.addr);
        }
    }
    let after = reachable(&certain, &next);
    let before = reachable(&certain, &previous);
    function
        .blocks
        .iter()
        .filter(|b| after.contains(&b.addr) && before.contains(&b.addr))
        .collect()
}

/// `from` and everything the edges lead to.
fn reachable(from: &BTreeSet<u64>, edges: &BTreeMap<u64, Vec<u64>>) -> BTreeSet<u64> {
    let mut seen = from.clone();
    let mut queue: Vec<u64> = from.iter().copied().collect();
    while let Some(at) = queue.pop() {
        for &target in edges.get(&at).into_iter().flatten() {
            if seen.insert(target) {
                queue.push(target);
            }
        }
    }
    seen
}

pub(super) fn extra_listing<'a>(
    instructions: &'a BTreeMap<u64, DecodedInstruction>,
    address: u64,
    used: &BTreeSet<u64>,
) -> Vec<&'a DecodedInstruction> {
    match used.iter().next_back() {
        Some(&last) if last >= address => used
            .range(..address)
            .filter_map(|at| instructions.get(at))
            .chain(instructions.range(address..=last).map(|(_, insn)| insn))
            .collect(),
        // A shared body can precede the extra entry. Keep its mapped instructions
        // and the entry without scanning unrelated code between the two.
        _ => used
            .iter()
            .copied()
            .chain(std::iter::once(address))
            .filter_map(|at| instructions.get(&at))
            .collect(),
    }
}

pub(super) fn emit_managed_methods(
    bytes: &[u8],
    options: &BatchOptions,
    emit: &mut impl FnMut(BatchEvent) -> Result<(), DecompileError>,
) -> Result<(), DecompileError> {
    let parse = |e: crate::extract::ExtractError| DecompileError::Input(e.to_string());
    let pe = crate::extract::dotnet::load(bytes).map_err(parse)?;
    let methods = crate::extract::dotnet::listing::method_listings(&pe).map_err(parse)?;
    let warnings = vec!["managed .NET assembly: methods are shown as IL".to_owned()];
    emit(BatchEvent::Start {
        names: methods
            .iter()
            .map(|m| (u64::from(m.token), m.name.clone()))
            .collect(),
        functions: methods.iter().map(|m| u64::from(m.token)).collect(),
        arch: Some("cil".into()),
        warnings: warnings.clone(),
        packed: None,
    })?;
    let (index, count) = options.shard.unwrap_or((0, 1));
    for method in methods
        .into_iter()
        .enumerate()
        .filter(|(i, _)| i % count == index)
        .map(|(_, m)| m)
    {
        emit(BatchEvent::Function(Box::new(BatchFunction {
            address: u64::from(method.token),
            name: Some(method.name),
            text: Some(method.text),
            asm: method
                .rows
                .into_iter()
                .map(|r| (u64::from(r.offset), r.bytes, r.text))
                .collect(),
            ..Default::default()
        })))?;
    }
    emit(BatchEvent::Settled)?;
    emit(BatchEvent::Done { warnings })
}

pub(super) fn emit_data_only_elf(
    bytes: &[u8],
    cpu: &str,
    emit: &mut impl FnMut(BatchEvent) -> Result<(), DecompileError>,
) -> Result<(), DecompileError> {
    goblin::elf::Elf::parse(bytes).map_err(|e| DecompileError::Input(e.to_string()))?;
    let warnings = vec![format!(
        "binfera does not decompile {cpu} code yet: showing the file's headers, symbols and strings only"
    )];
    emit(BatchEvent::Start {
        names: Default::default(),
        functions: Vec::new(),
        arch: None,
        warnings: warnings.clone(),
        packed: crate::packing::detect_elf(bytes),
    })?;
    emit(BatchEvent::Settled)?;
    emit(BatchEvent::Done { warnings })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::image::{Architecture, LoadedImage};
    use crate::extract::recovery::Edge;

    /// Blocks of one nop each at `address`, with the given successors.
    fn function(blocks: &[(u64, &[(u64, EdgeKind)])]) -> anyhow::Result<Function> {
        let image = LoadedImage::from_shellcode_at(&[0x90; 16], Architecture::X86, 0x1000);
        Ok(Function {
            addr: 0x1000,
            blocks: blocks
                .iter()
                .map(|(addr, succs)| {
                    Ok(BasicBlock {
                        addr: *addr,
                        insns: vec![image.decode_at(*addr)?],
                        succs: succs
                            .iter()
                            .map(|&(target, kind)| Edge { target, kind })
                            .collect(),
                    })
                })
                .collect::<anyhow::Result<_>>()?,
        })
    }

    fn shown(function: &Function, used: &[u64]) -> Vec<u64> {
        let used = used.iter().copied().collect();
        shown_blocks(
            function,
            &used,
            |block| block == function.addr,
            |block| block == 0x1008,
        )
        .iter()
        .map(|b| b.addr)
        .collect()
    }

    #[test]
    fn blocks_without_a_printed_line_stay_when_they_rejoin_the_function() -> anyhow::Result<()> {
        use EdgeKind::{Branch, Fallthrough, TailCall};
        let f = function(&[
            (0x1000, &[(0x1001, Fallthrough), (0x1002, Branch)]),
            // Only sets a return value, then joins the epilogue: no line maps to it.
            (0x1001, &[(0x1003, Branch)]),
            (0x1002, &[(0x1003, Fallthrough)]),
            (0x1003, &[]),
            // A shared routine reached by a jump, which never comes back.
            (0x1004, &[(0x1005, Fallthrough)]),
            (0x1005, &[]),
        ])?;
        assert_eq!(
            shown(&f, &[0x1002, 0x1003]),
            [0x1000, 0x1001, 0x1002, 0x1003]
        );

        let g = function(&[
            (0x1000, &[(0x1001, Branch), (0x1002, Fallthrough)]),
            (0x1001, &[(0x1003, Fallthrough)]),
            (0x1002, &[]),
            (0x1003, &[]),
            (0x1004, &[(0x1002, Fallthrough)]),
        ])?;
        // 0x1001 and 0x1003 lead nowhere that belongs, and nothing listed leads to 0x1004.
        assert_eq!(shown(&g, &[0x1002]), [0x1000, 0x1002]);

        // A recorded tail call is left, even when the routine runs on into listed code.
        let h = function(&[
            (0x1000, &[(0x1001, TailCall), (0x1002, Fallthrough)]),
            (0x1001, &[(0x1002, Fallthrough)]),
            (0x1002, &[]),
        ])?;
        assert_eq!(shown(&h, &[0x1002]), [0x1000, 0x1002]);

        // Another function's entry is a boundary, even when its code runs back into this one.
        let i = function(&[
            (0x1000, &[(0x1008, Branch), (0x1002, Fallthrough)]),
            (0x1008, &[(0x1002, Fallthrough)]),
            (0x1002, &[]),
        ])?;
        assert_eq!(shown(&i, &[0x1002]), [0x1000, 0x1002]);

        // Without a line mapping there is nothing to tell them apart: everything is listed.
        assert_eq!(shown(&h, &[]), [0x1000, 0x1001, 0x1002]);
        Ok(())
    }

    #[test]
    fn extra_listing_handles_shared_bodies_before_the_entry() -> anyhow::Result<()> {
        let image = LoadedImage::from_shellcode_at(&[0x90, 0x90, 0xc3], Architecture::X86, 0x1000);
        let instructions = (0x1000..=0x1002)
            .map(|at| image.decode_at(at).map(|insn| (at, insn)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        for (entry, used, expected) in [
            (0x1002, BTreeSet::from([0x1000]), vec![0x1000, 0x1002]),
            (
                0x1000,
                BTreeSet::from([0x1002]),
                vec![0x1000, 0x1001, 0x1002],
            ),
            (
                0x1001,
                BTreeSet::from([0x1000, 0x1002]),
                vec![0x1000, 0x1001, 0x1002],
            ),
            (0x1001, BTreeSet::new(), vec![0x1001]),
            (0x2000, BTreeSet::from([0x3000]), vec![]),
        ] {
            let actual: Vec<_> = extra_listing(&instructions, entry, &used)
                .iter()
                .map(|insn| insn.address)
                .collect();
            assert_eq!(actual, expected);
        }
        Ok(())
    }
}
