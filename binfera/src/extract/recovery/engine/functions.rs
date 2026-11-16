//! Function and compatibility block views, plus call indexes.
use super::*;

// codeblocks.py deletes a stale pointer before trying to decode its suffix.
// locmap resolves that deletion through the current location at the pointer's
// original start, so the overlapping opcode is removed instead. The stale
// suffix remains orphaned; revisiting it aborts block analysis.
pub(super) fn prepare_function_code(
    analysis: &mut Analysis,
    graph: &DirectFlowGraph,
    pointers: &mut super::super::pointers::Discovery,
    start: u64,
    block_starts_seen: &mut BTreeSet<u64>,
) -> Option<Result<u64, ()>> {
    let mut pending = vec![start];
    let mut done = BTreeSet::new();
    while let Some(mut address) = pending.pop() {
        if !done.insert(address) {
            continue;
        }
        let block_start = address;
        if instruction_location(analysis, address).is_some() {
            block_starts_seen.insert(address);
        }
        loop {
            let Some(location) = instruction_location(analysis, address) else {
                if let Some((pointer, end)) = pointers.pointer_location(analysis, address) {
                    if let Some(opcode) =
                        instruction_location(analysis, pointer).map(|insn| insn.address)
                    {
                        analysis.instructions.remove(&opcode);
                        pointers.remove_pointer_reference(pointer);
                        for sources in analysis.code_xrefs.values_mut() {
                            sources.retain(|source| *source != pointer);
                        }
                        analysis.code_xrefs.retain(|_, sources| !sources.is_empty());
                        analysis.diagnostics.push(RecoveryDiagnostic {
                            address,
                            message: format!(
                                "function {start:#x} has an overlapping pointer at {pointer:#x}"
                            ),
                        });
                        break;
                    }
                    if pointers.orphan_pointer(analysis, address) {
                        return Some(Err(()));
                    }
                    pointers.mark_code(pointer, end);
                    return Some(Ok(address));
                }
                break;
            };
            if analysis.image.decode_at_compat(address).is_err() {
                block_starts_seen.remove(&block_start);
                break;
            }
            let Some(next) = address.checked_add(location.bytes.len() as u64) else {
                break;
            };
            let branches: Vec<_> = graph
                .successors
                .get(&address)
                .into_iter()
                .flatten()
                .filter(|edge| edge.kind != EdgeKind::Fallthrough)
                .map(|edge| edge.target)
                .collect();
            pending.extend(branches.iter().copied());
            if matches!(
                location.flow,
                Flow::UnconditionalBranch | Flow::IndirectBranch | Flow::Return | Flow::Terminal
            ) || analysis.noreturn_calls.contains(&location.address)
            {
                break;
            }
            if !branches.is_empty() || analysis.code_xrefs.contains_key(&next) {
                pending.push(next);
                break;
            }
            address = next;
        }
    }
    None
}

pub(super) fn build_function_view(
    analysis: &Analysis,
    direct_flow: &DirectFlowGraph,
    start: u64,
    isolate_start: bool,
) -> Result<Function, RecoveryError> {
    if direct_flow.compatibility {
        return build_compatibility_view(analysis, direct_flow, start);
    }
    let mut reachable = BTreeSet::new();
    let mut pending = VecDeque::from([start]);
    while let Some(address) = pending.pop_front() {
        if !analysis.instructions.contains_key(&address) || !reachable.insert(address) {
            continue;
        }
        if reachable.len() > MAX_INSNS_PER_FUNCTION {
            return Err(RecoveryError::Limit(format!(
                "function {start:#x} exceeds {MAX_INSNS_PER_FUNCTION} instructions"
            )));
        }
        if !isolate_start {
            let Some(edges) = direct_flow.successors.get(&address) else {
                continue;
            };
            let tail_jump = direct_flow.function_entries.len() > 1
                && analysis.instructions.get(&address).is_some_and(|insn| {
                    controlling_instruction(analysis, insn).flow == Flow::UnconditionalBranch
                });
            for edge in edges {
                if tail_jump
                    && edge.target != start
                    && direct_flow.function_entries.contains(&edge.target)
                {
                    continue;
                }
                // A PE unwind or ELF exception-frame entry is a linker-provided function
                // start. Falling into it must not merge two function scopes.
                // Explicit branches may still share tails or chained code.
                if edge.kind == EdgeKind::Fallthrough
                    && edge.target != start
                    && analysis.seeds.get(&edge.target).is_some_and(|kinds| {
                        kinds.contains(&SeedKind::Unwind)
                            || kinds.contains(&SeedKind::EhFrame)
                            || kinds.contains(&SeedKind::ArmExidx)
                    })
                {
                    continue;
                }
                pending.push_back(edge.target);
            }
        }
    }

    let mut block_starts = BTreeSet::from([start]);
    // Intersect from the smaller side so small functions do not scan every
    // code-reference target in the image. Both paths retain address order.
    if reachable.len() < analysis.code_xrefs.len() {
        block_starts.extend(
            reachable
                .iter()
                .filter(|address| analysis.code_xrefs.contains_key(address))
                .copied(),
        );
    } else {
        block_starts.extend(
            analysis
                .code_xrefs
                .keys()
                .filter(|address| reachable.contains(address))
                .copied(),
        );
    }
    for &address in &reachable {
        let Some(insn) = analysis.instructions.get(&address) else {
            continue;
        };
        if native_terminator(analysis, insn) {
            block_starts.extend(
                direct_flow
                    .successors
                    .get(&address)
                    .into_iter()
                    .flatten()
                    .filter(|edge| reachable.contains(&edge.target))
                    .map(|edge| edge.target),
            );
        }
    }

    let mut blocks = Vec::new();
    for &block_start in &block_starts {
        if !reachable.contains(&block_start) {
            continue;
        }
        let mut insns = Vec::new();
        let mut address = block_start;
        let succs = loop {
            let Some(insn) = analysis.instructions.get(&address) else {
                break Vec::new();
            };
            insns.push(insn.clone());
            let edges: Vec<Edge> = direct_flow
                .successors
                .get(&address)
                .into_iter()
                .flatten()
                .filter(|edge| reachable.contains(&edge.target))
                .copied()
                .collect();
            if native_terminator(analysis, insn) {
                break edges;
            }
            let next = insn.next_address;
            if next != block_start && block_starts.contains(&next) {
                break vec![Edge {
                    target: next,
                    kind: EdgeKind::Fallthrough,
                }];
            }
            if !reachable.contains(&next) {
                break Vec::new();
            }
            address = next;
        };
        // Views hold a copy of every instruction, so growth slack adds up on large images.
        insns.shrink_to_fit();
        blocks.push(BasicBlock {
            addr: block_start,
            insns,
            succs,
        });
    }
    blocks.sort_by_key(|block| block.addr);
    Ok(Function {
        addr: start,
        blocks,
    })
}

pub(super) fn split_adjacent_tables(
    analysis: &mut Analysis,
    graph: &mut DirectFlowGraph,
    branch: &DecodedInstruction,
    targets: &[u64],
) {
    let (Some(base), Some(first)) = (branch.memory_target, targets.first()) else {
        return;
    };
    // makeJumpTable splits a previous table when this table's first arm
    // already has a reference from an earlier indexed dispatch.
    let previous: Vec<_> = analysis
        .code_xrefs
        .get(first)
        .into_iter()
        .flatten()
        .filter_map(|source| analysis.instructions.get(source))
        .filter(|insn| {
            insn.address != branch.address
                && insn.flow == Flow::IndirectBranch
                && insn.x86_instruction().memory_index() != iced_x86::Register::None
                && insn.memory_target.is_some_and(|previous| previous < base)
        })
        .map(|insn| insn.address)
        .collect();
    if previous.is_empty() {
        return;
    }
    let affected: Vec<_> = graph
        .completed_functions
        .iter()
        .filter(|(_, function)| {
            function.blocks.iter().any(|block| {
                block
                    .insns
                    .iter()
                    .any(|insn| previous.contains(&insn.address))
            })
        })
        .map(|(&address, _)| address)
        .collect();
    for source in previous {
        if let Some(edges) = graph.successors.get_mut(&source) {
            edges.retain(|edge| !targets.contains(&edge.target));
        }
        for target in targets {
            if let Some(sources) = analysis.code_xrefs.get_mut(target) {
                sources.retain(|address| *address != source);
            }
        }
    }
    // splitJumpTable removes the former owner's case blocks. Refresh scopes
    // whose dispatch edges changed so they no longer retain those arms.
    for target in targets {
        let owner = graph
            .completed_functions
            .iter()
            .filter(|(_, function)| function.blocks.iter().any(|block| block.addr == *target))
            .max_by_key(|(address, _)| analysis.function_order.get(address).copied().unwrap_or(0))
            .map(|(&address, _)| address);
        if let Some(function) = owner.and_then(|owner| graph.completed_functions.get_mut(&owner)) {
            function.blocks.retain(|block| block.addr != *target);
        }
    }
    for address in affected {
        match build_function_view(analysis, graph, address, false) {
            Ok(function) => {
                graph.completed_functions.insert(address, function);
            }
            Err(error) => analysis.diagnostics.push(RecoveryDiagnostic {
                address,
                message: format!("could not rebuild function after splitting its table: {error}"),
            }),
        }
    }
}

pub(super) fn instruction_location(
    analysis: &Analysis,
    address: u64,
) -> Option<&DecodedInstruction> {
    // VivWorkspace.locmap overwrites each covered byte when a later opcode
    // overlaps an earlier one. A location can start at most fourteen bytes
    // before this address because x86 instructions are at most fifteen bytes.
    analysis
        .instructions
        .range(address.saturating_sub(14)..=address)
        .filter(|(_, insn)| address < insn.next_address)
        .max_by_key(|(start, _)| analysis.instruction_order.get(start).copied().unwrap_or(0))
        .map(|(_, insn)| insn)
}

/// Vivisect 1.3.2 generic/codeblocks.py advances by the existing location's
/// size, even when a branch enters its interior. viv_utils.BasicBlock then
/// decodes the resulting byte interval independently of those locations.
pub(super) fn build_compatibility_view(
    analysis: &Analysis,
    graph: &DirectFlowGraph,
    start: u64,
) -> Result<Function, RecoveryError> {
    let mut pending = vec![start];
    let mut done = BTreeSet::new();
    let mut blocks = Vec::new();
    let mut count = 0usize;
    while let Some(block_start) = pending.pop() {
        if !done.insert(block_start) {
            continue;
        }
        let mut address = block_start;
        let mut succs = Vec::new();
        while let Some(location) = instruction_location(analysis, address) {
            count += 1;
            if count > MAX_INSNS_PER_FUNCTION {
                return Err(RecoveryError::Limit(format!(
                    "function {start:#x} exceeds {MAX_INSNS_PER_FUNCTION} instructions"
                )));
            }
            if !analysis.instructions.contains_key(&address)
                && analysis.image.decode_at_compat(address).is_err()
            {
                // A decoder exception leaves blocks[start] at zero upstream.
                // Only an existing block survives a failed reanalysis.
                address = graph
                    .completed_functions
                    .get(&start)
                    .and_then(|function| {
                        function
                            .blocks
                            .iter()
                            .find(|block| block.addr == block_start)
                    })
                    .and_then(|block| block.insns.last())
                    .map_or(block_start, |last| last.next_address);
                break;
            }
            let Some(next) = address.checked_add(location.bytes.len() as u64) else {
                break;
            };
            let edges = graph.successors.get(&address);
            let branches: Vec<_> = edges
                .into_iter()
                .flatten()
                .filter(|edge| edge.kind != EdgeKind::Fallthrough)
                .copied()
                .collect();
            pending.extend(branches.iter().map(|edge| edge.target));
            let nofall = matches!(
                location.flow,
                Flow::UnconditionalBranch | Flow::IndirectBranch | Flow::Return | Flow::Terminal
            ) || analysis.noreturn_calls.contains(&location.address);
            address = next;
            if nofall {
                succs = branches;
                break;
            }
            // vivisect/analysis/generic/codeblocks.py follows fallthrough
            // across other function entries, including PE unwind roots.
            // Unwind metadata seeds discovery but is not a flow barrier.
            if !branches.is_empty() || analysis.code_xrefs.contains_key(&next) {
                succs = branches;
                succs.push(Edge {
                    target: next,
                    kind: EdgeKind::Fallthrough,
                });
                pending.push(next);
                break;
            }
        }
        let mut insns = Vec::new();
        let mut cursor = block_start;
        while cursor < address {
            let decoded = analysis
                .instructions
                .get(&cursor)
                .cloned()
                .map(Ok)
                .unwrap_or_else(|| analysis.image.decode_at_compat(cursor));
            let Ok(insn) = decoded else {
                break;
            };
            cursor = insn.next_address;
            insns.push(insn);
        }
        if !insns.is_empty() {
            insns.shrink_to_fit();
            blocks.push(BasicBlock {
                addr: block_start,
                insns,
                succs,
            });
        }
    }
    blocks.sort_by_key(|block| block.addr);
    Ok(Function {
        addr: start,
        blocks,
    })
}

fn controlling_instruction<'a>(
    analysis: &'a Analysis,
    insn: &'a DecodedInstruction,
) -> &'a DecodedInstruction {
    analysis
        .instructions
        .get(&insn.address.saturating_sub(4))
        .filter(|previous| {
            previous.risc().is_some_and(|r| r.delay) && previous.next_address == insn.address
        })
        .unwrap_or(insn)
}

fn native_terminator(analysis: &Analysis, insn: &DecodedInstruction) -> bool {
    let control = controlling_instruction(analysis, insn);
    if control.address != insn.address {
        is_block_terminator(control.flow) || analysis.noreturn_calls.contains(&control.address)
    } else if let Some(risc) = insn.risc() {
        risc.likely || (is_block_terminator(insn.flow) && !risc.delay)
    } else {
        is_block_terminator(insn.flow)
    }
}

pub(super) fn is_block_terminator(flow: Flow) -> bool {
    !matches!(flow, Flow::Next | Flow::Call | Flow::IndirectCall)
}

pub(super) fn rebuild_call_indexes(analysis: &mut Analysis) {
    let mut callers = BTreeMap::<u64, BTreeSet<u64>>::new();
    let mut callees = BTreeMap::<u64, BTreeSet<u64>>::new();
    for (&function_address, function) in &analysis.functions {
        let mut seen = BTreeSet::new();
        for insn in function.blocks.iter().flat_map(|block| &block.insns) {
            if !seen.insert(insn.address) || insn.flow != Flow::Call {
                continue;
            }
            let Some(target) = insn.direct_target else {
                continue;
            };
            callees.entry(function_address).or_default().insert(target);
            callers.entry(target).or_default().insert(function_address);
        }
    }
    analysis.callers = callers;
    analysis.callees = callees;
}
