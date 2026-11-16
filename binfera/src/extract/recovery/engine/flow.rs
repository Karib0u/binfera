//! Recursive instruction flow discovery.
use super::*;

pub(super) fn discover_direct_flow(
    analysis: &mut Analysis,
    direct_flow: &mut DirectFlowGraph,
    start: u64,
    pointers: &mut super::super::pointers::Discovery,
) -> Result<BTreeSet<u64>, RecoveryError> {
    discover_flow(analysis, direct_flow, start, pointers, None)
}

enum FlowTask {
    Path(u64),
    ResumeOpcode(u64),
    CallbackTarget(u64, SeedKind),
    FinishFunction(u64),
    FinalizeFunction(u64),
    FlirtLocal(u64),
    ReleaseDelayed(u64),
    FollowPointers(VecDeque<(DecodedInstruction, u64)>),
    ResumeCall {
        address: u64,
        next: u64,
        target: u64,
    },
}

fn delay_function_for_branch(
    pending: &VecDeque<FlowTask>,
    target: u64,
    delayed: &mut BTreeMap<u64, BTreeSet<u64>>,
    loose_root: Option<u64>,
) {
    let mut active = pending.iter().filter_map(|task| match task {
        FlowTask::FinishFunction(address) => Some(*address),
        FlowTask::Path(_)
        | FlowTask::ResumeOpcode(_)
        | FlowTask::CallbackTarget(_, _)
        | FlowTask::ResumeCall { .. }
        | FlowTask::FinalizeFunction(_)
        | FlowTask::FlirtLocal(_)
        | FlowTask::ReleaseDelayed(_)
        | FlowTask::FollowPointers(_) => None,
    });
    if let Some(current) = active.next() {
        if current != target
            && (loose_root == Some(target) || active.any(|address| address == target))
        {
            delayed.entry(current).or_default().insert(target);
        }
    }
}

pub(super) fn discover_flow(
    analysis: &mut Analysis,
    direct_flow: &mut DirectFlowGraph,
    start: u64,
    pointers: &mut super::super::pointers::Discovery,
    mut import_functions: Option<&mut BTreeSet<u64>>,
) -> Result<BTreeSet<u64>, RecoveryError> {
    let mut pending = VecDeque::from([FlowTask::Path(start)]);
    if direct_flow.compatibility && import_functions.is_none() {
        pending.push_back(FlowTask::FinishFunction(start));
    }
    let mut calls = BTreeSet::new();
    let mut discovered = 0usize;
    // envi/codeflow.py delays the function callback when a branch enters
    // an ancestor still on the analysis stack. Its complete extent is only
    // available after that ancestor finishes.
    let mut delayed = BTreeMap::<u64, BTreeSet<u64>>::new();
    let mut released_callbacks = BTreeSet::new();
    let mut retyping_functions = BTreeSet::new();
    let mut failed_block_analysis = BTreeSet::new();
    let mut block_starts_seen = BTreeMap::<u64, BTreeSet<u64>>::new();
    let loose_root = import_functions.as_ref().map(|_| start);

    'tasks: while let Some(task) = pending.pop_front() {
        let mut resume_opcode = matches!(task, FlowTask::ResumeOpcode(_));
        let path_start = match task {
            FlowTask::Path(address) | FlowTask::ResumeOpcode(address) => address,
            FlowTask::ResumeCall {
                address,
                next,
                target,
            } => {
                if direct_flow.known_noreturn.contains(&target) {
                    analysis.noreturn_calls.insert(address);
                    remove_code_reference(analysis, address, target);
                    direct_flow.successors.insert(address, Vec::new());
                } else {
                    pending.push_front(FlowTask::Path(next));
                }
                continue;
            }
            FlowTask::FinishFunction(address) => {
                if delayed.contains_key(&address)
                    || direct_flow.completed_functions.contains_key(&address)
                {
                    continue;
                }
                let order = analysis.function_order.len();
                analysis.function_order.entry(address).or_insert(order);
                let pointer = if failed_block_analysis.remove(&address) {
                    Some(Err(()))
                } else if direct_flow.compatibility {
                    prepare_function_code(
                        analysis,
                        direct_flow,
                        pointers,
                        address,
                        block_starts_seen.entry(address).or_default(),
                    )
                } else {
                    None
                };
                if let Some(Ok(target)) = pointer {
                    retyping_functions.insert(address);
                    pending.push_front(FlowTask::FinishFunction(address));
                    pending.push_front(FlowTask::Path(target));
                    continue;
                }
                let view = if pointer.is_some() {
                    Ok(Function {
                        addr: address,
                        blocks: Vec::new(),
                    })
                } else {
                    build_function_view(analysis, direct_flow, address, false)
                };
                match view {
                    Ok(mut function) => {
                        // addCodeBlock installs blocks in address order and
                        // stops when a previously visited start was deleted
                        // by pointer reclassification during this analyzer.
                        if let Some(missing) = block_starts_seen
                            .get(&address)
                            .into_iter()
                            .flatten()
                            .find(|start| {
                                instruction_location(analysis, **start).is_none()
                                    && !pointers.has_data_location(**start)
                            })
                        {
                            function.blocks.retain(|block| block.addr < *missing);
                            analysis.diagnostics.push(RecoveryDiagnostic { address: *missing, message: format!("function {address:#x} block installation stopped at a deleted location") });
                        }
                        analysis.functions.insert(address, function.clone());
                        direct_flow
                            .completed_functions
                            .entry(address)
                            .or_insert(function);
                    }
                    Err(error) => analysis.diagnostics.push(RecoveryDiagnostic {
                        address,
                        message: format!("could not preserve function extent: {error}"),
                    }),
                }
                pointers.function_completed(analysis, address);
                pending.push_front(FlowTask::FinalizeFunction(address));
                // Calling analysis runs after codeblocks and before noret,
                // while the procedural caller is still suspended.
                if direct_flow.compatibility && super::super::callbacks::enabled(&analysis.image) {
                    let (targets, operands, branches) = super::super::callbacks::discover(
                        analysis,
                        address,
                        &direct_flow.known_noreturn,
                        pointers,
                    );
                    // generic/switchcase runs only for dispatches reached
                    // by calling emulation, after the initial codeblock pass.
                    let mut switch_targets = Vec::new();
                    for branch in branches {
                        if let Some(targets) = super::super::switch::targets_compat(
                            analysis,
                            &branch,
                            &direct_flow.known_noreturn,
                            &mut direct_flow.pending_table_locations,
                        ) {
                            let edges = targets
                                .iter()
                                .map(|target| {
                                    push_xref(&mut analysis.code_xrefs, *target, branch.address);
                                    Edge {
                                        target: *target,
                                        kind: EdgeKind::JumpTable,
                                    }
                                })
                                .collect();
                            direct_flow.successors.insert(branch.address, edges);
                            switch_targets.extend(targets);
                        }
                    }
                    if !switch_targets.is_empty() {
                        pending.pop_front();
                        direct_flow.completed_functions.remove(&address);
                        pending.push_front(FlowTask::FinishFunction(address));
                        for target in switch_targets.into_iter().rev() {
                            pending.push_front(FlowTask::Path(target));
                        }
                    }
                    // addAnalysisResults runs after calls discovered by the
                    // emulator have completed. Follow its operands one at a
                    // time before this function's noret and FLIRT analyses.
                    pending.push_front(FlowTask::FollowPointers(operands.into()));
                    for (target, kind) in targets.into_iter().rev() {
                        pending.push_front(FlowTask::CallbackTarget(target, kind));
                    }
                }
                continue;
            }
            FlowTask::CallbackTarget(target, kind) => {
                if (kind == SeedKind::ApiCallback
                    && super::super::pointers::covered(analysis, target))
                    || direct_flow.completed_functions.contains_key(&target)
                    || pending
                        .iter()
                        .any(|task| matches!(task, FlowTask::FinishFunction(va) if *va == target))
                {
                    continue;
                }
                analysis.seeds.entry(target).or_default().insert(kind);
                calls.insert(target);
                pending.push_front(FlowTask::FinishFunction(target));
                pending.push_front(FlowTask::Path(target));
                continue;
            }
            FlowTask::FollowPointers(mut operands) => {
                while let Some((instruction, target)) = operands.pop_front() {
                    pointers.observe_instruction(analysis, &instruction, false);
                    let Some(target) = pointers.follow_observed_pointer(
                        analysis,
                        target,
                        &direct_flow.known_noreturn,
                    ) else {
                        continue;
                    };
                    if direct_flow.completed_functions.contains_key(&target)
                        || pending.iter().any(
                            |task| matches!(task, FlowTask::FinishFunction(va) if *va == target),
                        )
                    {
                        continue;
                    }
                    calls.insert(target);
                    pending.push_front(FlowTask::FollowPointers(operands));
                    pending.push_front(FlowTask::FinishFunction(target));
                    pending.push_front(FlowTask::Path(target));
                    break;
                }
                continue;
            }
            FlowTask::FinalizeFunction(address) => {
                if direct_flow.compatibility
                    && direct_flow
                        .completed_functions
                        .get(&address)
                        .is_some_and(|function| {
                            noreturn::completed_function_never_returns(
                                analysis,
                                function,
                                &direct_flow.known_noreturn,
                            )
                        })
                {
                    direct_flow.known_noreturn.insert(address);
                }
                analysis
                    .function_flirt_counts
                    .insert(address, analysis.function_order.len());
                analysis
                    .function_location_counts
                    // Retyping can delete locations, but discovery order is
                    // monotonic. FLIRT visibility uses that same sequence.
                    .insert(address, analysis.instruction_order.len());
                // addEntryPoint releases only its immediate dependents via
                // _cb_function. Those callbacks do not recursively release
                // another level of deferred functions.
                if !released_callbacks.remove(&address) {
                    pending.push_front(FlowTask::ReleaseDelayed(address));
                }
                if let Some(flirt) = direct_flow.flirt.as_mut() {
                    for target in flirt
                        .function_completed(analysis, address)?
                        .into_iter()
                        .rev()
                    {
                        pending.push_front(FlowTask::FlirtLocal(target));
                    }
                }
                continue;
            }
            FlowTask::FlirtLocal(target) => {
                if instruction_location(analysis, target).is_none()
                    && !direct_flow.completed_functions.contains_key(&target)
                {
                    analysis
                        .seeds
                        .entry(target)
                        .or_default()
                        .insert(SeedKind::FlirtLocal);
                    calls.insert(target);
                    pending.push_front(FlowTask::FinishFunction(target));
                    pending.push_front(FlowTask::Path(target));
                }
                continue;
            }
            FlowTask::ReleaseDelayed(address) => {
                analysis
                    .function_analysis_counts
                    .insert(address, analysis.function_order.len());
                let mut ready = Vec::new();
                for (&waiting, dependencies) in &mut delayed {
                    dependencies.remove(&address);
                    if dependencies.is_empty() {
                        ready.push(waiting);
                    }
                }
                for waiting in ready.into_iter().rev() {
                    delayed.remove(&waiting);
                    released_callbacks.insert(waiting);
                    pending.push_front(FlowTask::FinishFunction(waiting));
                }
                continue;
            }
        };
        let mut address = path_start;
        loop {
            // Pinned Vivisect 1.3.2 discovers opcode locations and direct code
            // references before its generic codeblocks analysis assigns those
            // locations to functions. A known function entry is not a direct
            // flow barrier. Once an instruction is present in this shared
            // graph, every later function view can traverse its recorded edges.
            if direct_flow.compatibility && pointers.orphan_pointer(analysis, address) {
                if let Some(function) = pending
                    .iter()
                    .find_map(|task| match task {
                        FlowTask::FinishFunction(function) => Some(*function),
                        _ => None,
                    })
                    .filter(|function| retyping_functions.contains(function))
                {
                    failed_block_analysis.insert(function);
                    analysis.diagnostics.push(RecoveryDiagnostic { address, message: format!("function {function:#x} codeblock analysis reached a pointer without a reference") });
                }
            }
            if !resume_opcode
                && (super::super::emucode::in_data(pointers.code_barriers(), address)
                    || (direct_flow.compatibility
                        && pointers.pointer_location(analysis, address).is_some())
                    || (direct_flow.compatibility
                        && super::super::emucode::in_import(&analysis.image, address))
                    || direct_flow.successors.contains_key(&address)
                    || (direct_flow.compatibility
                        && instruction_location(analysis, address).is_some())
                    || !is_executable(&analysis.image, address))
            {
                break;
            }
            if discovered >= MAX_INSNS_PER_FUNCTION {
                analysis.diagnostics.push(RecoveryDiagnostic {
                    address: start,
                    message: format!(
                        "abandoned code walk: direct flow from {start:#x} exceeds {MAX_INSNS_PER_FUNCTION} instructions"
                    ),
                });
                // Keep the callees already found. Their no-return status may
                // cut this oversized walk down on the next recovery pass.
                return Ok(calls);
            }
            let decoded = if direct_flow.compatibility {
                analysis.image.decode_at_compat(address)
            } else {
                analysis.image.decode_at(address)
            };
            let insn = match decoded {
                Ok(insn) => insn,
                Err(error) => {
                    analysis.diagnostics.push(RecoveryDiagnostic {
                        address,
                        message: error.to_string(),
                    });
                    break;
                }
            };
            if !direct_flow.compatibility && insn.is_privileged_barrier() {
                analysis.diagnostics.push(RecoveryDiagnostic {
                    address,
                    message: "stopped recovery at privileged instruction".to_string(),
                });
                break;
            }
            super::super::super::risc::record_arm_context(&mut analysis.image, &insn);
            let mut next = insn.next_address;
            let mut control_address = address;
            if insn.risc().is_some_and(|r| r.delay) {
                let slot = match analysis.image.decode_at(next) {
                    Ok(slot) if slot.flow == Flow::Next => slot,
                    _ => {
                        analysis.diagnostics.push(RecoveryDiagnostic {
                            address,
                            message: "missing or invalid MIPS delay slot".into(),
                        });
                        break;
                    }
                };
                control_address = next;
                next = slot.next_address;
                direct_flow.successors.insert(
                    address,
                    vec![Edge {
                        target: control_address,
                        kind: EdgeKind::Fallthrough,
                    }],
                );
                analysis
                    .instruction_order
                    .entry(control_address)
                    .or_insert(analysis.instructions.len());
                direct_flow.note_new_instruction(control_address);
                analysis.instructions.insert(control_address, slot);
            }
            if let Some(target) = insn.memory_target {
                push_xref(&mut analysis.data_xrefs, target, address);
            }
            // makeOpcode records mapped non-dereferenced operands as REF_PTR.
            // These references also delimit adjacent jump tables.
            if direct_flow.compatibility {
                let op = insn.x86_instruction();
                for index in 0..op.op_count() {
                    let target = match op.op_kind(index) {
                        iced_x86::OpKind::Immediate32 => Some(u64::from(op.immediate32())),
                        iced_x86::OpKind::Immediate64 => Some(op.immediate64()),
                        iced_x86::OpKind::Immediate32to64 => Some(op.immediate32to64() as u64),
                        _ => None,
                    };
                    if let Some(target) =
                        target.filter(|target| analysis.image.section_containing(*target).is_some())
                    {
                        push_xref(&mut analysis.data_xrefs, target, address);
                    }
                }
            }
            let flow = insn.flow;
            discovered = discovered.saturating_add(1);
            if !analysis.instructions.contains_key(&address) {
                if let Some(limit) = instruction_limit() {
                    if analysis.instructions.len() >= limit {
                        return Err(RecoveryError::TooLarge { limit });
                    }
                }
                direct_flow.note_new_instruction(address);
                analysis.instructions.insert(address, insn.clone());
            }
            let order = analysis.instruction_order.len();
            analysis.instruction_order.entry(address).or_insert(order);
            if direct_flow.compatibility && !resume_opcode {
                pointers.mark_code(address, next);
                if let Some(target) = pointers
                    .observe_instruction(analysis, &insn, true)
                    .and_then(|target| {
                        pointers.follow_observed_pointer(
                            analysis,
                            target,
                            &direct_flow.known_noreturn,
                        )
                    })
                {
                    if !analysis.function_order.contains_key(&target)
                        && !pending.iter().any(
                            |task| matches!(task, FlowTask::FinishFunction(va) if *va == target),
                        )
                    {
                        // makeOpcode follows a newly typed data pointer before
                        // processing this instruction's control-flow edges.
                        calls.insert(target);
                        pending.push_front(FlowTask::ResumeOpcode(address));
                        pending.push_front(FlowTask::FinishFunction(target));
                        pending.push_front(FlowTask::Path(target));
                        continue 'tasks;
                    }
                }
            }
            resume_opcode = false;
            match flow {
                Flow::Next => {
                    direct_flow.successors.insert(
                        control_address,
                        vec![Edge {
                            target: next,
                            kind: EdgeKind::Fallthrough,
                        }],
                    );
                    address = next;
                }
                Flow::Call | Flow::IndirectCall => {
                    // envi/codeflow.py follows BR_DEREF procedural targets
                    // immediately. Import slots are removed by _cb_opcode
                    // before that step, so call [ExitProcess] still falls through.
                    let imported = insn
                        .memory_target
                        .is_some_and(|slot| analysis.image.external_bindings.contains_key(&slot));
                    let target = if flow == Flow::Call {
                        insn.direct_target
                    } else if direct_flow.compatibility
                        && !imported
                        && insn.x86_instruction().memory_index() == iced_x86::Register::None
                    {
                        insn.memory_target
                            .and_then(|slot| read_pointer(&analysis.image, slot))
                            .filter(|target| {
                                is_executable(&analysis.image, *target)
                                    && !analysis.image.is_uninitialized(*target)
                            })
                    } else {
                        None
                    };
                    if flow == Flow::IndirectCall && target.is_none() && !imported {
                        analysis.diagnostics.push(RecoveryDiagnostic {
                            address,
                            message: "unresolved indirect call".to_string(),
                        });
                    }
                    if let Some(target) = target {
                        if flow == Flow::Call {
                            push_xref(&mut analysis.code_xrefs, target, address);
                        }
                        // Pinned Vivisect 1.3.2 `envi/codeflow.py` records a
                        // procedural target only when it differs from the
                        // instruction after the call. `call $+5` remains a
                        // code reference and instruction feature, but it is
                        // not a function candidate.
                        if target != next && !analysis.image.is_code_excluded(target) {
                            calls.insert(target);
                        }
                    }
                    // `envi/codeflow.py:254-256`: still inside the
                    // `if bva != nextva` guard, a procedural branch to a
                    // no-return target gets `addNoFlow(va, nextva)` -- the
                    // call site keeps its code xref but loses its fallthrough,
                    // so the caller ends here instead of absorbing whatever
                    // bytes follow.
                    let ends_flow = target.is_some_and(|target| {
                        target != next && direct_flow.known_noreturn.contains(&target)
                    });
                    if ends_flow {
                        analysis.noreturn_calls.insert(address);
                        if let Some(target) = target {
                            remove_code_reference(analysis, address, target);
                        }
                        direct_flow.successors.insert(control_address, Vec::new());
                    } else {
                        direct_flow.successors.insert(
                            control_address,
                            vec![Edge {
                                target: next,
                                kind: EdgeKind::Fallthrough,
                            }],
                        );
                    }
                    // `envi/codeflow.py:addCodeFlow` descends into procedural
                    // targets before resuming a loose import-call fragment.
                    // `base.py:_cb_function` runs codeblocks.py immediately.
                    // A callee that meets already decoded fragment code can
                    // therefore end before the fragment's later continuation.
                    // Explicit tasks preserve that timing without Rust recursion.
                    if let Some(target) = target
                        .filter(|target| *target != next && is_executable(&analysis.image, *target))
                    {
                        if import_functions.as_deref_mut().is_some_and(|known| {
                            known.len() < MAX_FUNCTIONS && known.insert(target)
                        }) && !analysis.function_order.contains_key(&target)
                            && !pending.iter().any(|task| matches!(task, FlowTask::FinishFunction(va) if *va == target))
                        {
                            // Calling analysis can create a callee while an
                            // import fragment is suspended. The import pass's
                            // seed set alone does not track those active frames.
                            // Re-entering one would freeze its unfinished body.

                            if !ends_flow {
                                pending.push_front(FlowTask::ResumeCall {
                                    address,
                                    next,
                                    target,
                                });
                            }
                            direct_flow.import_functions.insert(target);
                            pending.push_front(FlowTask::FinishFunction(target));
                            pending.push_front(FlowTask::Path(target));
                            break;
                        }
                        if direct_flow.compatibility
                            && import_functions.is_none()
                            && !analysis.function_order.contains_key(&target)
                            && !pending.iter().any(|task| {
                                matches!(task, FlowTask::FinishFunction(address) if *address == target)
                            })
                        {
                            // addEntryPoint completes a callee even when its
                            // bytes were previously reached through a jump.
                            // Only a completed or currently active function
                            // suppresses that callback.
                            if !ends_flow {
                                pending.push_front(FlowTask::ResumeCall { address, next, target });
                            }
                            pending.push_front(FlowTask::FinishFunction(target));
                            pending.push_front(FlowTask::Path(target));
                            break;
                        }
                    }
                    if ends_flow {
                        break;
                    }
                    address = next;
                }
                Flow::ConditionalBranch => {
                    let mut edges = vec![Edge {
                        target: next,
                        kind: EdgeKind::Fallthrough,
                    }];
                    if !direct_flow.compatibility && import_functions.is_none() {
                        pending.push_back(FlowTask::Path(next));
                    }
                    if let Some(target) = insn.direct_target {
                        if direct_flow.compatibility {
                            delay_function_for_branch(&pending, target, &mut delayed, loose_root);
                            delay_function_for_branch(&pending, next, &mut delayed, loose_root);
                        }
                        edges.push(Edge {
                            target,
                            kind: EdgeKind::Branch,
                        });
                        if direct_flow.compatibility || import_functions.is_some() {
                            pending.push_front(FlowTask::Path(target));
                        } else {
                            pending.push_back(FlowTask::Path(target));
                        }
                        push_xref(&mut analysis.code_xrefs, target, address);
                    }
                    if direct_flow.compatibility || import_functions.is_some() {
                        pending.push_front(FlowTask::Path(next));
                    }
                    if insn.risc().is_some_and(|r| r.likely) {
                        direct_flow.successors.insert(
                            address,
                            vec![
                                Edge {
                                    target: next,
                                    kind: EdgeKind::Fallthrough,
                                },
                                Edge {
                                    target: control_address,
                                    kind: EdgeKind::Branch,
                                },
                            ],
                        );
                        edges.retain(|e| e.kind != EdgeKind::Fallthrough);
                    }
                    direct_flow.successors.insert(control_address, edges);
                    break;
                }
                Flow::UnconditionalBranch => {
                    if let Some(target) = insn.direct_target {
                        if direct_flow.compatibility {
                            delay_function_for_branch(&pending, target, &mut delayed, loose_root);
                        }
                        // Phase 2.1: a direct unconditional jump is ordinary
                        // control flow. A seed at the target only means the
                        // target *may* be a function entry -- it does not prove
                        // that this jump is a tail call, so we no longer split
                        // the function here on `seeds.contains_key(&target)`.
                        // Follow the edge as an ordinary branch; tail-call and
                        // thunk classification happens post-recovery (Phase 5)
                        // with full graph context, matching vivisect's codeflow
                        // which follows non-procedural branches and only later
                        // reclassifies single-block wrappers as thunks.
                        direct_flow.successors.insert(
                            control_address,
                            vec![Edge {
                                target,
                                kind: EdgeKind::Branch,
                            }],
                        );
                        push_xref(&mut analysis.code_xrefs, target, address);
                        if direct_flow.compatibility || import_functions.is_some() {
                            pending.push_front(FlowTask::Path(target));
                        } else {
                            pending.push_back(FlowTask::Path(target));
                        }
                    } else {
                        direct_flow.successors.insert(control_address, Vec::new());
                    }
                    break;
                }
                Flow::IndirectBranch => {
                    let preceding: Vec<_> = analysis
                        .instructions
                        .range(address.saturating_sub(80)..address)
                        .map(|(_, insn)| insn)
                        .collect();
                    if !direct_flow.compatibility {
                        if let Some(target) =
                            super::super::idioms::gcc_variadic(&analysis.image, &insn, &preceding)
                        {
                            direct_flow.successors.insert(
                                control_address,
                                vec![Edge {
                                    target,
                                    kind: EdgeKind::Branch,
                                }],
                            );
                            push_xref(&mut analysis.code_xrefs, target, address);
                            pending.push_back(FlowTask::Path(target));
                            break;
                        }
                    }
                    // `jmp [<import slot>]` is the tail of a PLT/IAT thunk, not
                    // a jump table. `_cb_opcode` (`vivisect/base.py:820`) drops
                    // every branch whose target is a `LOC_IMPORT` before
                    // codeflow inspects the branch list, so the reference never
                    // flows through one -- and never mistakes the neighbouring
                    // import slots for table entries either. Without this the
                    // lazy-binding initial value of a GOT slot (which points
                    // back at its own PLT stub) reads as a resolved table.
                    if insn.memory_target.is_some_and(|target| {
                        analysis.image.external_bindings.contains_key(&target)
                    }) {
                        direct_flow.successors.insert(control_address, Vec::new());
                        break;
                    }
                    let targets = if direct_flow.compatibility
                        && insn.memory_target.is_some()
                        && insn.x86_instruction().memory_index() != iced_x86::Register::None
                    {
                        Some(jump_table_targets_compat(
                            analysis,
                            &insn,
                            &direct_flow.known_noreturn,
                        ))
                    } else if direct_flow.compatibility
                        && !super::super::callbacks::enabled(&analysis.image)
                    {
                        super::super::switch::targets_compat(
                            analysis,
                            &insn,
                            &direct_flow.known_noreturn,
                            &mut direct_flow.pending_table_locations,
                        )
                    } else if direct_flow.compatibility {
                        // Register-based RVA switches are resolved by the
                        // calling emulator after function codeblocks exist.
                        None
                    } else {
                        super::super::switch::targets(analysis, &insn)
                    }
                    .unwrap_or_else(|| {
                        if direct_flow.compatibility {
                            jump_table_targets_compat(analysis, &insn, &direct_flow.known_noreturn)
                        } else {
                            jump_table_targets(&analysis.image, &insn)
                        }
                    });
                    if direct_flow.compatibility {
                        split_adjacent_tables(analysis, direct_flow, &insn, &targets);
                        for &target in &targets {
                            delay_function_for_branch(&pending, target, &mut delayed, loose_root);
                        }
                    }
                    // codeblocks.py excludes BR_DEREF xrefs from a function's
                    // extent. A plain pointer jump can discover loose code,
                    // but does not own the pointed-to function or inherit its
                    // no-return status. Indexed jump-table arms do belong to
                    // the dispatching function.
                    if !targets.is_empty() && is_pointer_jump(&analysis.image, &insn) {
                        for target in targets {
                            if direct_flow.compatibility || import_functions.is_some() {
                                pending.push_front(FlowTask::Path(target));
                            } else {
                                pending.push_back(FlowTask::Path(target));
                            }
                            push_xref(&mut analysis.code_xrefs, target, address);
                        }
                        direct_flow.successors.insert(control_address, Vec::new());
                        break;
                    }
                    // base.py:_cb_branchtable defines pointer locations for
                    // table entries. Without them, emucode may later accept
                    // the table bytes as another function.
                    if direct_flow.compatibility && !targets.is_empty() {
                        if let Some(base) = insn.memory_target {
                            let width = analysis.image.architecture.pointer_width();
                            let entries = analysis
                                .image
                                .bytes_at(base, usize::MAX)
                                .map_or(0, |bytes| bytes.len() / width);
                            for index in 0..entries {
                                let Some(slot) = base.checked_add((index * width) as u64) else {
                                    break;
                                };
                                if !read_pointer(&analysis.image, slot)
                                    .is_some_and(|target| targets.contains(&target))
                                {
                                    break;
                                }
                                direct_flow.pending_table_locations.push((slot, width));
                            }
                        }
                    }
                    if targets.is_empty() {
                        analysis.diagnostics.push(RecoveryDiagnostic {
                            address,
                            message: "unresolved indirect branch".to_string(),
                        });
                    } else {
                        // envi/codeflow.py completes every branch path before
                        // invoking the function callback. Queue switch arms
                        // ahead of FinishFunction in table order.
                        if direct_flow.compatibility || import_functions.is_some() {
                            for &target in targets.iter().rev() {
                                pending.push_front(FlowTask::Path(target));
                            }
                        } else {
                            for &target in &targets {
                                pending.push_back(FlowTask::Path(target));
                            }
                        }
                        let edges: Vec<_> = targets
                            .into_iter()
                            .map(|target| {
                                push_xref(&mut analysis.code_xrefs, target, address);
                                Edge {
                                    target,
                                    kind: EdgeKind::JumpTable,
                                }
                            })
                            .collect();
                        direct_flow.successors.insert(control_address, edges);
                    }
                    direct_flow.successors.entry(address).or_default();
                    break;
                }
                Flow::Return | Flow::Terminal => {
                    if !direct_flow.compatibility && flow == Flow::Return {
                        let continuation = analysis
                            .instructions
                            .range(address.saturating_sub(128)..address)
                            .filter_map(|(_, push)| {
                                super::super::idioms::delphi_finally(&analysis.image, push)
                            })
                            .find_map(|(site, target)| (site == address).then_some(target));
                        if let Some(target) = continuation {
                            direct_flow.successors.insert(
                                control_address,
                                vec![Edge {
                                    target,
                                    kind: EdgeKind::Branch,
                                }],
                            );
                            push_xref(&mut analysis.code_xrefs, target, address);
                            pending.push_back(FlowTask::Path(target));
                            break;
                        }
                    }
                    direct_flow.successors.insert(control_address, Vec::new());
                    break;
                }
            }
        }
    }

    direct_flow
        .delayed_functions
        .extend(delayed.keys().copied());
    Ok(calls)
}
