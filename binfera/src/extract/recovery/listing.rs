//! Which recovered functions a binary lists.
//!
//! The decompiler and the code-origin fingerprints must agree on what a function is: an analyst
//! filters the decompiler's list by origin, and a family pack is built from the same starts it
//! is queried with. This module holds that one choice. Native recovery is reconciled with the
//! capability-compatible recovery (a second, more conservative pass), interior and literal
//! starts are rejected, and import thunks, local labels and non-code addresses are dropped.
//!
//! [`select_analysis`] and [`listed_functions`] take a [`ListingContext`]: the decompiler passes its
//! session, which knows more names (Function ID, RTTI); everything else uses [`StaticListing`],
//! which reads the same facts from the [`Analysis`] alone.

use std::collections::{BTreeMap, BTreeSet};

use iced_x86::Mnemonic;

use crate::extract::decoder::Flow;
use crate::extract::image::{Architecture, ImageFormat, LoadedImage};
use crate::extract::recovery::{Analysis, SeedKind};

mod candidates;
pub use candidates::rejected_compatibility_entries;

/// What function listing needs to know beyond the recovered graph.
pub trait ListingContext {
    /// Whether an address is in mapped, file-backed executable code.
    fn is_code_address(&self, address: u64) -> bool;
    /// A validated compiler label (an exception funclet, a Delphi handler) that a recovery can
    /// mistake for a function.
    fn is_local_label(&self, address: u64) -> bool;
    /// Whether a symbol, export, signature or metadata names a function at this code address.
    fn is_named_function(&self, address: u64) -> bool;
    /// A forwarding entry that is only a jump through an import slot.
    fn is_import_thunk(&self, address: u64) -> bool;
    /// Records an image-wide diagnostic.
    fn warn(&mut self, message: String);
}

/// The compatibility pass runs unless the image is very large (its second recovery costs
/// gigabytes there) or a format it does not load.
pub fn needs_compatibility(analysis: &Analysis) -> bool {
    analysis.instructions.len() <= 1_000_000
        && !matches!(analysis.image.format, ImageFormat::Macho | ImageFormat::Sc)
}

/// The functions an analysis lists, given the starts [`select_analysis`] rejected: Go's own
/// function table where there is one, minus rejected starts, non-code addresses, local labels
/// and import thunks nothing establishes as an entry.
pub fn listed_functions(
    analysis: &Analysis,
    rejected: &BTreeSet<u64>,
    context: &impl ListingContext,
) -> BTreeSet<u64> {
    let mut functions: BTreeSet<u64> = analysis.functions.keys().copied().collect();
    // A Go binary lists its own functions: those are the functions, and anything recovery started
    // inside one is part of it.
    if let Some(go) = crate::golang::parse(&analysis.image) {
        functions.retain(|address| !go.functions.inside(*address));
        functions.extend(
            go.functions
                .functions
                .iter()
                .filter(|f| !matches!(f.name.as_str(), "go:buildid" | "go.buildid"))
                .map(|f| f.entry),
        );
    }
    functions.retain(|address| {
        !rejected.contains(address)
            && context.is_code_address(*address)
            && !context.is_local_label(*address)
    });
    let called_stubs = called_win64_stubs(analysis, functions.iter().copied());
    functions.retain(|address| {
        // Calls, exports, unwind records, Guard CF and incremental-linking thunks can
        // establish a linker stub as an entry.
        !context.is_import_thunk(*address)
            || called_stubs.contains(address)
            || (analysis.image.format == ImageFormat::Pe
                && analysis.seeds.get(address).is_some_and(|kinds| {
                    kinds.contains(&SeedKind::Export)
                        || kinds.contains(&SeedKind::Unwind)
                        || kinds.contains(&SeedKind::GuardCf)
                        || kinds.contains(&SeedKind::IncrementalTarget)
                        || (kinds.contains(&SeedKind::Unclaimed)
                            && analysis.image.architecture == Architecture::X64)
                }))
    });
    functions
}

/// Reconciles `native` recovery with the compatibility pass and lists its functions, reading
/// names and labels from the analysis alone. Returns the analysis whose graphs the listed
/// functions use: the compatibility one when it ran, with native graphs for shared starts.
pub fn list_functions(bytes: &[u8], native: Analysis) -> (Analysis, BTreeSet<u64>) {
    // Read from the native analysis, as the decompiler session is: a start only the compatibility
    // pass found is judged by the native graph's facts.
    let mut context = StaticListing::new(&native);
    let (analysis, rejected) = select_analysis(bytes, native, &mut context);
    let listed = listed_functions(&analysis, &rejected, &context);
    (analysis, listed)
}

/// A [`ListingContext`] read from an [`Analysis`] alone, for callers without a decompiler session.
///
/// It reproduces the session's code ranges, local labels and import thunks. Its names are the
/// image's own (symbols, exports, Go's function table, exception metadata, import thunks); the
/// session also names functions by Function ID and RTTI, which only matters for a native-only
/// start the compatibility pass did not find.
pub struct StaticListing {
    code: Vec<(u64, u64)>,
    named: BTreeSet<u64>,
    import_thunks: BTreeSet<u64>,
    local_labels: BTreeSet<u64>,
    pub warnings: Vec<String>,
}

impl StaticListing {
    pub fn new(analysis: &Analysis) -> Self {
        let image = &analysis.image;
        let code = executable_ranges(image);
        let in_code = |address: u64| {
            code.iter()
                .any(|&(start, end)| start <= address && address < end)
        };
        let import_thunks: BTreeMap<u64, String> = import_thunks(analysis);

        let mut exceptions = crate::msvc_eh::ExceptionInfo::read(image);
        exceptions.link_functions(analysis);
        let mut local_labels: BTreeSet<u64> = exceptions
            .contained_funclets(analysis)
            .into_keys()
            .collect();
        for insn in analysis.instructions.values() {
            if super::idioms::delphi_handler(image, insn) {
                local_labels.insert(u64::from(insn.x86_instruction().immediate32()));
            }
            if let Some((_, target)) = super::idioms::delphi_finally(image, insn) {
                local_labels.insert(target);
            }
            if insn.flow == Flow::IndirectBranch {
                let preceding: Vec<_> = analysis
                    .instructions
                    .range(insn.address.saturating_sub(80)..insn.address)
                    .map(|(_, op)| op)
                    .collect();
                if let Some(target) = super::idioms::gcc_variadic(image, insn, &preceding) {
                    local_labels.insert(target + 32);
                }
            }
        }
        local_labels.retain(|address| {
            !analysis
                .seeds
                .get(address)
                .is_some_and(|kinds| kinds.contains(&SeedKind::CallTarget))
        });

        let mut named: BTreeSet<u64> = analysis.elf_function_symbols.keys().copied().collect();
        named.extend(import_thunks.keys().copied());
        named.extend(
            analysis
                .seeds
                .iter()
                .filter(|(_, kinds)| kinds.contains(&SeedKind::Export))
                .map(|(address, _)| *address),
        );
        named.extend(
            exceptions
                .names()
                .into_keys()
                .filter(|address| analysis.functions.contains_key(address)),
        );
        if let Some(go) = crate::golang::parse(image) {
            named.extend(go.functions.functions.iter().map(|function| function.entry));
        }
        named.retain(|address| in_code(*address));

        StaticListing {
            code,
            named,
            import_thunks: import_thunks.into_keys().collect(),
            local_labels,
            warnings: Vec::new(),
        }
    }
}

impl ListingContext for StaticListing {
    fn is_code_address(&self, address: u64) -> bool {
        self.code
            .iter()
            .any(|&(start, end)| start <= address && address < end)
    }
    fn is_local_label(&self, address: u64) -> bool {
        self.local_labels.contains(&address)
    }
    fn is_named_function(&self, address: u64) -> bool {
        self.named.contains(&address)
    }
    fn is_import_thunk(&self, address: u64) -> bool {
        self.import_thunks.contains(&address)
    }
    fn warn(&mut self, message: String) {
        self.warnings.push(message);
    }
}

/// File-backed executable section bytes, minus validated image metadata: the decompiler
/// session's code ranges.
fn executable_ranges(image: &LoadedImage) -> Vec<(u64, u64)> {
    let mut starts: Vec<u64> = image.sections.iter().map(|s| s.address).collect();
    starts.sort_unstable();
    let mut ranges = Vec::new();
    for (index, section) in image.sections.iter().enumerate() {
        if !section.permissions.execute
            || (section.file_size == 0 && image.is_uninitialized(section.address))
        {
            continue;
        }
        let next = starts
            .iter()
            .find(|start| **start > section.address)
            .copied()
            .unwrap_or(u64::MAX);
        let virtual_size = section.virtual_size.min(next - section.address);
        let Some(bytes) = image.section_bytes(index) else {
            continue;
        };
        if virtual_size == 0 {
            continue;
        }
        // The session maps the file bytes and zero-fills the rest of the section, up to 16 MiB.
        let mapped = virtual_size.min((bytes.len() as u64).saturating_add(16 << 20));
        let Some(end) = section.address.checked_add(mapped) else {
            continue;
        };
        let mut start = section.address;
        for range in &image.code_exclusions {
            if range.start >= end {
                break;
            }
            if range.end <= start {
                continue;
            }
            if start < range.start {
                ranges.push((start, range.start));
            }
            start = range.end.min(end);
        }
        if start < end {
            ranges.push((start, end));
        }
    }
    ranges
}

/// Reconciles native recovery with the compatibility pass. Returns the analysis to list and the
/// starts it rejects.
pub fn select_analysis(
    bytes: &[u8],
    mut native: Analysis,
    session: &mut impl ListingContext,
) -> (Analysis, BTreeSet<u64>) {
    let mut rejected = BTreeSet::new();
    // The functions listed come from the capability-matching recovery, which finds functions the
    // decompiler's own misses; decompiling them first also tells the decompiler they are code. A
    // large image skips that second recovery and lists the decompiler's: each holds gigabytes
    // there, and the browser has 4 GB per worker.
    let analysis = if needs_compatibility(&native) {
        let mut listed = match crate::extract::recovery::analyze(bytes) {
            Ok(listed) => listed,
            Err(error) => {
                session.warn(format!(
                    "Optional compatibility recovery failed; using native function discovery: {error}"
                ));
                return (native, rejected);
            }
        };
        rejected = rejected_compatibility_entries(&native, &listed);
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
                        || kinds.contains(&SeedKind::GuardCf)
                        || (kinds.contains(&SeedKind::Relocation) && straight_line_leaf(function))
                        || kinds.contains(&SeedKind::IncrementalTarget)
                        || kinds.contains(&SeedKind::DelayLoadThunk)
                        || kinds.contains(&SeedKind::MsvcThrowMetadata)
                        // The linker emits a thunk per function; list the ones that code, data
                        // or image metadata (an exception handler, a relocation) reaches.
                        || (kinds.contains(&SeedKind::IncrementalThunk)
                            && (kinds.len() > 1
                                || native.code_xrefs.contains_key(address)
                                || native.data_xrefs.contains_key(address)))
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
            // Preserve entry evidence found by native recovery.
            for kind in [
                SeedKind::Unwind,
                SeedKind::GuardCf,
                SeedKind::IncrementalTarget,
                SeedKind::Unclaimed,
            ] {
                if kinds.is_some_and(|kinds| kinds.contains(&kind)) {
                    listed.seeds.entry(address).or_default().insert(kind);
                }
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
        reject_interior_starts(&native, &listed, &mut rejected, session);
        drop(native);
        listed
    } else {
        reject_interior_starts(&native, &native, &mut rejected, session);
        native
    };
    (analysis, rejected)
}

/// x64 unwind rows bound their functions: a listed start strictly inside a row, where no row
/// begins, is a block of that function (see [`crate::extract::recovery::interior_unwind_starts`]).
/// Compatibility recovery names many such blocks for capa (`/GS` cookie tails, catch
/// continuations, FLIRT local labels), and data pointer runs can be jump tables. One that an
/// export, image table or direct call names stays listed, with a warning.
fn reject_interior_starts(
    native: &Analysis,
    listed: &Analysis,
    rejected: &mut BTreeSet<u64>,
    session: &mut impl ListingContext,
) {
    let interior = crate::extract::recovery::interior_unwind_starts(
        native,
        listed
            .functions
            .keys()
            .copied()
            .filter(|address| !rejected.contains(address)),
    );
    rejected.extend(interior.rejected);
    if !interior.kept.is_empty() {
        let shown: Vec<String> = interior
            .kept
            .iter()
            .take(8)
            .map(|address| format!("{address:#x}"))
            .collect();
        let more = interior.kept.len().saturating_sub(shown.len());
        session.warn(format!(
            "{} function start(s) inside another function's unwind row, kept because an export, image table or direct call names them: {}{}",
            interior.kept.len(),
            shown.join(", "),
            if more > 0 { format!(" and {more} more") } else { String::new() },
        ));
    }
}

/// Show recovered Win64 jump stubs with a direct call from a listed function.
/// This keeps linker stubs reachable without listing every unused IAT entry.
pub fn called_win64_stubs(
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

/// Recovered functions whose only instruction is an indirect jump through an import slot,
/// with the import's name.
pub(crate) fn import_thunks(analysis: &Analysis) -> BTreeMap<u64, String> {
    if analysis.image.architecture.is_risc32() {
        return crate::extract::risc::import_thunks(analysis);
    }
    let mut thunks: BTreeMap<u64, String> = analysis
        .image
        .import_locations
        .iter()
        .filter(|(address, _)| {
            analysis.image.format == ImageFormat::Macho
                && analysis
                    .image
                    .elf_plt_ranges
                    .iter()
                    .any(|(start, end)| *start <= **address && **address < *end)
        })
        .map(|(address, name)| (*address, name.clone()))
        .collect();
    if analysis.image.architecture == Architecture::AArch64 {
        // A tail-only PLT entry may have been absorbed into its caller by recovery.
        let plt_entries = analysis
            .image
            .elf_plt_ranges
            .iter()
            .flat_map(|&(start, end)| {
                let size = usize::try_from(end - start).unwrap_or(0);
                let mapped = analysis
                    .image
                    .bytes_at(start, size)
                    .map_or(0, |bytes| bytes.len());
                (start..start.saturating_add(mapped as u64).min(end)).step_by(4)
            });
        for address in analysis
            .image
            .import_locations
            .keys()
            .copied()
            .chain(analysis.functions.keys().copied())
            .chain(plt_entries)
        {
            if let Some((_, slot)) = aarch64_import_thunk(analysis, address) {
                if let Some(name) = analysis.image.import_locations.get(&slot) {
                    thunks.insert(address, name.clone());
                } else if let Some(target) = aarch64_pointer(&analysis.image, slot) {
                    if let Some(name) = analysis
                        .elf_function_symbols
                        .get(&target)
                        .and_then(|n| n.first())
                    {
                        thunks.insert(address, format!("*.{name}"));
                    }
                }
            }
        }
        return thunks;
    }
    for (address, function) in &analysis.functions {
        let Some(only) = function
            .blocks
            .iter()
            .find(|block| block.addr == *address)
            .into_iter()
            .flat_map(|block| &block.insns)
            .find(|insn| {
                !matches!(
                    insn.x86_instruction().mnemonic(),
                    Mnemonic::Endbr64 | Mnemonic::Endbr32 | Mnemonic::Nop
                )
            })
        else {
            continue;
        };
        if only.flow != Flow::IndirectBranch {
            continue;
        }
        if let Some(name) = only
            .memory_target
            .and_then(|slot| analysis.image.import_locations.get(&slot))
        {
            thunks.insert(*address, name.clone());
        }
    }
    thunks
}

/// Ghidra's AARCH64PltThunkAnalyzer patterns: ADRP/LDR/[ADD]/BR, with an
/// optional BTI landing pad. Validate the complete stub and branch register;
/// an ordinary GOT load inside a function must not rename that function.
pub(crate) fn aarch64_import_thunk(analysis: &Analysis, entry: u64) -> Option<(u64, u64)> {
    let image = &analysis.image;
    if image.architecture != Architecture::AArch64 || !image.is_executable_address(entry) {
        return None;
    }
    let word = |address| -> Option<u32> {
        Some(u32::from_le_bytes(
            image.bytes_at(address, 4)?.try_into().ok()?,
        ))
    };
    let mut address = entry;
    if word(address)? & 0xffff_fc1f == 0xd503_241f {
        address = address.checked_add(4)?; // BTI
    }
    let adrp = word(address)?;
    let ldr = word(address.checked_add(4)?)?;
    if adrp & 0x9f00_0000 != 0x9000_0000 || ldr & 0xffc0_0000 != 0xf940_0000 {
        return None;
    }
    let base = adrp & 31;
    let target = ldr & 31;
    if base == 31 || target == 31 || (ldr >> 5) & 31 != base {
        return None;
    }
    let immediate = (((adrp >> 5) & 0x7ffff) << 2) | ((adrp >> 29) & 3);
    let offset = ((immediate as i64) << 43) >> 31;
    let page = (address & !0xfff).wrapping_add_signed(offset);
    let slot = page.wrapping_add(u64::from((ldr >> 10) & 0xfff) * 8);
    let mut branch = address.checked_add(8)?;
    let add = word(branch)?;
    if add & 0xffc0_0000 == 0x9100_0000 {
        // The ELF PLT updates its page register to the GOT slot for the resolver.
        if base == target
            || add & 31 != base
            || (add >> 5) & 31 != base
            || u64::from((add >> 10) & 0xfff) != slot & 0xfff
        {
            return None;
        }
        branch = branch.checked_add(4)?;
    }
    if word(branch)? != 0xd61f_0000 | (target << 5)
        || !(image.import_locations.contains_key(&slot)
            || aarch64_pointer(image, slot)
                .is_some_and(|target| image.is_executable_address(target)))
    {
        return None;
    }
    Some((branch, slot))
}

pub(crate) fn aarch64_pointer(image: &LoadedImage, slot: u64) -> Option<u64> {
    Some(u64::from_le_bytes(
        image.bytes_at(slot, 8)?.try_into().ok()?,
    ))
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
