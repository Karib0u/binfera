//! Whole-image decompilation with typed, streamed events.
//!
//! Selection, sharding, supporting callees and bounded retries live here so native,
//! WebAssembly and language bindings can use the same policy. The caller owns output.
use super::{DecompilationTimings, DecompileError, DecompilerSession};
use crate::api::Format;
use crate::extract::image::ImageFormat;
use crate::extract::recovery::{Analysis, SeedKind};
use crate::packing::Packing;
use crate::parallel::Jobs;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

mod cache;
mod evidence;
mod graph;
#[doc(hidden)]
pub use cache::{
    prepare as prepare_decompile_all,
    prepare_with_signature_jobs as prepare_decompile_all_with_signature_jobs,
};
mod listings;
mod options;
mod selection;
use crate::image_info::unsupported_elf_cpu;
pub use evidence::StartEvidence;
pub use graph::{FunctionGraph, GraphBlock, GraphEdge, GraphEdgeKind, Reference};
use listings::{emit_data_only_elf, emit_managed_methods};
pub use options::{BatchOptions, RetryPolicy};
pub(super) use selection::needs_compatibility;

pub type InstructionRow = (u64, String, String);

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum BatchEvent {
    Start {
        functions: Vec<u64>,
        #[serde(skip_serializing_if = "BTreeMap::is_empty")]
        names: BTreeMap<u64, String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        arch: Option<String>,
        warnings: Vec<String>,
        packed: Option<Packing>,
        /// Seed kinds and unwind fragments, only with [`BatchOptions::evidence`].
        #[serde(skip_serializing_if = "Option::is_none")]
        evidence: Option<Box<StartEvidence>>,
    },
    Function(Box<BatchFunction>),
    Settled,
    Done {
        warnings: Vec<String>,
    },
}

#[derive(Debug, Default, Serialize)]
pub struct BatchFunction {
    pub address: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_retry: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_pending: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incomplete: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_callees: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub asm: Vec<InstructionRow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg: Option<FunctionGraph>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calls: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_refs: Option<Vec<Reference>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<std::collections::BTreeMap<u64, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lines: Option<Vec<Vec<u64>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame: Option<Vec<super::StackSlot>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timings: Option<DecompilationTimings>,
}

/// Emit the function inventory, each completed function and final diagnostics.
/// Returning an error from `emit` stops the batch immediately.
pub fn decompile_all(
    bytes: &[u8],
    options: &BatchOptions,
    emit: impl FnMut(BatchEvent) -> Result<(), DecompileError>,
) -> Result<(), DecompileError> {
    decompile_all_with_signature_jobs(bytes, options, Jobs::SERIAL, emit)
}

/// Set the native PE startup budget for loading bundled compatibility signatures.
#[doc(hidden)]
pub fn decompile_all_with_signature_jobs(
    bytes: &[u8],
    options: &BatchOptions,
    signature_jobs: Jobs,
    emit: impl FnMut(BatchEvent) -> Result<(), DecompileError>,
) -> Result<(), DecompileError> {
    decompile_all_impl(bytes, options, None, signature_jobs, emit)
}

/// Use the invocation-local recovery snapshot created by `prepare_decompile_all`.
#[doc(hidden)]
pub fn decompile_all_cached(
    bytes: &[u8],
    options: &BatchOptions,
    path: &std::path::Path,
    emit: impl FnMut(BatchEvent) -> Result<(), DecompileError>,
) -> Result<(), DecompileError> {
    decompile_all_impl(bytes, options, Some(path), Jobs::SERIAL, emit)
}

fn decompile_all_impl(
    bytes: &[u8],
    options: &BatchOptions,
    cached: Option<&std::path::Path>,
    signature_jobs: Jobs,
    mut emit: impl FnMut(BatchEvent) -> Result<(), DecompileError>,
) -> Result<(), DecompileError> {
    let repaired = crate::extract::elf::without_corrupt_section_headers(bytes);
    let bytes = repaired.as_deref().unwrap_or(bytes);
    let shard = options.shard;
    options.validate()?;
    if matches!(options.format, Format::Auto | Format::Dotnet)
        && crate::extract::dotnet::looks_like_dotnet_pe(bytes)
    {
        return emit_managed_methods(bytes, options, &mut emit);
    }
    if matches!(options.format, Format::Auto | Format::Elf) {
        if let Some(cpu) = unsupported_elf_cpu(bytes) {
            return emit_data_only_elf(bytes, cpu, &mut emit);
        }
    }
    // The listed analysis can be the compatibility one, which keeps few of the native seeds.
    let mut native_seeds = None;
    let (mut session, analysis, rejected) = if let Some(path) = cached {
        cache::open(bytes, options, path)?
    } else {
        let (mut session, native) = options.open_recovered(bytes, None, signature_jobs)?;
        native_seeds = options.evidence.then(|| native.seeds.clone());
        let (analysis, rejected) = selection::select_analysis(bytes, native, &mut session)?;
        (session, analysis, rejected)
    };
    session.set_limits(options.limits)?;
    let mut functions: std::collections::BTreeSet<u64> =
        analysis.functions.keys().copied().collect();
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
            && session.is_code_address(*address)
            && !session.is_local_label(*address)
    });
    let called_stubs = selection::called_win64_stubs(&analysis, functions.iter().copied());
    functions.retain(|address| {
        // Calls, exports, unwind records and incremental-linking thunks can establish a linker
        // stub as an entry.
        !session.is_import_thunk(*address)
            || called_stubs.contains(address)
            || (analysis.image.format == ImageFormat::Pe
                && analysis.seeds.get(address).is_some_and(|kinds| {
                    kinds.contains(&SeedKind::Export)
                        || kinds.contains(&SeedKind::Unwind)
                        || kinds.contains(&SeedKind::IncrementalTarget)
                        || (kinds.contains(&SeedKind::Unclaimed)
                            && analysis.image.architecture
                                == crate::extract::image::Architecture::X64)
                }))
    });
    let addresses: Vec<u64> = functions.iter().copied().collect();
    // The viewer reads branches out of the listing, and AArch64 text is not x86's.
    let arch_name = analysis.image.architecture.name();
    emit(BatchEvent::Start {
        names: addresses
            .iter()
            .filter_map(|&a| session.function_name(a).map(|n| (a, n)))
            .collect(),
        functions: addresses.clone(),
        arch: Some(arch_name.into()),
        warnings: session.warnings().to_vec(),
        packed: crate::packing::detect(&analysis.image, bytes),
        evidence: options.evidence.then(|| {
            Box::new(StartEvidence::collect(
                bytes,
                &analysis,
                native_seeds.take(),
                |address| session.function_name(address),
            ))
        }),
    })?;
    // Cap on callees found only through decompiled text, so a pathological image stays bounded.
    const MAX_EXTRA: usize = 2000;
    let mut seen: std::collections::BTreeSet<u64> = addresses.iter().copied().collect();
    let (shard_index, shard_count) = shard.unwrap_or((0, 1));
    let mut queue: std::collections::VecDeque<u64> = addresses
        .into_iter()
        .enumerate()
        .filter(|(position, _)| position % shard_count == shard_index)
        .map(|(_, address)| address)
        .collect();
    let mut deferred = match &options.retry {
        RetryPolicy::Only(addresses) => {
            queue.clear();
            addresses
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<VecDeque<_>>()
        }
        _ => VecDeque::new(),
    };
    let mut settled = false;
    let references = graph::reference_index(&analysis);
    let mut extras = 0usize;
    // An engine fault poisons the session, and every later request then fails without trying.
    // Rebuild it and retry. Each rebuild repeats recovery, so bound the total time spent
    // rebuilding rather than their count: a cheap image can recover from hundreds of faults, and
    // an expensive one stops early.
    const MAX_REBUILDS: usize = 512;
    const REBUILD_BUDGET: std::time::Duration = std::time::Duration::from_secs(120);
    let mut rebuilds = 0usize;
    let mut rebuild_time = std::time::Duration::ZERO;
    let mut resource_retries = 0usize;
    loop {
        let (address, resource_retry) = if let Some(address) = queue.pop_front() {
            (address, false)
        } else {
            if !settled {
                emit(BatchEvent::Settled)?;
                settled = true;
            }
            match deferred.pop_front() {
                Some(address) => (address, true),
                None => break,
            }
        };
        let extra = !functions.contains(&address);
        if resource_retry {
            session.set_limits(super::ResourceLimits::retry())?;
        }
        let mut decompiled = session.decompile_function(address);
        let poisoned = matches!(&decompiled, Err(crate::decompiler::DecompileError::Native { message, .. })
            if message.contains("session failed previously"));
        if poisoned && rebuilds < MAX_REBUILDS && rebuild_time < REBUILD_BUDGET {
            rebuilds += 1;
            let began = std::time::Instant::now();
            drop(session);
            session = match cached {
                Some(path) => cache::open(bytes, options, path)?.0,
                None => options.open(bytes)?.0,
            };
            rebuild_time += began.elapsed();
            session.set_limits(if resource_retry {
                super::ResourceLimits::retry()
            } else {
                options.limits
            })?;
            decompiled = session.decompile_function(address);
        }
        if resource_retry {
            session.set_limits(options.limits)?;
            if let Ok(result) = &mut decompiled {
                result.notes.push("Completed after a resource-limit retry (60000 ms per phase, 100000 instructions, 200000000 work units).".into());
            }
        }
        let retry_pending = !resource_retry
            && resource_retries < 16
            && matches!(&decompiled, Err(DecompileError::Native { message, .. })
                if message == "native work limit exceeded" || message == "native decompilation deadline exceeded");
        if retry_pending {
            resource_retries += 1;
            if !matches!(options.retry, RetryPolicy::Skip) {
                deferred.push_back(address);
            }
        }
        if extra && decompiled.is_err() && !retry_pending && !resource_retry {
            continue;
        }
        // Instruction listing in address order, as [address, hex bytes, text]; see `shown_blocks`
        // for which of the recovery's blocks it covers.
        let used: std::collections::BTreeSet<u64> = decompiled
            .as_ref()
            .map(|r| r.line_addresses.iter().flatten().copied().collect())
            .unwrap_or_default();
        let labels = session.function_labels(address);
        let mut listing: Vec<_> = if extra || !analysis.functions.contains_key(&address) {
            // Not a recovered function (an extra, or a Go function recovery missed): take the
            // decoded instructions it spans.
            listings::extra_listing(&analysis.instructions, address, &used)
        } else {
            analysis
                .functions
                .get(&address)
                .map(|function| {
                    listings::shown_blocks(
                        function,
                        &used,
                        |block| block == address || labels.contains_key(&block),
                        |block| block != address && analysis.functions.contains_key(&block),
                    )
                    .into_iter()
                    .flat_map(|block| block.insns.iter())
                    .collect()
                })
                .unwrap_or_default()
        };
        listing.sort_by_key(|insn| insn.address);
        let asm: Vec<_> = listing
            .iter()
            .map(|insn| {
                let bytes: String = insn.bytes.iter().map(|b| format!("{b:02x}")).collect();
                (insn.address, bytes, insn.disassembly().unwrap_or_default())
            })
            .collect();
        let cfg = graph::function_graph(&analysis, address, &asm);
        let calls = Some(graph::calls(&listing));
        let data_refs = Some(graph::data_references(&references, &asm));
        let record = match decompiled {
            Ok(result) => {
                if let Some(next) = discover_callees(&result.text) {
                    for callee in next {
                        if extras < MAX_EXTRA
                            && !rejected.contains(&callee)
                            && !session.is_import_thunk(callee)
                            && !session.is_local_label(callee)
                            && session.is_code_address(callee)
                            && seen.insert(callee)
                        {
                            extras += 1;
                            queue.push_back(callee);
                        }
                    }
                }
                BatchFunction {
                    address: result.address,
                    extra: Some(extra),
                    resource_retry: Some(resource_retry),
                    name: result.name,
                    text: Some(result.text),
                    warnings: Some(result.warnings),
                    notes: Some(result.notes),
                    incomplete: Some(result.incomplete),
                    unknown_callees: Some(result.unknown_callees),
                    ms: Some(result.timings.decompilation_ms),
                    timings: Some(result.timings),
                    asm,
                    cfg,
                    calls,
                    data_refs,
                    labels: Some(labels.into_iter().map(|(a, n)| (a, n.to_owned())).collect()),
                    lines: Some(result.line_addresses),
                    frame: Some(result.frame),
                    ..Default::default()
                }
            }
            Err(e) => BatchFunction {
                address,
                name: session.function_name(address),
                retry_pending: retry_pending.then_some(true),
                resource_retry: Some(resource_retry),
                asm,
                cfg,
                calls,
                data_refs,
                error: Some(e.to_string()),
                ..Default::default()
            },
        };
        emit(BatchEvent::Function(Box::new(record)))?;
    }
    emit(BatchEvent::Done {
        warnings: session.warnings().to_vec(),
    })
}

fn discover_callees(text: &str) -> Option<Vec<u64>> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("FUN_") {
        rest = &rest[at + 4..];
        let digits: String = rest.chars().take_while(char::is_ascii_hexdigit).collect();
        if (6..=16).contains(&digits.len()) {
            if let Ok(address) = u64::from_str_radix(&digits, 16) {
                found.push(address);
            }
        }
    }
    (!found.is_empty()).then_some(found)
}
