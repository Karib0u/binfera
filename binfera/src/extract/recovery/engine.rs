//! x86/x64 function and control-flow recovery.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
mod flow;
mod functions;
mod interior;
mod leaves;
mod seeds;
use flow::*;
use functions::*;
pub use interior::{interior_unwind_starts, InteriorStarts};
use seeds::*;
#[cfg(test)]
mod tests;

use goblin::elf::dynamic::{
    DT_FINI, DT_FINI_ARRAY, DT_FINI_ARRAYSZ, DT_INIT, DT_INIT_ARRAY, DT_INIT_ARRAYSZ,
};
use goblin::elf::sym::{st_type, STT_FUNC, STT_GNU_IFUNC};
use goblin::elf::Elf;
use goblin::mach::load_command::CommandVariant;
use goblin::mach::MachO;
use goblin::pe::options::{ParseMode, ParseOptions};
use goblin::pe::PE;
use iced_x86::{Mnemonic, OpKind, Register};

use super::decoder;
use super::decoder::Flow;
use super::golang;
use super::image::{Architecture, DecodedInstruction, ImageError, ImageFormat, LoadedImage};
use super::importcalls;
use super::libc_start_main;
use super::msvcfunc;
use super::noreturn;

const MAX_FUNCTIONS: usize = 100_000;
const MAX_INSNS_PER_FUNCTION: usize = 200_000;
const MAX_PROLOGUE_SCAN_BYTES: usize = 32 * 1024 * 1024;
const MAX_UNCLAIMED_SWEEPS: usize = 4;
const MAX_PROLOGUE_SEEDS_PER_SECTION: usize = 8_192;
const MAX_SWEEP_CALL_SEEDS: usize = 32_768;

/// Most instructions one recovery decodes before it refuses the image, so a large file fails with
/// [`RecoveryError::TooLarge`] instead of running out of memory. Memory grows with the
/// instructions decoded: an 88 MB Node.js executable decodes 7.9 million and its recovery alone
/// peaks above 4 GB, the most a 32-bit WebAssembly module can address. The WebAssembly build
/// therefore has a limit by default; native builds have none unless the caller sets one
/// ([`set_instruction_limit`]).
static INSTRUCTION_LIMIT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(DEFAULT_INSTRUCTION_LIMIT);

/// Measured in the browser build, where each worker has 4 GB; see `web/README.md`.
#[cfg(target_family = "wasm")]
pub const DEFAULT_INSTRUCTION_LIMIT: usize = 2_500_000;
#[cfg(not(target_family = "wasm"))]
pub const DEFAULT_INSTRUCTION_LIMIT: usize = usize::MAX;

/// Sets the process-wide limit on decoded instructions per recovery; `None` removes it.
pub fn set_instruction_limit(limit: Option<usize>) {
    INSTRUCTION_LIMIT.store(
        limit.unwrap_or(usize::MAX),
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// The current limit set by [`set_instruction_limit`], `None` when there is none.
pub fn instruction_limit() -> Option<usize> {
    let limit = INSTRUCTION_LIMIT.load(std::sync::atomic::Ordering::Relaxed);
    (limit != usize::MAX).then_some(limit)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "decompiler", derive(serde::Serialize, serde::Deserialize))]
pub enum SeedKind {
    EntryPoint,
    Export,
    TlsCallback,
    SafeSeh,
    Unwind,
    /// ELF exception-frame FDE entry, native recovery only.
    EhFrame,
    /// ARM EHABI exception-index function boundary.
    ArmExidx,
    Symbol,
    Init,
    Fini,
    InitArray,
    FiniArray,
    Relocation,
    /// Validated RTTI table or a run of absolute code pointers.
    Vtable,
    /// Undefined pointer target accepted by candidate evaluation.
    PointerTarget,
    /// Named or instruction-referenced address accepted by candidate evaluation.
    Emulated,
    /// Known API argument explicitly typed as a function pointer.
    ApiCallback,
    /// Undefined local symbol from a validated FLIRT signature.
    FlirtLocal,
    LibcMain,
    GoRuntimeMain,
    FunctionSignature,
    MsvcCookieBlock,
    /// Validated MSVC C++ catch, cleanup or frame-handler entry.
    MsvcException,
    Prologue,
    /// Aligned entry validated after all ordinary native recovery passes.
    Unclaimed,
    SweepCallTarget,
    CallTarget,
    /// `LC_FUNCTION_STARTS` (Mach-O only): a high-quality, linker-emitted
    /// function-start table, ULEB128-delta-encoded from `__TEXT`'s load
    /// address. See the Mach-O loader's function-start handling.
    /// task 3.
    MachoFunctionStarts,
    /// The Go linker's function table (`pclntab`, native backend only): every Go function's
    /// entry and extent, stripped or not. See [`crate::golang`].
    GoFunctionTable,
    /// Embedded DWARF subprogram entries, native decompiler builds only.
    Dwarf,
    /// Delphi VMT, published method or property accessor.
    DelphiMethod,
    /// Entry of an MSVC incremental-linking thunk table (`/INCREMENTAL`): a `jmp rel32` the
    /// linker emits for each function so it can relink in place.
    IncrementalThunk,
    /// Target of an incremental-linking thunk: the linker gives every function in the image
    /// one, referenced or not.
    IncrementalTarget,
    /// Initial value of a delay-load IAT slot: the linker stub that resolves the import on its
    /// first call.
    DelayLoadThunk,
    /// x64 unwind language handler, or a destructor or copy constructor a C++ `ThrowInfo`
    /// names: called only by the runtime.
    MsvcThrowMetadata,
    /// Callable entry recorded in the PE Guard CF function table.
    GuardCf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryBackend {
    /// Reproduce the pinned Vivisect loader and deterministic analysis inputs.
    VivisectCompat,
    /// Enable recovery heuristics that are useful but not Vivisect-compatible.
    Native,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "decompiler", derive(serde::Serialize, serde::Deserialize))]
pub enum EdgeKind {
    Fallthrough,
    Branch,
    TailCall,
    JumpTable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "decompiler", derive(serde::Serialize, serde::Deserialize))]
pub struct Edge {
    pub target: u64,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "decompiler", derive(serde::Serialize, serde::Deserialize))]
pub struct BasicBlock {
    pub addr: u64,
    pub insns: Vec<DecodedInstruction>,
    pub succs: Vec<Edge>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "decompiler", derive(serde::Serialize, serde::Deserialize))]
pub struct Function {
    pub addr: u64,
    pub blocks: Vec<BasicBlock>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "decompiler", derive(serde::Serialize, serde::Deserialize))]
pub struct RecoveryDiagnostic {
    pub address: u64,
    pub message: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "decompiler", derive(serde::Serialize, serde::Deserialize))]
pub struct Analysis {
    #[cfg(feature = "decompiler")]
    pub dwarf: Option<std::sync::Arc<crate::dwarf::DebugInfo>>,
    pub image: LoadedImage,
    pub seeds: BTreeMap<u64, BTreeSet<SeedKind>>,
    pub functions: BTreeMap<u64, Function>,
    /// Order of function completion during compatibility codeflow. FLIRT
    /// public names can only label functions that already exist at that point.
    pub function_order: BTreeMap<u64, usize>,
    /// Functions visible after recursive function analyzers finish. FLIRT
    /// public names are applied after its local functions have been created.
    pub function_analysis_counts: BTreeMap<u64, usize>,
    /// Functions visible when FLIRT starts, after calling analysis completes.
    pub function_flirt_counts: BTreeMap<u64, usize>,
    /// Opcode discovery count when FLIRT starts.
    pub function_location_counts: BTreeMap<u64, usize>,
    /// First-definition order for opcode locations.
    pub instruction_order: BTreeMap<u64, usize>,
    /// Discovered opcode locations. In compatibility mode, block extraction
    /// may expose a different stream starting inside one of these locations.
    pub instructions: BTreeMap<u64, DecodedInstruction>,
    pub code_xrefs: BTreeMap<u64, Vec<u64>>,
    pub data_xrefs: BTreeMap<u64, Vec<u64>>,
    pub callers: BTreeMap<u64, BTreeSet<u64>>,
    pub callees: BTreeMap<u64, BTreeSet<u64>>,
    pub diagnostics: Vec<RecoveryDiagnostic>,
    /// ELF `STT_FUNC`/`STT_GNU_IFUNC` symbol names by address, from `.symtab`
    /// and `.dynsym`. Ported from `capa.features.extractors.elf.SymTab`:
    /// `viv/insn.py`'s ELF `api` branch and `viv/function.py`'s
    /// `extract_function_symtab_names` both look up a call/function address
    /// in this table (`sym_value == target and sym_info & STT_FUNC != 0`).
    /// Also carries Mach-O `LC_SYMTAB` `N_SECT` symbol names by address
    /// (`collect_macho_seeds`) -- same "address to
    /// function-name feature" role, no upstream source since Mach-O has
    /// none. Also carries PE COFF function names and Delphi method names in native
    /// recovery; PE compatibility recovery and shellcode leave it empty. The field
    /// name is historical.
    pub elf_function_symbols: BTreeMap<u64, Vec<String>>,
    /// Addresses Vivisect treats as non-returning procedural branch targets --
    /// `CodeFlowContext._cf_noret` (`envi/codeflow.py:41`). Holds import
    /// locations *and* function entry VAs in one map, matching upstream; see
    /// [`super::noreturn`].
    pub noreturn: BTreeSet<u64>,
    /// Call sites whose fallthrough edge was suppressed because the target is
    /// no-return -- Vivisect's `NoReturnCalls` VA set
    /// (`vivisect/base.py:810`).
    pub noreturn_calls: BTreeSet<u64>,
}

impl Analysis {
    /// Port of `VivWorkspace.isNoReturnVa` (`vivisect/__init__.py:521-527`):
    /// an address is no-return if it is a registered no-return VA *or* the
    /// site of a suppressed no-return call.
    pub fn is_noreturn_va(&self, address: u64) -> bool {
        self.noreturn.contains(&address) || self.noreturn_calls.contains(&address)
    }
}

#[derive(Default)]
struct DirectFlowGraph {
    /// Instructions decoded since the last data pointer wave, so that a wave need not revisit
    /// every instruction. `None` until the first wave, which indexes all of them.
    new_instructions: Option<Vec<u64>>,
    compatibility: bool,
    flirt: Option<super::flirt::Discovery>,
    known_noreturn: BTreeSet<u64>,
    successors: BTreeMap<u64, Vec<Edge>>,
    /// Preserve the codeblocks.py view when each compatibility function
    /// completes. Later discoveries must not expand an earlier function.
    completed_functions: BTreeMap<u64, Function>,
    /// A branch into a loose code-flow root can defer a function forever:
    /// that root has no function callback to release the dependency.
    delayed_functions: BTreeSet<u64>,
    /// Functions created while walking otherwise unclaimed import-call fragments.
    import_functions: BTreeSet<u64>,
    pending_table_locations: Vec<(u64, usize)>,
    /// Native PE recovery: every function entry, known before the views are built. A direct
    /// `jmp` to another entry is a tail call, so a view ends there as Ghidra's does.
    function_entries: BTreeSet<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error(transparent)]
    Signature(#[from] super::flirt::FlirtError),
    #[error(transparent)]
    Image(#[from] ImageError),
    #[error("collecting {format:?} recovery seeds: {context}")]
    Seeds {
        format: ImageFormat,
        context: String,
    },
    #[error("recovery limit exceeded: {0}")]
    Limit(String),
    /// The image has more code than [`instruction_limit`] allows. Unlike [`Self::Limit`], which
    /// drops one runaway function, this refuses the whole image.
    #[error(
        "the file is too large to analyze within the memory limit: code recovery stopped after \
         {limit} instructions (--max-instructions)"
    )]
    TooLarge { limit: usize },
}

pub fn analyze(bytes: &[u8]) -> Result<Analysis, RecoveryError> {
    analyze_with_backend(bytes, RecoveryBackend::VivisectCompat)
}

pub fn analyze_with_backend(
    bytes: &[u8],
    backend: RecoveryBackend,
) -> Result<Analysis, RecoveryError> {
    if super::super::looks_like_macho(bytes) {
        return analyze_macho(bytes, None);
    }
    let image = if super::super::looks_like_elf(bytes) {
        LoadedImage::from_elf_with_import_policy(bytes, backend == RecoveryBackend::VivisectCompat)?
    } else {
        LoadedImage::parse(bytes)?
    };
    analyze_image(bytes, image, backend)
}

/// Native recovery for a PE whose malformed import directory is dropped with a
/// diagnostic instead of refusing the image. Used by the decompiler only.
pub fn analyze_partial_pe(bytes: &[u8]) -> Result<Analysis, RecoveryError> {
    let image = LoadedImage::parse_partial(bytes)?;
    analyze_image(bytes, image, RecoveryBackend::Native)
}

/// PE recovery with the same signatures used by the caller for library recognition.
pub fn analyze_with_signatures(
    bytes: &[u8],
    signatures: &super::flirt::Signatures,
) -> Result<Analysis, RecoveryError> {
    let image = LoadedImage::parse(bytes)?;
    let backend = RecoveryBackend::VivisectCompat;
    let (seeds, symbols, diagnostics) = collect_seeds(bytes, &image, backend)?;
    analyze_seeded_image_with_signatures(
        image,
        backend,
        seeds,
        symbols,
        diagnostics,
        Some(signatures),
    )
}

/// `-f sc32`/`sc64`, matching capa.loader.get_workspace's shellcode
/// workspace. There are no container-specific exports, TLS callbacks,
/// relocations, or symbol tables.
pub fn analyze_shellcode(
    bytes: &[u8],
    architecture: Architecture,
) -> Result<Analysis, RecoveryError> {
    let image = LoadedImage::from_shellcode(bytes, architecture);
    analyze_image(bytes, image, RecoveryBackend::VivisectCompat)
}

/// Native raw-code recovery, with file offsets as addresses.
pub fn analyze_shellcode_native(
    bytes: &[u8],
    architecture: Architecture,
) -> Result<Analysis, RecoveryError> {
    let image = LoadedImage::from_shellcode_at(bytes, architecture, 0);
    analyze_image(bytes, image, RecoveryBackend::Native)
}

/// `-f macho` uses native recovery because the pinned reference does not
/// load this format.
pub fn analyze_macho(bytes: &[u8], arch: Option<&str>) -> Result<Analysis, RecoveryError> {
    let (slice, _) = super::image::select_macho_slice(bytes, arch)?;
    let image = LoadedImage::from_macho(slice, None)?;
    analyze_image(slice, image, RecoveryBackend::Native)
}

pub(crate) fn analyze_image(
    bytes: &[u8],
    mut image: LoadedImage,
    backend: RecoveryBackend,
) -> Result<Analysis, RecoveryError> {
    let arm = super::arm_unwind::read(bytes, &image);
    for entry in &arm.entries {
        image.set_thumb(entry.start, entry.thumb);
    }
    if backend == RecoveryBackend::Native && image.format == ImageFormat::Elf {
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        let mut entries: Vec<_> = super::eh_frame::ranges(bytes, &image)
            .into_iter()
            .chain(arm.entries.iter().map(|entry| (entry.start, entry.end)))
            .collect();
        entries.sort_unstable();
        for (start, end) in entries {
            if let Some(last) = ranges.last_mut().filter(|last| start <= last.1) {
                last.1 = last.1.max(end);
            } else {
                ranges.push((start, end));
            }
        }
        image.function_ranges = ranges;
    }
    let (mut seeds, elf_function_symbols, mut diagnostics) = collect_seeds(bytes, &image, backend)?;
    for entry in &arm.entries {
        add_seed(&image, &mut seeds, entry.start, SeedKind::ArmExidx);
    }
    diagnostics.extend(arm.diagnostics);
    #[cfg(feature = "decompiler")]
    let dwarf = {
        let dwarf = (backend == RecoveryBackend::Native && image.format != ImageFormat::Sc)
            .then(|| std::sync::Arc::new(crate::dwarf::DebugInfo::read(bytes, &image)));
        if let Some(debug) = &dwarf {
            for address in debug.functions.keys() {
                seeds.entry(*address).or_default().insert(SeedKind::Dwarf);
            }
        }
        dwarf
    };
    if backend == RecoveryBackend::Native && image.format == ImageFormat::Pe {
        for target in vtable_targets(&image) {
            add_seed(&image, &mut seeds, target, SeedKind::Vtable);
        }
    }
    let analysis = analyze_seeded_image(image, backend, seeds, elf_function_symbols, diagnostics)?;
    #[cfg(feature = "decompiler")]
    let analysis = {
        let mut analysis = analysis;
        analysis.dwarf = dwarf;
        analysis
    };
    Ok(analysis)
}

fn analyze_seeded_image(
    image: LoadedImage,
    backend: RecoveryBackend,
    seeds: SeedMap,
    elf_function_symbols: FunctionSymbolMap,
    diagnostics: Vec<RecoveryDiagnostic>,
) -> Result<Analysis, RecoveryError> {
    let signatures = if backend == RecoveryBackend::VivisectCompat
        && image.format == ImageFormat::Pe
        && image.architecture.is_x86()
    {
        Some(super::flirt::Signatures::embedded()?)
    } else {
        None
    };
    analyze_seeded_image_with_signatures(
        image,
        backend,
        seeds,
        elf_function_symbols,
        diagnostics,
        signatures.as_ref(),
    )
}

fn analyze_seeded_image_with_signatures(
    mut image: LoadedImage,
    backend: RecoveryBackend,
    mut seeds: SeedMap,
    elf_function_symbols: FunctionSymbolMap,
    diagnostics: Vec<RecoveryDiagnostic>,
    signatures: Option<&super::flirt::Signatures>,
) -> Result<Analysis, RecoveryError> {
    let mut elf_function_symbols = elf_function_symbols;
    if backend == RecoveryBackend::Native {
        let delphi = crate::delphi::Rtti::read(&image);
        image.code_exclusions.extend(delphi.data_ranges);
        let exceptions = crate::msvc_eh::ExceptionInfo::read(&image);
        image
            .code_exclusions
            .extend(exceptions.data_ranges.iter().cloned());
        image.code_exclusions.sort_by_key(|range| range.start);
        let mut merged: Vec<std::ops::Range<u64>> = Vec::new();
        for range in image.code_exclusions.drain(..) {
            if let Some(last) = merged.last_mut().filter(|last| range.start <= last.end) {
                last.end = last.end.max(range.end);
            } else {
                merged.push(range);
            }
        }
        image.code_exclusions = merged;
        image
            .load_diagnostics
            .extend(exceptions.diagnostics.iter().cloned());
        for info in exceptions.functions.values() {
            for address in info.targets() {
                add_seed(&image, &mut seeds, address, SeedKind::MsvcException);
            }
        }
        seeds.retain(|address, _| !image.is_code_excluded(*address));
        for address in delphi.function_starts {
            add_seed(&image, &mut seeds, address, SeedKind::DelphiMethod);
        }
        for (address, name) in delphi.methods {
            elf_function_symbols
                .entry(address)
                .or_insert_with(|| vec![name]);
        }
        seeds.retain(|address, kinds| {
            kinds.remove(&SeedKind::Emulated);
            if image.format == ImageFormat::Pe
                && matches!(image.architecture, Architecture::X86 | Architecture::X64)
                && !plausible_relocation_function(&image, *address)
            {
                kinds.remove(&SeedKind::Relocation);
            }
            !kinds.is_empty()
        });
    }
    // A Go binary lists its functions exactly, as `.pdata` does for x64 PE: every entry is a
    // start, and nothing strictly inside one is.
    let go = if backend == RecoveryBackend::Native {
        crate::golang::parse(&image)
    } else {
        None
    };
    if let Some(go) = &go {
        // `go:buildid` holds the build ID string, not code.
        for function in go
            .functions
            .functions
            .iter()
            .filter(|function| !matches!(function.name.as_str(), "go:buildid" | "go.buildid"))
        {
            add_seed(
                &image,
                &mut seeds,
                function.entry,
                SeedKind::GoFunctionTable,
            );
        }
        seeds.retain(|address, _| !go.functions.inside(*address));
    }
    let mut fallback = BTreeMap::new();
    add_backend_fallback_seeds(&image, backend, &mut fallback);
    fallback.retain(|address, _| !image.is_code_excluded(*address));
    if let Some(go) = &go {
        fallback.retain(|address, _| !go.functions.inside(*address));
    }
    for (&address, kinds) in &fallback {
        seeds
            .entry(address)
            .or_default()
            .extend(kinds.iter().copied());
    }

    // The import locations `addNoReturnApi` resolves are known before any code
    // flow runs; everything else is derived from a completed pass.
    let mut noreturn_seed = noreturn::seed_addresses(&image);
    if image.format == ImageFormat::Macho {
        noreturn_seed.extend(
            elf_function_symbols
                .iter()
                .filter(|(_, names)| names.iter().any(|name| noreturn::macho_noreturn(name)))
                .map(|(address, _)| *address),
        );
    }
    let base_seeds = seeds.clone();
    let base_diagnostics = diagnostics.clone();

    let mut analysis = Analysis {
        #[cfg(feature = "decompiler")]
        dwarf: None,
        image,
        seeds,
        functions: BTreeMap::new(),
        function_order: BTreeMap::new(),
        function_analysis_counts: BTreeMap::new(),
        function_flirt_counts: BTreeMap::new(),
        function_location_counts: BTreeMap::new(),
        instruction_order: BTreeMap::new(),
        instructions: BTreeMap::new(),
        code_xrefs: BTreeMap::new(),
        data_xrefs: BTreeMap::new(),
        callers: BTreeMap::new(),
        callees: BTreeMap::new(),
        diagnostics,
        elf_function_symbols,
        noreturn: BTreeSet::new(),
        noreturn_calls: BTreeSet::new(),
    };

    // Vivisect interleaves no-return discovery with code flow: `addEntryPoint`
    // descends into a callee *before* deciding whether the call site falls
    // through (`envi/codeflow.py:239-256`), so a callee later proven
    // non-returning truncates the caller that was still being walked.
    // binfera discovers flow for the whole image in one sweep instead, so it
    // reaches the same fixpoint by re-running the sweep with the enlarged set
    // until it stops growing. Suppressing a fallthrough only ever *removes*
    // edges, so the set is monotonic and the loop terminates.
    let mut noreturn = noreturn_seed.clone();
    for pass in 0..noreturn::MAX_PASSES {
        if pass > 0 {
            analysis.seeds.clone_from(&base_seeds);
            analysis.diagnostics.clone_from(&base_diagnostics);
            analysis.functions.clear();
            analysis.function_order.clear();
            analysis.function_analysis_counts.clear();
            analysis.function_flirt_counts.clear();
            analysis.function_location_counts.clear();
            analysis.instruction_order.clear();
            analysis.instructions.clear();
            analysis.code_xrefs.clear();
            analysis.data_xrefs.clear();
            analysis.noreturn_calls.clear();
        }
        let next = recover_functions(&mut analysis, &fallback, &noreturn, backend, signatures)?;
        if backend == RecoveryBackend::VivisectCompat
            && matches!(
                analysis.image.architecture,
                Architecture::X86 | Architecture::X64
            )
        {
            noreturn = next;
            break;
        }
        if next == noreturn || pass.saturating_add(1) == noreturn::MAX_PASSES {
            break;
        }
        noreturn = next;
    }
    analysis.noreturn = noreturn;
    if let Some(go) = &go {
        // Starts the sweep found later (jump-table arms, code named by data) are dropped the same
        // way; the enclosing function's view already covers their code.
        // `go:buildid` is the build ID string, which other seeds may still have decoded.
        let build_id: BTreeSet<u64> = go
            .functions
            .functions
            .iter()
            .filter(|f| matches!(f.name.as_str(), "go:buildid" | "go.buildid"))
            .map(|f| f.entry)
            .collect();
        let inside: Vec<u64> = analysis
            .functions
            .keys()
            .copied()
            .filter(|address| go.functions.inside(*address) || build_id.contains(address))
            .collect();
        for address in inside {
            analysis.functions.remove(&address);
            analysis.function_order.remove(&address);
            analysis.function_analysis_counts.remove(&address);
            analysis.function_flirt_counts.remove(&address);
            analysis.function_location_counts.remove(&address);
        }
    }

    if backend == RecoveryBackend::Native {
        let mut exceptions = crate::msvc_eh::ExceptionInfo::read(&analysis.image);
        exceptions.link_functions(&analysis);
        for (label, owner) in exceptions.contained_funclets(&analysis) {
            if let Some(funclet) = analysis.functions.remove(&label) {
                if let Some(parent) = analysis.functions.get_mut(&owner) {
                    parent.blocks.extend(funclet.blocks);
                    parent.blocks.sort_by_key(|block| block.addr);
                    parent.blocks.dedup_by_key(|block| block.addr);
                }
            }
            analysis.function_order.remove(&label);
            analysis.function_analysis_counts.remove(&label);
            analysis.function_flirt_counts.remove(&label);
            analysis.function_location_counts.remove(&label);
        }
    }
    rebuild_call_indexes(&mut analysis);
    analysis
        .diagnostics
        .sort_by(|left, right| (left.address, &left.message).cmp(&(right.address, &right.message)));
    analysis.diagnostics.dedup();
    Ok(analysis)
}

/// One full recursive-descent sweep: discover direct flow from every seed,
/// then materialise a function view per discovered start. `noreturn` is the
/// call-target set whose fallthrough edges this sweep must suppress.
fn recover_functions(
    analysis: &mut Analysis,
    fallback: &SeedMap,
    noreturn: &BTreeSet<u64>,
    backend: RecoveryBackend,
    signatures: Option<&super::flirt::Signatures>,
) -> Result<BTreeSet<u64>, RecoveryError> {
    let evaluate_candidates = backend == RecoveryBackend::VivisectCompat
        && matches!(
            analysis.image.architecture,
            Architecture::X86 | Architecture::X64
        );
    let mut pointers = super::pointers::Discovery::new(analysis, evaluate_candidates);
    let mut initial: Vec<u64> = analysis.seeds.keys().copied().collect();
    initial.sort_by_key(|address| {
        let priority = analysis
            .seeds
            .get(address)
            .map(|kinds| seed_priority(kinds, evaluate_candidates))
            .unwrap_or(usize::MAX);
        // pe.py registers the image entry point before exports, SafeSEH,
        // and unwind entries. Keep those roots ahead of Guard CF-only entries:
        // function-analyzer order affects FLIRT reference matching.
        let pe_root_order = if evaluate_candidates && analysis.image.format == ImageFormat::Pe {
            let kinds = analysis.seeds.get(address);
            if analysis.image.entry_point == Some(*address) {
                0
            } else if kinds.is_some_and(|kinds| kinds.contains(&SeedKind::Export)) {
                1
            } else if kinds.is_some_and(|kinds| kinds.contains(&SeedKind::SafeSeh)) {
                2
            } else if kinds.is_some_and(|kinds| {
                kinds.contains(&SeedKind::GuardCf)
                    && !kinds
                        .iter()
                        .any(|&kind| kind != SeedKind::GuardCf && is_authoritative_seed(kind))
            }) {
                4
            } else {
                3
            }
        } else {
            0
        };
        (priority, pe_root_order, *address)
    });
    let mut pending: VecDeque<u64> = initial.into();
    let mut function_starts = BTreeSet::new();
    let mut isolated_starts = BTreeSet::new();
    let mut direct_flow = DirectFlowGraph {
        compatibility: evaluate_candidates,
        flirt: signatures.cloned().map(super::flirt::Discovery::new),
        known_noreturn: noreturn.clone(),
        ..DirectFlowGraph::default()
    };
    if evaluate_candidates && analysis.image.format == ImageFormat::Elf {
        // elf.elfplt analyzes undefined PLT bytes before entry points. Its
        // loose code can call ordinary functions, which finish immediately.
        let ranges = analysis.image.elf_plt_ranges.clone();
        let mut known_functions = BTreeSet::new();
        for (mut address, end) in ranges {
            while address < end {
                if let Some(instruction) = instruction_location(analysis, address) {
                    address = instruction.next_address;
                    continue;
                }
                let calls = discover_flow(
                    analysis,
                    &mut direct_flow,
                    address,
                    &mut pointers,
                    Some(&mut known_functions),
                )?;
                for target in calls {
                    analysis
                        .seeds
                        .entry(target)
                        .or_default()
                        .insert(SeedKind::CallTarget);
                    pending.push_back(target);
                }
                address = instruction_location(analysis, address)
                    .map(|instruction| instruction.next_address)
                    .unwrap_or_else(|| address.saturating_add(1));
            }
        }
    }
    let mut late_waves_done = false;
    // A leaf found by one sweep can be the tail-call target that validates another, so the
    // sweep repeats while it finds entries, a bounded number of times.
    let mut unclaimed_sweeps = if backend == RecoveryBackend::Native {
        MAX_UNCLAIMED_SWEEPS
    } else {
        0
    };
    let mut data_pointer_wave = None;
    let mut early_candidates_done = !evaluate_candidates;
    let mut function_budget_reported = false;
    loop {
        for (address, size) in direct_flow.pending_table_locations.drain(..) {
            pointers.mark_data(address, size);
        }
        // `generic.relocations/pointers` and `generic.emucode` precede
        // `i386.importcalls` and `generic.funcentries`. In particular, a
        // relocation to `call [TlsAlloc]; ret` must become a function before
        // importcalls can claim it as loose code.
        if !early_candidates_done
            && pending.front().is_none_or(|address| {
                analysis.image.format == ImageFormat::Pe
                    && analysis.seeds.get(address).is_some_and(|kinds| {
                        kinds.iter().all(|kind| {
                            matches!(
                                kind,
                                SeedKind::FunctionSignature
                                    | SeedKind::Prologue
                                    | SeedKind::SweepCallTarget
                            )
                        })
                    })
            })
        {
            if let Some(address) = pointers.next(analysis, &direct_flow.known_noreturn) {
                pending.push_front(address);
            } else {
                if let Some(signatures) = signatures {
                    // FLIRT local symbols can expose code that must exist
                    // before generic.funcentries scans undefined bytes.
                    // Keep oversized functions out of this optional pass;
                    // final materialization emits their limit diagnostic.
                    for &address in &function_starts {
                        match build_function_view(analysis, &direct_flow, address, false) {
                            Ok(function) => {
                                analysis.functions.insert(address, function);
                            }
                            Err(RecoveryError::Limit(_)) => {
                                analysis.functions.remove(&address);
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    let (_, mut locals) =
                        super::flirt::identify_with_local_starts(analysis, signatures)?;
                    locals.retain(|address| !function_starts.contains(address));
                    if !locals.is_empty() && function_starts.len() < MAX_FUNCTIONS {
                        for address in locals.into_iter().rev() {
                            analysis
                                .seeds
                                .entry(address)
                                .or_default()
                                .insert(SeedKind::FlirtLocal);
                            pending.push_front(address);
                        }
                        continue;
                    }
                }
                early_candidates_done = true;
                pointers.finish_emucode();
                run_import_call_wave(
                    analysis,
                    &mut direct_flow,
                    &mut pending,
                    &mut pointers,
                    Some(&function_starts),
                )?;
            }
        }
        let Some(start) = pending.pop_front() else {
            if late_waves_done {
                if evaluate_candidates {
                    if let Some(address) = pointers.next(analysis, &direct_flow.known_noreturn) {
                        pending.push_back(address);
                        continue;
                    }
                } else if run_data_pointer_wave(
                    analysis,
                    &mut direct_flow,
                    &mut data_pointer_wave,
                    &mut pending,
                ) {
                    continue;
                }
                if unclaimed_sweeps > 0 {
                    // Only the x64 leaf sweep depends on entries an earlier sweep found.
                    unclaimed_sweeps = if leaves::sweeps_x64_leaves(&analysis.image) {
                        unclaimed_sweeps - 1
                    } else {
                        0
                    };
                    let mut found_new = false;
                    for address in unclaimed_entries(analysis, &function_starts) {
                        analysis
                            .seeds
                            .entry(address)
                            .or_default()
                            .insert(SeedKind::Unclaimed);
                        found_new |= !function_starts.contains(&address);
                        pending.push_back(address);
                    }
                    if !found_new {
                        unclaimed_sweeps = 0;
                    }
                    if !pending.is_empty() {
                        continue;
                    }
                }
                break;
            }
            // Compatibility import-call discovery ran after emucode and
            // before function signatures, as in the reference module order.
            // Native recovery keeps its late import-call scan.
            // The Go pass reads
            // the *recovered* entry function's basic blocks, so it cannot run
            // until that function's flow exists.
            late_waves_done = true;
            run_go_runtime_main_wave(analysis, &direct_flow, &mut pending)?;
            if !evaluate_candidates {
                run_import_call_wave(
                    analysis,
                    &mut direct_flow,
                    &mut pending,
                    &mut pointers,
                    None,
                )?;
            }
            // `vivisect.analysis.ms.msvcfunc` is amodlist[9]/[10] -- after
            // the import-call pass, and reading the function set the earlier
            // ones produced.
            // Splitting the `/GS` cookie tail into a function is Vivisect's
            // layout. Ghidra keeps the check inside its caller, so native
            // recovery does too.
            if evaluate_candidates {
                run_msvc_cookie_wave(analysis, &direct_flow, &function_starts, &mut pending);
            }
            // Not a pinned Vivisect pass (there is none to port -- Vivisect
            // never analysed AArch64): reads `analysis.instructions`, so it
            // waits for the same reason the passes above do.
            run_aarch64_plt_wave(analysis);
            continue;
        };
        if direct_flow.delayed_functions.contains(&start) {
            continue;
        }
        let late_signature_only = analysis.seeds.get(&start).is_some_and(|kinds| {
            kinds.iter().all(|kind| {
                matches!(
                    kind,
                    SeedKind::FunctionSignature | SeedKind::Prologue | SeedKind::Unclaimed
                )
            })
        }) && !(analysis.image.architecture == Architecture::AArch64
            && analysis.seeds.get(&start).is_some_and(|kinds| {
                kinds.contains(&SeedKind::Unclaimed) && kinds.contains(&SeedKind::Prologue)
            }));
        // generic/funcentries.py scans undefined locations only. A match
        // inside an instruction is not a new function, even if its bytes
        // look like an entry signature.
        if function_starts.contains(&start)
            || (late_signature_only
                && (instruction_location(analysis, start).is_some()
                    || (evaluate_candidates && super::pointers::covered(analysis, start))))
            || !is_executable(&analysis.image, start)
        {
            continue;
        }
        if function_starts.len() >= MAX_FUNCTIONS {
            // Degrade like the two walk budgets: stop taking new starts and
            // analyse the ones already found. Reported once, not once per
            // remaining seed.
            if !function_budget_reported {
                function_budget_reported = true;
                analysis.diagnostics.push(RecoveryDiagnostic {
                    address: start,
                    message: format!("stopped taking function starts at {MAX_FUNCTIONS}"),
                });
            }
            continue;
        }
        if should_isolate_overlapping_candidate(
            fallback,
            &analysis.seeds,
            start,
            analysis.instructions.contains_key(&start),
        ) {
            // Native relocation candidates retain the existing containment
            // rule: an overlapping speculative seed must not claim an
            // entire shared graph. Compatibility pointers have already been
            // evaluated against defined instruction locations.
            //
            // On x86-32 such a relocation is nearly always a switch arm or an
            // exception-unwind block of a function already walked, because
            // jump tables and unwind maps are relocated data. It is not a function.
            if !evaluate_candidates
                && analysis.image.format == ImageFormat::Pe
                && analysis.image.architecture == Architecture::X86
            {
                continue;
            }
            isolated_starts.insert(start);
        }
        function_starts.insert(start);
        // Same rule as the import-call wave below: upstream has no per-walk
        // instruction budget, so a walk that blows past binfera's is a
        // statement about this backend's guard rail, not about the image.
        // Keep what the walk did discover and record why it stopped, rather
        // than failing the whole image on one runaway start.
        let calls = discover_direct_flow(analysis, &mut direct_flow, start, &mut pointers)?;
        for target in calls.into_iter().rev() {
            if !is_executable(&analysis.image, target) {
                continue;
            }
            let is_new = !analysis.seeds.contains_key(&target);
            // A call target is discovered code, so it has to be walked before
            // the prologue-signature seeds: vivisect's codeflow completes for
            // every entry point before `generic/funcentries.py` scans what is
            // *still undefined* for prologue byte patterns. This queue is
            // priority-sorted once, at its initial fill, so an address that
            // was a signature seed then keeps that seed's last-place position
            // even after a call proves it a real function. Requeue it at the
            // front; otherwise a lower-addressed signature hit inside its body
            // -- the `jmp` target of an MSVC hot-patch thunk, say -- is walked
            // first and becomes a function of its own, which vivisect never
            // creates.
            let was_heuristic_only = !is_new
                && analysis.seeds.get(&target).is_some_and(|kinds| {
                    kinds.iter().all(|kind| {
                        matches!(
                            kind,
                            SeedKind::FunctionSignature
                                | SeedKind::Prologue
                                | SeedKind::SweepCallTarget
                        )
                    })
                });
            analysis
                .seeds
                .entry(target)
                .or_default()
                .insert(SeedKind::CallTarget);
            if is_new
                || (!function_starts.contains(&target)
                    && (was_heuristic_only
                        || direct_flow.completed_functions.contains_key(&target)))
            {
                pending.push_front(target);
            }
        }
    }
    analysis.functions.clear();
    if !direct_flow.compatibility && analysis.image.format == ImageFormat::Pe {
        direct_flow.function_entries = function_starts.clone();
    }
    for start in function_starts {
        if direct_flow.delayed_functions.contains(&start) {
            continue;
        }
        let function = match build_function_view(
            analysis,
            &direct_flow,
            start,
            isolated_starts.contains(&start),
        ) {
            Ok(function) => function,
            // A function whose reachable set is past the budget is dropped
            // rather than truncated: a partial view would invent an extent
            // neither backend has, and rules evaluated at function scope would
            // see an arbitrary prefix of it. The diagnostic keeps it visible.
            Err(RecoveryError::Limit(message)) => {
                analysis.diagnostics.push(RecoveryDiagnostic {
                    address: start,
                    message: format!("dropped oversized function: {message}"),
                });
                continue;
            }
            Err(error) => return Err(error),
        };
        analysis.functions.insert(start, function);
    }
    // Compatibility propagates no-return decisions as functions complete.
    // Native recovery uses the complete graph for its fixed point. Preserve
    // import-call fragments in that graph, then apply captured feature scopes
    // after recovery decisions.
    for address in &direct_flow.import_functions {
        if let Some(captured) = direct_flow.completed_functions.get(address) {
            analysis.functions.insert(*address, captured.clone());
        }
    }
    let next = if direct_flow.compatibility {
        direct_flow.known_noreturn.clone()
    } else {
        noreturn::propagate(analysis, &noreturn::seed_addresses(&analysis.image))
    };
    for (address, captured) in direct_flow.completed_functions {
        if let Some(function) = analysis.functions.get_mut(&address) {
            *function = captured;
        }
    }
    Ok(next)
}

/// Vivisect's `i386.golang` pass: seed `runtime_main`, the start every Go
/// application hangs off and that no direct call reaches.
fn run_go_runtime_main_wave(
    analysis: &mut Analysis,
    direct_flow: &DirectFlowGraph,
    pending: &mut VecDeque<u64>,
) -> Result<(), RecoveryError> {
    if !golang::is_go_image(&analysis.image) {
        return Ok(());
    }
    let Some(entry) = analysis.image.entry_point else {
        return Ok(());
    };
    if !direct_flow.successors.contains_key(&entry) {
        return Ok(());
    }
    // The Go wave is an optional enrichment; if the entry walk is past the
    // budget there is nothing to enrich from, and that is not a reason to fail
    // the image.
    let Ok(entry_view) = build_function_view(analysis, direct_flow, entry, false) else {
        return Ok(());
    };
    // `find_golang_bblock_via_stack` needs the blocks of a *second* function,
    // the one the entry stub pushes; build it the same way on demand.
    let blocks_at = |address: u64| {
        direct_flow
            .successors
            .contains_key(&address)
            .then(|| build_function_view(analysis, direct_flow, address, false).ok())
            .flatten()
    };
    let Some(runtime_main) = golang::runtime_main(&analysis.image, &entry_view, &blocks_at) else {
        return Ok(());
    };
    if !is_executable(&analysis.image, runtime_main) {
        return Ok(());
    }
    let is_new = !analysis.seeds.contains_key(&runtime_main);
    analysis
        .seeds
        .entry(runtime_main)
        .or_default()
        .insert(SeedKind::GoRuntimeMain);
    if is_new {
        pending.push_front(runtime_main);
    }
    Ok(())
}

/// `vw.getCodeBlock(va)[L_VA]`: the start of the code block containing `va`.
/// binfera has no standing block graph -- [`build_function_view`] derives
/// block starts per function -- so walk back to the nearest one using the
/// same two rules it does: an address begins a block if something branches to
/// it, or if the instruction it follows ends one.
fn code_block_start(analysis: &Analysis, direct_flow: &DirectFlowGraph, va: u64) -> Option<u64> {
    if direct_flow.compatibility {
        // getCodeBlock reads the last block written to the workspace map.
        // Reconstructing a boundary from nearby instruction addresses loses
        // that ownership when instruction streams or function views overlap.
        return direct_flow
            .completed_functions
            .iter()
            .flat_map(|(function, view)| {
                view.blocks.iter().filter_map(|block| {
                    let end = block.insns.last()?.next_address;
                    (block.addr <= va && va < end).then_some((
                        analysis.function_order.get(function).copied().unwrap_or(0),
                        block.addr,
                    ))
                })
            })
            .max()
            .map(|(_, start)| start);
    }
    let mut address = va;
    loop {
        if !analysis.instructions.contains_key(&address) {
            return None;
        }
        if analysis.code_xrefs.contains_key(&address) {
            return Some(address);
        }
        let Some((&previous, insn)) = analysis.instructions.range(..address).next_back() else {
            return Some(address);
        };
        if insn.next_address != address
            || is_block_terminator(insn.flow)
            || !direct_flow.successors.contains_key(&previous)
        {
            return Some(address);
        }
        address = previous;
    }
}

/// Vivisect's `ms.msvcfunc` pass: split the `/GS` cookie-restoring tail of a
/// function off into a function of its own. See [`super::msvcfunc`].
fn run_msvc_cookie_wave(
    analysis: &mut Analysis,
    direct_flow: &DirectFlowGraph,
    function_starts: &BTreeSet<u64>,
    pending: &mut VecDeque<u64>,
) {
    if analysis.image.format != ImageFormat::Pe {
        return;
    }
    let mut cookies = BTreeSet::new();
    for &start in function_starts {
        if !msvcfunc::is_security_check_cookie(&analysis.image, start) {
            continue;
        }
        let Some(insn) = analysis.instructions.get(&start) else {
            continue;
        };
        // `msvcfunc.py` reads `op.opers[1]` and requires it to be a deref.
        // (Upstream `return`s from the whole module when it isn't; every
        // byte pattern the signature table matches starts with a two-operand
        // `cmp reg, [cookie]`, so that early-out cannot fire -- this skips
        // the one function instead, which is order-independent.)
        if insn.x86_instruction().op_count() != 2
            || insn.x86_instruction().op_kind(1) != OpKind::Memory
        {
            continue;
        }
        if let Some(cookie) = insn.memory_target {
            cookies.insert(cookie);
        }
    }
    if cookies.is_empty() {
        return;
    }

    let starts = msvcfunc::new_function_starts(
        &cookies,
        |cookie| {
            analysis
                .data_xrefs
                .get(&cookie)
                .map(|sources| sources.to_vec())
                .unwrap_or_default()
        },
        |from| {
            analysis
                .instructions
                .get(&from)
                .map(|insn| insn.x86_instruction().mnemonic())
        },
        |from| code_block_start(analysis, direct_flow, from),
    );

    for start in starts {
        if function_starts.contains(&start) || !is_executable(&analysis.image, start) {
            continue;
        }
        analysis
            .seeds
            .entry(start)
            .or_default()
            .insert(SeedKind::MsvcCookieBlock);
        // Upstream's condition is `if not vw.isFunction(va)` -- a cookie block
        // becomes a function whatever else the workspace already knows about
        // the address. Requeueing only *newly seeded* addresses silently drops
        // the ones a heuristic seed had already claimed: the main loop skips a
        // `FunctionSignature`/`Prologue`-only seed whose bytes are already
        // decoded, so such an address is neither a function nor requeueable,
        // and the deterministic seed vanishes. `function_starts` above is the
        // `isFunction` check; everything past it is queue work.
        pending.push_front(start);
    }
}

/// Native x64 PE only: promote code addresses stored in data to functions.
///
/// MSVC leaves entries that no call reaches: C++ unwind and catch funclets,
/// vtable slots and callbacks. They have no `.pdata` entry when they are leaves
/// and are named only by image-relative (`u32`) or absolute (`u64`) values in
/// `.rdata`/`.xdata`. Against Ghidra's function list this single source is
/// about two thirds of the functions recovery misses.
///
/// A raw value is a weak signal (jump-table arms are also image-relative), so a
/// target must be undiscovered code that begins right after a block terminator
/// and optional alignment padding: the place where one function ends and the
/// next begins. Adjacent entries are admitted on later rounds, once the one
/// before them has been decoded. Returns whether it queued a new start.
fn run_data_pointer_wave(
    analysis: &mut Analysis,
    direct_flow: &mut DirectFlowGraph,
    state: &mut Option<DataPointerWave>,
    pending: &mut VecDeque<u64>,
) -> bool {
    if analysis.image.format != ImageFormat::Pe
        || !matches!(
            analysis.image.architecture,
            Architecture::X64 | Architecture::X86
        )
    {
        return false;
    }
    let first_round = state.is_none();
    let wide = analysis.image.architecture == Architecture::X64;
    let wave = state.get_or_insert_with(|| {
        // x86-32 has no unwind data, and values in its data sections are mostly
        // not code pointers, so only the jump-derived sources apply there.
        if !wide {
            return DataPointerWave {
                unwound: Vec::new(),
                remaining: collect_eh_handler_targets(&analysis.image),
                weak: collect_data_pointer_targets(&analysis.image),
                ..DataPointerWave::default()
            };
        }
        let unwound = unwind_extents(&analysis.image);
        let mut remaining = collect_data_pointer_targets(&analysis.image);
        remaining.retain(|&target| !inside_unwind_extent(&unwound, target));
        DataPointerWave {
            unwound,
            remaining,
            ..DataPointerWave::default()
        }
    });
    match direct_flow.new_instructions.replace(Vec::new()) {
        Some(addresses) => {
            for address in addresses {
                if let Some(insn) = analysis.instructions.get(&address) {
                    wave.index(insn);
                }
            }
        }
        None => analysis
            .instructions
            .values()
            .for_each(|insn| wave.index(insn)),
    }
    debug_assert!(
        analysis
            .instructions
            .values()
            .all(|insn| wave.indexed(insn)),
        "a recovered instruction reached the wave index without being reported"
    );
    let direct_flow = &*direct_flow;
    let mut accepted = if first_round {
        import_stub_starts(analysis)
    } else {
        Vec::new()
    };
    if wide {
        accepted.extend(
            wave.remaining
                .iter()
                .copied()
                .filter(|&target| begins_after_function_end(analysis, direct_flow, target)),
        );
        // A callback can be materialized directly in code with RIP-relative
        // LEA, without a pointer stored in a data section. Apply the same
        // boundary and unwind checks used for data-named entries.
        let lea_sites = wave.lea_sites.iter();
        let sites = lea_sites.filter_map(|address| analysis.instructions.get(address));
        accepted.extend(sites.filter_map(|insn| {
            let target = insn.memory_target?;
            (is_rip_relative_lea(insn)
                && is_executable(&analysis.image, target)
                && !inside_unwind_extent(&wave.unwound, target)
                && !analysis.seeds.contains_key(&target)
                && begins_after_function_end(analysis, direct_flow, target))
            .then_some(target)
        }));
    } else {
        // The structure names the entry, so no function end has to precede it.
        accepted.extend(wave.remaining.iter().copied().filter(|&target| {
            !analysis.instructions.contains_key(&target)
                && !super::pointers::covered(analysis, target)
                && analysis.image.decode_at(target).is_ok_and(|first| {
                    !matches!(
                        first.x86_instruction().mnemonic(),
                        Mnemonic::Int3 | Mnemonic::Nop
                    )
                })
        }));
    }
    if !wide {
        let scope_blocks = seh_scope_blocks(&analysis.image);
        let callbacks: Vec<_> = wave
            .weak
            .iter()
            .copied()
            .filter(|&target| begins_after_function_end(analysis, direct_flow, target))
            .filter(|&target| {
                !resumes_parent_frame(&analysis.image, target) && !scope_blocks.contains(&target)
            })
            .collect();
        for target in callbacks {
            wave.weak.remove(&target);
            analysis
                .seeds
                .entry(target)
                .or_default()
                .insert(SeedKind::Vtable);
            accepted.push(target);
        }
    }
    accepted.extend(tail_jump_targets(
        analysis,
        direct_flow,
        &wave.unwound,
        &wave.direct_jumps,
    ));
    if !wide {
        accepted.extend(folded_prologue_starts(analysis, direct_flow));
    }
    accepted.sort_unstable();
    accepted.dedup();
    for target in &accepted {
        wave.remaining.remove(target);
        analysis
            .seeds
            .entry(*target)
            .or_default()
            .insert(SeedKind::PointerTarget);
        pending.push_back(*target);
    }
    !accepted.is_empty()
}

#[derive(Default)]
struct DataPointerWave {
    /// RIP-relative LEA and direct jump addresses. Each wave checks only these, not all of the
    /// millions of instructions a large image has. An entry can go stale when flow rewrites an
    /// instruction, so readers look it up and check it again.
    lea_sites: BTreeSet<u64>,
    direct_jumps: BTreeSet<u64>,
    /// Sorted `.pdata` extents.
    unwound: Vec<(u64, u64)>,
    /// Data-named code addresses not yet admitted.
    remaining: BTreeSet<u64>,
    /// Isolated absolute pointers need a validated preceding function boundary.
    weak: BTreeSet<u64>,
}

/// An unwind entry bounds a function exactly. An address strictly inside one,
/// or on a chained fragment, is a catch continuation, a switch arm or a
/// frame-sharing block of that function, not a new function.
fn inside_unwind_extent(unwound: &[(u64, u64)], address: u64) -> bool {
    let index = unwound.partition_point(|&(begin, _)| begin <= address);
    index
        .checked_sub(1)
        .and_then(|index| unwound.get(index))
        .is_some_and(|&(_, end)| address < end)
}

/// Direct `jmp` targets that start a function: decoded code right after a
/// function end (and `int3` padding) that a jump reaches. Such a jump is a
/// tail call, so the target is a function entry that flow had folded into the
/// jumping function. Ghidra's shared-return analysis makes the same call.
impl DirectFlowGraph {
    fn note_new_instruction(&mut self, address: u64) {
        if let Some(addresses) = &mut self.new_instructions {
            addresses.push(address);
        }
    }
}

fn is_rip_relative_lea(insn: &DecodedInstruction) -> bool {
    let instruction = insn.x86_instruction();
    instruction.mnemonic() == Mnemonic::Lea && instruction.is_ip_rel_memory_operand()
}

fn is_direct_jump(insn: &DecodedInstruction) -> bool {
    insn.direct_target.is_some() && insn.flow == Flow::UnconditionalBranch
}

impl DataPointerWave {
    fn index(&mut self, insn: &DecodedInstruction) {
        if insn.memory_target.is_some() && is_rip_relative_lea(insn) {
            self.lea_sites.insert(insn.address);
        }
        if is_direct_jump(insn) {
            self.direct_jumps.insert(insn.address);
        }
    }

    fn indexed(&self, insn: &DecodedInstruction) -> bool {
        (insn.memory_target.is_none()
            || !is_rip_relative_lea(insn)
            || self.lea_sites.contains(&insn.address))
            && (!is_direct_jump(insn) || self.direct_jumps.contains(&insn.address))
    }
}

fn tail_jump_targets(
    analysis: &Analysis,
    direct_flow: &DirectFlowGraph,
    unwound: &[(u64, u64)],
    direct_jumps: &BTreeSet<u64>,
) -> Vec<u64> {
    // Without unwind data (x86-32) a jump target after a function end is also a loop
    // head or a block placed after a `ret`, so a target must be vouched for: a jump
    // stub reaches it, or a prologue pattern marked it before flow folded it away.
    let wide = analysis.image.architecture == Architecture::X64;
    let heuristic_only = |kinds: &BTreeSet<SeedKind>| {
        kinds.iter().all(|kind| {
            matches!(
                kind,
                SeedKind::FunctionSignature | SeedKind::Prologue | SeedKind::SweepCallTarget
            )
        })
    };
    let mut targets = BTreeSet::new();
    for insn in direct_jumps
        .iter()
        .filter_map(|address| analysis.instructions.get(address))
    {
        let Some(target) = insn
            .direct_target
            .filter(|_| insn.flow == Flow::UnconditionalBranch)
        else {
            continue;
        };
        let admitted = if wide {
            !analysis.seeds.contains_key(&target)
        } else {
            match analysis.seeds.get(&target) {
                None => is_jump_stub(analysis, insn) || follows_int3_alignment(analysis, target),
                Some(kinds) => heuristic_only(kinds),
            }
        };
        if admitted
            && analysis.instructions.contains_key(&target)
            && is_executable(&analysis.image, target)
            && !inside_unwind_extent(unwound, target)
        {
            targets.insert(target);
        }
    }
    targets
        .into_iter()
        .filter(|&target| ends_function_before(analysis, direct_flow, target, false))
        .collect()
}

/// Prologue-signature addresses that flow had already decoded as part of another function
/// (reached by a branch from elsewhere) but that sit right after a function end: the
/// signature scan skips decoded bytes, so nothing else would make them functions.
fn folded_prologue_starts(analysis: &Analysis, direct_flow: &DirectFlowGraph) -> Vec<u64> {
    analysis
        .seeds
        .iter()
        .filter(|(address, kinds)| {
            kinds.iter().all(|kind| {
                matches!(
                    kind,
                    SeedKind::FunctionSignature | SeedKind::Prologue | SeedKind::Unclaimed
                )
            }) && analysis.instructions.contains_key(address)
        })
        .map(|(address, _)| *address)
        .filter(|&address| {
            // Undecoded bytes before it are an unreached function body or padding: the
            // signature stands at a boundary even though no instruction ends there.
            let gap = analysis
                .instructions
                .range(..address)
                .next_back()
                .is_none_or(|(_, previous)| previous.next_address < address);
            gap || ends_function_before(analysis, direct_flow, address, false)
        })
        .collect()
}

/// A 16-byte aligned address right after `int3` padding: the way MSVC lays out one function
/// after another. Other jump targets after a function end are loop heads and cold blocks.
fn follows_int3_alignment(analysis: &Analysis, target: u64) -> bool {
    target & 15 == 0
        && target
            .checked_sub(1)
            .and_then(|before| analysis.image.bytes_at(before, 1))
            .is_some_and(|byte| byte == [0xcc])
}

/// A `jmp` that is a whole function: something calls or jumps to it, and the next
/// instruction belongs to another function or to padding.
fn is_jump_stub(analysis: &Analysis, jump: &DecodedInstruction) -> bool {
    analysis.seeds.contains_key(&jump.address)
        && analysis
            .instructions
            .get(&jump.next_address)
            .is_none_or(|next| analysis.seeds.contains_key(&next.address))
}

/// x86-32 Visual C++ exception-handling data names code that no call or jump reaches:
/// a catch block (`HandlerType::addressOfHandler`) and the frame-handler stub stored
/// before a `FuncInfo` (magic `0x1993052x`). Ghidra makes both functions. The slot is
/// accepted only inside one of these two shapes, because a bare code address in data
/// is as often a switch arm or an unwind funclet it leaves inside its parent.
fn collect_eh_handler_targets(image: &LoadedImage) -> BTreeSet<u64> {
    const MAGIC: std::ops::RangeInclusive<u32> = 0x1993_0520..=0x1993_0522;
    let mut targets = BTreeSet::new();
    for section in &image.sections {
        if section.permissions.execute
            || !section.permissions.read
            || image.is_uninitialized(section.address)
            || matches!(section.name.as_str(), ".reloc" | ".rsrc")
        {
            continue;
        }
        let Some(bytes) = usize::try_from(section.virtual_size)
            .ok()
            .and_then(|length| image.bytes_at(section.address, length))
        else {
            continue;
        };
        let word = |index: usize| -> Option<u32> {
            let chunk = bytes.get(index.checked_mul(4)?..index.checked_mul(4)?.checked_add(4)?)?;
            Some(u32::from_le_bytes(<[u8; 4]>::try_from(chunk).ok()?))
        };
        for index in 3..bytes.len() / 4 {
            let (Some(value), Some(next)) = (word(index), word(index + 1)) else {
                continue;
            };
            let target = u64::from(value);
            if !is_executable(image, target) {
                continue;
            }
            let frame_handler = MAGIC.contains(&next);
            let catch_handler = match (word(index - 3), word(index - 2)) {
                (Some(adjectives), Some(type_info)) => {
                    adjectives <= 0xfff && (type_info == 0 || is_type_descriptor(image, type_info))
                }
                _ => false,
            };
            if frame_handler || catch_handler {
                targets.insert(target);
            }
        }
    }
    targets
}

/// A `std::type_info` descriptor: vtable pointer, spare pointer, then the decorated
/// name, which starts with `.`.
fn is_type_descriptor(image: &LoadedImage, address: u32) -> bool {
    !is_executable(image, u64::from(address))
        && image
            .bytes_at(u64::from(address) + 8, 3)
            .is_some_and(|name| name.len() == 3 && name[0] == b'.')
}

/// RTTI is authoritative. Without RTTI require at least two adjacent absolute
/// code pointers in read-only data, with independently plausible entry instructions.
fn vtable_targets(image: &LoadedImage) -> BTreeSet<u64> {
    let mut targets: BTreeSet<_> = crate::rtti::Rtti::read(image)
        .vftables
        .iter()
        .flat_map(|table| table.slots.iter().copied())
        .collect();
    let width = image.architecture.pointer_width();
    if !matches!(image.architecture, Architecture::X86 | Architecture::X64) {
        return targets;
    }
    let scope_blocks = seh_scope_blocks(image);
    // A run of absolute code pointers is also how compilers lay out a jump table. Its arms lie
    // inside the switching function's unwind row, where no function begins.
    let unwound = unwind_extents(image);
    for section in &image.sections {
        if !section.permissions.read
            || section.permissions.write
            || section.permissions.execute
            || matches!(section.name.as_str(), ".pdata" | ".reloc" | ".rsrc")
        {
            continue;
        }
        let mut run = Vec::new();
        let mut run_start = section.address;
        let mut flush = |run: &mut Vec<u64>, run_start: u64| {
            if run.len() >= 2 && !scope_record(image, run_start, run.len()) {
                targets.extend(run.iter().copied().filter(|&t| {
                    pointer_entry_boundary(image, t) && !interior::inside_unwind_row(&unwound, t)
                }));
            }
            run.clear();
        };
        let length = section.file_size.min(section.virtual_size);
        for offset in (0..length).step_by(width) {
            let target = super::read_pointer(image, section.address + offset)
                .filter(|&target| is_executable(image, target))
                .filter(|&target| {
                    image.decode_at(target).is_ok_and(|first| {
                        let i = first.x86_instruction();
                        !matches!(i.mnemonic(), Mnemonic::Int3 | Mnemonic::Nop | Mnemonic::Add)
                            && i.mnemonic() != Mnemonic::INVALID
                    }) && !resumes_parent_frame(image, target)
                        && !scope_blocks.contains(&target)
                });
            if let Some(target) = target {
                if run.is_empty() {
                    run_start = section.address + offset;
                }
                run.push(target);
            } else {
                flush(&mut run, run_start);
            }
        }
        flush(&mut run, run_start);
    }
    targets
}

/// An x86 SEH scope-table record is `{try level, filter, handler}`. The level (-1, -2 or a
/// small index) breaks a run of code pointers just before the filter/handler pair. Both
/// blocks run in their parent's frame: they are not functions.
fn scope_record(image: &LoadedImage, first: u64, run: usize) -> bool {
    image.architecture == Architecture::X86
        && run == 2
        && first
            .checked_sub(4)
            .and_then(|at| image.bytes_at(at, 4))
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map(u32::from_le_bytes)
            .is_some_and(|level| !(0x100..0xffff_fffe).contains(&level))
}

/// Filters and handlers named by x86 SEH scope records `{try level, filter, handler}` whose
/// handler resumes its parent's frame. Both run inside the parent: neither is a function, and a
/// filter (`push 1; pop eax; ret`) otherwise looks like one.
fn seh_scope_blocks(image: &LoadedImage) -> BTreeSet<u64> {
    let mut blocks = BTreeSet::new();
    if image.architecture != Architecture::X86 {
        return blocks;
    }
    for section in &image.sections {
        if !section.permissions.read || section.permissions.execute {
            continue;
        }
        let length = section.file_size.min(section.virtual_size);
        let Some(bytes) = usize::try_from(length)
            .ok()
            .and_then(|length| image.bytes_at(section.address, length))
        else {
            continue;
        };
        let word = |at: usize| {
            bytes
                .get(at..at + 4)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map(u32::from_le_bytes)
        };
        for at in (0..bytes.len().saturating_sub(11)).step_by(4) {
            let (Some(level), Some(filter), Some(handler)) = (word(at), word(at + 4), word(at + 8))
            else {
                continue;
            };
            let (filter, handler) = (u64::from(filter), u64::from(handler));
            if (0x100..0xffff_fffe).contains(&level)
                || !is_executable(image, handler)
                || !resumes_parent_frame(image, handler)
                || (filter != 0 && !is_executable(image, filter))
            {
                continue;
            }
            blocks.insert(handler);
            if filter != 0 {
                blocks.insert(filter);
            }
        }
    }
    blocks
}

/// `__except` handlers resume in their parent's frame (`mov esp,[ebp-n]`); no function
/// starts by loading its stack pointer from a frame it has not set up.
fn resumes_parent_frame(image: &LoadedImage, target: u64) -> bool {
    image.decode_at(target).is_ok_and(|first| {
        let i = first.x86_instruction();
        i.mnemonic() == Mnemonic::Mov
            && i.op0_kind() == OpKind::Register
            && matches!(i.op0_register(), Register::ESP | Register::RSP)
            && i.op1_kind() == OpKind::Memory
            && matches!(i.memory_base(), Register::EBP | Register::RBP)
    })
}

/// Weak pointer tables must not turn adjacent switch arms into functions.
/// Require padding, a return, or the beginning of an executable section.
fn pointer_entry_boundary(image: &LoadedImage, target: u64) -> bool {
    let Some(section) = image.sections.iter().find(|s| s.contains_va(target)) else {
        return false;
    };
    if target == section.address {
        return true;
    }
    let start = target.saturating_sub(16).max(section.address);
    let Some(before) = image.bytes_at(start, (target - start) as usize) else {
        return false;
    };
    if before.ends_with(&[0xcc]) || before.ends_with(&[0xc3]) {
        return true;
    }
    let padding = before
        .iter()
        .rev()
        .take_while(|&&b| b == 0x90 || b == 0xcc)
        .count();
    if padding >= 3 {
        return true;
    }
    let end = before.len() - padding;
    before
        .get(end.saturating_sub(3)..end)
        .is_some_and(|tail| tail.len() == 3 && tail[0] == 0xc2 && tail[1] & 3 == 0 && tail[2] == 0)
}

/// Executable addresses named by aligned image-relative or absolute values in
/// initialized data. Unwind and relocation directories are skipped: their
/// RVAs name function starts and blocks that other sources already handle.
fn collect_data_pointer_targets(image: &LoadedImage) -> BTreeSet<u64> {
    let mut targets = BTreeSet::new();
    for section in &image.sections {
        if section.permissions.execute
            || !section.permissions.read
            || image.is_uninitialized(section.address)
            || matches!(section.name.as_str(), ".pdata" | ".reloc" | ".rsrc")
        {
            continue;
        }
        let Ok(length) = usize::try_from(section.virtual_size) else {
            continue;
        };
        let Some(bytes) = image.bytes_at(section.address, length) else {
            continue;
        };
        for (index, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
            let relative = u32::from_le_bytes(*chunk);
            if image.architecture == Architecture::X86 {
                let target = u64::from(relative);
                if is_executable(image, target) {
                    targets.insert(target);
                }
                continue;
            }
            if let Some(target) = image.image_base.checked_add(u64::from(relative)) {
                if is_executable(image, target) {
                    targets.insert(target);
                }
            }
            if index % 2 == 0 {
                if let Some(pair) = bytes.get(index * 4..index * 4 + 8) {
                    if let Ok(pair) = <[u8; 8]>::try_from(pair) {
                        let absolute = u64::from_le_bytes(pair);
                        if is_executable(image, absolute) {
                            targets.insert(absolute);
                        }
                    }
                }
            }
        }
    }
    targets
}

/// Import stubs (`jmp [import]`) that other code branches to. Each is a thunk,
/// a function of its own, but flow gave it no entry because only `jmp`s, not
/// calls, reach it and the jump stayed inside the caller. A stub nothing
/// references is not promoted: no call site could name it.
fn import_stub_starts(analysis: &Analysis) -> Vec<u64> {
    analysis
        .instructions
        .iter()
        .filter(|(address, insn)| {
            insn.flow == Flow::IndirectBranch
                && insn
                    .memory_target
                    .is_some_and(|slot| analysis.image.import_locations.contains_key(&slot))
                && analysis.code_xrefs.contains_key(address)
        })
        .map(|(address, _)| *address)
        .collect()
}

/// Sorted `(begin, end)` extents of the x64 `.pdata` unwind entries. Malformed
/// or truncated entries are skipped; they only make the filter more permissive.
pub(crate) fn unwind_extents(image: &LoadedImage) -> Vec<(u64, u64)> {
    let mut extents = Vec::new();
    for section in image.sections.iter().filter(|s| s.name == ".pdata") {
        let Some(bytes) = usize::try_from(section.virtual_size)
            .ok()
            .and_then(|length| image.bytes_at(section.address, length))
        else {
            continue;
        };
        for entry in bytes.as_chunks::<12>().0 {
            let word = |at: usize| {
                entry
                    .get(at..at + 4)
                    .and_then(|value| <[u8; 4]>::try_from(value).ok())
                    .map(u32::from_le_bytes)
            };
            if let (Some(begin), Some(end)) = (word(0), word(4)) {
                if let (Some(begin), Some(end)) = (
                    image.image_base.checked_add(u64::from(begin)),
                    image.image_base.checked_add(u64::from(end)),
                ) {
                    if begin < end {
                        extents.push((begin, end));
                    }
                }
            }
        }
    }
    extents.sort_unstable();
    extents
}

/// True when `target` is undecoded code directly after a function-ending
/// instruction, with only `int3`/`nop` padding between them.
fn begins_after_function_end(
    analysis: &Analysis,
    direct_flow: &DirectFlowGraph,
    target: u64,
) -> bool {
    if !analysis.image.architecture.is_x86() {
        return false;
    }
    // Padding is never an entry: a value naming the `int3` before a function
    // is an end marker, not a start.
    let starts_with_code = analysis.image.decode_at(target).is_ok_and(|first| {
        !matches!(
            first.x86_instruction().mnemonic(),
            Mnemonic::Int3 | Mnemonic::Nop
        )
    });
    !analysis.instructions.contains_key(&target)
        && !super::pointers::covered(analysis, target)
        && starts_with_code
        && ends_function_before(analysis, direct_flow, target, true)
}

/// True when the decoded instruction before `target` ends a function and only
/// padding separates them. `nop` padding is also accepted when `nops` is set:
/// compilers align loop heads inside a function with `nop`, but only
/// functions with `int3`.
fn ends_function_before(
    analysis: &Analysis,
    direct_flow: &DirectFlowGraph,
    target: u64,
    nops: bool,
) -> bool {
    let Some((_, previous)) = analysis.instructions.range(..target).next_back() else {
        return false;
    };
    let ends_function = match previous.flow {
        Flow::Return | Flow::UnconditionalBranch | Flow::IndirectBranch | Flow::Terminal => true,
        Flow::Call => previous
            .direct_target
            .is_some_and(|callee| direct_flow.known_noreturn.contains(&callee)),
        Flow::IndirectCall => previous
            .memory_target
            .is_some_and(|slot| direct_flow.known_noreturn.contains(&slot)),
        Flow::Next | Flow::ConditionalBranch => false,
    };
    if !ends_function {
        return false;
    }
    let mut address = previous.next_address;
    while address < target {
        match analysis.image.decode_at(address) {
            Ok(padding)
                if padding.x86_instruction().mnemonic() == Mnemonic::Int3
                    || (nops && padding.x86_instruction().mnemonic() == Mnemonic::Nop) =>
            {
                address = padding.next_address;
            }
            _ => return false,
        }
    }
    address == target
}

/// Vivisect's `i386.importcalls` pass: flow through every `call [<import>]`
/// encoding left in undefined space, and promote the direct call targets found
/// along the way to function seeds.
///
/// The fragment start itself never becomes a function -- upstream calls
/// `vw.makeCode`, not `vw.makeFunction`, so the recovered run stays loose code
/// exactly as it does in the reference workspace.
fn run_import_call_wave(
    analysis: &mut Analysis,
    direct_flow: &mut DirectFlowGraph,
    pending: &mut VecDeque<u64>,
    pointers: &mut super::pointers::Discovery,
    function_starts: Option<&BTreeSet<u64>>,
) -> Result<(), RecoveryError> {
    let mut known_functions = function_starts.cloned();
    let starts = {
        let instructions = &analysis.instructions;
        importcalls::fragment_starts(&analysis.image, &|address| {
            instructions
                .range(..=address)
                .next_back()
                .map(|(start, insn)| (*start, insn.next_address))
                .filter(|(_, end)| address < *end)
                .map(|(_, end)| end)
                .or_else(|| {
                    function_starts?;
                    // `generic.relocations.analyze` makes pointer locations
                    // at undefined PE relocation slots before importcalls.
                    // findPointers skips these locations even when the slot
                    // happens to encode the operand of an undiscovered call.
                    let slots = &analysis.image.relocation_locations;
                    let index = slots.partition_point(|source| *source <= address);
                    let source = slots.get(index.checked_sub(1)?)?;
                    let end =
                        source.checked_add(analysis.image.architecture.pointer_width() as u64)?;
                    (address < end).then_some(end)
                })
        })
    };

    for start in starts {
        // Already-walked bytes are not undiscovered space.
        if direct_flow.successors.contains_key(&start) || !is_executable(&analysis.image, start) {
            continue;
        }
        let calls = discover_flow(
            analysis,
            direct_flow,
            start,
            pointers,
            known_functions.as_mut(),
        )?;
        for target in calls.into_iter().rev() {
            if !is_executable(&analysis.image, target) {
                continue;
            }
            let is_new = !analysis.seeds.contains_key(&target);
            analysis
                .seeds
                .entry(target)
                .or_default()
                .insert(SeedKind::CallTarget);
            if is_new || direct_flow.completed_functions.contains_key(&target) {
                pending.push_front(target);
            }
        }
    }
    Ok(())
}

/// AArch64 ELF/PE PLT stubs are `adrp Xn, page; ldr Xn, [Xn, #off]; ...; br
/// Xn` -- four instructions, unlike x86's single `jmp [rip+X]`, because
/// AArch64 has no instruction whose own operand computes an absolute
/// address. `discover_direct_flow`'s generic `Flow::IndirectBranch` handling
/// already recognizes a resolved thunk by checking `memory_target` against
/// `external_bindings`, but AArch64's `br` never has a memory operand (see
/// `decoder.rs`), so it can never match that check on its own.
///
/// This wave closes the gap the other way: once ordinary recovery has
/// decoded a stub's `adrp`+`ldr` pair (reached because something called the
/// stub directly, `bl <stub>`, which is an ordinary direct call and thus an
/// ordinary function candidate), resolve the pair's GOT-slot target and, if
/// it is a known import, register the **stub's own start address** --
/// exactly what a caller's `bl` targets -- as an alias for that same import.
/// The AArch64 API-feature extraction is the intended
/// downstream reader: it can look up a call's direct target in
/// `import_locations` directly, the same way x86 feature extraction does,
/// without redoing this pattern match itself. (`noreturn.rs`'s own
/// thunk/no-return check does not depend on this wave -- it needs the GOT
/// slot address, not the stub's, and resolves the pattern independently so
/// it isn't sensitive to wave ordering across recovery passes.)
fn run_aarch64_plt_wave(analysis: &mut Analysis) {
    if analysis.image.architecture != Architecture::AArch64 {
        return;
    }
    let mut resolved: Vec<(u64, Vec<String>)> = Vec::new();
    for (&address, first) in &analysis.instructions {
        let Some(second) = analysis.instructions.get(&first.next_address) else {
            continue;
        };
        let Some(target) = decoder::aarch64_plt_got_target(first, second) else {
            continue;
        };
        let Some(names) = analysis.image.external_bindings.get(&target) else {
            continue;
        };
        resolved.push((address, names.clone()));
    }
    for (address, names) in resolved {
        analysis.image.add_external_binding(address, names.clone());
        // `*.{name}`, matching `from_elf`'s own `"*"`-library convention for
        // every ELF relocation import (`image.rs`) -- `noreturn.rs`'s
        // `matches_noreturn_api` and the AArch64 API-feature extraction
        // both key off that exact prefix, and the GOT-slot entry this is an
        // alias of already carries it. A stub resolving to more than one
        // name only happens if upstream's own symbol versioning does, so
        // this takes the first the same way `import_locations` (a single
        // `String`, not a `Vec`) already forces on that GOT-slot entry.
        if let Some(name) = names.into_iter().next() {
            analysis
                .image
                .import_locations
                .entry(address)
                .or_insert_with(|| format!("*.{name}"));
        }
    }
}

fn seed_priority(kinds: &BTreeSet<SeedKind>, evaluate_candidates: bool) -> usize {
    // The prologue scan is the weakest, most false-positive-prone seed: a
    // `push ebp; mov ebp, esp` byte pattern often falls *inside* a real
    // function (a shared tail, a loop head). Processing it last -- after all
    // authoritative and call/relocation-driven flow has claimed its
    // instructions -- lets [`analyze_image`]'s heuristic-seed guard skip such
    // spurious starts, mirroring vivisect's flow-first discovery.
    if kinds.iter().any(|kind| is_authoritative_seed(*kind)) {
        0
    } else if kinds.contains(&SeedKind::CallTarget) {
        1
    } else if kinds.contains(&SeedKind::SweepCallTarget) {
        // Preserve native recovery's existing recall without letting the raw
        // byte heuristic invent reference operands for the emucode pass.
        if evaluate_candidates {
            4
        } else {
            1
        }
    } else if !kinds.contains(&SeedKind::Prologue) && !kinds.contains(&SeedKind::FunctionSignature)
    {
        2
    } else {
        3
    }
}

fn should_isolate_overlapping_candidate(
    fallback: &SeedMap,
    seeds: &SeedMap,
    start: u64,
    already_discovered: bool,
) -> bool {
    already_discovered
        && !fallback.contains_key(&start)
        && seeds.get(&start).is_some_and(|kinds| {
            kinds.contains(&SeedKind::Relocation)
                && !kinds.contains(&SeedKind::CallTarget)
                && !kinds.contains(&SeedKind::SweepCallTarget)
                && !kinds.iter().any(|kind| is_authoritative_seed(*kind))
        })
}

/// Printable text ending in a terminator: six ASCII or four UTF-16LE characters. Shorter
/// ASCII runs are left alone, since `push esi; push edi; push ebx; push 0` reads `VWSj\0`.
/// Strings placed in code sections (`"http://"` decodes as `push 3a707474h; das; das`) are
/// not entries, however plausible their first instructions.
fn terminated_text(bytes: &[u8]) -> bool {
    let printable = |b: u8| (0x20..0x7f).contains(&b) || matches!(b, b'\t' | b'\n' | b'\r');
    let narrow = bytes.iter().take_while(|&&b| printable(b)).count();
    if narrow >= 6 && bytes.get(narrow) == Some(&0) {
        return true;
    }
    let wide = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .take_while(|pair| pair[1] == 0 && printable(pair[0]))
        .count();
    wide >= 4 && bytes.get(2 * wide..2 * wide + 2) == Some(&[0, 0][..])
}

/// Whether a recovered jump or conditional branch reaches `address`.
fn branched_to(analysis: &Analysis, address: u64) -> bool {
    analysis.code_xrefs.get(&address).is_some_and(|sources| {
        sources.iter().any(|source| {
            analysis
                .instructions
                .get(source)
                .is_none_or(|insn| insn.flow != Flow::Call)
        })
    })
}

/// Number of whole x64 `RUNTIME_FUNCTION` rows of the PE exception directory that the file
/// actually holds. A truncated file can declare a directory far larger than what is present,
/// and the loader zero-fills the rest of the section, so `bytes_at` would count phantom rows.
fn exception_directory_entries(image: &LoadedImage) -> usize {
    let Some((address, size)) = image.pe_exception_directory else {
        return 0;
    };
    let declared = usize::try_from(size).unwrap_or(usize::MAX);
    image
        .file_backed_at(address, declared)
        .map_or(0, |bytes| bytes.len() / 12)
}

/// Last-resort entry sweep. Existing instructions and unwind extents always win.
fn unclaimed_entries(analysis: &Analysis, function_starts: &BTreeSet<u64>) -> Vec<u64> {
    let image = &analysis.image;
    if image.architecture == Architecture::AArch64 {
        return unclaimed_aarch64_entries(analysis, function_starts);
    }
    if !matches!(image.architecture, Architecture::X86 | Architecture::X64)
        || crate::golang::parse(image).is_some()
    {
        return Vec::new();
    }
    let unwound = unwind_extents(image);
    if leaves::sweeps_x64_leaves(image) {
        return leaves::unclaimed_x64_leaf_entries(analysis, function_starts, &unwound);
    }
    let mut found = Vec::new();
    for section in image
        .sections
        .iter()
        .filter(|s| s.permissions.execute && image.is_primary_code_address(s.address))
    {
        let relocatable = image.format == ImageFormat::Elf && !section.name.starts_with("PT_LOAD");
        // x64 PE functions normally come from `.pdata`; images without an exception directory
        // (UEFI drivers, some MinGW and hand-built code) have only call and pointer flow.
        let unwindless_x64 = image.architecture == Architecture::X64
            && unwound.is_empty()
            && image
                .pe_exception_directory
                .is_none_or(|(_, size)| size == 0);
        // A truncated file can declare `.pdata` yet hold none of it. Its unwind data existed and
        // was lost, so it gets the padding-only sweep of x86 rather than the relaxed one above.
        let truncated_x64 = image.architecture == Architecture::X64
            && unwound.is_empty()
            && !unwindless_x64
            && exception_directory_entries(image) == 0;
        if !(relocatable
            || image.format == ImageFormat::Pe
                && (image.architecture == Architecture::X86 || unwindless_x64 || truncated_x64))
        {
            continue;
        }
        let Some(bytes) = image.bytes_at(section.address, MAX_PROLOGUE_SCAN_BYTES) else {
            continue;
        };
        // Without unwind data there are no extents to keep the sweep honest, and such compilers
        // align functions to 4 bytes rather than 16; boundaries are then required instead.
        let step = if unwindless_x64 { 4 } else { 16 };
        for offset in (0..bytes.len()).step_by(step) {
            let address = section.address + offset as u64;
            let swept_function = function_starts.contains(&address)
                && analysis
                    .seeds
                    .get(&address)
                    .is_some_and(|kinds| kinds.contains(&SeedKind::SweepCallTarget));
            // Flow that was explored and then discarded (a rejected pointer candidate) leaves its
            // instructions behind. Without unwind data such a start, which only calls reach, is
            // still unclaimed; a branch target is part of the function that branches to it.
            let orphan_entry = unwindless_x64
                && analysis
                    .instructions
                    .get(&address)
                    .is_some_and(|_| !branched_to(analysis, address));
            if (instruction_location(analysis, address).is_some()
                && !swept_function
                && !orphan_entry)
                || image.is_code_excluded(address)
                || inside_unwind_extent(&unwound, address)
            {
                continue;
            }
            let padding = offset == 0
                || bytes[..offset].ends_with(&[0xcc, 0xcc])
                || bytes[..offset].ends_with(&[0x90, 0x90]);
            let previous_end = analysis
                .instructions
                .range(..address)
                .next_back()
                .is_some_and(|(_, i)| {
                    i.next_address == address
                        && matches!(i.flow, Flow::Return | Flow::UnconditionalBranch)
                });
            if (padding
                || ((relocatable || unwindless_x64)
                    && (previous_end || super::prologues::boundary(&bytes[..offset]))))
                && !terminated_text(&bytes[offset..])
                // The x64 convention has the caller clean the stack, so a `ret imm16` is
                // a table value, not code; only a truncated image has nothing to rule it out.
                && !(truncated_x64 && bytes[offset] == 0xc2)
                && super::prologues::raw_entry(image, address)
                && super::prologues::valid_code(image, address, 1)
            {
                found.push(address);
                if found.len() >= MAX_PROLOGUE_SEEDS_PER_SECTION {
                    return found;
                }
            }
        }
    }
    found
}

/// Leaf assembly routines and large frames can have no ordinary prologue.
/// Accept only code following a terminal instruction, outside all unwind extents.
fn unclaimed_aarch64_entries(analysis: &Analysis, starts: &BTreeSet<u64>) -> Vec<u64> {
    let image = &analysis.image;
    if image.format != ImageFormat::Elf || crate::golang::parse(image).is_some() {
        return Vec::new();
    }
    let mut found = Vec::new();
    for (start, length) in primary_code_spans(image) {
        for offset in (4..length).step_by(4) {
            let address = start + offset as u64;
            if starts.contains(&address)
                || image.is_code_excluded(address)
                || inside_unwind_extent(&image.function_ranges, address)
            {
                continue;
            }
            if image.bytes_at(address, 4) == Some(&0xd503201fu32.to_le_bytes()) {
                continue;
            }
            let mut before = address - 4;
            for _ in 0..16 {
                if before <= start
                    || image.bytes_at(before, 4) != Some(&0xd503201fu32.to_le_bytes())
                {
                    break;
                }
                before -= 4;
            }
            let Ok(previous) = image.decode_at(before) else {
                continue;
            };
            let folded_prologue = analysis
                .seeds
                .get(&address)
                .is_some_and(|k| k.contains(&SeedKind::Prologue));
            // BR and B often precede inline switch arms. A direct jump is a
            // boundary only with an independent frame-opening signature.
            if !(matches!(previous.flow, Flow::Return | Flow::Terminal)
                || folded_prologue && previous.flow == Flow::UnconditionalBranch)
            {
                continue;
            }
            if analysis.code_xrefs.get(&address).is_some_and(|sites| {
                sites.iter().any(|site| {
                    analysis
                        .instructions
                        .get(site)
                        .is_some_and(|i| i.flow == Flow::ConditionalBranch)
                })
            }) {
                continue;
            }
            if image
                .decode_at(address)
                .is_ok_and(|i| i.flow == Flow::UnconditionalBranch)
            {
                continue;
            }
            if analysis.instructions.contains_key(&address) && !folded_prologue {
                continue;
            }
            if plausible_aarch64_pointer(image, address) {
                found.push(address);
                if found.len() >= MAX_PROLOGUE_SEEDS_PER_SECTION {
                    return found;
                }
            }
        }
    }
    found
}

/// The primary code of each executable section, as (start, length to scan). A Mach-O section
/// here is a whole segment, and `__TEXT` starts with the header, not with `__text`: its code
/// sections are the primary ranges inside it.
fn primary_code_spans(image: &LoadedImage) -> Vec<(u64, usize)> {
    let mut spans = Vec::new();
    for section in image.sections.iter().filter(|s| s.permissions.execute) {
        let file_len = usize::try_from(section.file_size).unwrap_or(usize::MAX);
        if image.is_primary_code_address(section.address) {
            spans.push((section.address, file_len.min(MAX_PROLOGUE_SCAN_BYTES)));
        } else if image.format == ImageFormat::Macho {
            let end = section.address.saturating_add(file_len as u64);
            for (start, stop) in image.primary_code_ranges() {
                let (start, stop) = ((*start).max(section.address), (*stop).min(end));
                if start < stop {
                    let len = usize::try_from(stop - start).unwrap_or(usize::MAX);
                    spans.push((start, len.min(MAX_PROLOGUE_SCAN_BYTES)));
                }
            }
        }
    }
    spans
}

fn add_prologue_seeds(image: &LoadedImage, seeds: &mut BTreeMap<u64, BTreeSet<SeedKind>>) {
    if image.architecture.is_risc32() {
        super::super::risc::add_prologue_seeds(image, seeds);
        return;
    }
    if image.architecture == Architecture::AArch64 {
        add_aarch64_prologue_seeds(image, seeds);
        return;
    }
    for (start, scan_len) in primary_code_spans(image) {
        let Some(bytes) = image.bytes_at(start, scan_len) else {
            continue;
        };
        let mut found = 0usize;
        let mut covered_until = 0usize;
        for offset in 0..bytes.len() {
            if offset < covered_until {
                continue;
            }
            if let Some(pattern_len) = super::prologues::match_len(image, bytes, offset) {
                if let Some(address) = start.checked_add(offset as u64) {
                    if super::prologues::valid_code(image, address, pattern_len) {
                        seeds.entry(address).or_default().insert(SeedKind::Prologue);
                        found += 1;
                        covered_until = offset.saturating_add(pattern_len);
                    }
                }
                if found >= MAX_PROLOGUE_SEEDS_PER_SECTION {
                    break;
                }
            }
        }
    }
}

/// Not a Vivisect port (Vivisect never analysed AArch64): task 4 added this
/// once feature extraction's own fixture table showed several pinned-corpus
/// functions are reachable by no seed this loader already collects (no
/// symbol, no relocation, never a `bl` target -- apparently only found by
/// Ghidra's own function-start heuristics).
///
/// Unlike x86, there is no single dominant byte signature: the AAPCS64
/// callee-saved-register save sequence a compiler emits varies both in which
/// register pair starts it (`x29`/`x30`, the frame-pointer pair, is
/// frequently saved several stores *into* the sequence rather than first --
/// an earlier, narrower version of this heuristic that only matched
/// `stp x29, x30, [sp, #-N]!` missed every function whose save order starts
/// with a different pair) and in whether the frame is carved out by the
/// first store's own pre-indexed writeback or by a preceding
/// `sub sp, sp, #N`. So this is a decode-based structural scan instead of a
/// pattern list, reusing the same decoder and `is_formattable`-gated
/// formatter this file's feature extraction already trusts
/// (`aarch64_features::is_prologue_candidate`) rather than hand-deriving a
/// second, parallel set of bitfield offsets here.
fn add_aarch64_prologue_seeds(image: &LoadedImage, seeds: &mut BTreeMap<u64, BTreeSet<SeedKind>>) {
    // Go's stack check, `ldr x16,[x28,#16]` (or `#24`, stackguard1), opens every function that can
    // grow its stack; its frame store then follows the check and is not an entry.
    const GO_STACK_CHECK: [u32; 2] = [0xf940_0b90, 0xf940_0f90];
    let word = |bytes: &[u8], offset: usize| {
        bytes
            .get(offset..offset + 4)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(u32::from_le_bytes)
    };
    for (start, scan_len) in primary_code_spans(image) {
        let Some(bytes) = image.bytes_at(start, scan_len) else {
            continue;
        };
        let mut found = 0usize;
        // Every AArch64 instruction is exactly 4 bytes, unlike x86's
        // variable length -- a genuine prologue can only start on a 4-byte
        // boundary, so this steps by word rather than by byte.
        for offset in (0..bytes.len().saturating_sub(4)).step_by(4) {
            let Some(address) = start.checked_add(offset as u64) else {
                break;
            };
            let go_entry = word(bytes, offset).is_some_and(|w| GO_STACK_CHECK.contains(&w));
            let after_go_check = offset >= 12
                && word(bytes, offset - 12).is_some_and(|w| GO_STACK_CHECK.contains(&w));
            if go_entry
                || (!after_go_check
                    && super::aarch64_features::is_prologue_candidate(image, address))
            {
                seeds.entry(address).or_default().insert(SeedKind::Prologue);
                found += 1;
                if found >= MAX_PROLOGUE_SEEDS_PER_SECTION {
                    break;
                }
            }
        }
    }
}

fn add_backend_fallback_seeds(image: &LoadedImage, backend: RecoveryBackend, seeds: &mut SeedMap) {
    // Native formats and AArch64 retain their recovery heuristics. Vivisect
    // has no AArch64 backend. Its x86 compatibility path uses registered
    // entry signatures after candidate discovery.
    if backend == RecoveryBackend::Native || !image.architecture.is_x86() {
        add_prologue_seeds(image, seeds);
        add_swept_call_seeds(image, seeds);
    }
    // Vivisect runs generic function-entry signatures after other analyses.
    add_vivisect_function_signature_seeds(image, seeds);
}

fn add_vivisect_function_signature_seeds(image: &LoadedImage, seeds: &mut SeedMap) {
    if image.architecture != Architecture::X86 {
        return;
    }
    // Exact port of pinned Vivisect 1.3.2
    // `vivisect/analysis/i386/__init__.py:addEntrySigs`. Unlike the native
    // prologue fallback, these are the complete masked signatures used by the
    // compatibility backend's late `generic.funcentries` pass.
    const SIGNATURES: &[(&[u8], &[u8])] = &[
        (b"\x55\x8b\xec", b"\xff\xff\xff"),
        (b"\x56\x8b\xf1", b"\xff\xff\xff"),
        (b"\x55\x89\xe5", b"\xff\xff\xff"),
        (b"\x8b\xff\x55\x8b\xec", b"\xff\xff\xff\xff\xff"),
        (
            b"\x6a\x00\x68\x00\x00\x00\x00\xe8",
            b"\xff\x00\xff\x00\x00\x00\x00\xff",
        ),
    ];
    for section in image.sections.iter().filter(|section| {
        section.permissions.execute && image.is_primary_code_address(section.address)
    }) {
        if image.is_uninitialized(section.address) {
            continue;
        }
        let scan_len = usize::try_from(section.virtual_size)
            .unwrap_or(usize::MAX)
            .min(MAX_PROLOGUE_SCAN_BYTES);
        let Some(bytes) = image.bytes_at(section.address, scan_len) else {
            continue;
        };
        for offset in 0..bytes.len() {
            let Some(rest) = bytes.get(offset..) else {
                continue;
            };
            let matched = SIGNATURES.iter().any(|(signature, mask)| {
                rest.get(..signature.len()).is_some_and(|candidate| {
                    candidate
                        .iter()
                        .zip(signature.iter())
                        .zip(mask.iter())
                        .all(|((&actual, &expected), &mask)| actual & mask == expected & mask)
                })
            });
            if matched {
                if let Some(address) = section.address.checked_add(offset as u64) {
                    seeds
                        .entry(address)
                        .or_default()
                        .insert(SeedKind::FunctionSignature);
                }
            }
        }
    }
}

fn matches_x86_seh_entry_signature(bytes: &[u8]) -> bool {
    bytes.first() == Some(&0x6a) && bytes.get(2) == Some(&0x68) && bytes.get(7) == Some(&0xe8)
}

/// Recover callees from otherwise unreachable code islands. This is limited
/// to images with sparse deterministic recovery and requires the target to be
/// an executable, plausibly decoded entry.
fn add_swept_call_seeds(image: &LoadedImage, seeds: &mut BTreeMap<u64, BTreeSet<SeedKind>>) {
    // Dense seed maps already cover ordinary compiler output and make raw
    // byte sweeps counterproductive. Reserve this fallback for sparse images
    // where recursive descent otherwise has almost no foothold.
    if image.format != ImageFormat::Pe
        || !matches!(image.architecture, Architecture::X86 | Architecture::X64)
        || seeds.len() > 128
    {
        return;
    }
    // A Go binary reaches its application code through `runtime_main`, which
    // `golang::runtime_main` seeds directly. Sweeping its dense `.text` for
    // `e8` bytes on top of that is pure guesswork: measured on
    // `49a34cfbeed733c24392c9217ef46bb6.exe_`, the sweep produced 3124
    // functions against the reference's 1709, and all 11 of that sample's
    // rule diffs were *extra* matches inside the 1553 invented ones.
    if golang::is_go_image(image) {
        return;
    }
    let mut references = BTreeMap::<u64, usize>::new();
    for section in image.sections.iter().filter(|section| {
        section.permissions.execute && image.is_primary_code_address(section.address)
    }) {
        let scan_len = usize::try_from(section.file_size)
            .unwrap_or(usize::MAX)
            .min(MAX_PROLOGUE_SCAN_BYTES);
        let Some(bytes) = image.bytes_at(section.address, scan_len) else {
            continue;
        };
        for (offset, window) in bytes.windows(5).enumerate() {
            if window.first() != Some(&0xe8) {
                continue;
            }
            let Some(raw) = window.get(1..5).and_then(|value| value.try_into().ok()) else {
                continue;
            };
            let call_address = section.address + offset as u64;
            if image.is_code_excluded(call_address) || image.is_code_excluded(call_address + 4) {
                continue;
            }
            let displacement = i64::from(i32::from_le_bytes(raw));
            let Some(next) = section
                .address
                .checked_add(offset as u64)
                .and_then(|address| address.checked_add(5))
            else {
                continue;
            };
            let target = if displacement >= 0 {
                next.checked_add(displacement as u64)
            } else {
                next.checked_sub(displacement.unsigned_abs())
            };
            let Some(target) = target else {
                continue;
            };
            if is_executable(image, target) && plausible_sweep_function(image, target) {
                let count = references.entry(target).or_default();
                *count = count.saturating_add(1);
            }
        }
    }
    let mut added = 0usize;
    for (address, _count) in references {
        if added >= MAX_SWEEP_CALL_SEEDS {
            continue;
        }
        seeds
            .entry(address)
            .or_default()
            .insert(SeedKind::SweepCallTarget);
        added += 1;
    }
}

fn is_authoritative_seed(kind: SeedKind) -> bool {
    matches!(
        kind,
        SeedKind::EntryPoint
            | SeedKind::Export
            | SeedKind::TlsCallback
            | SeedKind::SafeSeh
            | SeedKind::GuardCf
            | SeedKind::Unwind
            | SeedKind::EhFrame
            | SeedKind::ArmExidx
            | SeedKind::Symbol
            | SeedKind::Init
            | SeedKind::Fini
            | SeedKind::InitArray
            | SeedKind::FiniArray
            | SeedKind::LibcMain
            | SeedKind::GoRuntimeMain
            | SeedKind::MsvcCookieBlock
            | SeedKind::MsvcException
            | SeedKind::MachoFunctionStarts
            | SeedKind::GoFunctionTable
            | SeedKind::DelphiMethod
            | SeedKind::IncrementalThunk
            | SeedKind::IncrementalTarget
            | SeedKind::DelayLoadThunk
            | SeedKind::MsvcThrowMetadata
    )
}

/// Thin accessor over the pre-computed [`DecodedInstruction::direct_target`],
/// kept as a free function so callers outside this module (e.g.
/// `basicblock_features.rs`, `libc_start_main.rs`) read unchanged.
pub(crate) fn direct_target(insn: &DecodedInstruction) -> Option<u64> {
    insn.direct_target
}

/// Thin accessor over the pre-computed [`DecodedInstruction::memory_target`],
/// kept as a free function so callers outside this module (e.g.
/// `noreturn.rs`, `libc_start_main.rs`) read unchanged.
pub(crate) fn memory_target(insn: &DecodedInstruction) -> Option<u64> {
    insn.memory_target
}

pub(crate) fn jump_table_targets(image: &LoadedImage, insn: &DecodedInstruction) -> Vec<u64> {
    let mut targets = scan_jump_table(image, insn, |_, _| true);
    targets.sort_unstable();
    targets.dedup();
    targets
}

fn jump_table_targets_compat(
    analysis: &mut Analysis,
    insn: &DecodedInstruction,
    noreturn: &BTreeSet<u64>,
) -> Vec<u64> {
    if is_pointer_jump(&analysis.image, insn) {
        return jump_table_targets(&analysis.image, insn);
    }
    let Some(base) = insn.memory_target else {
        return Vec::new();
    };
    let width = analysis.image.architecture.pointer_width() as u64;
    let candidates = scan_jump_table(&analysis.image, insn, |_, _| true);
    let mut targets = Vec::new();
    for (index, target) in candidates.into_iter().enumerate() {
        let Some(slot) = base.checked_add((index as u64).saturating_mul(width)) else {
            break;
        };
        if Some(slot) != insn.memory_target
            && (analysis.code_xrefs.contains_key(&slot) || analysis.data_xrefs.contains_key(&slot))
        {
            break;
        }
        let signature = analysis
            .seeds
            .get(&target)
            .is_some_and(|kinds| kinds.contains(&SeedKind::FunctionSignature));
        if !signature && !targets.contains(&target) {
            match super::emucode::evaluate_candidate(analysis, target, noreturn, &[]) {
                super::emucode::Verdict::NotCode => break,
                super::emucode::Verdict::Inconclusive { address, reason } => {
                    analysis.diagnostics.push(RecoveryDiagnostic {
                        address,
                        message: format!(
                            "switch {:#x} arm {target:#x} candidate evaluation inconclusive: {reason}",
                            insn.address
                        ),
                    });
                    break;
                }
                super::emucode::Verdict::Code => {}
            }
        }
        // _cb_branchtable records each reference before evaluating the
        // next entry. Subsequent candidate traces see that partial table.
        push_xref(&mut analysis.code_xrefs, target, insn.address);
        targets.push(target);
    }
    let mut seen = BTreeSet::new();
    targets.retain(|target| seen.insert(*target));
    targets
}

fn scan_jump_table(
    image: &LoadedImage,
    insn: &DecodedInstruction,
    mut accept: impl FnMut(u64, u64) -> bool,
) -> Vec<u64> {
    let Some(base) = insn.memory_target else {
        return Vec::new();
    };
    // `i386Opcode.getBranches` only labels scale-four SIB operands as
    // BR_TABLE. Other indexed operands have no static address without an
    // emulator. In particular, scanning an unbounded x64 scale-eight table
    // absorbs adjacent tables and prevents later pointer discovery.
    if image.architecture.is_x86()
        && insn.x86_instruction().memory_index() != iced_x86::Register::None
        && insn.x86_instruction().memory_index_scale() != 4
    {
        return Vec::new();
    }
    let width = image.architecture.pointer_width();
    // envi/archs/i386/__init__.py distinguishes BR_DEREF from BR_TABLE:
    // a plain memory jump dereferences one pointer, while an indexed jump
    // selects among table entries. Adjacent pointers are not its successors.
    let entries = if is_pointer_jump(image, insn) {
        1
    } else {
        // VivWorkspace.iterJumpTable scans until a table boundary, including
        // switches with more than 256 cases. Mapped bytes bound the scan.
        image
            .bytes_at(base, usize::MAX)
            .map_or(0, |bytes| bytes.len() / width)
    };
    let mut targets = Vec::new();
    for index in 0..entries {
        let Some(slot) = base.checked_add((index.saturating_mul(width)) as u64) else {
            break;
        };
        let Some(raw) = image.bytes_at(slot, width) else {
            break;
        };
        let target = if width == 8 {
            let Some(value) = raw.get(..8).and_then(|value| value.try_into().ok()) else {
                break;
            };
            u64::from_le_bytes(value)
        } else {
            let Some(value) = raw.get(..4).and_then(|value| value.try_into().ok()) else {
                break;
            };
            u64::from(u32::from_le_bytes(value))
        };
        if !is_executable(image, target) || !accept(slot, target) {
            break;
        }
        targets.push(target);
    }
    targets
}

fn is_pointer_jump(image: &LoadedImage, insn: &DecodedInstruction) -> bool {
    image.architecture.is_x86()
        && insn.memory_target.is_some()
        && insn.x86_instruction().memory_index() == iced_x86::Register::None
}

pub(crate) fn is_executable(image: &LoadedImage, address: u64) -> bool {
    image.is_executable_address(address)
}

pub(crate) fn read_pointer(image: &LoadedImage, address: u64) -> Option<u64> {
    image.read_pointer(address)
}

fn remove_code_reference(analysis: &mut Analysis, source: u64, target: u64) {
    if let Some(sources) = analysis.code_xrefs.get_mut(&target) {
        sources.retain(|address| *address != source);
        if sources.is_empty() {
            analysis.code_xrefs.remove(&target);
        }
    }
}

fn push_xref(index: &mut BTreeMap<u64, Vec<u64>>, target: u64, source: u64) {
    let sources = index.entry(target).or_default();
    if !sources.contains(&source) {
        sources.push(source);
    }
}
