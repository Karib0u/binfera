//! Optional, serial, in-process PE, ELF, Mach-O and explicit raw-code decompilation.
//!
//! A session owns one image and its native SLEIGH translator. Reuse it for
//! explicit function requests. Native failures poison the session; construct
//! a new session after such an error. Invalid Rust requests do not poison it.
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use iced_x86::{
    FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register,
};
use serde::Serialize;

/// Scalar and pointer types accepted by explicit function signatures.
pub use binfera_ghidra::ValueType;

use crate::bundled::bundled;
use crate::demangle;
use crate::extract::decoder::{DecodedInstruction, Flow};
use crate::extract::image::{Architecture, ImageFormat, LoadedImage};
use crate::extract::recovery::flirt::{self, Signatures};
use crate::extract::recovery::{self, Analysis};
use crate::fid;
use crate::golang::{self, GoBinary};
use crate::parallel::{AnalysisOptions, Jobs};
use crate::rtti;
use crate::target::{Abi, Compiler, TargetProfile};

mod batch;
pub use batch::{
    decompile_all, decompile_all_cached, decompile_all_with_signature_jobs, prepare_decompile_all,
    prepare_decompile_all_with_signature_jobs, BatchEvent, BatchFunction, BatchOptions,
    FunctionGraph, GraphBlock, GraphEdge, GraphEdgeKind, InstructionRow, Reference, RetryPolicy,
};

mod candidates;
mod conventions;
pub(crate) mod ctypes;
mod effects;
mod go_stack;
mod go_strings;
mod golang_flow;
mod golang_names;
mod leaf_effects;
mod macho;
mod memset_loops;
mod rust;
mod stack_protector;
mod stack_purge;
mod stack_strings;
mod strlen_loops;
mod unit;
mod win64_args;

pub use candidates::rejected_compatibility_entries;
pub use unit::{Guess, Unit, UnitFunction};

/// Ghidra 12.1.4 Function ID data for x64 and x86 Visual Studio runtimes; see `sigs/FID.md`.

#[derive(Debug, thiserror::Error)]
pub enum DecompileError {
    #[error("writing decompilation output: {0}")]
    Output(String),
    #[error(
        "decompilation supports native x86/x64/AArch64 PE and ELF, ARM32/Thumb PE and ELF, MIPS32 o32 ELF, x64/AArch64 Mach-O, and x86 raw code: {0}"
    )]
    Unsupported(String),
    #[error("preparing decompiler image: {0}")]
    Input(String),
    #[error("invalid decompilation request: {0}")]
    Request(String),
    #[error("initializing native decompiler: {0}")]
    Initialization(String),
    #[error("decompiling function {address:#x}: {message}")]
    Native { address: u64, message: String },
    /// Recovery refused the image ([`recovery::RecoveryError::TooLarge`]).
    #[error("{0}")]
    TooLarge(String),
}

impl DecompileError {
    fn recovery(error: recovery::RecoveryError) -> DecompileError {
        match error {
            recovery::RecoveryError::TooLarge { .. } => DecompileError::TooLarge(error.to_string()),
            _ => DecompileError::Input(error.to_string()),
        }
    }
}

/// Local safety policy, not constants copied from upstream. Deadlines are
/// cooperative: checked during translation, allocation and action processing.
#[derive(Clone, Copy, Debug)]
pub struct ResourceLimits {
    pub timeout_ms: u32,
    pub max_instructions: u32,
    pub max_work: u32,
}
impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            timeout_ms: 10_000,
            max_instructions: 10_000,
            max_work: 20_000_000,
        }
    }
}

impl ResourceLimits {
    /// Limits used by an explicit or deferred resource retry.
    pub fn retry() -> Self {
        Self {
            timeout_ms: 60_000,
            max_instructions: 100_000,
            max_work: 200_000_000,
        }
    }
}

/// Windows x64 uses Ghidra's x86-64-win.cspec default __fastcall model. Windows x86
/// has several conventions; `x86win.cspec` defaults to __stdcall with the stack
/// purge inferred per function, and the packed archives name each import's own.
/// System V x86-64 uses `x86-64-gcc.cspec` and System V i386 `x86gcc.cspec` (cdecl).
/// Delphi (`x86delphi.cspec`, `__register`: `EAX`, `EDX`, `ECX`) and Borland C++
/// (`x86borland.cspec`, a register `__fastcall`) are x86-32 Windows programs whose own
/// functions use another default; their imports keep the archives' Win32 conventions.
/// Go programs (`x86-64-golang.cspec`, `x86-32-golang.cspec`) use Go's register ABI from Go 1.17 on
/// amd64 and its stack ABI otherwise, on either platform; imports keep the platform's C convention.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallingConvention {
    SystemVArm,
    SystemVArmSoft,
    WindowsArm,
    SystemVMips,
    SystemVMipsBe,
    #[default]
    WindowsX64,
    WindowsX86,
    SystemVX64,
    SystemVX86,
    DelphiX86,
    BorlandX86,
    GoWindowsX64,
    GoWindowsX86,
    GoSystemVX64,
    GoSystemVX86,
    WindowsAArch64,
    SystemVAArch64,
    DarwinX64,
    DarwinAArch64,
    GoDarwinX64,
    GoWindowsAArch64,
    GoSystemVAArch64,
    GoDarwinAArch64,
}
impl CallingConvention {
    fn of(profile: TargetProfile) -> Result<Self, DecompileError> {
        match (profile.abi, profile.architecture, profile.compiler) {
            (Abi::SystemV, Architecture::Arm, Compiler::Platform) => Ok(Self::SystemVArmSoft),
            (Abi::Windows, Architecture::Arm, Compiler::Platform) => Ok(Self::WindowsArm),
            (Abi::SystemV, Architecture::Mips, Compiler::Platform) => Ok(Self::SystemVMips),
            (Abi::SystemV, Architecture::MipsBe, Compiler::Platform) => Ok(Self::SystemVMipsBe),
            (Abi::Darwin, Architecture::AArch64, Compiler::Go) => Ok(Self::GoDarwinAArch64),
            (Abi::Windows, Architecture::AArch64, Compiler::Go) => Ok(Self::GoWindowsAArch64),
            (Abi::SystemV, Architecture::AArch64, Compiler::Go) => Ok(Self::GoSystemVAArch64),
            (Abi::Darwin, Architecture::X64, Compiler::Go) => Ok(Self::GoDarwinX64),
            (Abi::Darwin, Architecture::X64, Compiler::Platform) => Ok(Self::DarwinX64),
            (Abi::Darwin, Architecture::AArch64, Compiler::Platform) => Ok(Self::DarwinAArch64),
            (Abi::Windows, Architecture::AArch64, Compiler::Platform) => Ok(Self::WindowsAArch64),
            (Abi::SystemV, Architecture::AArch64, Compiler::Platform) => Ok(Self::SystemVAArch64),
            (Abi::Windows, Architecture::X64, Compiler::Go) => Ok(Self::GoWindowsX64),
            (Abi::Windows, Architecture::X86, Compiler::Go) => Ok(Self::GoWindowsX86),
            (Abi::SystemV, Architecture::X64, Compiler::Go) => Ok(Self::GoSystemVX64),
            (Abi::SystemV, Architecture::X86, Compiler::Go) => Ok(Self::GoSystemVX86),
            (Abi::Windows, Architecture::X64, _) => Ok(Self::WindowsX64),
            (Abi::Windows, Architecture::X86, Compiler::Platform) => Ok(Self::WindowsX86),
            (Abi::Windows, Architecture::X86, Compiler::Delphi) => Ok(Self::DelphiX86),
            (Abi::Windows, Architecture::X86, Compiler::BorlandCpp) => Ok(Self::BorlandX86),
            (Abi::SystemV, Architecture::X64, _) => Ok(Self::SystemVX64),
            (Abi::SystemV, Architecture::X86, _) => Ok(Self::SystemVX86),
            (abi, architecture, _) => Err(DecompileError::Unsupported(format!(
                "{abi:?} {architecture:?}"
            ))),
        }
    }
    pub(crate) fn language(self) -> binfera_ghidra::Language {
        match self {
            Self::SystemVArm => binfera_ghidra::Language::ArmLinux,
            Self::SystemVArmSoft => binfera_ghidra::Language::ArmLinuxSoft,
            Self::WindowsArm => binfera_ghidra::Language::ArmWindows,
            Self::SystemVMips => binfera_ghidra::Language::MipsLittle,
            Self::SystemVMipsBe => binfera_ghidra::Language::MipsBig,
            Self::GoDarwinAArch64 => binfera_ghidra::Language::AArch64GoApple,
            Self::GoWindowsAArch64 => binfera_ghidra::Language::AArch64GoWindows,
            Self::GoSystemVAArch64 => binfera_ghidra::Language::AArch64GoLinux,
            Self::DarwinX64 => binfera_ghidra::Language::X86Apple64,
            Self::GoDarwinX64 => binfera_ghidra::Language::X86GoApple64,
            Self::DarwinAArch64 => binfera_ghidra::Language::AArch64Apple,
            Self::WindowsAArch64 => binfera_ghidra::Language::AArch64Windows,
            Self::SystemVAArch64 => binfera_ghidra::Language::AArch64Linux,
            Self::WindowsX64 => binfera_ghidra::Language::X86Windows64,
            Self::WindowsX86 => binfera_ghidra::Language::X86Windows32,
            Self::SystemVX64 => binfera_ghidra::Language::X86Linux64,
            Self::SystemVX86 => binfera_ghidra::Language::X86Linux32,
            Self::DelphiX86 => binfera_ghidra::Language::X86Delphi32,
            Self::BorlandX86 => binfera_ghidra::Language::X86Borland32,
            Self::GoWindowsX64 => binfera_ghidra::Language::X86GoWindows64,
            Self::GoWindowsX86 => binfera_ghidra::Language::X86GoWindows32,
            Self::GoSystemVX64 => binfera_ghidra::Language::X86GoLinux64,
            Self::GoSystemVX86 => binfera_ghidra::Language::X86GoLinux32,
        }
    }
    /// The pointer width is 64 bits.
    fn wide(self) -> bool {
        matches!(
            self,
            Self::WindowsX64
                | Self::SystemVX64
                | Self::GoWindowsX64
                | Self::GoSystemVX64
                | Self::WindowsAArch64
                | Self::SystemVAArch64
                | Self::DarwinX64
                | Self::DarwinAArch64
                | Self::GoDarwinX64
                | Self::GoDarwinAArch64
                | Self::GoSystemVAArch64
                | Self::GoWindowsAArch64
        )
    }
    fn is_windows(self) -> bool {
        !matches!(
            self,
            Self::SystemVArm
                | Self::SystemVArmSoft
                | Self::SystemVMips
                | Self::SystemVMipsBe
                | Self::SystemVX64
                | Self::SystemVX86
                | Self::GoSystemVX64
                | Self::GoSystemVX86
                | Self::SystemVAArch64
                | Self::DarwinX64
                | Self::DarwinAArch64
                | Self::GoDarwinX64
                | Self::GoDarwinAArch64
                | Self::GoSystemVAArch64
        )
    }
    fn is_darwin(self) -> bool {
        matches!(
            self,
            Self::DarwinX64 | Self::DarwinAArch64 | Self::GoDarwinX64 | Self::GoDarwinAArch64
        )
    }
    fn is_go(self) -> bool {
        matches!(
            self,
            Self::GoWindowsX64
                | Self::GoWindowsX86
                | Self::GoSystemVX64
                | Self::GoSystemVX86
                | Self::GoDarwinX64
                | Self::GoDarwinAArch64
                | Self::GoSystemVAArch64
                | Self::GoWindowsAArch64
        )
    }
    /// The image's ABI and architecture: any compiler of the platform is a valid request.
    fn fits(self, profile: TargetProfile) -> bool {
        let architecture = if matches!(
            self,
            Self::SystemVArm | Self::SystemVArmSoft | Self::WindowsArm
        ) {
            Architecture::Arm
        } else if self == Self::SystemVMips {
            Architecture::Mips
        } else if self == Self::SystemVMipsBe {
            Architecture::MipsBe
        } else if matches!(
            self,
            Self::WindowsAArch64
                | Self::SystemVAArch64
                | Self::DarwinAArch64
                | Self::GoWindowsAArch64
                | Self::GoSystemVAArch64
                | Self::GoDarwinAArch64
        ) {
            Architecture::AArch64
        } else if self.wide() {
            Architecture::X64
        } else {
            Architecture::X86
        };
        let abi = if self.is_darwin() {
            Abi::Darwin
        } else if self.is_windows() {
            Abi::Windows
        } else {
            Abi::SystemV
        };
        profile.abi == abi && profile.architecture == architecture
    }
}

#[derive(Debug, Serialize)]
pub struct DecompilationTimings {
    /// Session preparation, recorded once. `from_pe` includes recovery and
    /// library recognition; `from_analysis` includes only native adapter setup.
    pub initialization_ms: f64,
    pub decompilation_ms: f64,
    /// Native phases are disjoint wall times. Inference includes callee analysis
    /// and the selected function's reanalysis with the inferred prototypes.
    pub initial_ms: f64,
    pub data_ms: f64,
    pub returns_ms: f64,
    pub inference_ms: f64,
    pub print_ms: f64,
    pub analysis_passes: u32,
    pub inference_cache_hits: u32,
    pub inference_cache_misses: u32,
    pub inference_cache_invalidations: u32,
    pub inference_cache_evictions: u32,
    pub inference_invalidation_reasons: Vec<String>,
}

/// The class of a data symbol's type, as the decompiler's analysis settled it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    Float,
    Signed,
    Unsigned,
    Bool,
    Pointer,
    Unknown,
}

/// A data symbol the text names (`DAT_`, `PTR_`, `s_`, `u_`), typed by the analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalSymbol {
    pub name: String,
    pub address: u64,
    /// Bytes of the type, or of the symbol when the analysis gave it no type.
    pub size: u32,
    pub kind: ValueKind,
}

/// Separate from capa's capability result document.
#[derive(Debug, Serialize)]
pub struct Decompilation {
    pub address: u64,
    pub name: Option<String>,
    pub calling_convention: CallingConvention,
    pub text: String,
    /// For each line of `text` (split on `\n`), the sorted instruction addresses of the p-code
    /// operations printed on it. Empty when the mapping could not be established. Not serialized:
    /// the CLI's `--decompile-all` is its only consumer.
    #[serde(skip)]
    pub line_addresses: Vec<Vec<u64>>,
    /// Gaps only: each one is a reason for `incomplete`.
    pub warnings: Vec<String>,
    /// Informational: a call replaced by its modeled effect, inferred prototypes and
    /// types. None of these makes the result incomplete, so they stay out of `warnings`.
    pub notes: Vec<String>,
    /// MSVC exception tables related to this function or funclet.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exception_handling: Vec<crate::msvc_eh::FunctionInfo>,
    /// A gap in this function. File-wide diagnostics are available on the session.
    pub incomplete: bool,
    /// At least one callee has no known prototype, so call arguments and return
    /// values may be missing. This is the usual reason for `incomplete`; when it is
    /// the only one, no other gap was detected. This is not a correctness guarantee:
    /// unknown call effects can also affect the caller's data flow.
    pub unknown_callees: bool,
    /// The data symbols the text names, with their analyzed types. Not serialized: the
    /// self-contained unit is its consumer.
    #[serde(skip)]
    pub globals: Vec<GlobalSymbol>,
    /// Stack symbols by offset, then register parameters. Not serialized: the CLI's `--decompile-all` is its only consumer.
    #[serde(skip)]
    pub frame: Vec<StackSlot>,
    pub timings: DecompilationTimings,
}

/// A stack symbol of a decompiled function, with the instructions that use it.
#[derive(Debug, Clone, Serialize)]
pub struct StackSlot {
    pub name: String,
    /// The register holding a parameter passed in one, which has no offset.
    #[serde(rename = "register", skip_serializing_if = "String::is_empty")]
    pub register_name: String,
    /// From the stack pointer at entry.
    pub offset: i64,
    pub size: u32,
    #[serde(rename = "type")]
    pub type_name: String,
    pub parameter: bool,
    pub reads: Vec<u64>,
    pub writes: Vec<u64>,
    pub references: Vec<u64>,
}

pub struct DecompilerSession {
    native: binfera_ghidra::Session,
    executable_ranges: Vec<(u64, u64)>,
    names: BTreeMap<u64, String>,
    caller_return_uses: BTreeMap<u64, u32>,
    recursive_cdecl: BTreeSet<u64>,
    x86_low32_returns: BTreeSet<u64>,
    x86_forwarded_imports: BTreeSet<u64>,
    explicit_signatures: BTreeSet<u64>,
    has_debug_types: bool,
    exceptions: crate::msvc_eh::ExceptionInfo,
    warnings: Vec<String>,
    duff_helpers: BTreeMap<String, golang_flow::Duff>,
    go_strings: Option<go_strings::Strings>,
    /// Constant `CFString` objects by label, printed as `CFSTR("…")`.
    cfstrings: BTreeMap<String, String>,
    import_thunks: BTreeSet<u64>,
    local_labels: BTreeSet<u64>,
    funclet_labels: BTreeMap<u64, (u64, String)>,
    initialization_ms: f64,
    limits: ResourceLimits,
    convention: CallingConvention,
    /// The type archive as C declarations, read on the first unit request.
    unit_pack: std::cell::OnceCell<ctypes::Pack>,
}
impl DecompilerSession {
    pub(crate) fn into_emulation_parts(self) -> (binfera_ghidra::Session, CallingConvention) {
        (self.native, self.convention)
    }

    /// Open PE, ELF or Mach-O by the file's magic.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecompileError> {
        Self::from_bytes_with_analysis(bytes).map(|(session, _)| session)
    }

    /// [`Self::from_bytes`], also returning the recovery the session was built from, so a caller
    /// that lists functions or instructions does not recover the image a second time (on a large
    /// image each recovery holds gigabytes).
    pub fn from_bytes_with_analysis(bytes: &[u8]) -> Result<(Self, Analysis), DecompileError> {
        Self::from_bytes_with_arch_and_analysis(bytes, None)
    }

    /// Select a universal Mach-O slice consistently for recovery, DWARF and decompilation.
    pub fn from_bytes_with_arch_and_analysis(
        bytes: &[u8],
        arch: Option<&str>,
    ) -> Result<(Self, Analysis), DecompileError> {
        Self::open_bytes(bytes, arch, Jobs::SERIAL)
    }

    fn open_bytes(
        bytes: &[u8],
        arch: Option<&str>,
        signature_jobs: Jobs,
    ) -> Result<(Self, Analysis), DecompileError> {
        if crate::extract::looks_like_macho(bytes) {
            Self::open_macho(bytes, arch)
        } else if bytes.starts_with(b"\x7fELF") {
            Self::open_elf(bytes)
        } else {
            Self::open_pe_recovered(bytes, None, signature_jobs)
        }
    }

    /// Open explicitly selected x86 raw code at offset zero. The caller supplies its ABI.
    pub fn from_shellcode_with_analysis(
        bytes: &[u8],
        convention: CallingConvention,
    ) -> Result<(Self, Analysis), DecompileError> {
        let architecture = match convention {
            CallingConvention::WindowsX86 | CallingConvention::SystemVX86 => Architecture::X86,
            CallingConvention::WindowsX64 | CallingConvention::SystemVX64 => Architecture::X64,
            _ => {
                return Err(DecompileError::Request(
                    "raw code requires an x86 platform convention".into(),
                ))
            }
        };
        if bytes.is_empty() {
            return Err(DecompileError::Input("empty raw code image".into()));
        }
        let analysis = recovery::analyze_shellcode_native(bytes, architecture)
            .map_err(DecompileError::recovery)?;
        let mut session = Self::from_analysis(&analysis, &BTreeMap::new(), convention)?;
        session.warnings.push(
            "Raw code has no platform metadata; the calling convention is supplied by the caller."
                .into(),
        );
        Ok((session, analysis))
    }

    /// Parse and recover once. Native SLEIGH, not iced-x86, translates the
    /// requested function. Existing callers can avoid recovery via from_analysis.
    pub fn from_pe(bytes: &[u8]) -> Result<Self, DecompileError> {
        Self::open_pe_recovered(bytes, None, Jobs::SERIAL).map(|(session, _)| session)
    }

    fn open_pe_recovered(
        bytes: &[u8],
        recovered: Option<Analysis>,
        signature_jobs: Jobs,
    ) -> Result<(Self, Analysis), DecompileError> {
        let started = Instant::now();
        // A malformed import directory only costs the imports, with a warning.
        let image = match recovered.as_ref() {
            Some(analysis) => analysis.image.clone(),
            None => LoadedImage::parse_partial(bytes)
                .map_err(|e| DecompileError::Input(e.to_string()))?,
        };
        validate_image(&image)?;
        let image_base = image.image_base;
        let imports_skipped = image.imports_skipped;
        let mut options = goblin::pe::options::ParseOptions::default();
        options.parse_mode = goblin::options::ParseMode::Permissive;
        options.parse_tls_data = false;
        options.parse_resources = false;
        options.parse_attribute_certificates = false;
        options.parse_imports = !imports_skipped;
        let parsed = crate::extract::loader::image::tolerate_rich_header(bytes);
        let pe = goblin::pe::PE::parse_with_opts(&parsed, &options)
            .map_err(|e| DecompileError::Input(e.to_string()))?;
        if pe
            .header
            .optional_header
            .as_ref()
            .is_some_and(|h| h.data_directories.get_clr_runtime_header().is_some())
        {
            return Err(DecompileError::Unsupported("managed PE image".into()));
        }
        let analysis = match recovered {
            Some(analysis) => analysis,
            None => recovery::analyze_image(bytes, image, recovery::RecoveryBackend::Native)
                .map_err(DecompileError::recovery)?,
        };
        let go = golang::parse(&analysis.image);
        let mut profile = TargetProfile::of_pe(&analysis.image, bytes);
        if go.is_some() {
            profile.compiler = Compiler::Go;
        }
        let convention = CallingConvention::of(profile)?;
        if !analysis.image.architecture.is_x86() {
            let mut names: BTreeMap<u64, String> = analysis
                .elf_function_symbols
                .iter()
                .filter_map(|(address, names)| names.first().map(|name| (*address, name.clone())))
                .collect();
            for export in &pe.exports {
                if let Some(name) = export.name {
                    names.insert(image_base + export.rva as u64, name.to_owned());
                }
            }
            let thunks = import_thunks(&analysis);
            for (address, name) in &thunks {
                names
                    .entry(*address)
                    .or_insert_with(|| display_import(name));
            }
            let mut session = Self::build(&analysis, &names, convention, None)?;
            for (address, name) in thunks {
                if let Some(function) = import_function(convention, &name) {
                    session
                        .native
                        .apply_prototype(address, function)
                        .map_err(|e| DecompileError::Initialization(e.to_string()))?;
                }
            }
            session.apply_dwarf(&analysis);
            return Ok((session, analysis));
        }
        if !cfg!(target_arch = "wasm32")
            && !signature_jobs.is_serial()
            && !imports_skipped
            && batch::needs_compatibility(&analysis)
        {
            // Parse the bundled databases together before either path needs the shared CRT.
            // Compatibility recovery still reports any error from its cached load.
            let _ = Signatures::embedded_with_options(&AnalysisOptions::with_jobs(signature_jobs));
        }
        let wide = convention.wide();
        let signatures =
            Signatures::decompiler_runtime().map_err(|e| DecompileError::Input(e.to_string()))?;
        let mut libraries = flirt::identify_library_functions(&analysis, &signatures)
            .map_err(|e| DecompileError::Input(e.to_string()))?;
        // Extra CRT signatures must not replace C++ identities with database
        // aliases. C++ names continue to use Function ID and RTTI evidence.
        libraries.retain(|_, name| !name.contains(['?', ':', '<', '>']));
        // A Go function's own name beats a runtime signature match: Go code is not the Visual C
        // runtime the signatures describe.
        let go_names = go.as_ref().map(go_function_names).unwrap_or_default();
        libraries.retain(|address, _| !go_names.contains_key(address));
        // Three instructions, below the signature databases' minimum. Ghidra names the x86-32
        // check but prints the call, unlike the x64 one, so it gets a name and a prototype and
        // no call fixup.
        let cookie_checks: Vec<u64> = if wide {
            Vec::new()
        } else {
            analysis
                .functions
                .keys()
                .copied()
                .filter(|address| is_x86_cookie_check(&analysis.image, *address))
                .collect()
        };
        let mut names = libraries.clone();
        // COFF and Delphi metadata override inferred names, but validated library matches still
        // supply their prototypes and effect models, just as they do for an exported function.
        for (address, aliases) in &analysis.elf_function_symbols {
            if let Some(name) = aliases.first() {
                names.insert(*address, name.clone());
            }
        }
        names.extend(
            go_names
                .iter()
                .map(|(address, name)| (*address, name.clone())),
        );
        for address in &cookie_checks {
            names
                .entry(*address)
                .or_insert_with(|| "__security_check_cookie".into());
        }
        for export in &pe.exports {
            if export.reexport.is_none() {
                if let Some(name) = export.name {
                    let address = image_base
                        .checked_add(export.rva as u64)
                        .ok_or_else(|| DecompileError::Input("export address overflow".into()))?;
                    names.insert(address, name.to_owned());
                }
            }
        }
        // A function that is only `jmp [import slot]` is the import under another address;
        // Ghidra names such a thunk after the import and types it the same way.
        let thunks = import_thunks(&analysis);
        for (address, name) in &thunks {
            names.entry(*address).or_insert_with(|| name.clone());
        }
        let export_addresses: Vec<(u64, String)> = names
            .iter()
            .filter(|(address, _)| {
                pe.exports.iter().any(|export| {
                    export.reexport.is_none()
                        && image_base.checked_add(export.rva as u64) == Some(**address)
                })
            })
            .map(|(address, name)| (*address, name.clone()))
            .collect();
        let dll_entry = pe.is_lib.then_some(analysis.image.entry_point).flatten();
        if let Some(entry) = dll_entry {
            names.entry(entry).or_insert_with(|| "DllEntryPoint".into());
        }
        let pack_bytes = if wide {
            bundled!("fid-x64.pack")
        } else {
            bundled!("fid-x86.pack")
        }
        .map_err(DecompileError::Input)?;
        let pack = fid::pack::Pack::parse(&pack_bytes)
            .map_err(|e| DecompileError::Input(e.to_string()))?;
        let (recognized, conflicts) =
            fid::names::name_functions_with_conflicts(&analysis, &pack, &|address| {
                names.contains_key(&address)
            });
        for (address, name) in &recognized {
            names.insert(*address, name.clone());
        }
        // An ambiguous match is named as Ghidra does, `FID_conflict:<name>`, so the reader sees
        // that the name is a guess. It gets no prototype, and its fixup is decided below.
        for (address, candidates) in &conflicts {
            if let Some(name) = fid::matcher::conflict_name(candidates) {
                names.entry(*address).or_insert(name);
            }
        }
        // A virtual function no other source names is named for its class, `Class::FUN_...`, as
        // Ghidra's class recovery does.
        let rtti = if go.is_none() {
            rtti::Rtti::read(&analysis.image)
        } else {
            rtti::Rtti::default()
        };
        let methods = rtti.methods();
        for (address, method) in &methods {
            names.entry(*address).or_insert_with(|| {
                let class = class_label(&rtti.classes[method.class]);
                if wide {
                    format!("{class}::FUN_{address:x}")
                } else {
                    format!("{class}::FUN_{address:08x}")
                }
            });
        }
        // On x86 a virtual function takes `this` in ECX (`__thiscall`) unless it implements a COM
        // interface, whose methods are `__stdcall` with `this` on the stack.
        let ecx_this: BTreeSet<u64> = if wide {
            BTreeSet::new()
        } else {
            let mut info = InstructionInfoFactory::new();
            let preserves_ecx = |target: u64| {
                names.get(&target).is_some_and(|name| {
                    let name = name.trim_start_matches('_');
                    ["EH_prolog", "SEH_prolog", "alloca_probe", "chkstk"]
                        .iter()
                        .any(|helper| name.starts_with(helper))
                })
            };
            rtti.vftables
                .iter()
                .flat_map(|table| table.slots.iter())
                .filter_map(|slot| analysis.functions.get(slot))
                .filter(|function| reads_ecx_first(function, &preserves_ecx, &mut info))
                .map(|function| function.addr)
                .collect()
        };
        if let Some(debug) = &analysis.dwarf {
            names.extend(
                debug
                    .functions
                    .iter()
                    .map(|(address, function)| (*address, function.name.clone())),
            );
        }
        let mut session = Self::build(&analysis, &names, convention, go.as_ref())?;
        if analysis.image.architecture == Architecture::X64 && go.is_none() {
            let ranges = recovery::unwind_extents(&analysis.image)
                .into_iter()
                .filter(|&(start, end)| session.in_code(start) && session.in_code(end - 1))
                .collect();
            session
                .native
                .set_function_ranges(&unambiguous_ranges(ranges))
                .map_err(|error| DecompileError::Initialization(error.to_string()))?;
        }
        for class in crate::delphi::Rtti::read(&analysis.image).classes {
            let _ = session.native.add_label(
                class.vmt,
                &format!("{}::VMT", class.name),
                if wide { 8 } else { 4 },
            );
        }
        // Only entries inside file-backed executable memory are registered with the engine.
        let registered = |session: &Self, address: u64| session.in_code(address);
        let recognized: BTreeMap<u64, String> = recognized
            .into_iter()
            .filter(|(address, _)| registered(&session, *address))
            .collect();
        let libraries: BTreeMap<u64, String> = libraries
            .into_iter()
            .filter(|(address, _)| registered(&session, *address))
            .collect();
        let thunks: BTreeMap<u64, String> = thunks
            .into_iter()
            .filter(|(address, _)| registered(&session, *address))
            .collect();
        let conflicts: BTreeMap<u64, Vec<String>> = conflicts
            .into_iter()
            .filter(|(address, _)| registered(&session, *address))
            .collect();
        let cookie_checks: Vec<u64> = cookie_checks
            .into_iter()
            .filter(|address| registered(&session, *address))
            .collect();
        let export_addresses: Vec<(u64, String)> = export_addresses
            .into_iter()
            .filter(|(address, _)| registered(&session, *address))
            .collect();
        for (address, name) in &recognized {
            // Naming a runtime function also types it when the archives know it. A demangled C++
            // name can exceed the archive's bounded key, and no archive holds such a name.
            if name.len() > 256 {
                continue;
            }
            session
                .native
                .apply_prototype(*address, name)
                .map_err(|error| {
                    DecompileError::Initialization(format!(
                        "prototype for {name} at {address:#x}: {error}"
                    ))
                })?;
        }
        for address in &cookie_checks {
            session
                .native
                .apply_prototype(*address, "__security_check_cookie")
                .map_err(|error| {
                    DecompileError::Initialization(format!(
                        "prototype for the cookie check at {address:#x}: {error}"
                    ))
                })?;
        }
        for (address, import) in &thunks {
            if let Some(function) = system_import_function(import) {
                session
                    .native
                    .apply_prototype(*address, function)
                    .map_err(|error| {
                        DecompileError::Initialization(format!(
                            "prototype for thunk {import} at {address:#x}: {error}"
                        ))
                    })?;
            }
        }
        // Ghidra also types a function by its exported name when the archives know it
        // (a proxy DLL's `GetFileVersionInfoA`). An unknown name keeps the generic prototype.
        for (address, name) in &export_addresses {
            // Decorated C++ names never match an archive function, and the lookup key is bounded.
            let plain = name.len() <= 256 && !name.contains(['?', '@']);
            if plain && !thunks.contains_key(address) && !recognized.contains_key(address) {
                session
                    .native
                    .apply_prototype(*address, name)
                    .map_err(|error| {
                        DecompileError::Initialization(format!(
                            "prototype for export {name} at {address:#x}: {error}"
                        ))
                    })?;
            }
        }
        for (address, name) in &libraries {
            session
                .native
                .apply_prototype(*address, name)
                .map_err(|error| {
                    DecompileError::Initialization(format!(
                        "prototype for {name} at {address:#x}: {error}"
                    ))
                })?;
            // Apply runtime prototypes only to validated FLIRT matches.
            if let Some((result, parameters)) = runtime_prototype(name, wide) {
                session.set_signature(*address, result, &parameters)?;
            }
        }
        // Effect models need a name from a validated source, FLIRT or Function ID.
        // An export is only a claim by the image, so it never selects a model.
        let mut applied_fixups = BTreeMap::new();
        for (address, name) in libraries.iter().chain(recognized.iter()) {
            if let Some(fixup) = effects::call_fixup(name, wide) {
                session
                    .native
                    .set_call_fixup(*address, fixup)
                    .map_err(|error| {
                        DecompileError::Initialization(format!(
                            "{fixup} fixup for {name} at {address:#x}: {error}"
                        ))
                    })?;
                applied_fixups.insert(*address, fixup);
            }
        }
        // Ghidra labels an ambiguous match `FID_conflict:<name>` for every candidate, and its
        // fixups list those labels. Here a function is left unnamed, but when every candidate
        // selects the same fixup (`__SEH_prolog4` and `__SEH_prolog4_GS`), the effect is known.
        for (address, candidates) in &conflicts {
            let mut fixups = candidates
                .iter()
                .map(|name| effects::call_fixup(name, wide));
            if let Some(Some(fixup)) = fixups.next() {
                if fixups.all(|other| other == Some(fixup)) {
                    session
                        .native
                        .set_call_fixup(*address, fixup)
                        .map_err(|error| {
                            DecompileError::Initialization(format!(
                                "{fixup} fixup for {candidates:?} at {address:#x}: {error}"
                            ))
                        })?;
                    applied_fixups.insert(*address, fixup);
                }
            }
        }
        // The same validated names type the helpers behind jump stubs.
        let mut stub_names: BTreeMap<u64, (&str, bool)> = recognized
            .iter()
            .filter(|(_, name)| name.len() <= 256)
            .map(|(address, name)| (*address, (name.as_str(), false)))
            .collect();
        stub_names.extend(
            libraries
                .iter()
                .map(|(address, name)| (*address, (name.as_str(), true))),
        );
        let typed: BTreeSet<u64> = stub_names
            .keys()
            .chain(thunks.keys())
            .chain(cookie_checks.iter())
            .chain(export_addresses.iter().map(|(address, _)| address))
            .copied()
            .collect();
        session.inherit_through_jump_stubs(&analysis, &applied_fixups, &stub_names, &typed)?;
        if let Some(entry) = dll_entry {
            session.set_signature(
                entry,
                ValueType::I32,
                &[ValueType::Pointer, ValueType::U32, ValueType::Pointer],
            )?;
        }
        if let Some(go) = &go {
            session.apply_go(&analysis, go)?;
        }
        session.apply_rtti(&rtti, &methods, &ecx_this);
        session.initialization_ms = started.elapsed().as_secs_f64() * 1000.0;
        session.apply_dwarf(&analysis);
        Ok((session, analysis))
    }

    /// MSVC incremental-link stubs are a single direct jump, so they keep the
    /// helper's effects and prototype. Without this the stack-cookie model and
    /// a runtime helper's signature disappear behind the stub.
    fn inherit_through_jump_stubs(
        &mut self,
        analysis: &Analysis,
        applied_fixups: &BTreeMap<u64, &str>,
        names: &BTreeMap<u64, (&str, bool)>,
        typed: &BTreeSet<u64>,
    ) -> Result<(), DecompileError> {
        if self.convention != CallingConvention::WindowsX64
            || (applied_fixups.is_empty() && names.is_empty())
        {
            return Ok(());
        }
        let wide = true;
        for address in analysis.functions.keys() {
            if self.funclet_labels.contains_key(address) || !self.in_code(*address) {
                continue;
            }
            let Some(target) = jump_stub_target(analysis, *address) else {
                continue;
            };
            if let Some(fixup) = applied_fixups.get(&target) {
                if !applied_fixups.contains_key(address) {
                    self.native
                        .set_call_fixup(*address, fixup)
                        .map_err(|error| {
                            DecompileError::Initialization(format!(
                                "{fixup} fixup for jump stub at {address:#x}: {error}"
                            ))
                        })?;
                }
            }
            let Some(&(name, library)) = names.get(&target) else {
                continue;
            };
            if typed.contains(address) {
                continue;
            }
            self.native
                .apply_prototype(*address, name)
                .map_err(|error| {
                    DecompileError::Initialization(format!(
                        "prototype for {name} through jump stub at {address:#x}: {error}"
                    ))
                })?;
            if let Some((result, parameters)) = runtime_prototype(name, wide).filter(|_| library) {
                self.set_signature(*address, result, &parameters)?;
            }
        }
        Ok(())
    }

    /// Classes from RTTI: each a structure holding pointers to its virtual function tables, each
    /// table labeled (`Class::vftable`) and typed with one method pointer per slot, so a call
    /// through it names its target. A virtual function found in a class's primary table gets
    /// `this` typed as that class unless its prototype is already known (on x86, only when it
    /// reads `this` from ECX). Type descriptors are labeled for `dynamic_cast` and `typeid`.
    fn apply_rtti(
        &mut self,
        rtti: &rtti::Rtti,
        methods: &BTreeMap<u64, rtti::Method>,
        ecx_this: &BTreeSet<u64>,
    ) {
        let wide = self.convention.wide();
        let pointer = if wide { 8 } else { 4 };
        // On x86, `__thiscall` needs evidence: a method that reads ECX for `this`. A table none of
        // whose methods does is a COM interface's, `__stdcall` with `this` on the stack.
        let thiscall = |address: &u64| wide || ecx_this.contains(address);
        let labels: Vec<String> = rtti.classes.iter().map(class_label).collect();
        // A class the engine refuses (a name it cannot hold) is left out, with its methods'
        // `this`; the rest of the program is unaffected.
        let mut refused = BTreeSet::new();
        for (index, class) in rtti.classes.iter().enumerate() {
            let name = &labels[index];
            let mut tables = Vec::new();
            for table in rtti.vftables.iter().filter(|table| table.class == index) {
                if !table.slots.iter().all(|slot| self.in_code(*slot)) {
                    continue;
                }
                let base = table.base.map(|base| labels[base].as_str());
                let field = match (table.offset, base) {
                    (0, _) => "vftable".to_owned(),
                    (_, Some(base)) => format!("vftable_for_{}", demangle::member_of(base)),
                    (offset, None) => format!("vftable_{offset:x}"),
                };
                tables.push(binfera_ghidra::VfTable {
                    offset: table.offset,
                    address: table.address,
                    label: format!("{name}::{field}"),
                    type_name: format!("{name}_{field}"),
                    field,
                    this_class: match table.offset {
                        0 => name.clone(),
                        _ => base.unwrap_or_default().to_owned(),
                    },
                    model: if table.slots.iter().any(thiscall) {
                        "__thiscall"
                    } else {
                        "__stdcall"
                    }
                    .into(),
                    slots: table.slots.clone(),
                });
            }
            if !tables.is_empty() && self.native.add_class(name, &tables).is_err() {
                refused.insert(index);
                continue;
            }
            let size = 2 * pointer + class.mangled.len() as u32 + 1;
            let label = format!("{name}::RTTI_Type_Descriptor");
            if self
                .native
                .add_label(class.type_descriptor, &label, size)
                .is_err()
            {
                refused.insert(index);
            }
        }
        for (address, method) in methods {
            if method.this_offset == 0
                && thiscall(address)
                && !refused.contains(&method.class)
                && self.in_code(*address)
            {
                // A refusal leaves this one method's `this` untyped.
                let _ = self.native.set_method(*address, &labels[method.class]);
            }
        }
    }

    /// Parse and recover a supported native ELF image. Symbols and resolved PLT
    /// stubs supply names; available architecture-specific archives supply types.
    pub fn from_elf(bytes: &[u8]) -> Result<Self, DecompileError> {
        Self::open_elf(bytes).map(|(session, _)| session)
    }

    fn open_elf(bytes: &[u8]) -> Result<(Self, Analysis), DecompileError> {
        Self::open_elf_recovered(bytes, None)
    }

    fn open_elf_recovered(
        bytes: &[u8],
        recovered: Option<Analysis>,
    ) -> Result<(Self, Analysis), DecompileError> {
        let analysis = match recovered {
            Some(analysis) => analysis,
            None => recovery::analyze_with_backend(bytes, recovery::RecoveryBackend::Native)
                .map_err(DecompileError::recovery)?,
        };
        let go = golang::parse(&analysis.image);
        let mut profile = TargetProfile::of(&analysis.image);
        if go.is_some() {
            profile.compiler = Compiler::Go;
        }
        let mut convention = CallingConvention::of(profile)?;
        let elf =
            goblin::elf::Elf::parse(bytes).map_err(|e| DecompileError::Input(e.to_string()))?;
        if analysis.image.architecture == Architecture::Arm && elf.header.e_flags & 0x400 != 0 {
            convention = CallingConvention::SystemVArm;
        }
        let mut names: BTreeMap<_, _> = analysis
            .elf_function_symbols
            .iter()
            .filter_map(|(address, aliases)| aliases.first().map(|name| (*address, name.clone())))
            .collect();
        let symbols = names.clone();
        // A stripped Go binary still names every function in its function table.
        if let Some(go) = &go {
            for (address, name) in go_function_names(go) {
                names.entry(address).or_insert(name);
            }
        }
        // A PLT stub is `jmp [GOT slot]`: the import under another address, named and typed as it.
        let mut stubs = import_thunks(&analysis);
        if analysis.image.architecture == Architecture::X86 {
            // goblin's `info.pltgot` is translated to a file offset; the stubs need the address.
            let pltgot = elf.dynamic.as_ref().and_then(|dynamic| {
                dynamic
                    .dyns
                    .iter()
                    .find(|entry| entry.d_tag == goblin::elf::dynamic::DT_PLTGOT)
                    .map(|entry| entry.d_val)
            });
            if let Some(got) = pltgot {
                let got = got.wrapping_add(analysis.image.load_bias);
                for (address, import) in pic_plt_thunks(&analysis, got) {
                    stubs.entry(address).or_insert(import);
                }
            }
        }
        let thunks: BTreeMap<u64, String> = stubs
            .into_iter()
            .filter_map(|(address, import)| {
                let plain = import_function(convention, &import)?.to_owned();
                Some((address, plain))
            })
            .collect();
        for (address, name) in &thunks {
            names.entry(*address).or_insert_with(|| name.clone());
        }
        // gcc's position-independent i386 code reads its own address through a thunk the
        // calling convention cannot describe (it returns in `ebx`, say); the compiler spec models
        // each one. A stripped image still has the thunk's body, which names it.
        if convention == CallingConvention::SystemVX86 {
            for address in analysis.functions.keys() {
                if let Some(name) = analysis
                    .image
                    .bytes_at(*address, 4)
                    .and_then(effects::gcc_x86_pc_thunk)
                {
                    names.entry(*address).or_insert_with(|| name.into());
                }
            }
        }
        if let Some(debug) = &analysis.dwarf {
            names.extend(
                debug
                    .functions
                    .iter()
                    .map(|(address, function)| (*address, function.name.clone())),
            );
        }
        let mut session = Self::build(&analysis, &names, convention, go.as_ref())?;
        if matches!(
            analysis.image.architecture,
            Architecture::Mips | Architecture::MipsBe
        ) {
            let bias = analysis.image.load_bias;
            let gp = elf
                .syms
                .iter()
                .find(|s| elf.strtab.get_at(s.st_name) == Some("_gp"))
                .map(|s| s.st_value)
                .or_else(|| {
                    elf.dynamic.as_ref().and_then(|d| {
                        d.dyns
                            .iter()
                            .find(|d| d.d_tag == 3)
                            .map(|d| d.d_val + 0x7ff0)
                    })
                });
            if let Some(gp) = gp {
                session
                    .native
                    .set_register_value(0, 0xffff_ffff, "gp", gp.wrapping_add(bias))
                    .map_err(|e| DecompileError::Initialization(e.to_string()))?;
            }
            if elf.header.e_flags & 6 != 0 {
                for &address in analysis.functions.keys() {
                    session
                        .native
                        .set_register_value(address, address + 4, "t9", address)
                        .map_err(|e| DecompileError::Initialization(e.to_string()))?;
                }
            }
        }
        // Bare System V ELF headers are common on static Linux binaries. An explicit other
        // OS must not inherit Linux's syscall numbering merely because its C ABI is System V.
        let ranges: Vec<_> = recovery::elf_unwind_ranges(bytes, &analysis.image)
            .into_iter()
            .collect();
        session
            .native
            .set_function_ranges(&unambiguous_ranges(ranges))
            .map_err(|error| DecompileError::Initialization(error.to_string()))?;
        let os = crate::extract::loader::elf_os::detect_elf_os(bytes);
        session.import_thunks.extend(thunks.keys().copied());
        if os != "linux" && os != "unknown" {
            session
                .native
                .set_linux_syscalls(false)
                .map_err(|error| DecompileError::Initialization(error.to_string()))?;
        }
        if convention == CallingConvention::SystemVX86 {
            for (address, name) in &names {
                if let Some(fixup) = effects::gcc_x86_call_fixup(name) {
                    if session.in_code(*address) {
                        session
                            .native
                            .set_call_fixup(*address, fixup)
                            .map_err(|error| {
                                DecompileError::Initialization(format!(
                                    "{fixup} fixup for {name} at {address:#x}: {error}"
                                ))
                            })?;
                    }
                }
            }
        }
        for (address, name) in &thunks {
            if session.in_code(*address) {
                session
                    .native
                    .apply_prototype(*address, name)
                    .map_err(|error| {
                        DecompileError::Initialization(format!(
                            "prototype for PLT stub {name} at {address:#x}: {error}"
                        ))
                    })?;
            }
        }
        // Like Ghidra's archive analyzer, a function the image defines under a C library name
        // (a wrapper, or a rootkit's hook of `access`) takes that function's prototype.
        for (address, name) in &symbols {
            if name.len() <= 256 && !thunks.contains_key(address) && session.in_code(*address) {
                session
                    .native
                    .apply_prototype(*address, name)
                    .map_err(|error| {
                        DecompileError::Initialization(format!(
                            "prototype for symbol {name} at {address:#x}: {error}"
                        ))
                    })?;
            }
        }
        if let Some(go) = &go {
            session.apply_go(&analysis, go)?;
        }
        session.apply_dwarf(&analysis);
        Ok((session, analysis))
    }

    /// Open a thin or universal Mach-O. Automatic selection follows fat-header order.
    pub fn from_macho(bytes: &[u8], arch: Option<&str>) -> Result<Self, DecompileError> {
        Self::open_macho(bytes, arch).map(|(session, _)| session)
    }

    fn open_macho(bytes: &[u8], arch: Option<&str>) -> Result<(Self, Analysis), DecompileError> {
        Self::open_macho_recovered(bytes, arch, None)
    }

    fn open_macho_recovered(
        bytes: &[u8],
        arch: Option<&str>,
        recovered: Option<Analysis>,
    ) -> Result<(Self, Analysis), DecompileError> {
        let analysis = match recovered {
            Some(analysis) => analysis,
            None => recovery::analyze_macho(bytes, arch).map_err(DecompileError::recovery)?,
        };
        let go = golang::parse(&analysis.image);
        let mut profile = TargetProfile::of(&analysis.image);
        if go.is_some() {
            profile.compiler = Compiler::Go;
        }
        let convention = CallingConvention::of(profile)?;
        let mut names: BTreeMap<u64, String> = analysis
            .elf_function_symbols
            .iter()
            .filter(|(address, _)| analysis.functions.contains_key(address))
            .filter_map(|(address, names)| names.first().map(|name| (*address, name.clone())))
            .collect();
        if let Some(go) = &go {
            names.extend(go_function_names(go));
        }
        let thunks = import_thunks(&analysis);
        for (address, import) in &thunks {
            if let Some(name) = import.rsplit_once('.').map(|(_, name)| name) {
                names.entry(*address).or_insert_with(|| name.to_owned());
            }
        }
        let (slice, _) = crate::extract::image::select_macho_slice(bytes, arch)
            .map_err(|e| DecompileError::Input(e.to_string()))?;
        let mut metadata = crate::extract::loader::macho_metadata::read(slice, &analysis.image);
        names.extend(metadata.functions.clone());
        for (address, (name, _, _)) in macho::selector_stubs(&analysis, &metadata) {
            names.insert(address, name);
        }
        let mut session = Self::build(&analysis, &names, convention, go.as_ref())?;
        session
            .native
            .set_linux_syscalls(false)
            .map_err(|e| DecompileError::Initialization(e.to_string()))?;
        for (address, import) in &thunks {
            if session.in_code(*address) {
                if let Some(name) = import_function(convention, import) {
                    session
                        .native
                        .apply_prototype(*address, name)
                        .map_err(|e| DecompileError::Initialization(e.to_string()))?;
                }
            }
        }
        if let Some(go) = &go {
            session.apply_go(&analysis, go)?;
        }
        for (address, label) in &metadata.labels {
            let size = if metadata.cfstrings.contains_key(label) {
                32
            } else {
                8
            };
            session
                .native
                .add_label(*address, label, size)
                .map_err(|e| DecompileError::Initialization(e.to_string()))?;
        }
        session.cfstrings = std::mem::take(&mut metadata.cfstrings);
        macho::apply(&mut session, &analysis, &metadata)?;
        session.warnings.extend(metadata.diagnostics);
        session.apply_dwarf(&analysis);
        Ok((session, analysis))
    }

    /// Reuse binfera's loaded bytes, recovered entry points and no-return set.
    /// `names` can supply exports, FLIRT or caller-provided symbols.
    pub fn from_analysis(
        analysis: &Analysis,
        names: &BTreeMap<u64, String>,
        convention: CallingConvention,
    ) -> Result<Self, DecompileError> {
        let mut session = Self::build(analysis, names, convention, None)?;
        session.apply_dwarf(analysis);
        Ok(session)
    }

    fn from_recovered(
        bytes: &[u8],
        arch: Option<&str>,
        analysis: Analysis,
    ) -> Result<(Self, Analysis), DecompileError> {
        if crate::extract::looks_like_macho(bytes) {
            Self::open_macho_recovered(bytes, arch, Some(analysis))
        } else if bytes.starts_with(b"\x7fELF") {
            Self::open_elf_recovered(bytes, Some(analysis))
        } else {
            Self::open_pe_recovered(bytes, Some(analysis), Jobs::SERIAL)
        }
    }

    /// [`Self::from_analysis`], for a Go binary: its release selects the default model and the
    /// standard library signatures, and must be set before any function is registered.
    fn build(
        analysis: &Analysis,
        names: &BTreeMap<u64, String>,
        convention: CallingConvention,
        go: Option<&GoBinary>,
    ) -> Result<Self, DecompileError> {
        let started = Instant::now();
        let image = &analysis.image;
        let mut names = names.clone();
        if let Some(go) = go {
            for helper in ["runtime.duffzero", "runtime.duffcopy"] {
                if let Some(body) = golang_flow::duff_helper(image, go, helper) {
                    for target in analysis
                        .instructions
                        .values()
                        .filter(|i| i.flow == Flow::Call)
                        .filter_map(|i| i.direct_target)
                        .filter(|t| body.entry < *t && *t < body.end)
                    {
                        names.entry(target).or_insert_with(|| {
                            format!(
                                "go_{}_{target:x}",
                                if helper == "runtime.duffcopy" {
                                    "duffcopy"
                                } else {
                                    "duffzero"
                                }
                            )
                        });
                    }
                }
            }
        }
        if let Some(debug) = &analysis.dwarf {
            for (address, function) in &debug.functions {
                names
                    .entry(*address)
                    .or_insert_with(|| function.name.clone());
            }
        }
        let mut exceptions = crate::msvc_eh::ExceptionInfo::read(image);
        exceptions.link_functions(analysis);
        let exception_names = exceptions.names();
        let funclet_labels: BTreeMap<_, _> = exceptions
            .contained_funclets(analysis)
            .into_iter()
            .map(|(label, owner)| {
                let name = exception_names
                    .get(&label)
                    .cloned()
                    .unwrap_or_else(|| format!("eh_resume_{owner:x}_{label:x}"));
                (label, (owner, name))
            })
            .collect();
        for (address, name) in exception_names {
            // A caller can supply partial recovery. Do not register a missing
            // function without its flow overrides; explicit selection handles it.
            if analysis.functions.contains_key(&address) {
                names.entry(address).or_insert(name);
            }
        }
        let names = &names;
        validate_image(image)?;
        let wide = convention.wide();
        let mut profile = TargetProfile::of(image);
        if image.format == ImageFormat::Sc {
            profile.abi = if convention.is_windows() {
                Abi::Windows
            } else if convention.is_darwin() {
                Abi::Darwin
            } else {
                Abi::SystemV
            };
        }
        if !convention.fits(profile) {
            return Err(DecompileError::Request(format!(
                "{convention:?} does not match the {:?} {:?} image",
                image.format, image.architecture
            )));
        }
        let init = |e: binfera_ghidra::Error| DecompileError::Initialization(e.to_string());
        let mut native = binfera_ghidra::Session::new(convention.language()).map_err(init)?;
        if image.architecture == Architecture::Arm {
            let mut entries = Vec::new();
            for (&start, &mode) in &image.arm_context {
                let thumb = mode & 1 != 0;
                if entries
                    .last()
                    .is_none_or(|(_, previous)| *previous != thumb)
                {
                    entries.push((start, thumb));
                }
            }
            let limit = image
                .sections
                .iter()
                .filter_map(|s| s.end_address())
                .max()
                .unwrap_or(0);
            for (index, &(start, thumb)) in entries.iter().enumerate() {
                let end = entries.get(index + 1).map_or(limit, |(end, _)| *end);
                if start < end {
                    native.set_arm_mode(start, end, thumb).map_err(init)?;
                }
            }
        }
        let mut go_noreturn = BTreeSet::new();
        if let (Some(go), true) = (go, convention.is_go()) {
            let version = go.version();
            let functions = &go.functions.functions;
            let start = functions.iter().map(|f| f.entry).min();
            let end = functions.iter().map(|f| f.end).max();
            if let (Some(start), Some(end), 1) = (start, end, version.major) {
                let os = match image.format {
                    ImageFormat::Pe => "w",
                    ImageFormat::Macho => "d",
                    _ => "l",
                };
                native
                    .set_go_target(
                        os,
                        version.minor,
                        wide && version.has_register_abi(),
                        start,
                        end.max(start + 1),
                    )
                    .map_err(init)?;
            }
            let noreturn = golang_names::noreturn_names();
            go_noreturn = functions
                .iter()
                .filter(|f| noreturn.contains(f.name.as_str()))
                .map(|f| f.entry)
                .collect();
        }
        let mut executable_ranges = Vec::new();
        // PE sections are mapped padded to FileAlignment (Vivisect parity), so in an image with
        // small section alignment, such as a UEFI driver, one section's padding covers the start
        // of the next. Each section is clipped at the next one's start for the engine.
        let mut starts: Vec<u64> = image.sections.iter().map(|s| s.address).collect();
        starts.sort_unstable();
        for (index, section) in image.sections.iter().enumerate() {
            let next = starts
                .iter()
                .find(|start| **start > section.address)
                .copied()
                .unwrap_or(u64::MAX);
            let virtual_size = section.virtual_size.min(next - section.address);
            if virtual_size == 0 {
                continue;
            }
            let size = usize::try_from(virtual_size)
                .map_err(|_| DecompileError::Input("section size overflow".into()))?;
            let bytes = image.section_bytes(index).ok_or_else(|| {
                DecompileError::Input(format!("unmapped section at {:#x}", section.address))
            })?;
            let bytes = &bytes[..bytes.len().min(size)];
            // An ELF segment's memory size can exceed its file bytes (`.bss`), and a PE section
            // can run past the end of a truncated file (carved or dumped modules); the loader maps
            // only the file bytes, and the rest reads as zeros, as IDA maps it. Cap the padding so
            // a huge `.bss` cannot exhaust the engine's image limit.
            let padded;
            let bytes = if bytes.len() == size {
                bytes
            } else {
                const MAX_ZERO_FILL: usize = 16 << 20;
                padded = {
                    let mut filled = bytes.to_vec();
                    filled.resize(size.min(bytes.len() + MAX_ZERO_FILL), 0);
                    filled
                };
                &padded[..]
            };
            let end = section
                .address
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| DecompileError::Input("section address overflow".into()))?;
            // Native import registration clears read-only only on each IAT
            // slot, retaining constants and strings elsewhere in the section.
            // Zero-filled space that the file does not carry (a packer's unpack target) holds no
            // code to read. Ghidra reports bad instruction data there and ends the flow; mapping
            // it as executable would decode the zeros as instructions until the limit.
            let code = section.permissions.execute
                && !(section.file_size == 0 && image.is_uninitialized(section.address));
            // Map bytes once. Metadata boundaries must not consume native section slots.
            native
                .add_section(section.address, bytes, code, !section.permissions.write)
                .map_err(init)?;
            if code {
                let mut start = section.address;
                for range in &image.code_exclusions {
                    if range.start >= end {
                        break;
                    }
                    if range.end <= start {
                        continue;
                    }
                    if start < range.start {
                        executable_ranges.push((start, range.start));
                    }
                    start = range.end.min(end);
                }
                if start < end {
                    executable_ranges.push((start, end));
                }
            }
        }
        let exclusions: Vec<_> = image
            .code_exclusions
            .iter()
            .map(|range| binfera_ghidra::CodeRange {
                start: range.start,
                end: range.end,
            })
            .collect();
        native.set_code_exclusions(&exclusions).map_err(init)?;
        executable_ranges.sort_unstable();
        let in_code = |address| in_executable_ranges(&executable_ranges, address);
        let mut skipped_entries = 0usize;
        let is_rust = go.is_none() && rust::detected(analysis, names);
        if go.is_some() || is_rust {
            native.set_counted_strings(true).map_err(init)?;
        }
        for address in analysis.functions.keys().chain(names.keys()) {
            if funclet_labels.contains_key(address) {
                continue;
            }
            // Recovery can decode zero-filled space as code; that is not mapped as code here.
            if !in_code(*address) {
                skipped_entries += 1;
                continue;
            }
            // An empty name (an export the file leaves blank) is no name at all.
            let name = names
                .get(address)
                .filter(|name| !name.is_empty())
                .map(|name| bounded_name(&display_name(name), *address))
                .unwrap_or_else(|| {
                    // Ghidra pads default names to the address width of the image.
                    if wide {
                        format!("FUN_{address:x}")
                    } else {
                        format!("FUN_{address:08x}")
                    }
                });
            native
                .add_function(
                    *address,
                    &name,
                    analysis.noreturn.contains(address)
                        || go_noreturn.contains(address)
                        || names.get(address).is_some_and(|name| rust::noreturn(name)),
                )
                .map_err(init)?;
        }
        for (label, (owner, name)) in &funclet_labels {
            if in_code(*owner) && in_code(*label) {
                native.add_code_label(*owner, *label, name).map_err(init)?;
            }
        }
        for (address, names) in &image.external_bindings {
            if !image.import_locations.contains_key(address)
                && image
                    .section_containing(*address)
                    .is_some_and(|s| s.name == "EXTERNAL")
            {
                if let Some(name) = names.first() {
                    native
                        .add_label(*address, name, image.architecture.pointer_width() as u32)
                        .map_err(init)?;
                }
            }
        }
        for (address, name) in &image.import_locations {
            // Relocatable objects use symbolic addresses for direct extern calls.
            // Register the function at that address as well as its data reference.
            if image
                .section_containing(*address)
                .is_some_and(|s| s.name == "EXTERNAL")
            {
                native
                    .add_function(
                        *address,
                        import_symbol(name).unwrap_or(name),
                        analysis.noreturn.contains(address),
                    )
                    .map_err(init)?;
            }
            // Recovery also aliases AArch64 import stubs at executable addresses.
            // Only GOT/IAT slots are external-reference data symbols.
            if image.is_executable_address(*address)
                && (aarch64_import_thunk(analysis, *address).is_some()
                    || (image.format == ImageFormat::Macho
                        && image
                            .elf_plt_ranges
                            .iter()
                            .any(|(start, end)| *start <= *address && *address < *end)))
            {
                continue;
            }
            // The class word of each constant `CFString` binds to this symbol; the object is
            // labelled whole from the Mach-O metadata instead.
            if image.format == ImageFormat::Macho
                && name.ends_with("__CFConstantStringClassReference")
            {
                continue;
            }
            native
                .add_import(
                    *address,
                    &bounded_name(
                        &if image.format == ImageFormat::Macho {
                            name.rsplit_once('.')
                                .map_or(name.clone(), |(_, symbol)| display_name(symbol))
                        } else {
                            display_import(name)
                        },
                        *address,
                    ),
                    analysis.noreturn.contains(address)
                        || import_symbol(name).is_some_and(rust::noreturn),
                )
                .map_err(init)?;
            if let Some(function) = import_function(convention, name) {
                // Unknown names are fine: the call keeps its warning.
                native.apply_prototype(*address, function).map_err(init)?;
            } else if let Some(prototype) = import_symbol(name)
                .and_then(demangle::demangle)
                .and_then(|demangled| demangled.prototype)
            {
                // A C++ import's decoration gives its prototype, `this` first for a method.
                apply_demangled(&mut native, *address, &prototype);
            }
        }
        if convention == CallingConvention::WindowsX86 {
            let mut purges = BTreeMap::new();
            for address in image.import_locations.keys() {
                purges.insert(*address, native.stack_purge(*address).map_err(init)?);
            }
            for (address, import) in import_thunks(analysis) {
                if let Some((slot, _)) = image
                    .import_locations
                    .iter()
                    .find(|(_, name)| **name == import)
                {
                    if let Some(purge) = purges.get(slot).copied() {
                        purges.insert(address, purge);
                    }
                }
            }
            for (address, purge) in stack_purge::infer(analysis, &purges) {
                native.set_stack_purge(address, purge).map_err(init)?;
            }
        }
        if convention == CallingConvention::WindowsX86 {
            for address in conventions::fastcall(analysis, is_rust) {
                native
                    .set_function_model(address, "__fastcall")
                    .map_err(init)?;
            }
        }
        for (address, name) in names.iter().chain(image.import_locations.iter()) {
            let raw = import_symbol(name)
                .filter(|_| image.import_locations.contains_key(address))
                .unwrap_or(name);
            if let Some((parameters, varargs)) =
                demangle::itanium_parameters(raw, wide && !convention.is_windows())
            {
                let parameters: Vec<_> = parameters
                    .into_iter()
                    .map(|(value, pointee)| binfera_ghidra::CppParameter {
                        value: demangled_value(value),
                        pointee,
                    })
                    .collect();
                native
                    .set_cpp_parameters(*address, &parameters, varargs)
                    .map_err(init)?;
            }
        }
        // So does a C++ export's or symbol's.
        for (address, name) in names {
            let Some(prototype) = demangle::demangle(name).and_then(|d| d.prototype) else {
                continue;
            };
            if in_code(*address) {
                apply_demangled(&mut native, *address, &prototype);
            }
        }
        for (address, name) in names {
            if in_code(*address) {
                rust::apply_function(&mut native, *address, name, image).map_err(init)?;
            }
        }
        for (address, name) in &image.import_locations {
            if let Some(name) = import_symbol(name) {
                rust::apply_function(&mut native, *address, name, image).map_err(init)?;
            }
        }
        if is_rust {
            for string in rust::strings(analysis) {
                native
                    .add_rust_string(string.address, string.length, 0)
                    .map_err(init)?;
                for descriptor in string.descriptors {
                    native
                        .add_rust_string(string.address, string.length, descriptor)
                        .map_err(init)?;
                }
            }
        }
        for address in names.keys() {
            if in_code(*address) {
                if let Some((branch, slot)) =
                    aarch64_import_thunk(analysis, *address).or_else(|| {
                        image
                            .architecture
                            .is_risc32()
                            .then(|| crate::extract::risc::import_thunk(analysis, *address))
                            .flatten()
                    })
                {
                    let target = if image.import_locations.contains_key(&slot) {
                        slot
                    } else {
                        aarch64_pointer(image, slot).unwrap_or(slot)
                    };
                    native
                        .add_tail_call(*address, branch, target)
                        .map_err(init)?;
                }
            }
        }
        for (caller, function) in &analysis.functions {
            if !in_code(*caller) {
                continue;
            }
            for block in &function.blocks {
                for insn in &block.insns {
                    // Preserve direct jumps to separate recovered entries and
                    // IAT jump thunks. Self-loops and local branches stay flow.
                    let target = match insn.flow {
                        Flow::UnconditionalBranch => insn.direct_target.filter(|target| {
                            target != caller
                                && !funclet_labels.contains_key(target)
                                && (analysis.functions.contains_key(target)
                                    || names.contains_key(target))
                        }),
                        Flow::IndirectBranch => insn
                            .memory_target
                            .filter(|target| image.import_locations.contains_key(target)),
                        _ => None,
                    };
                    if let Some(target) =
                        target.filter(|t| in_code(*t) || image.import_locations.contains_key(t))
                    {
                        native
                            .add_tail_call(*caller, insn.address, target)
                            .map_err(init)?;
                    }
                }
            }
        }
        if !convention.is_go() {
            for address in analysis.functions.keys().filter(|a| in_code(**a)) {
                if let Some(effects) = leaf_effects::infer(analysis, *address) {
                    if effects.zero_from != 0 || effects.preserves_ecx {
                        native
                            .set_leaf_effects(*address, effects.zero_from, effects.preserves_ecx)
                            .map_err(init)?;
                    }
                }
            }
        }
        let mut local_labels: BTreeSet<_> = funclet_labels.keys().copied().collect();
        for insn in analysis.instructions.values() {
            if recovery::idioms::delphi_handler(image, insn) {
                local_labels.insert(u64::from(insn.x86_instruction().immediate32()));
            }
            if let Some((site, target)) = recovery::idioms::delphi_finally(image, insn) {
                native.add_branch(site, target, 1, 4).map_err(init)?;
                local_labels.insert(target);
            }
            if insn.flow == Flow::IndirectBranch {
                let preceding: Vec<_> = analysis
                    .instructions
                    .range(insn.address.saturating_sub(80)..insn.address)
                    .map(|(_, op)| op)
                    .collect();
                if let Some(target) = recovery::idioms::gcc_variadic(image, insn, &preceding) {
                    local_labels.insert(target + 32);
                    native
                        .add_branch(insn.address, target, insn.bytes.len() as u32, 0)
                        .map_err(init)?;
                    if let Some((entry, fixed, callee)) =
                        recovery::idioms::gcc_variadic_forwarder(image, insn, &preceding)
                    {
                        if analysis.functions.contains_key(&entry) {
                            native
                                .set_variadic_forwarder(entry, fixed, callee)
                                .map_err(init)?;
                        }
                    }
                }
            }
        }
        let call_arguments = win64_args::calls(analysis);
        for (caller, site, target, count) in call_arguments.variadic {
            native
                .set_callsite_arguments(caller, site, target, count)
                .map_err(init)?;
        }
        if !call_arguments.stack_arguments.is_empty() {
            let (targets, counts): (Vec<u64>, Vec<u32>) =
                call_arguments.stack_arguments.into_iter().unzip();
            native
                .set_win64_stack_arguments(&targets, &counts)
                .map_err(init)?;
        }
        let mut warnings = image.load_diagnostics.clone();
        warnings.extend(exceptions.diagnostics.iter().cloned());
        if skipped_entries > 0 {
            warnings.push(format!(
                "{skipped_entries} recovered entries lie outside executable file-backed code and were not registered"
            ));
        }
        // Discovery diagnostics describe the independent iced-x86 graph.
        // Keep them on Analysis; Ghidra reports its own unresolved flow.
        warnings.sort();
        warnings.dedup();
        local_labels.retain(|address| {
            !analysis
                .seeds
                .get(address)
                .is_some_and(|kinds| kinds.contains(&recovery::SeedKind::CallTarget))
        });
        Ok(Self {
            native,
            executable_ranges,
            names: names
                .iter()
                .map(|(address, name)| (*address, display_name(name)))
                .collect(),
            caller_return_uses: caller_return_uses(analysis),
            recursive_cdecl: recursive_cdecl(analysis),
            x86_low32_returns: x86_low32_returns(analysis),
            x86_forwarded_imports: x86_forwarded_imports(analysis),
            explicit_signatures: BTreeSet::new(),
            has_debug_types: false,
            exceptions,
            warnings,
            duff_helpers: BTreeMap::new(),
            go_strings: go.map(|go| {
                go_strings::Strings::new(
                    image,
                    go.functions
                        .functions
                        .iter()
                        .map(|function| function.end)
                        .max(),
                )
            }),
            cfstrings: BTreeMap::new(),
            import_thunks: import_thunks(analysis).into_keys().collect(),
            local_labels,
            funclet_labels,
            initialization_ms: started.elapsed().as_secs_f64() * 1000.0,
            limits: ResourceLimits::default(),
            convention,
            unit_pack: std::cell::OnceCell::new(),
        })
    }

    fn apply_dwarf(&mut self, analysis: &Analysis) {
        let Some(debug) = &analysis.dwarf else {
            return;
        };
        self.warnings.extend(debug.diagnostics.iter().cloned());
        if debug.functions.is_empty() {
            return;
        }
        if let Err(error) = self.native.add_debug_types(&debug.types) {
            self.warnings.push(format!("DWARF types: {error}"));
            return;
        }
        let assembly: BTreeSet<u64> = if debug.functions.values().any(|f| f.go) {
            golang::parse(&analysis.image)
                .map(|go| {
                    go.functions
                        .functions
                        .into_iter()
                        .filter(|f| f.assembly)
                        .map(|f| f.entry)
                        .collect()
                })
                .unwrap_or_default()
        } else {
            BTreeSet::new()
        };
        let mut skipped = 0;
        for (address, function) in &debug.functions {
            // Assembly helpers' empty DWARF signatures do not describe their custom ABI.
            if assembly.contains(address) {
                continue;
            }
            if !self.in_code(*address) {
                continue;
            }
            if function.signature {
                match self.native.set_debug_signature(
                    *address,
                    function.result,
                    &function.model,
                    &function.parameters,
                    function.varargs,
                    function.go,
                    function.multi,
                    function.noreturn,
                ) {
                    Ok(true) => {
                        self.explicit_signatures.insert(*address);
                        self.has_debug_types = true;
                    }
                    Ok(false) | Err(_) => skipped += 1,
                }
            } else {
                skipped += 1;
            }
            let frame = crate::dwarf::stack_frame_base(&analysis.image, *address, function.frame);
            if let Some(frame) = frame {
                for local in &function.locals {
                    if let Some(offset) = local.offset.checked_add(frame) {
                        if self
                            .native
                            .add_debug_local(*address, &local.name, local.type_id, offset)
                            .unwrap_or(false)
                        {
                            self.has_debug_types = true;
                        }
                    }
                }
            }
        }
        if skipped > 0 {
            self.warnings.push(format!("DWARF: {skipped} function signatures have unsupported types or storage and remain inferred"));
        }
    }

    /// Go's own conventions and the standard library signatures, for the functions of the function
    /// table that kept their Go names (an export can rename one).
    fn apply_go(&mut self, analysis: &Analysis, go: &GoBinary) -> Result<(), DecompileError> {
        if !self.convention.is_go() {
            return Ok(());
        }
        let version = go.version();
        let wide = self.convention.wide();
        fn error(
            address: u64,
            name: &str,
        ) -> impl FnOnce(binfera_ghidra::Error) -> DecompileError + '_ {
            move |e| {
                DecompileError::Initialization(format!("Go function {name} at {address:#x}: {e}"))
            }
        }
        let noreturn_names = golang_names::noreturn_names();
        let noreturn: BTreeSet<_> = go
            .functions
            .functions
            .iter()
            .filter(|f| noreturn_names.contains(f.name.as_str()))
            .map(|f| f.entry)
            .chain(analysis.noreturn.iter().copied())
            .collect();
        // The batched barriers came with Go 1.21; their shape is the evidence, since a release
        // guessed from the table layout alone reads 1.20.
        let barriers = golang_flow::arm64_write_barriers(&analysis.image, go);
        for function in &go.functions.functions {
            let (address, name) = (function.entry, function.name.as_str());
            if !self.in_code(address) || self.names.get(&address).map(String::as_str) != Some(name)
            {
                continue;
            }
            // Panic helpers name x86 registers. On arm64 keep the stack-growth helpers, the
            // write barriers and Duff's device, which AARCH64_golang.cspec models by the same
            // names, and `spillArgs`, which the build adds to it.
            let arm64 = analysis.image.architecture == Architecture::AArch64;
            let special = if arm64 && name == "runtime.spillArgs" {
                Some("spillargs".to_owned())
            } else {
                golang_names::special(name, version, wide)
                    .or_else(|| barriers.get(&address).cloned())
            };
            if let Some(kind) = special.filter(|kind| {
                !arm64
                    || matches!(
                        kind.as_str(),
                        "void"
                            | "gcwrite_batch"
                            | "gcwrite_batch_numbytes"
                            | "gcwrite_buffered"
                            | "duffzero"
                            | "duffcopy"
                            | "spillargs"
                    )
            }) {
                self.native
                    .set_go_special(address, &kind)
                    .map_err(error(address, name))?;
            } else if name.ends_with(".abi0") {
                // `GoRttiMapper.isAbi0Func`: the stack ABI, parameters inferred.
                self.native
                    .set_go_special(address, "abi0")
                    .map_err(error(address, name))?;
            } else if !function.assembly {
                let typed = if let Some(key) = golang_names::snapshot_key(name) {
                    self.native
                        .apply_go_prototype(address, &key)
                        .map_err(error(address, name))?
                } else {
                    false
                };
                if !typed && !wide {
                    if let Some((inputs, results)) =
                        go_stack::layout(&analysis.image, function, &noreturn)
                    {
                        self.native
                            .set_go_stack_layout(address, inputs, results)
                            .map_err(error(address, name))?;
                    }
                }
            }
        }
        for (site, target, length) in golang_flow::stack_checks(&analysis.image, go) {
            self.native
                .add_branch(site, target, length, 0)
                .map_err(error(site, "stack check"))?;
        }
        // `FixupDuffAlternateEntryPointsBackgroundCommand`: code calls into the middle of
        // `duffzero` and `duffcopy` to clear or copy fewer bytes; each target is an entry point
        // with the helper's convention.
        for helper in ["runtime.duffzero", "runtime.duffcopy"] {
            let Some(kind) = golang_names::special(helper, version, wide) else {
                continue;
            };
            let Some(body) = golang_flow::duff_helper(&analysis.image, go, helper) else {
                continue;
            };
            let targets: BTreeSet<u64> = analysis
                .functions
                .values()
                .flat_map(|function| &function.blocks)
                .flat_map(|block| &block.insns)
                .filter(|insn| insn.flow == Flow::Call)
                .filter_map(|insn| insn.direct_target)
                .filter(|target| {
                    body.entry <= *target && *target < body.end && self.in_code(*target)
                })
                .collect();
            for target in targets {
                let details = golang_flow::duff(
                    &analysis.image,
                    target,
                    body.end,
                    helper == "runtime.duffcopy",
                );
                let alias = format!(
                    "go_{}_{target:x}",
                    if helper == "runtime.duffcopy" {
                        "duffcopy"
                    } else {
                        "duffzero"
                    }
                );
                let alias = self.names.get(&target).cloned().unwrap_or(alias);
                if let Some(details) = details {
                    self.duff_helpers.insert(alias.clone(), details);
                }
                self.native
                    .add_function(target, &alias, false)
                    .map_err(error(target, &alias))?;
                self.native
                    .set_go_special(target, &kind)
                    .map_err(error(target, &alias))?;
                self.names.entry(target).or_insert(alias);
            }
        }
        Ok(())
    }

    /// A recovered entry with a metadata, runtime-signature or class name.
    pub fn is_named_function(&self, address: u64) -> bool {
        self.in_code(address) && self.names.contains_key(&address)
    }

    /// A forwarding entry whose calls retain the import's name and prototype.
    pub fn is_import_thunk(&self, address: u64) -> bool {
        self.import_thunks.contains(&address)
    }

    /// A validated compiler label that a compatibility recovery can mistake for a function.
    pub fn is_local_label(&self, address: u64) -> bool {
        self.local_labels.contains(&address)
    }

    /// Labels belonging to a function's in-body exception handlers.
    pub fn function_labels(&self, address: u64) -> BTreeMap<u64, &str> {
        self.funclet_labels
            .iter()
            .filter_map(|(label, (owner, name))| {
                (*owner == address).then_some((*label, name.as_str()))
            })
            .collect()
    }

    /// Whether an address is in mapped code, excluding validated image metadata.
    pub fn is_code_address(&self, address: u64) -> bool {
        self.in_code(address)
    }

    /// Image-wide diagnostics, reported once by callers rather than on every function.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    fn in_code(&self, address: u64) -> bool {
        in_executable_ranges(&self.executable_ranges, address)
    }

    /// Supply a known fixed-argument platform signature for a registered
    /// function entry or import slot. No speculative prototypes are installed.
    pub fn set_signature(
        &mut self,
        address: u64,
        result: ValueType,
        parameters: &[ValueType],
    ) -> Result<(), DecompileError> {
        if parameters.len() > 32 || parameters.contains(&ValueType::Void) {
            return Err(DecompileError::Request(
                "signatures allow at most 32 non-void parameters".into(),
            ));
        }
        self.native
            .set_signature(address, result, parameters)
            .map_err(|e| DecompileError::Request(format!("signature at {address:#x}: {e}")))?;
        self.explicit_signatures.insert(address);
        Ok(())
    }

    pub fn set_limits(&mut self, limits: ResourceLimits) -> Result<(), DecompileError> {
        if limits.timeout_ms == 0
            || limits.timeout_ms > 60_000
            || limits.max_instructions == 0
            || limits.max_instructions > 100_000
            || limits.max_work == 0
            || limits.max_work > 200_000_000
        {
            return Err(DecompileError::Request("limits must be nonzero and at most 60000 ms, 100000 instructions, 200000000 work units".into()));
        }
        self.limits = limits;
        Ok(())
    }

    /// Decompile one function or a set and wrap the text in a unit a C compiler accepts
    /// (see [`Unit`]). Duplicate addresses are decompiled once. Any function that fails to
    /// decompile fails the unit: a partial unit would hide the gap.
    pub fn decompile_unit(&mut self, addresses: &[u64]) -> Result<Unit, DecompileError> {
        if self.has_debug_types {
            return Err(DecompileError::Unsupported(
                "standalone units cannot yet declare DWARF types".into(),
            ));
        }
        const MAX_FUNCTIONS: usize = 256;
        let mut unique = Vec::new();
        for address in addresses {
            if !unique.contains(address) {
                unique.push(*address);
            }
        }
        if unique.is_empty() || unique.len() > MAX_FUNCTIONS {
            return Err(DecompileError::Request(format!(
                "a unit needs between 1 and {MAX_FUNCTIONS} functions"
            )));
        }
        let mut bodies = Vec::new();
        for address in unique {
            let result = self.decompile(address, false)?;
            if result
                .exception_handling
                .iter()
                .any(|info| info.owners.contains(&address))
            {
                return Err(DecompileError::Unsupported(
                    "standalone C units cannot represent MSVC C++ exception handling".into(),
                ));
            }
            bodies.push(unit::Body {
                address,
                text: result.text,
                incomplete: result.incomplete,
                unknown_callees: result.unknown_callees,
                unknown_storage: result
                    .notes
                    .iter()
                    .any(|note| note.starts_with("Untyped storage")),
                globals: result.globals,
            });
        }
        let wide = self.convention.wide();
        // The unit's prelude spells the Visual C conventions only.
        if !matches!(
            self.convention,
            CallingConvention::WindowsX64 | CallingConvention::WindowsX86
        ) {
            return Err(DecompileError::Unsupported(
                "self-contained units are only built for Visual C conventions on Windows images"
                    .into(),
            ));
        }
        if let Some(body) = bodies
            .iter()
            .find(|body| unit::names_cpp_symbol(&body.text))
        {
            return Err(DecompileError::Unsupported(format!(
                "self-contained units need C identifiers, and the function at {:#x} names demangled C++ or Rust symbols",
                body.address
            )));
        }
        if self.unit_pack.get().is_none() {
            let pack =
                ctypes::Pack::parse(binfera_ghidra::prototype_pack(self.convention.language()))
                    .map_err(DecompileError::Initialization)?;
            let _ = self.unit_pack.set(pack);
        }
        let pack = self
            .unit_pack
            .get()
            .ok_or_else(|| DecompileError::Initialization("type archive unavailable".into()))?;
        unit::build(pack, wide, &bodies).map_err(DecompileError::Initialization)
    }

    /// A supplied symbol, export, signature or Go name, without decompiling the body.
    pub fn function_name(&self, address: u64) -> Option<String> {
        self.names.get(&address).cloned()
    }

    pub fn decompile_function(&mut self, address: u64) -> Result<Decompilation, DecompileError> {
        self.decompile(address, true)
    }

    fn decompile(
        &mut self,
        address: u64,
        hide_boilerplate: bool,
    ) -> Result<Decompilation, DecompileError> {
        if !self.in_code(address) {
            return Err(DecompileError::Request(format!(
                "{address:#x} is not in executable mapped memory"
            )));
        }
        let started = Instant::now();
        let error = |e: binfera_ghidra::Error| DecompileError::Native {
            address,
            message: e.to_string(),
        };
        // Explicit selection is allowed even if recovery did not discover it.
        let name = self.function_name(address);
        // Go's stack ABI returns results in memory, never in EAX, and pops nothing.
        let supplied = self.explicit_signatures.contains(&address)
            || (self.convention.is_go() && !self.convention.wide());
        let cdecl = !supplied && self.recursive_cdecl.contains(&address);
        // An x86 return can occupy EDX:EAX. Only infer a 32-bit result when
        // a complete leaf cannot compute a high result. The native layer also
        // recognizes undefined local stack values popped into EDX.
        let return_bytes = if !supplied && self.caller_return_uses.get(&address) == Some(&8) {
            8
        } else if !supplied
            && self.x86_forwarded_imports.contains(&address)
            && self.caller_return_uses.get(&address) == Some(&4)
        {
            // The bridge accepts this only with a locked four-byte import prototype.
            1
        } else if !supplied && (self.convention.wide() || self.x86_low32_returns.contains(&address))
        {
            match self
                .caller_return_uses
                .get(&address)
                .copied()
                .unwrap_or_else(|| {
                    if self.x86_low32_returns.contains(&address) {
                        4
                    } else {
                        0
                    }
                }) {
                1 if !self.convention.wide() => 0,
                width => width,
            }
        } else {
            0
        };
        let output = self
            .native
            .decompile_with_hints(
                address,
                self.limits.timeout_ms,
                self.limits.max_instructions,
                self.limits.max_work,
                return_bytes,
                cdecl,
            )
            .map_err(error)?;
        self.warnings.extend(output.file_warnings);
        self.warnings.sort();
        self.warnings.dedup();
        // The native layer decides which of its own warnings mean incomplete.
        let mut warnings = output.warnings;
        if self.caller_return_uses.contains_key(&address)
            && !self.explicit_signatures.contains(&address)
            && output.text.split('{').next().is_some_and(|header| {
                header
                    .lines()
                    .any(|line| line.trim_start().starts_with("void "))
            })
        {
            warnings.push("A caller reads the return register, but this function was decompiled as void; its return value may be missing.".into());
        }
        if !self.explicit_signatures.contains(&address)
            && boolean_return_may_lose_bits(&output.text)
        {
            warnings.push("A boolean return converts a value greater than one; verify that the inferred return type is correct.".into());
        }
        let incomplete = output.incomplete || !warnings.is_empty();
        let mut notes = output.notes;
        // Inferred types remain a quality limitation even without native errors.
        notes.push("Types and prototypes without supplied signatures are inferred; validate pseudocode against machine code.".into());
        let mut line_addresses = line_addresses(
            &output.markup,
            &output.op_times,
            &output.op_addrs,
            &output.text,
        );
        let globals = output
            .globals
            .iter()
            .map(|global| {
                let kind = match global.kind.as_str() {
                    "float" => ValueKind::Float,
                    "signed" => ValueKind::Signed,
                    "unsigned" => ValueKind::Unsigned,
                    "bool" => ValueKind::Bool,
                    "pointer" => ValueKind::Pointer,
                    "unknown" => ValueKind::Unknown,
                    other => {
                        return Err(DecompileError::Native {
                            address,
                            message: format!(
                                "data symbol {} has an unknown type class {other:?}",
                                global.name
                            ),
                        })
                    }
                };
                Ok(GlobalSymbol {
                    name: global.name.clone(),
                    address: global.address,
                    size: global.size,
                    kind,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let comments = self.exceptions.comments(address);
        let mut text = golang_flow::render_duff(&output.text, &self.duff_helpers);
        if let Some(strings) = &self.go_strings {
            text = strings.render(&text);
            text = strings.render_untyped(&text);
        }
        if !self.cfstrings.is_empty() {
            text = macho::render_cfstrings(&text, &self.cfstrings);
        }
        text = stack_strings::render(&text, &mut line_addresses);
        text = memset_loops::render(&text, &mut line_addresses).0;
        text = strlen_loops::render(&text, &mut line_addresses).0;
        if hide_boilerplate {
            let (rendered, hidden_canary) = stack_protector::render(&text, &mut line_addresses);
            text = rendered;
            if hidden_canary {
                notes.push("Compiler stack-protector save and check omitted from pseudocode; the instruction listing retains them.".into());
            }
        }
        if !comments.is_empty() {
            let prefix = comments
                .iter()
                .map(|line| format!("/* {line} */\n"))
                .collect::<String>();
            if !line_addresses.is_empty() {
                line_addresses.splice(0..0, std::iter::repeat_n(Vec::new(), comments.len()));
            }
            text.insert_str(0, &prefix);
            notes.push("MSVC exception tables are annotated; exceptional control flow is not reconstructed as C++ try/catch syntax.".into());
        }
        Ok(Decompilation {
            address,
            name,
            calling_convention: self.convention,
            text,
            line_addresses,
            warnings,
            notes,
            exception_handling: self.exceptions.for_function(address),
            incomplete,
            unknown_callees: output.unknown_callees,
            globals,
            frame: output
                .frame
                .into_iter()
                .map(|slot| StackSlot {
                    name: slot.name,
                    register_name: slot.register_name,
                    offset: slot.offset,
                    size: slot.size,
                    type_name: slot.type_name,
                    parameter: slot.parameter,
                    reads: slot.reads,
                    writes: slot.writes,
                    references: slot.references,
                })
                .collect(),
            timings: DecompilationTimings {
                initialization_ms: self.initialization_ms,
                decompilation_ms: started.elapsed().as_secs_f64() * 1000.0,
                initial_ms: output.initial_ms,
                data_ms: output.data_ms,
                returns_ms: output.returns_ms,
                inference_ms: output.inference_ms,
                print_ms: output.print_ms,
                analysis_passes: output.analysis_passes,
                inference_cache_hits: output.inference_cache_hits,
                inference_cache_misses: output.inference_cache_misses,
                inference_cache_invalidations: output.inference_cache_invalidations,
                inference_cache_evictions: output.inference_cache_evictions,
                inference_invalidation_reasons: output.inference_invalidation_reasons,
            },
        })
    }
}
/// Overlapping unwind records cannot safely establish function ownership.
fn unambiguous_ranges(mut ranges: Vec<(u64, u64)>) -> Vec<binfera_ghidra::CodeRange> {
    ranges.sort_unstable();
    ranges.dedup();
    let mut prior_end = 0;
    let mut result = Vec::new();
    for (index, &(start, end)) in ranges.iter().enumerate() {
        let overlap =
            start < prior_end || ranges.get(index + 1).is_some_and(|&(next, _)| next < end);
        prior_end = prior_end.max(end);
        if !overlap {
            result.push(binfera_ghidra::CodeRange { start, end });
        }
    }
    result
}

/// The function table's names, by entry.
fn go_function_names(go: &GoBinary) -> BTreeMap<u64, String> {
    go.functions
        .functions
        .iter()
        .filter(|function| !golang_names::ignored(&function.name))
        .map(|function| (function.entry, function.name.clone()))
        .collect()
}

/// Collect direct callees whose return register is read before it is overwritten.
/// This is evidence of a missing return, not proof of its type or width.
fn caller_return_uses(analysis: &Analysis) -> BTreeMap<u64, u32> {
    let mut uses = BTreeMap::new();
    if !analysis.image.architecture.is_x86() {
        return uses;
    }
    let mut info = InstructionInfoFactory::new();
    for function in analysis.functions.values() {
        for block in &function.blocks {
            for (index, call) in block.insns.iter().enumerate() {
                if call.flow != Flow::Call {
                    continue;
                }
                let Some(target) = call.direct_target else {
                    continue;
                };
                if analysis.image.architecture == Architecture::X86
                    && reads_edx(&block.insns[index + 1..], &mut info)
                {
                    uses.insert(target, 8);
                    continue;
                }
                if let Some(width) = return_read_width(
                    block.insns[index + 1..]
                        .iter()
                        .map(|insn| insn.x86_instruction()),
                    &mut info,
                ) {
                    uses.entry(target)
                        .and_modify(|previous| {
                            if *previous != width && *previous != 8 {
                                *previous = 0;
                            }
                        })
                        .or_insert(width);
                }
            }
        }
    }
    // A direct jump thunk forwards the entire callee result. A caller that
    // reads only EAX does not establish that the forwarded result is 32-bit.
    for (address, width) in &mut uses {
        if analysis
            .functions
            .get(address)
            .and_then(direct_tail_target)
            .is_some()
        {
            *width = 0;
        }
    }
    uses
}

/// Runtime prototypes that FLIRT names select but the archives do not hold.
fn runtime_prototype(name: &str, wide: bool) -> Option<(ValueType, Vec<ValueType>)> {
    match name.trim_start_matches('_') {
        "security_init_cookie" => Some((ValueType::Void, vec![])),
        "security_check_cookie" if wide => Some((ValueType::Void, vec![ValueType::U64])),
        "DllMainCRTStartup" | "DllMain" => Some((
            ValueType::I32,
            vec![ValueType::Pointer, ValueType::U32, ValueType::Pointer],
        )),
        _ => None,
    }
}

/// The function a chain of single-jump stubs at `address` ends in.
fn jump_stub_target(analysis: &Analysis, address: u64) -> Option<u64> {
    let mut target = direct_tail_target(analysis.functions.get(&address)?)?;
    for _ in 0..8 {
        match analysis.functions.get(&target).and_then(direct_tail_target) {
            Some(next) if next != address => target = next,
            Some(_) => return None,
            None => return Some(target),
        }
    }
    None
}

/// The target of a function whose entry block is one direct jump. Recovery can
/// follow that jump and attach the target's blocks, so only the entry counts.
fn direct_tail_target(function: &recovery::Function) -> Option<u64> {
    let entry = function
        .blocks
        .iter()
        .find(|block| block.addr == function.addr)?;
    let [jump] = entry.insns.as_slice() else {
        return None;
    };
    if jump.address != function.addr || jump.flow != Flow::UnconditionalBranch {
        return None;
    }
    jump.direct_target
}

/// Whether an x86 function's first use of ECX, along its straight-line entry, is a read: the `this`
/// of a `__thiscall` method. `push ecx` alone is neutral (MSVC reserves a stack slot with it), and
/// the walk continues past a call only into a helper that preserves ECX (`__EH_prolog3`).
fn reads_ecx_first(
    function: &recovery::Function,
    preserves_ecx: &dyn Fn(u64) -> bool,
    info: &mut InstructionInfoFactory,
) -> bool {
    let instructions: BTreeMap<u64, &DecodedInstruction> = function
        .blocks
        .iter()
        .flat_map(|block| block.insns.iter())
        .map(|insn| (insn.address, insn))
        .collect();
    let mut address = function.addr;
    for _ in 0..32 {
        let Some(insn) = instructions.get(&address) else {
            return false;
        };
        let instruction = insn.x86_instruction();
        match insn.flow {
            Flow::Call if insn.direct_target.is_some_and(preserves_ecx) => {}
            Flow::Call => return false,
            _ if instruction.flow_control() != FlowControl::Next => return false,
            _ => {
                let push_ecx = instruction.mnemonic() == Mnemonic::Push
                    && instruction.op0_kind() == OpKind::Register
                    && instruction.op0_register() == Register::ECX;
                if !push_ecx {
                    let uses = info.info(instruction);
                    let (mut read, mut written) = (false, false);
                    for used in uses
                        .used_registers()
                        .iter()
                        .filter(|used| used.register().full_register() == Register::RCX)
                    {
                        read |= matches!(
                            used.access(),
                            OpAccess::Read
                                | OpAccess::CondRead
                                | OpAccess::ReadWrite
                                | OpAccess::ReadCondWrite
                        );
                        written |= matches!(used.access(), OpAccess::Write | OpAccess::CondWrite);
                    }
                    if read {
                        return true;
                    }
                    if written {
                        return false;
                    }
                }
            }
        }
        address = insn.next_address;
    }
    false
}

#[cfg(test)]
fn reads_return_before_write<'a>(
    instructions: impl Iterator<Item = &'a Instruction>,
    info: &mut InstructionInfoFactory,
) -> bool {
    return_read_width(instructions, info).is_some()
}

fn return_read_width<'a>(
    instructions: impl Iterator<Item = &'a Instruction>,
    info: &mut InstructionInfoFactory,
) -> Option<u32> {
    for instruction in instructions.take(6) {
        if instruction.flow_control() != FlowControl::Next {
            return None;
        }
        let uses = info.info(instruction);
        let return_uses = uses
            .used_registers()
            .iter()
            .filter(|used| used.register().full_register() == Register::RAX);
        let mut read = false;
        let mut written = false;
        let mut width = 0;
        let mut high_byte = false;
        for used in return_uses {
            let reads = matches!(
                used.access(),
                OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
            );
            read |= reads;
            if reads {
                width = width.max(used.register().size() as u32);
                high_byte |= used.register() == Register::AH;
            }
            written |= matches!(
                used.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            );
        }
        if read {
            return Some(if (width == 1 && !high_byte) || width == 4 || width == 8 {
                width
            } else {
                0
            });
        }
        if written {
            return None;
        }
    }
    None
}

/// On x86, a recursive call whose pushed arguments are immediately removed
/// by its caller, and whose function returns without a stack purge, supplies
/// evidence for cdecl. Other calling conventions remain unconstrained.
fn recursive_cdecl(analysis: &Analysis) -> BTreeSet<u64> {
    let mut result = BTreeSet::new();
    if analysis.image.architecture != Architecture::X86 || analysis.image.format != ImageFormat::Pe
    {
        return result;
    }
    let mut info = InstructionInfoFactory::new();
    for function in analysis.functions.values() {
        let returns: Vec<_> = function
            .blocks
            .iter()
            .flat_map(|block| &block.insns)
            .filter(|insn| insn.flow == Flow::Return)
            .collect();
        if returns.is_empty()
            || returns
                .iter()
                .any(|insn| insn.x86_instruction().op_count() != 0)
        {
            continue;
        }
        for block in &function.blocks {
            for (index, call) in block.insns.iter().enumerate() {
                if call.flow != Flow::Call || call.direct_target != Some(function.addr) {
                    continue;
                }
                if matching_stack_cleanup(&block.insns, index, &mut info) {
                    result.insert(function.addr);
                }
            }
        }
    }
    result
}

fn matching_stack_cleanup(
    insns: &[DecodedInstruction],
    call: usize,
    info: &mut InstructionInfoFactory,
) -> bool {
    let Some(after) = insns.get(call + 1) else {
        return false;
    };
    let op = after.x86_instruction();
    if op.mnemonic() != Mnemonic::Add || op.op0_register() != Register::ESP {
        return false;
    }
    let cleanup = match op.op1_kind() {
        OpKind::Immediate8 => u32::from(op.immediate8()),
        OpKind::Immediate8to32 => u32::try_from(op.immediate8to32()).unwrap_or(0),
        OpKind::Immediate32 => op.immediate32(),
        _ => 0,
    };
    if cleanup == 0 || cleanup > 32 || cleanup % 4 != 0 {
        return false;
    }
    let mut pushed = 0;
    for prior in insns[..call].iter().rev().take(8) {
        let op = prior.x86_instruction();
        if op.mnemonic() == Mnemonic::Push {
            if op.stack_pointer_increment() != -4 {
                break;
            }
            pushed += 4;
            if pushed >= cleanup {
                break;
            }
        } else if prior.flow != Flow::Next
            || info.info(op).used_registers().iter().any(|used| {
                used.register().full_register() == Register::RSP
                    && matches!(
                        used.access(),
                        OpAccess::Write
                            | OpAccess::CondWrite
                            | OpAccess::ReadWrite
                            | OpAccess::ReadCondWrite
                    )
            })
        {
            break;
        }
    }
    pushed == cleanup
}

fn x86_low32_returns(analysis: &Analysis) -> BTreeSet<u64> {
    if analysis.image.architecture != Architecture::X86 {
        return BTreeSet::new();
    }
    let mut info = InstructionInfoFactory::new();
    analysis
        .functions
        .values()
        .filter(|f| {
            closed_leaf_graph(f)
                && x86_low32_leaf(
                    f.blocks
                        .iter()
                        .flat_map(|b| &b.insns)
                        .map(|i| i.x86_instruction()),
                    &mut info,
                )
        })
        .map(|f| f.addr)
        .collect()
}

fn reads_edx(instructions: &[DecodedInstruction], info: &mut InstructionInfoFactory) -> bool {
    for insn in instructions.iter().take(24) {
        if !matches!(insn.flow, Flow::Next | Flow::ConditionalBranch) {
            break;
        }
        let uses = info.info(insn.x86_instruction());
        let mut written = false;
        for used in uses
            .used_registers()
            .iter()
            .filter(|u| u.register().full_register() == Register::RDX)
        {
            if matches!(
                used.access(),
                OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
            ) {
                return true;
            }
            written |= used.access() == OpAccess::Write;
        }
        if written || insn.flow != Flow::Next {
            break;
        }
    }
    false
}

/// A straight-line x86 wrapper can forward a known imported return unchanged.
/// The native bridge still requires the import's locked four-byte prototype.
fn x86_forwarded_imports(analysis: &Analysis) -> BTreeSet<u64> {
    if analysis.image.architecture != Architecture::X86 || analysis.image.format != ImageFormat::Pe
    {
        return BTreeSet::new();
    }
    let mut info = InstructionInfoFactory::new();
    analysis
        .functions
        .values()
        .filter(|function| forwarded_import(function, &analysis.image.import_locations, &mut info))
        .map(|function| function.addr)
        .collect()
}

fn forwarded_import(
    function: &recovery::Function,
    imports: &BTreeMap<u64, String>,
    info: &mut InstructionInfoFactory,
) -> bool {
    let [block] = function.blocks.as_slice() else {
        return false;
    };
    if !block.succs.is_empty() {
        return false;
    }
    let Some(index) = block
        .insns
        .iter()
        .position(|insn| insn.flow == Flow::IndirectCall)
    else {
        return false;
    };
    let call = &block.insns[index];
    if call
        .memory_target
        .and_then(|slot| imports.get(&slot))
        .is_none_or(|name| system_import_function(name).is_none())
    {
        return false;
    }
    if block.insns[..index]
        .iter()
        .any(|insn| insn.flow != Flow::Next)
    {
        return false;
    }
    let after = &block.insns[index + 1..];
    let Some((last, epilogue)) = after.split_last() else {
        return false;
    };
    if last.flow != Flow::Return {
        return false;
    }
    for insn in epilogue {
        if insn.flow != Flow::Next
            || info
                .info(insn.x86_instruction())
                .used_registers()
                .iter()
                .any(|used| {
                    matches!(
                        used.register().full_register(),
                        Register::RAX | Register::RDX
                    ) && matches!(
                        used.access(),
                        OpAccess::Write
                            | OpAccess::CondWrite
                            | OpAccess::ReadWrite
                            | OpAccess::ReadCondWrite
                    )
                })
        {
            return false;
        }
    }
    true
}

fn closed_leaf_graph(function: &recovery::Function) -> bool {
    let starts: BTreeSet<_> = function.blocks.iter().map(|block| block.addr).collect();
    !starts.is_empty()
        && function.blocks.iter().all(|block| {
            let Some(last) = block.insns.last() else {
                return false;
            };
            let complete = match last.flow {
                Flow::Return => block.succs.is_empty(),
                Flow::Next => !block.succs.is_empty(),
                Flow::ConditionalBranch => block.succs.len() >= 2,
                _ => false,
            };
            complete && block.succs.iter().all(|edge| starts.contains(&edge.target))
        })
}

/// A leaf with no EDX use cannot construct a conventional EDX:EAX result.
/// Reject jumps that might leave the recovered function, calls and errors.
fn x86_low32_leaf<'a>(
    instructions: impl Iterator<Item = &'a Instruction>,
    info: &mut InstructionInfoFactory,
) -> bool {
    let mut returns = false;
    let mut writes_eax = false;
    for instruction in instructions {
        match instruction.flow_control() {
            FlowControl::Next | FlowControl::ConditionalBranch => {}
            FlowControl::Return => returns = true,
            _ => return false,
        }
        if instruction.op0_kind() == OpKind::Memory
            && matches!(
                instruction.memory_base().full_register(),
                Register::RSP | Register::RBP
            )
            && matches!(
                info.info(instruction).op0_access(),
                OpAccess::Write
                    | OpAccess::ReadWrite
                    | OpAccess::CondWrite
                    | OpAccess::ReadCondWrite
            )
        {
            return false;
        }
        for used in info.info(instruction).used_registers() {
            let register = used.register().full_register();
            // A discarded local or saved register popped into EDX is not a
            // computed high result. Reject stack stores above to avoid mistaking
            // a constructed stack result for discarded space.
            if register == Register::RDX && instruction.mnemonic() != Mnemonic::Pop {
                return false;
            }
            if register == Register::RAX
                && used.register().size() >= 4
                && matches!(
                    used.access(),
                    OpAccess::Write
                        | OpAccess::CondWrite
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                )
            {
                writes_eax = true;
            }
        }
    }
    returns && writes_eax
}

fn boolean_return_may_lose_bits(text: &str) -> bool {
    let Some((header, body)) = text.split_once('{') else {
        return false;
    };
    if !header
        .lines()
        .any(|line| line.trim_start().starts_with("bool "))
    {
        return false;
    }
    body.lines().any(|line| {
        let Some(value) = line.trim().strip_prefix("return (bool)") else {
            return false;
        };
        let Some(value) = value.trim().strip_suffix(';') else {
            return false;
        };
        let number = if let Some(hex) = value.strip_prefix("0x") {
            u64::from_str_radix(hex, 16)
        } else {
            value.parse::<u64>()
        };
        number.is_ok_and(|number| number > 1)
    })
}
/// Maps each printed line to the instruction addresses behind it, using the `opref` attributes of
/// Ghidra's token markup. Returns nothing unless the markup's line count matches the plain text's,
/// so a misaligned mapping is never shown.
fn line_addresses(markup: &[u8], op_times: &[u32], op_addrs: &[u64], text: &str) -> Vec<Vec<u64>> {
    if markup.is_empty() {
        return Vec::new();
    }
    let address_of: BTreeMap<u32, u64> = op_times
        .iter()
        .copied()
        .zip(op_addrs.iter().copied())
        .collect();
    let markup = String::from_utf8_lossy(markup);
    let mut lines: Vec<std::collections::BTreeSet<u64>> = vec![Default::default()];
    let mut rest = markup.as_ref();
    while let Some(start) = rest.find('<') {
        let Some(end) = rest[start..].find('>') else {
            break;
        };
        let tag = &rest[start + 1..start + end];
        rest = &rest[start + end + 1..];
        if tag.starts_with('/') {
            continue;
        }
        if tag.starts_with("break") {
            lines.push(Default::default());
        } else if let Some(at) = tag.find("opref=\"") {
            let value = &tag[at + 7..];
            let value = value.split('"').next().unwrap_or("");
            let parsed = match value.strip_prefix("0x") {
                Some(hex) => u32::from_str_radix(hex, 16).ok(),
                None => value.parse().ok(),
            };
            if let Some(address) = parsed.and_then(|time| address_of.get(&time)) {
                if let Some(line) = lines.last_mut() {
                    line.insert(*address);
                }
            }
        }
    }
    if lines.len() != text.split('\n').count() {
        return Vec::new();
    }
    lines
        .into_iter()
        .map(|line| line.into_iter().collect())
        .collect()
}

/// Recovered functions whose only instruction is an indirect jump through an import slot,
/// with the import's name.
fn import_thunks(analysis: &Analysis) -> BTreeMap<u64, String> {
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
fn aarch64_import_thunk(analysis: &Analysis, entry: u64) -> Option<(u64, u64)> {
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

fn aarch64_pointer(image: &LoadedImage, slot: u64) -> Option<u64> {
    Some(u64::from_le_bytes(
        image.bytes_at(slot, 8)?.try_into().ok()?,
    ))
}

/// The PLT stubs of a position-independent i386 ELF, `jmp [ebx + disp]`, by the import they jump
/// to. The i386 psABI has `ebx` hold the GOT's address (`DT_PLTGOT`, here `got` after the load
/// bias) whenever PLT code runs, so the slot is `got + disp`. An `endbr32` may come first.
fn pic_plt_thunks(analysis: &Analysis, got: u64) -> BTreeMap<u64, String> {
    let image = &analysis.image;
    let mut thunks = BTreeMap::new();
    for &address in analysis.functions.keys() {
        if !image
            .elf_plt_ranges
            .iter()
            .any(|&(start, end)| start <= address && address < end)
        {
            continue;
        }
        let Some(code) = image.bytes_at(address, 10) else {
            continue;
        };
        let code = code.strip_prefix(&[0xf3, 0x0f, 0x1e, 0xfb]).unwrap_or(code);
        let displacement = match code {
            [0xff, 0xa3, a, b, c, d, ..] => i64::from(i32::from_le_bytes([*a, *b, *c, *d])),
            [0xff, 0x63, d, ..] => i64::from(*d as i8),
            _ => continue,
        };
        let slot = got.wrapping_add_signed(displacement) & 0xffff_ffff;
        if let Some(name) = image.import_locations.get(&slot) {
            thunks.insert(address, name.clone());
        }
    }
    thunks
}

/// The Visual C++ `/GS` check on x86-32: `cmp ecx, [__security_cookie]`, a `jne` over a
/// (possibly `rep`-prefixed) `ret`, then the jump or call to the failure reporter.
/// Both the compiler's `ret` and its `rep ret` form exist, and the `jne` distance is 1 or 2.
fn is_x86_cookie_check(image: &LoadedImage, address: u64) -> bool {
    let Some(code) = image.bytes_at(address, 14) else {
        return false;
    };
    let tail = match code {
        [0x3b, 0x0d, a, b, c, d, rest @ ..] => {
            let slot = u64::from(u32::from_le_bytes([*a, *b, *c, *d]));
            if image.bytes_at(slot, 4).is_none() || image.is_executable_address(slot) {
                return false;
            }
            rest
        }
        _ => return false,
    };
    let tail = match tail {
        [0xf2, rest @ ..] => rest,
        rest => rest,
    };
    let [0x75, skip, rest @ ..] = tail else {
        return false;
    };
    let (ret, rest) = match rest {
        [0xf3 | 0xf2, 0xc3, rest @ ..] => (2u8, rest),
        [0xc3, rest @ ..] => (1u8, rest),
        _ => return false,
    };
    // The branch lands on the instruction after the `ret`.
    *skip == ret && matches!(rest, [0xe9 | 0xe8 | 0xff, ..] | [0xf2, 0xe9, ..])
}

fn validate_image(image: &LoadedImage) -> Result<(), DecompileError> {
    let supported = match image.format {
        ImageFormat::Pe => matches!(
            image.architecture,
            Architecture::X64
                | Architecture::X86
                | Architecture::AArch64
                | Architecture::Arm
                | Architecture::Mips
                | Architecture::MipsBe
        ),
        ImageFormat::Elf | ImageFormat::Macho => matches!(
            image.architecture,
            Architecture::X64
                | Architecture::X86
                | Architecture::AArch64
                | Architecture::Arm
                | Architecture::Mips
                | Architecture::MipsBe
        ),
        ImageFormat::Sc => matches!(image.architecture, Architecture::X86 | Architecture::X64),
    };
    if !supported {
        return Err(DecompileError::Unsupported(format!(
            "{:?} {:?}",
            image.format, image.architecture
        )));
    }
    Ok(())
}

/// The engine rejects names over 256 bytes (functions) and 1024 bytes (symbols). Mangled Rust,
/// Go and C++ names pass that easily, so a long one keeps its start and gains the address, which
/// also keeps two long names that share a prefix apart.
fn bounded_name(name: &str, address: u64) -> String {
    const LIMIT: usize = 200;
    if name.is_empty() {
        return format!("import_{address:x}");
    }
    if name.len() <= LIMIT {
        return name.to_owned();
    }
    let mut end = LIMIT - 20;
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}_{address:x}", &name[..end])
}

/// A class's name as the engine holds it: bounded like any symbol, so a deeply nested template
/// keeps its start and gains its type descriptor's address.
fn class_label(class: &rtti::Class) -> String {
    bounded_name(&class.name, class.type_descriptor)
}

/// The name a function is shown under: a Rust or C++ symbol's demangled label,
/// anything else as it is.
fn display_name(name: &str) -> String {
    demangle::demangle(name).map_or_else(|| name.to_owned(), |demangled| demangled.name)
}

/// The symbol of an import location: `msvcp140.??0_Lockit@std@@QAE@H@Z` on PE, `*._ZdlPv` on ELF.
fn import_symbol(location: &str) -> Option<&str> {
    location.split_once('.').map(|(_, symbol)| symbol)
}

/// An import is shown as `module_name` (`kernel32_GetTickCount`); a Rust or C++ one by its demangled
/// label alone, whose namespaces already say where it comes from.
fn display_import(location: &str) -> String {
    import_symbol(location)
        .and_then(demangle::demangle)
        .map_or_else(|| location.to_owned(), |demangled| demangled.name)
}

/// Lock the prototype a C++ decoration encodes, as Ghidra's demangler analysis does. The name is
/// the sample's own: one the engine cannot hold (a class name past its limits) or a prototype it
/// cannot place leaves that function or import untyped, never the session unusable.
fn demangled_value(scalar: demangle::Scalar) -> ValueType {
    match scalar {
        demangle::Scalar::Void => ValueType::Void,
        demangle::Scalar::Bool => ValueType::Bool,
        demangle::Scalar::I8 => ValueType::I8,
        demangle::Scalar::U8 => ValueType::U8,
        demangle::Scalar::I16 => ValueType::I16,
        demangle::Scalar::U16 => ValueType::U16,
        demangle::Scalar::I32 => ValueType::I32,
        demangle::Scalar::U32 => ValueType::U32,
        demangle::Scalar::I64 => ValueType::I64,
        demangle::Scalar::U64 => ValueType::U64,
        demangle::Scalar::F32 => ValueType::F32,
        demangle::Scalar::F64 => ValueType::F64,
        demangle::Scalar::Pointer => ValueType::Pointer,
        demangle::Scalar::CharPointer => ValueType::CharPointer,
        demangle::Scalar::WideCharPointer => ValueType::WideCharPointer,
    }
}

fn apply_demangled(
    native: &mut binfera_ghidra::Session,
    address: u64,
    prototype: &demangle::Prototype,
) {
    if prototype
        .this_class
        .as_ref()
        .is_some_and(|class| class.len() > 256)
    {
        return;
    }
    let parameters: Vec<ValueType> = prototype
        .parameters
        .iter()
        .map(|p| demangled_value(*p))
        .collect();
    let _ = native.set_method_signature(
        address,
        prototype.convention.model(),
        prototype.this_class.as_deref().unwrap_or(""),
        demangled_value(prototype.result),
        &parameters,
        prototype.varargs,
    );
}

/// The archive function an import is typed by. On Windows that is a system DLL's export (see
/// [`system_import_function`]); on System V the loader records every dynamic import as `*.name`
/// and the C library archive is keyed by the plain name.
fn import_function(convention: CallingConvention, import: &str) -> Option<&str> {
    if convention.is_windows() {
        system_import_function(import)
    } else if convention.is_darwin() {
        let (library, name) = import.rsplit_once('.')?;
        matches!(
            library,
            "libSystem.B"
                | "libSystem"
                | "libobjc.A"
                | "libobjc"
                | "libsystem_c"
                | "libsystem_kernel"
                | "libsystem_pthread"
                | "libdispatch"
                | "Foundation"
                | "CoreFoundation"
                | "AppKit"
                | "Security"
                | "IOKit"
                | "SystemConfiguration"
                | "CoreServices"
        )
        .then_some(name)
        .filter(|name| !name.is_empty() && name.len() <= 256)
    } else {
        // The archive lookup key is bounded; a longer name is a mangled one that no archive holds.
        import
            .strip_prefix("*.")
            .filter(|name| !name.is_empty() && name.len() <= 256)
    }
}

/// The function name of an import from a Windows system DLL, whose prototype
/// Windows, kernel and C library archives describe. Matching by module
/// as well as name keeps a same-named export of an unrelated DLL untyped.
fn system_import_function(name: &str) -> Option<&str> {
    const MODULES: &[&str] = &[
        "kernel32",
        "kernelbase",
        "advapi32",
        "user32",
        "ntdll",
        "ntoskrnl",
        "ntkrnlpa",
        "ntkrnlmp",
        "ntkrpamp",
        "hal",
        "fltmgr",
        "ndis",
        "ws2_32",
        "wsock32",
        "shell32",
        "shlwapi",
        "ole32",
        "oleaut32",
        "gdi32",
        "wininet",
        "winhttp",
        "urlmon",
        "crypt32",
        "secur32",
        "netapi32",
        "iphlpapi",
        "comctl32",
        "comdlg32",
        "psapi",
        "version",
        "winmm",
        "rpcrt4",
        "bcrypt",
        "ncrypt",
        "dbghelp",
        "imm32",
        "mpr",
        "userenv",
        "wtsapi32",
        "msvcrt",
        "ucrtbase",
        "wintrust",
        "setupapi",
        "cfgmgr32",
        "powrprof",
        "dnsapi",
        "ws2help",
        // The Win32 metadata pack (scripts/decompiler_types/pack_win32_metadata.py) types the
        // exports of these system DLLs.
        "activeds",
        "avicap32",
        "avifil32",
        "avrt",
        "cabinet",
        "cldapi",
        "clfsw32",
        "combase",
        "cryptbase",
        "d3d9",
        "dbgeng",
        "dinput8",
        "dwmapi",
        "fltlib",
        "fwpuclnt",
        "gdiplus",
        "hid",
        "httpapi",
        "imagehlp",
        "ktmw32",
        "mscoree",
        "msacm32",
        "msdelta",
        "msimg32",
        "msvfw32",
        "mswsock",
        "normaliz",
        "oleacc",
        "opengl32",
        "rasapi32",
        "rstrtmgr",
        "shcore",
        "shfolder",
        "snmpapi",
        "uxtheme",
        "virtdisk",
        "wer",
        "wevtapi",
        "windowscodecs",
        "winscard",
        "winspool",
        "wlanapi",
        "wldap32",
    ];
    let (module, function) = name.rsplit_once('.')?;
    let module = module.to_ascii_lowercase();
    let module = module
        .strip_suffix(".dll")
        .or_else(|| module.strip_suffix(".exe"))
        .or_else(|| module.strip_suffix(".sys"))
        .unwrap_or(&module);
    // Import names come in Vivisect's `normFileName` form, so the API-set DLLs
    // (`api-ms-win-crt-string-l1-1-0.dll`, the UCRT) arrive as `api_ms_win_...`.
    let api_set = module.starts_with("api-ms-win-") || module.starts_with("api_ms_win_");
    (MODULES.contains(&module) || api_set).then_some(function)
}

fn in_executable_ranges(ranges: &[(u64, u64)], address: u64) -> bool {
    let index = ranges.partition_point(|(start, _)| *start <= address);
    index > 0 && address < ranges[index - 1].1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn function_ownership_excludes_overlaps_but_keeps_adjacent_ranges() {
        let ranges = unambiguous_ranges(vec![
            (0x1000, 0x1020),
            (0x1010, 0x1030),
            (0x1040, 0x1060),
            (0x1040, 0x1060),
            (0x1060, 0x1080),
        ]);
        assert_eq!(
            ranges
                .iter()
                .map(|range| (range.start, range.end))
                .collect::<Vec<_>>(),
            [(0x1040, 0x1060), (0x1060, 0x1080)]
        );
    }

    #[test]
    fn import_thunks_use_the_entry_block_not_the_lowest_block() -> anyhow::Result<()> {
        use crate::extract::image::SHELLCODE_BASE;
        let base = SHELLCODE_BASE;
        let mut bytes = vec![0xeb, 30]; // Enter the wrapper after the lower-addressed PLT stub.
        bytes.resize(16, 0x90);
        bytes.extend([0xff, 0x25, 0, 0, 0, 0]);
        bytes.resize(32, 0x90);
        bytes.extend([0xb9, 7, 0, 0, 0, 0xeb, 0xe9]); // mov ecx,7; jmp stub
        let mut analysis = recovery::analyze_shellcode(&bytes, Architecture::X64)?;
        let mut wrapper = analysis
            .functions
            .remove(&base)
            .ok_or_else(|| anyhow::anyhow!("missing wrapper"))?;
        wrapper.addr = base + 32;
        wrapper.blocks.retain(|block| block.addr != base);
        assert_eq!(
            wrapper.blocks.first().map(|block| block.addr),
            Some(base + 16)
        );
        analysis.functions.insert(base + 32, wrapper);
        analysis
            .image
            .import_locations
            .insert(base + 22, "lib.sink".into());
        assert!(!import_thunks(&analysis).contains_key(&(base + 32)));
        Ok(())
    }

    #[test]
    fn metadata_does_not_exhaust_mapping_slots() -> anyhow::Result<()> {
        use crate::extract::image::{MappedSection, Permissions, SHELLCODE_BASE};

        let mut bytes = vec![0xb8, 42, 0, 0, 0, 0xc3];
        let mut analysis = recovery::analyze_shellcode(&bytes, Architecture::X64)?;
        let code_size = bytes.len() as u64;
        let data = SHELLCODE_BASE + 0x10000;
        bytes.resize(bytes.len() + 10_000, 0);
        analysis.image = LoadedImage::for_test(
            ImageFormat::Pe,
            Architecture::X64,
            SHELLCODE_BASE,
            vec![
                MappedSection {
                    name: ".text".into(),
                    address: SHELLCODE_BASE,
                    virtual_size: code_size,
                    file_offset: 0,
                    file_size: code_size,
                    permissions: Permissions {
                        read: true,
                        write: false,
                        execute: true,
                    },
                },
                MappedSection {
                    name: ".rdata".into(),
                    address: data,
                    virtual_size: 10_000,
                    file_offset: code_size,
                    file_size: 10_000,
                    permissions: Permissions {
                        read: true,
                        write: false,
                        execute: false,
                    },
                },
            ],
            BTreeMap::new(),
            bytes,
        );
        analysis.image.code_exclusions = (data..data + 10_000)
            .step_by(2)
            .map(|address| address..address + 1)
            .collect();
        for executable in [false, true] {
            analysis.image.sections[1].permissions.execute = executable;
            let mut session = DecompilerSession::from_analysis(
                &analysis,
                &BTreeMap::new(),
                CallingConvention::WindowsX64,
            )?;
            session.decompile_function(SHELLCODE_BASE)?;
            assert!(session.is_code_address(SHELLCODE_BASE));
            assert!(!session.is_code_address(data));
            assert_eq!(session.is_code_address(data + 1), executable);
            assert!(session.decompile_function(data).is_err());
        }
        Ok(())
    }

    #[test]
    fn return_use_requires_read_before_clobber_or_branch() {
        fn detects(bytes: &[u8]) -> bool {
            let mut decoder = iced_x86::Decoder::new(64, bytes, iced_x86::DecoderOptions::NONE);
            let mut instructions = Vec::new();
            while decoder.can_decode() {
                instructions.push(decoder.decode());
            }
            reads_return_before_write(instructions.iter(), &mut InstructionInfoFactory::new())
        }
        assert!(detects(&[0x89, 0xc9, 0x01, 0xc3])); // mov ecx,ecx; add ebx,eax
        assert!(!detects(&[0x31, 0xc0, 0x89, 0xc3])); // xor eax,eax; mov ebx,eax
        assert!(!detects(&[0xeb, 0, 0x89, 0xc3])); // jump; mov ebx,eax
    }

    #[test]
    fn return_evidence_preserves_width_and_distinguishes_low_and_high_bytes() {
        fn width(bytes: &[u8]) -> Option<u32> {
            let mut decoder = iced_x86::Decoder::new(64, bytes, iced_x86::DecoderOptions::NONE);
            let mut instructions = Vec::new();
            while decoder.can_decode() {
                instructions.push(decoder.decode());
            }
            return_read_width(instructions.iter(), &mut InstructionInfoFactory::new())
        }
        assert_eq!(width(&[0x89, 0xc3]), Some(4)); // mov ebx,eax
        assert_eq!(width(&[0x48, 0x89, 0xc3]), Some(8)); // mov rbx,rax
        assert_eq!(width(&[0x88, 0xc3]), Some(1)); // mov bl,al, requires Boolean callee corroboration
        assert_eq!(width(&[0x88, 0xe3]), Some(0)); // mov bl,ah
    }

    #[test]
    fn x86_low32_leaf_rejects_high_register_and_forwarded_results() {
        fn leaf(bytes: &[u8]) -> bool {
            let mut decoder = iced_x86::Decoder::new(32, bytes, iced_x86::DecoderOptions::NONE);
            let mut instructions = Vec::new();
            while decoder.can_decode() {
                instructions.push(decoder.decode());
            }
            x86_low32_leaf(instructions.iter(), &mut InstructionInfoFactory::new())
        }
        assert!(leaf(&[0x8b, 0x44, 0x24, 4, 0xc3])); // mov eax,[esp+4]; ret
        assert!(!leaf(&[0x8b, 0x44, 0x24, 4, 0x8b, 0x54, 0x24, 8, 0xc3])); // EDX:EAX
        assert!(!leaf(&[0xe8, 0, 0, 0, 0, 0xc3])); // forwarded call
        assert!(!leaf(&[0xb8, 1, 0, 0, 0])); // no return
        assert!(leaf(&[0x83, 0xec, 4, 0x8b, 0x44, 0x24, 8, 0x5a, 0xc3]));
        assert!(!leaf(&[0x50, 0x89, 0x04, 0x24, 0x5a, 0xc3]));
    }

    #[test]
    fn low32_inference_requires_a_closed_control_flow_graph() {
        let bytes = [0xb8, 1, 0, 0, 0, 0xc3];
        let mut decoder =
            iced_x86::Decoder::with_ip(32, &bytes, 0x1000, iced_x86::DecoderOptions::NONE);
        let mut insns = Vec::new();
        while decoder.can_decode() {
            let instruction = decoder.decode();
            let offset = (instruction.ip() - 0x1000) as usize;
            insns.push(crate::extract::decoder::from_x86(
                instruction.ip(),
                &bytes[offset..offset + instruction.len()],
                instruction,
                None,
            ));
        }
        let mut function = recovery::Function {
            addr: 0x1000,
            blocks: vec![recovery::BasicBlock {
                addr: 0x1000,
                insns,
                succs: Vec::new(),
            }],
        };
        assert!(closed_leaf_graph(&function));
        function.blocks[0].insns.pop();
        assert!(!closed_leaf_graph(&function));
    }

    #[test]
    fn cdecl_evidence_requires_matching_four_byte_pushes() {
        fn matches(bytes: &[u8]) -> bool {
            let mut decoder =
                iced_x86::Decoder::with_ip(32, bytes, 0x1000, iced_x86::DecoderOptions::NONE);
            let mut insns = Vec::new();
            while decoder.can_decode() {
                let instruction = decoder.decode();
                let offset = (instruction.ip() - 0x1000) as usize;
                insns.push(crate::extract::decoder::from_x86(
                    instruction.ip(),
                    &bytes[offset..offset + instruction.len()],
                    instruction,
                    None,
                ));
            }
            let call = insns
                .iter()
                .position(|insn| insn.flow == Flow::Call)
                .unwrap();
            matching_stack_cleanup(&insns, call, &mut InstructionInfoFactory::new())
        }
        assert!(matches(&[0x50, 0xe8, 0, 0, 0, 0, 0x83, 0xc4, 4]));
        assert!(!matches(&[0x50, 0xe8, 0, 0, 0, 0, 0x83, 0xc4, 8]));
        assert!(!matches(&[0x66, 0x50, 0xe8, 0, 0, 0, 0, 0x83, 0xc4, 4]));
        assert!(!matches(&[0x50, 0xe8, 0, 0, 0, 0]));
    }

    #[test]
    fn forwarded_import_requires_an_unchanged_return_register() {
        fn wrapper(bytes: &[u8]) -> recovery::Function {
            let mut decoder =
                iced_x86::Decoder::with_ip(32, bytes, 0x1000, iced_x86::DecoderOptions::NONE);
            let mut insns = Vec::new();
            while decoder.can_decode() {
                let instruction = decoder.decode();
                let offset = (instruction.ip() - 0x1000) as usize;
                insns.push(crate::extract::decoder::from_x86(
                    instruction.ip(),
                    &bytes[offset..offset + instruction.len()],
                    instruction,
                    None,
                ));
            }
            recovery::Function {
                addr: 0x1000,
                blocks: vec![recovery::BasicBlock {
                    addr: 0x1000,
                    insns,
                    succs: Vec::new(),
                }],
            }
        }
        let imports = BTreeMap::from([(0x2000, "user32.MessageBoxA".into())]);
        let mut info = InstructionInfoFactory::new();
        assert!(forwarded_import(
            &wrapper(&[0xff, 0x15, 0, 0x20, 0, 0, 0x5d, 0xc3]),
            &imports,
            &mut info
        ));
        assert!(!forwarded_import(
            &wrapper(&[0xff, 0x15, 0, 0x20, 0, 0, 0x31, 0xc0, 0xc3]),
            &imports,
            &mut info
        ));
        assert!(!forwarded_import(
            &wrapper(&[0xff, 0x15, 4, 0x20, 0, 0, 0xc3]),
            &imports,
            &mut info
        ));
    }

    #[test]
    fn direct_tail_thunks_do_not_prove_a_return_width() {
        fn function(bytes: &[u8]) -> recovery::Function {
            let mut decoder =
                iced_x86::Decoder::with_ip(64, bytes, 0x1000, iced_x86::DecoderOptions::NONE);
            let mut insns = Vec::new();
            while decoder.can_decode() {
                let instruction = decoder.decode();
                let offset = (instruction.ip() - 0x1000) as usize;
                let encoded = &bytes[offset..offset + instruction.len()];
                insns.push(crate::extract::decoder::from_x86(
                    instruction.ip(),
                    encoded,
                    instruction,
                    None,
                ));
            }
            recovery::Function {
                addr: 0x1000,
                blocks: vec![recovery::BasicBlock {
                    addr: 0x1000,
                    insns,
                    succs: Vec::new(),
                }],
            }
        }
        assert_eq!(
            direct_tail_target(&function(&[0xe9, 0, 0, 0, 0])),
            Some(0x1005)
        );
        assert_eq!(direct_tail_target(&function(&[0xff, 0xe0])), None); // jmp rax
        assert_eq!(
            direct_tail_target(&function(&[0x90, 0xe9, 0, 0, 0, 0])),
            None
        );
    }

    #[test]
    fn pe_jump_stub_is_found_when_recovery_attaches_its_target() -> anyhow::Result<()> {
        // A minimal PE32+ with one executable section at RVA 0x1000.
        let mut bytes = vec![0; 0x1200];
        let put = |bytes: &mut [u8], at: usize, value: u32| {
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        };
        bytes[..2].copy_from_slice(b"MZ");
        put(&mut bytes, 0x3c, 0x80);
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        bytes[0x96..0x98].copy_from_slice(&0x22u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        put(&mut bytes, 0x98 + 16, 0x1000);
        bytes[0xb0..0xb8].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        for (offset, value) in [
            (32, 0x1000),
            (36, 0x200),
            (56, 0x2000),
            (60, 0x200),
            (108, 16),
        ] {
            put(&mut bytes, 0x98 + offset, value);
        }
        bytes[0x188..0x190].copy_from_slice(b".text\0\0\0");
        for (offset, value) in [
            (8, 0x200),
            (12, 0x1000),
            (16, 0x200),
            (20, 0x1000),
            (36, 0x60000020),
        ] {
            put(&mut bytes, 0x188 + offset, value);
        }
        let code = [
            0x48, 0x83, 0xec, 0x28, // sub rsp, 0x28
            0xe8, 0x27, 0, 0, 0, // call helper (0x1030)
            0xe8, 0x12, 0, 0, 0, // call stub (0x1020)
            0x48, 0x83, 0xc4, 0x28, // add rsp, 0x28
            0xc3, // ret
        ];
        bytes[0x1000..0x1000 + code.len()].copy_from_slice(&code);
        bytes[0x1020..0x1025].copy_from_slice(&[0xe9, 0x0b, 0, 0, 0]); // jmp helper
        bytes[0x1030] = 0xc3;
        let analysis = recovery::analyze(&bytes)?;
        let (stub, helper) = (0x1_4000_1020, 0x1_4000_1030);
        assert_eq!(jump_stub_target(&analysis, stub), Some(helper));
        Ok(())
    }

    #[test]
    fn x64_jump_stub_chain_inherits_fixup_and_prototype() -> anyhow::Result<()> {
        use crate::extract::image::SHELLCODE_BASE;

        let mut bytes = vec![0xcc; 0x31];
        let caller = [
            0x48, 0x83, 0xec, 0x28, // sub rsp, 0x28
            0xe8, 0x27, 0, 0, 0, // call helper directly, so recovery has its entry
            0xb8, 0x2a, 0, 0, 0, // mov eax, 42
            0xe8, 0x0d, 0, 0, 0, // call the first stub
            0x48, 0x83, 0xc4, 0x28, // add rsp, 0x28
            0xc3, // ret
        ];
        bytes[..caller.len()].copy_from_slice(&caller);
        bytes[0x20..0x22].copy_from_slice(&[0xeb, 0x06]); // jmp second stub
        bytes[0x28..0x2a].copy_from_slice(&[0xeb, 0x06]); // jmp helper
        bytes[0x30] = 0xc3;
        let mut analysis = recovery::analyze_shellcode(&bytes, Architecture::X64)?;
        let (first, second, target) = (
            SHELLCODE_BASE + 0x20,
            SHELLCODE_BASE + 0x28,
            SHELLCODE_BASE + 0x30,
        );
        // Raw-code recovery has no entry for the second stub; give both stubs one.
        for stub in [first, second] {
            let insn = analysis
                .instructions
                .get(&stub)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("stub {stub:#x} was not decoded"))?;
            analysis.functions.insert(
                stub,
                recovery::Function {
                    addr: stub,
                    blocks: vec![recovery::BasicBlock {
                        addr: stub,
                        insns: vec![insn],
                        succs: Vec::new(),
                    }],
                },
            );
        }
        assert_eq!(jump_stub_target(&analysis, first), Some(target));
        assert_eq!(jump_stub_target(&analysis, second), Some(target));
        let session = |analysis: &Analysis| -> anyhow::Result<DecompilerSession> {
            let mut session = DecompilerSession::from_analysis(
                analysis,
                &BTreeMap::new(),
                CallingConvention::WindowsX64,
            )?;
            session
                .native
                .set_call_fixup(target, "security_check_cookie")?;
            Ok(session)
        };
        let mut plain = session(&analysis)?;
        let before = plain.decompile_function(SHELLCODE_BASE)?;
        assert!(!before.text.contains("return 0x2a;"), "{}", before.text);

        let mut fixed = session(&analysis)?;
        fixed.inherit_through_jump_stubs(
            &analysis,
            &BTreeMap::from([(target, "security_check_cookie")]),
            &BTreeMap::new(),
            &BTreeSet::new(),
        )?;
        let after = fixed.decompile_function(SHELLCODE_BASE)?;
        assert!(after.text.contains("return 0x2a;"), "{}", after.text);
        assert!(after
            .notes
            .iter()
            .any(|note| note.contains("replaced with injection: security_check_cookie")));

        let mut typed = session(&analysis)?;
        typed.inherit_through_jump_stubs(
            &analysis,
            &BTreeMap::new(),
            &BTreeMap::from([(target, ("DllMain", true))]),
            &BTreeSet::from([second]),
        )?;
        let stub = typed.decompile_function(first)?;
        assert!(stub.text.contains("param_3"), "{}", stub.text);
        let untouched = typed.decompile_function(second)?;
        assert!(!untouched.text.contains("param_3"), "{}", untouched.text);
        Ok(())
    }

    #[test]
    fn boolean_return_warning_requires_a_non_boolean_constant() {
        assert!(boolean_return_may_lose_bits(
            "bool f(void) {\n return (bool)3;\n}"
        ));
        assert!(!boolean_return_may_lose_bits(
            "bool f(void) {\n return (bool)1;\n}"
        ));
        assert!(!boolean_return_may_lose_bits(
            "int f(void) {\n return (bool)3;\n}"
        ));
    }

    #[test]
    fn system_imports_match_in_the_loader_name_form() {
        assert_eq!(
            system_import_function("kernel32.CreateFileA"),
            Some("CreateFileA")
        );
        assert_eq!(
            system_import_function("api_ms_win_crt_string_l1_1_0.strlen"),
            Some("strlen")
        );
        assert_eq!(
            system_import_function("api_ms_win_core_synch_l1_2_0.Sleep"),
            Some("Sleep")
        );
        assert_eq!(system_import_function("mylib.strlen"), None);
        assert_eq!(system_import_function("strlen"), None);
    }

    #[test]
    fn kernel_imports_match_normalized_and_explicit_module_names() {
        for module in [
            "ntoskrnl",
            "ntkrnlpa",
            "ntkrnlmp",
            "ntkrpamp",
            "hal",
            "fltmgr",
            "ndis",
            "NTOSKRNL.EXE",
            "HAL.DLL",
            "FLTMGR.SYS",
            "NDIS.SYS",
        ] {
            let name = format!("{module}.KernelExport");
            assert_eq!(system_import_function(&name), Some("KernelExport"));
        }
        assert_eq!(system_import_function("custom.sys.IoCreateDevice"), None);
        assert_eq!(system_import_function("fake_ntoskrnl.IoCreateDevice"), None);
        assert_eq!(system_import_function("IoCreateDevice"), None);
    }
}

#[cfg(test)]
mod aarch64_tests {
    use super::*;
    use crate::extract::image::SHELLCODE_BASE;

    #[test]
    fn thunk_requires_a_matching_branch_and_accepts_bti() -> anyhow::Result<()> {
        // adrp x16, current page; ldr x17,[x16,#32]; add x16,x16,#32; br x17
        let words = [0x90000010u32, 0xf9401211, 0x91008210, 0xd61f0220];
        for bti in [false, true] {
            let prefix = if bti { vec![0xd503245fu32] } else { Vec::new() };
            let code: Vec<u8> = prefix
                .iter()
                .chain(words.iter())
                .flat_map(|w| w.to_le_bytes())
                .collect();
            let mut analysis = recovery::analyze_shellcode(&code, Architecture::AArch64)?;
            analysis
                .image
                .import_locations
                .insert(SHELLCODE_BASE + 32, "*.puts".into());
            let branch = SHELLCODE_BASE + if bti { 16 } else { 12 };
            assert_eq!(
                aarch64_import_thunk(&analysis, SHELLCODE_BASE),
                Some((branch, SHELLCODE_BASE + 32))
            );
        }
        for replacement in [0xd61f0200u32, 0xd65f03c0, 0xd63f0220] {
            let mut wrong = words;
            wrong[3] = replacement; // br x16, ret, blr x17
            let code: Vec<u8> = wrong.iter().flat_map(|w| w.to_le_bytes()).collect();
            let mut analysis = recovery::analyze_shellcode(&code, Architecture::AArch64)?;
            analysis
                .image
                .import_locations
                .insert(SHELLCODE_BASE + 32, "*.puts".into());
            assert_eq!(aarch64_import_thunk(&analysis, SHELLCODE_BASE), None);
        }
        Ok(())
    }
}
