//! FLIRT signature loading and library-function recognition.
//!
//! The matching behavior follows the pinned `viv_utils/flirt.py`: signature
//! files are applied in deterministic order, recursive reference names are
//! validated, conflicting root names are rejected, and the first signature
//! database that recognizes a function wins.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use lancelot_flirt::{FlirtSignature, Name, SigElement, Symbol};

use crate::address::Address;
use crate::features::Feature;
use crate::freeze::{BasicBlockFeatures, FunctionFeatures, InstructionFeatures, StaticFeatures};
use crate::parallel::{self, AnalysisOptions};

use crate::bundled::bundled;

use super::aarch64_basicblock_features;
use super::aarch64_features;
use super::basicblock_features;
use super::engine::{Analysis, EdgeKind, Function};
use super::function_features;
use super::image::{Architecture, ImageFormat};
use super::insn_features::{self, InsnContext};

const MATCH_WINDOW: usize = 0x1_0000;

#[cfg(feature = "decompiler")]
static RUNTIME_CRT_BYTES: &[u8] = include_bytes!("../../../sigs/1_flare_msvc_rtf_32_64.sig");

/// A bundled signature database: its file name and contents.
type NamedSignatures = (&'static str, Cow<'static, [u8]>);

/// The default databases, in first-file-wins order.
fn default_signatures() -> Result<Vec<NamedSignatures>, FlirtError> {
    let load = |name: &'static str, bytes: Result<Cow<'static, [u8]>, String>| {
        bytes
            .map(|bytes| (name, bytes))
            .map_err(|context| FlirtError::Io {
                path: PathBuf::from(format!("(bundled signatures)/{name}")),
                context,
            })
    };
    Ok(vec![
        load(
            "1_flare_msvc_rtf_32_64.sig",
            bundled!("1_flare_msvc_rtf_32_64.sig"),
        )?,
        load(
            "2_flare_msvc_atlmfc_32_64.sig",
            bundled!("2_flare_msvc_atlmfc_32_64.sig"),
        )?,
        load(
            "3_flare_common_libs.sig",
            bundled!("3_flare_common_libs.sig"),
        )?,
    ])
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum FlirtError {
    #[error("signature pack targets {expected}, image is {actual}")]
    ArchitectureMismatch { expected: String, actual: String },
    #[error("signature path {path} does not exist")]
    MissingPath { path: PathBuf },
    #[error("reading signature path {path}: {context}")]
    Io { path: PathBuf, context: String },
    #[error("unsupported signature file extension: {path}")]
    UnsupportedExtension { path: PathBuf },
    #[error("parsing signature file {path}: {context}")]
    Parse { path: PathBuf, context: String },
    #[error("compiling signature file {path}: matcher panicked")]
    CompilePanic { path: PathBuf },
    #[error("matching signature file {path} at {address:#x}: matcher panicked")]
    MatchPanic { path: PathBuf, address: u64 },
    #[error("matching signature file {path} at {address:#x}: matched signature has no root name")]
    MissingRootName { path: PathBuf, address: u64 },
}

struct SignatureDatabase {
    path: PathBuf,
    matcher: SignatureMatcher,
}

/// Compact lossless index over lancelot's parsed signatures.
///
/// `lancelot_flirt::FlirtSignatureSet` builds a one-pattern-per-leaf decision
/// tree. Wildcard patterns are copied into every applicable branch, which
/// makes the pinned 14 MiB signature corpus take hundreds of MiB and seconds
/// to initialize. The first eight head bytes are enough to form a selective
/// index without changing any matching rule: candidates still pass through
/// lancelot's head, CRC, tail-byte, and footer checks below.
struct SignatureMatcher {
    signatures: Vec<FlirtSignature>,
    prefix_shapes: Vec<(u8, u8)>,
    prefixes: HashMap<(u8, u8, u64), Vec<usize>>,
}

impl SignatureMatcher {
    const PREFIX_LEN: usize = 8;

    fn with_signatures(signatures: Vec<FlirtSignature>) -> Self {
        let mut shapes = BTreeSet::new();
        let mut prefixes: HashMap<(u8, u8, u64), Vec<usize>> = HashMap::new();
        for (index, signature) in signatures.iter().enumerate() {
            let (length, mask, value) = signature_prefix(signature);
            shapes.insert((length, mask));
            prefixes
                .entry((length, mask, value))
                .or_default()
                .push(index);
        }
        Self {
            signatures,
            prefix_shapes: shapes.into_iter().collect(),
            prefixes,
        }
    }

    fn r#match(&self, bytes: &[u8]) -> Vec<&FlirtSignature> {
        let mut candidates = Vec::new();
        for &(length, mask) in &self.prefix_shapes {
            let length = usize::from(length);
            if bytes.len() < length {
                continue;
            }
            let value = masked_prefix_value(&bytes[..length], mask);
            if let Some(indices) = self.prefixes.get(&(length as u8, mask, value)) {
                candidates.extend(indices.iter().copied());
            }
        }
        candidates.sort_unstable();
        candidates.dedup();
        candidates
            .into_iter()
            .filter_map(|index| self.signatures.get(index))
            .filter(|signature| signature_head_matches(signature, bytes))
            .filter(|signature| signature.match_crc16(bytes))
            .filter(|signature| signature.match_tail_bytes(bytes))
            .filter(|signature| signature.match_footer(bytes))
            .collect()
    }

    fn has_local_candidate(&self, bytes: &[u8]) -> bool {
        self.prefix_shapes.iter().any(|&(length, mask)| {
            let Some(prefix) = bytes.get(..usize::from(length)) else {
                return false;
            };
            let key = (length, mask, masked_prefix_value(prefix, mask));
            self.prefixes.get(&key).is_some_and(|indices| {
                indices
                    .iter()
                    .filter_map(|index| self.signatures.get(*index))
                    .any(|signature| {
                        signature
                            .names
                            .iter()
                            .any(|symbol| matches!(symbol, Symbol::Local(name) if name.offset != 0))
                    })
            })
        })
    }
}

fn signature_prefix(signature: &FlirtSignature) -> (u8, u8, u64) {
    let head_len = effective_head_len(signature).min(SignatureMatcher::PREFIX_LEN);
    let mut mask = 0u8;
    let mut value = 0u64;
    for (index, element) in signature.byte_sig.0.iter().take(head_len).enumerate() {
        if let SigElement::Byte(byte) = element {
            mask |= 1 << index;
            value |= u64::from(*byte) << (index * 8);
        }
    }
    (head_len as u8, mask, value)
}

fn masked_prefix_value(bytes: &[u8], mask: u8) -> u64 {
    bytes
        .iter()
        .enumerate()
        .filter(|(index, _)| mask & (1 << index) != 0)
        .fold(0u64, |value, (index, byte)| {
            value | (u64::from(*byte) << (index * 8))
        })
}

fn effective_head_len(signature: &FlirtSignature) -> usize {
    // `FlirtSignatureSet::with_signatures` indexes the complete byte pattern;
    // its separate single-signature regex helper truncates short functions,
    // but that helper is not used by binfera's set-matching path.
    signature.byte_sig.0.len()
}

fn signature_head_matches(signature: &FlirtSignature, bytes: &[u8]) -> bool {
    let head_len = effective_head_len(signature);
    if bytes.len() < head_len {
        return false;
    }
    signature
        .byte_sig
        .0
        .iter()
        .take(head_len)
        .zip(bytes)
        .all(|(element, byte)| match element {
            SigElement::Byte(expected) => expected == byte,
            SigElement::Wildcard => true,
        })
}

/// Ordered FLIRT databases. Keeping databases separate preserves upstream's
/// first-file-wins behavior instead of creating false ambiguity across files.
#[derive(Clone)]
pub struct Signatures {
    architecture: Option<Architecture>,
    databases: Arc<[Arc<SignatureDatabase>]>,
}

// Native decompilation and compatibility recovery use the same CRT database.
// Share its parsed matcher while retaining each caller's database ordering.
fn embedded_database(name: &str, bytes: &[u8]) -> Result<Arc<SignatureDatabase>, FlirtError> {
    let parse = || {
        parse_database(
            PathBuf::from(format!("(embedded signatures)/{name}")),
            bytes,
        )
        .map(Arc::new)
    };
    #[cfg(feature = "decompiler")]
    if name == "1_flare_msvc_rtf_32_64.sig" && bytes == RUNTIME_CRT_BYTES {
        static CRT: OnceLock<Result<Arc<SignatureDatabase>, FlirtError>> = OnceLock::new();
        return CRT.get_or_init(parse).clone();
    }
    parse()
}

impl Signatures {
    /// The bundled MSVC runtime database covers both older CRT and UCRT builds.
    /// Cache the parsed index; keep matching ambiguity and reference checks intact.
    #[cfg(feature = "decompiler")]
    pub(crate) fn decompiler_runtime() -> Result<Self, FlirtError> {
        static RUNTIME: OnceLock<Result<Signatures, FlirtError>> = OnceLock::new();
        RUNTIME
            .get_or_init(|| {
                let database = embedded_database("1_flare_msvc_rtf_32_64.sig", RUNTIME_CRT_BYTES)?;
                let kernel = embedded_database(
                    "kernel-runtime.pat",
                    include_bytes!("../../../sigs/kernel-runtime.pat"),
                )?;
                Ok(Self {
                    architecture: None,
                    databases: vec![database, kernel].into(),
                })
            })
            .clone()
    }

    /// Shares immutable bundled databases, initialized once and retained until
    /// process exit. Cloning this handle does not copy parsed signatures.
    pub fn embedded() -> Result<Self, FlirtError> {
        Self::embedded_with_options(&AnalysisOptions::SERIAL)
    }

    /// Like [`Self::embedded`], using the first caller's job count to load the
    /// databases. Later callers reuse that result regardless of their job count.
    pub fn embedded_with_options(options: &AnalysisOptions) -> Result<Self, FlirtError> {
        // Bundled bytes are immutable for the life of the process. OnceLock
        // serializes concurrent first callers; later analyses share the parsed
        // databases. Custom paths deliberately bypass this cache.
        static EMBEDDED: OnceLock<Result<Signatures, FlirtError>> = OnceLock::new();
        EMBEDDED
            .get_or_init(|| {
                let defaults = default_signatures()?;
                let databases = parallel::try_map(options.jobs, &defaults, |(name, bytes)| {
                    embedded_database(name, bytes)
                })?;
                Ok(Self {
                    architecture: None,
                    databases: databases.into(),
                })
            })
            .clone()
    }

    /// Loads one `.sig`, `.pat`, or `.pat.gz` file, or every such file under
    /// a directory. Directory entries are sorted by filename like
    /// `capa.loader.get_signatures`, with full path as a deterministic tie
    /// breaker for equally named files in separate subdirectories.
    pub fn from_path(path: &Path) -> Result<Self, FlirtError> {
        Self::from_path_with_options(path, &AnalysisOptions::SERIAL)
    }

    pub fn from_path_with_options(
        path: &Path,
        options: &AnalysisOptions,
    ) -> Result<Self, FlirtError> {
        if !path.exists() {
            return Err(FlirtError::MissingPath {
                path: path.to_path_buf(),
            });
        }
        if path.extension().is_some_and(|ext| ext == "json") {
            return Self::from_manifest(path);
        }
        let mut paths = Vec::new();
        if path.is_file() {
            if !is_supported_signature(path) {
                return Err(FlirtError::UnsupportedExtension {
                    path: path.to_path_buf(),
                });
            }
            paths.push(path.to_path_buf());
        } else {
            collect_signature_paths(path, &mut paths)?;
        }
        paths.sort_by(|left, right| {
            left.file_name()
                .cmp(&right.file_name())
                .then_with(|| left.cmp(right))
        });

        let databases = parallel::try_map(options.jobs, &paths, |path| {
            let bytes = read_signature_file(path)?;
            parse_database(path.clone(), &bytes).map(Arc::new)
        })?;
        Ok(Self {
            architecture: None,
            databases: databases.into(),
        })
    }

    /// Loads an explicit, ordered list of `.sig`/`.pat`/`.pat.gz` files,
    /// preserving first-database-wins order across the list (unlike
    /// [`Signatures::from_path`] on a directory, which re-sorts by
    /// filename). Needed so difftest/parity harnesses can reproduce the
    /// pinned Python test suite's `sigpaths` lists exactly, where the
    /// test-only `.pat` signatures are listed before the default `.sig`
    /// files.
    pub fn from_paths(paths: &[PathBuf]) -> Result<Self, FlirtError> {
        let mut databases = Vec::with_capacity(paths.len());
        for path in paths {
            if !path.exists() {
                return Err(FlirtError::MissingPath { path: path.clone() });
            }
            if !is_supported_signature(path) {
                return Err(FlirtError::UnsupportedExtension { path: path.clone() });
            }
            let bytes = read_signature_file(path)?;
            databases.push(Arc::new(parse_database(path.clone(), &bytes)?));
        }
        Ok(Self {
            architecture: None,
            databases: databases.into(),
        })
    }

    /// A manifest is required to opt a pack into a specific non-x86 ISA.
    /// Untagged legacy files retain the pinned x86 PE matching behavior.
    fn from_manifest(path: &Path) -> Result<Self, FlirtError> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Manifest {
            architecture: String,
            signatures: Vec<PathBuf>,
        }
        let error = |context: String| FlirtError::Parse {
            path: path.into(),
            context,
        };
        let bytes = fs::read(path).map_err(|e| error(e.to_string()))?;
        if bytes.len() > 1 << 20 {
            return Err(error("signature manifest exceeds 1 MiB".into()));
        }
        let manifest: Manifest =
            serde_json::from_slice(&bytes).map_err(|e| error(e.to_string()))?;
        let architecture = match manifest.architecture.as_str() {
            "arm" => Architecture::Arm,
            "aarch64" => Architecture::AArch64,
            "mips" => Architecture::MipsBe,
            "mipsel" => Architecture::Mips,
            "x86" => Architecture::X86,
            "x64" => Architecture::X64,
            _ => return Err(error("unknown signature architecture".into())),
        };
        if manifest.signatures.is_empty() || manifest.signatures.len() > 256 {
            return Err(error("manifest requires 1 to 256 signature files".into()));
        }
        let root = path.parent().unwrap_or_else(|| Path::new("."));
        let mut paths = Vec::new();
        for file in manifest.signatures {
            if file
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
            {
                return Err(error(
                    "signature paths must stay within the pack directory".into(),
                ));
            }
            paths.push(root.join(file));
        }
        let mut signatures = Self::from_paths(&paths)?;
        signatures.architecture = Some(architecture);
        Ok(signatures)
    }

    pub fn is_empty(&self) -> bool {
        self.databases.is_empty()
    }
}

fn collect_signature_paths(directory: &Path, out: &mut Vec<PathBuf>) -> Result<(), FlirtError> {
    let entries = fs::read_dir(directory).map_err(|error| FlirtError::Io {
        path: directory.to_path_buf(),
        context: error.to_string(),
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| FlirtError::Io {
            path: directory.to_path_buf(),
            context: error.to_string(),
        })?;
        let file_type = entry.file_type().map_err(|error| FlirtError::Io {
            path: entry.path(),
            context: error.to_string(),
        })?;
        if file_type.is_dir() {
            collect_signature_paths(&entry.path(), out)?;
        } else if file_type.is_file() && is_supported_signature(&entry.path()) {
            out.push(entry.path());
        }
    }
    Ok(())
}

fn is_supported_signature(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    name.ends_with(".sig") || name.ends_with(".pat") || name.ends_with(".pat.gz")
}

fn read_signature_file(path: &Path) -> Result<Vec<u8>, FlirtError> {
    let bytes = fs::read(path).map_err(|error| FlirtError::Io {
        path: path.to_path_buf(),
        context: error.to_string(),
    })?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !name.ends_with(".pat.gz") {
        return Ok(bytes);
    }
    let mut decoded = Vec::new();
    flate2::read::GzDecoder::new(bytes.as_slice())
        .read_to_end(&mut decoded)
        .map_err(|error| FlirtError::Parse {
            path: path.to_path_buf(),
            context: format!("decompressing gzip data: {error}"),
        })?;
    Ok(decoded)
}

fn parse_database(path: PathBuf, bytes: &[u8]) -> Result<SignatureDatabase, FlirtError> {
    let lower_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let parsed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if lower_name.ends_with(".sig") {
            lancelot_flirt::sig::parse(bytes).map_err(|error| error.to_string())
        } else {
            let text =
                std::str::from_utf8(bytes).map_err(|error| format!("PAT is not UTF-8: {error}"))?;
            lancelot_flirt::pat::parse(&text.replace("\r\n", "\n"))
                .map_err(|error| error.to_string())
        }
    }))
    .map_err(|_| FlirtError::Parse {
        path: path.clone(),
        context: "parser panicked".to_string(),
    })?
    .map_err(|error| FlirtError::Parse {
        path: path.clone(),
        context: error.to_string(),
    })?;

    let matcher = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        SignatureMatcher::with_signatures(parsed)
    }))
    .map_err(|_| FlirtError::CompilePanic { path: path.clone() })?;
    Ok(SignatureDatabase { path, matcher })
}

/// port of `viv_utils/flirt.py:get_match_name`: the function's root name is
/// *any* name at offset 0, regardless of symbol kind (public/local/
/// reference) -- unlike `lancelot_flirt::FlirtSignature::get_name()`, which
/// only recognizes a `Public` name at offset 0 and so misses signatures
/// whose offset-0 entry happens to be `Local`, wrongly rejecting them as
/// rootless.
fn root_name(candidate: &FlirtSignature) -> Option<&str> {
    for symbol in &candidate.names {
        let name = match symbol {
            Symbol::Public(name) | Symbol::Local(name) | Symbol::Reference(name) => name,
        };
        if name.offset == 0 {
            return Some(&name.name);
        }
    }
    None
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CacheEntry {
    Visiting,
    Complete(Option<String>),
}

struct MatcherState<'a> {
    analysis: &'a Analysis,
    database: &'a SignatureDatabase,
    code_xrefs_from: Option<&'a BTreeMap<u64, Vec<u64>>>,
    data_xrefs_from: Option<&'a BTreeMap<u64, Vec<u64>>>,
    recognized: &'a mut BTreeMap<u64, String>,
    cache: BTreeMap<u64, CacheEntry>,
    function_order: usize,
    location_count: usize,
    local_starts: &'a mut BTreeSet<u64>,
}

pub(super) struct Discovery {
    signatures: Signatures,
    recognized: BTreeMap<u64, String>,
}

impl Discovery {
    pub(super) fn new(signatures: Signatures) -> Self {
        Self {
            signatures,
            recognized: BTreeMap::new(),
        }
    }

    pub(super) fn function_completed(
        &mut self,
        analysis: &Analysis,
        address: u64,
    ) -> Result<BTreeSet<u64>, FlirtError> {
        let mut locals = BTreeSet::new();
        let Some(prefix) = analysis
            .image
            .bytes_at(address, SignatureMatcher::PREFIX_LEN)
        else {
            return Ok(locals);
        };
        if !self
            .signatures
            .databases
            .iter()
            .any(|database| database.matcher.has_local_candidate(prefix))
        {
            return Ok(locals);
        }
        for database in self.signatures.databases.iter() {
            if self.recognized.contains_key(&address) {
                break;
            }
            let mut state = MatcherState {
                analysis,
                database,
                code_xrefs_from: None,
                data_xrefs_from: None,
                recognized: &mut self.recognized,
                cache: BTreeMap::new(),
                function_order: usize::MAX,
                location_count: usize::MAX,
                local_starts: &mut locals,
            };
            state.match_function(address)?;
        }
        Ok(locals)
    }
}

fn index_xrefs_by_source(index: &BTreeMap<u64, Vec<u64>>) -> BTreeMap<u64, Vec<u64>> {
    let mut by_source = BTreeMap::<u64, Vec<u64>>::new();
    for (target, sources) in index {
        for source in sources {
            by_source.entry(*source).or_default().push(*target);
        }
    }
    by_source
}

/// Identifies recovered library functions. Legacy packs are x86 PE-only;
/// explicitly scoped manifests can target another ISA and native container.
pub fn identify_library_functions(
    analysis: &Analysis,
    signatures: &Signatures,
) -> Result<BTreeMap<u64, String>, FlirtError> {
    identify_with_local_starts(analysis, signatures).map(|(libraries, _)| libraries)
}

/// Undefined local symbols cause makeFunction in viv_utils/flirt.py. Recovery
/// consumes these starts before the fallback function-entry scan.
pub(super) fn identify_with_local_starts(
    analysis: &Analysis,
    signatures: &Signatures,
) -> Result<(BTreeMap<u64, String>, BTreeSet<u64>), FlirtError> {
    if let Some(architecture) = signatures.architecture {
        if architecture != analysis.image.architecture {
            return Err(FlirtError::ArchitectureMismatch {
                expected: architecture.name().into(),
                actual: analysis.image.architecture.name().into(),
            });
        }
    } else if analysis.image.format != ImageFormat::Pe || !analysis.image.architecture.is_x86() {
        return Ok((BTreeMap::new(), BTreeSet::new()));
    }
    if signatures.is_empty() {
        return Ok((BTreeMap::new(), BTreeSet::new()));
    }

    let mut local_starts = BTreeSet::new();
    let mut recognized = BTreeMap::new();
    let code_xrefs_from = index_xrefs_by_source(&analysis.code_xrefs);
    let data_xrefs_from = index_xrefs_by_source(&analysis.data_xrefs);
    let mut addresses: Vec<_> = analysis.functions.keys().copied().collect();
    addresses.sort_by_key(|address| {
        (
            analysis
                .function_analysis_counts
                .get(address)
                .copied()
                .unwrap_or_else(|| {
                    analysis
                        .function_order
                        .get(address)
                        .copied()
                        .unwrap_or(usize::MAX)
                }),
            std::cmp::Reverse(
                analysis
                    .function_order
                    .get(address)
                    .copied()
                    .unwrap_or(usize::MAX),
            ),
            *address,
        )
    });
    // viv_utils.flirt.FlirtFunctionAnalyzer runs each database when a
    // function is created, with a fresh recursive cache for that invocation.
    for address in addresses {
        for database in signatures.databases.iter() {
            if recognized.contains_key(&address) {
                break;
            }
            let mut state = MatcherState {
                analysis,
                database,
                code_xrefs_from: Some(&code_xrefs_from),
                data_xrefs_from: Some(&data_xrefs_from),
                recognized: &mut recognized,
                cache: BTreeMap::new(),
                local_starts: &mut local_starts,
                function_order: analysis
                    .function_flirt_counts
                    .get(&address)
                    .map(|count| count.saturating_sub(1))
                    .or_else(|| analysis.function_order.get(&address).copied())
                    .unwrap_or(usize::MAX),
                location_count: analysis
                    .function_location_counts
                    .get(&address)
                    .copied()
                    .unwrap_or(usize::MAX),
            };
            let _ = state.match_function(address)?;
        }
    }
    Ok((recognized, local_starts))
}

/// Adds the recovered code hierarchy while omitting recognized library
/// functions, and emits upstream-compatible file-scope function names for
/// every recognized address. The leading-underscore alias mirrors
/// `viv/file.py:extract_file_function_names`.
///
/// Each scope's `.features` is populated by the
/// corresponding ported extractor
/// ([`super::insn_features`]/[`super::basicblock_features`]/
/// [`super::function_features`]), not left empty.
///
/// The per-function body is the crate's first parallel seam
/// (`options.jobs`): every recovered function reads the same immutable
/// [`Analysis`] and writes only its own owned [`FunctionFeatures`], and the
/// results are collected in input -- that is, address -- order before being
/// inserted, so the produced [`StaticFeatures`] does not depend on how many
/// threads ran. See [`crate::parallel`].
pub fn enrich_static_features(
    features: &mut StaticFeatures,
    analysis: &Analysis,
    libraries: &BTreeMap<u64, String>,
    options: &AnalysisOptions,
) {
    for (address, name) in libraries {
        features.file_features.push((
            Address::Absolute(*address),
            Feature::FunctionName(name.clone()),
        ));
        if let Some(unmangled) = name.strip_prefix('_') {
            features.file_features.push((
                Address::Absolute(*address),
                Feature::FunctionName(unmangled.to_string()),
            ));
        }
    }

    // Each instruction backend supplies its own features. The RISC basic-block
    // extractor and architecture-independent function features are shared.
    let targets: Vec<(&u64, &Function)> = analysis
        .functions
        .iter()
        .filter(|(address, _)| !libraries.contains_key(address))
        .collect();
    let risc_thunks = if analysis.image.architecture.is_risc32() {
        crate::extract::risc::import_thunks(analysis)
    } else {
        BTreeMap::new()
    };
    let extracted = parallel::map(options.jobs, &targets, |(address, recovered_function)| {
        (
            Address::Absolute(**address),
            extract_function_features(analysis, libraries, recovered_function, &risc_thunks),
        )
    });
    features.functions.extend(extracted);
}

/// The body of [`enrich_static_features`]' per-function loop, lifted out so it
/// can run on a worker thread. Takes only shared references, returns an owned
/// result, touches no shared state.
fn extract_function_features(
    analysis: &Analysis,
    libraries: &BTreeMap<u64, String>,
    recovered_function: &Function,
    risc_thunks: &BTreeMap<u64, String>,
) -> FunctionFeatures {
    let function = function_with_tail_blocks(analysis, recovered_function);
    let mut function_features = FunctionFeatures {
        features: function_features::extract_features(analysis, &function),
        basic_blocks: BTreeMap::new(),
    };
    let is_aarch64 = analysis.image.architecture == Architecture::AArch64;
    for block in &function.blocks {
        let mut basic_block = BasicBlockFeatures {
            features: if !analysis.image.architecture.is_x86() {
                aarch64_basicblock_features::extract_features(block)
            } else {
                basicblock_features::extract_features(block)
            },
            instructions: BTreeMap::new(),
        };
        if analysis.image.architecture.is_risc32() {
            for (address, features) in
                crate::extract::risc::features(analysis, &function, block, risc_thunks)
            {
                basic_block
                    .instructions
                    .insert(address, InstructionFeatures { features });
            }
        } else if is_aarch64 {
            for (address, features) in
                aarch64_features::extract_block_insn_features(analysis, &function, block)
            {
                basic_block
                    .instructions
                    .insert(address, InstructionFeatures { features });
            }
        } else {
            let ctx = InsnContext {
                analysis,
                libraries,
                function: &function,
                block,
            };
            for instruction in &block.insns {
                basic_block.instructions.insert(
                    Address::Absolute(instruction.address),
                    InstructionFeatures {
                        features: insn_features::extract_features(&ctx, instruction),
                    },
                );
            }
        }
        if !analysis.image.architecture.is_x86() {
            for insn in &block.insns {
                if matches!(
                    insn.flow,
                    super::super::decoder::Flow::Call
                        | super::super::decoder::Flow::UnconditionalBranch
                ) {
                    if let Some(name) = insn.direct_target.and_then(|target| libraries.get(&target))
                    {
                        if let Some(features) = basic_block
                            .instructions
                            .get_mut(&Address::Absolute(insn.address))
                        {
                            features.features.extend(
                                crate::extract::helpers::generate_symbols("", name, false)
                                    .into_iter()
                                    .map(|name| {
                                        (Address::Absolute(insn.address), Feature::Api(name))
                                    }),
                            );
                        }
                    }
                }
            }
        }
        function_features
            .basic_blocks
            .insert(Address::Absolute(block.addr), basic_block);
    }
    function_features
}

/// Compose blocks behind recovery's shared tail-call boundaries. This keeps
/// large connected regions available to the root scope without decoding the
/// same bytes repeatedly.
fn function_with_tail_blocks<'a>(analysis: &Analysis, root: &'a Function) -> Cow<'a, Function> {
    let mut pending = Vec::new();
    for block in &root.blocks {
        for edge in &block.succs {
            if edge.kind == EdgeKind::TailCall {
                pending.push(edge.target);
            }
        }
    }
    if pending.is_empty() {
        return Cow::Borrowed(root);
    }
    let mut function = Cow::Borrowed(root);
    let mut seen_blocks: BTreeSet<u64> = function.blocks.iter().map(|block| block.addr).collect();
    let mut seen_functions = BTreeSet::from([root.addr]);
    while let Some(address) = pending.pop() {
        if !seen_functions.insert(address) {
            continue;
        }
        let Some(target) = analysis.functions.get(&address) else {
            continue;
        };
        for block in &target.blocks {
            if seen_blocks.insert(block.addr) {
                for edge in &block.succs {
                    if edge.kind == EdgeKind::TailCall {
                        pending.push(edge.target);
                    }
                }
                function.to_mut().blocks.push(block.clone());
            }
        }
    }
    if let Cow::Owned(function) = &mut function {
        function.blocks.sort_by_key(|block| block.addr);
    }
    function
}

impl MatcherState<'_> {
    fn function_exists(&self, address: u64) -> bool {
        self.analysis.functions.contains_key(&address)
            && self
                .analysis
                .function_order
                .get(&address)
                .is_none_or(|order| *order <= self.function_order)
    }

    fn match_function(&mut self, address: u64) -> Result<Option<String>, FlirtError> {
        if let Some(name) = self.recognized.get(&address) {
            return Ok(Some(name.clone()));
        }
        if !self.function_exists(address) {
            return Ok(None);
        }
        if let Some(entry) = self.cache.get(&address) {
            return Ok(match entry {
                CacheEntry::Visiting => None,
                CacheEntry::Complete(name) => name.clone(),
            });
        }
        self.cache.insert(address, CacheEntry::Visiting);

        let function_size = self
            .analysis
            .functions
            .get(&address)
            .and_then(|function| {
                function
                    .blocks
                    .iter()
                    .flat_map(|block| block.insns.iter())
                    .filter_map(|instruction| instruction.next_address.checked_sub(address))
                    .max()
            })
            .and_then(|size| usize::try_from(size).ok())
            .unwrap_or(0);
        let Some(bytes) = self
            .analysis
            .image
            .bytes_at(address, MATCH_WINDOW.max(function_size))
        else {
            self.cache.insert(address, CacheEntry::Complete(None));
            return Ok(None);
        };
        let candidates: Vec<FlirtSignature> =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let candidates: Vec<FlirtSignature> = self
                    .database
                    .matcher
                    .r#match(bytes)
                    .into_iter()
                    .cloned()
                    .collect();
                if candidates.len() < 2 {
                    return candidates;
                }

                // Candidate order is observable when signatures share a root
                // name but carry different local/public names. Reconstruct
                // lancelot's original ordering over only the fully matched
                // candidates, avoiding its corpus-wide wildcard tree while
                // retaining that tie-break.
                let ordering = lancelot_flirt::FlirtSignatureSet::with_signatures(candidates);
                ordering.r#match(bytes).into_iter().cloned().collect()
            }))
            .map_err(|_| FlirtError::MatchPanic {
                path: self.database.path.clone(),
                address,
            })?;

        let mut valid = Vec::new();
        for candidate in candidates {
            if self.references_match(address, &candidate)? {
                valid.push(candidate);
            }
        }
        let mut names = BTreeSet::new();
        for candidate in &valid {
            let Some(name) = root_name(candidate) else {
                return Err(FlirtError::MissingRootName {
                    path: self.database.path.clone(),
                    address,
                });
            };
            names.insert(name.to_string());
        }
        let name = if names.len() == 1 {
            names.into_iter().next()
        } else {
            None
        };

        if let Some(name) = &name {
            if let Some(candidate) = valid
                .iter()
                .find(|candidate| root_name(candidate) == Some(name.as_str()))
            {
                self.apply_names(address, candidate);
            }
        }
        let result = self.recognized.get(&address).cloned().or(name);
        self.cache
            .insert(address, CacheEntry::Complete(result.clone()));
        Ok(result)
    }

    fn references_match(
        &mut self,
        function_address: u64,
        signature: &FlirtSignature,
    ) -> Result<bool, FlirtError> {
        for symbol in &signature.names {
            let Symbol::Reference(reference) = symbol else {
                continue;
            };
            let Ok(offset) = u64::try_from(reference.offset) else {
                return Ok(false);
            };
            let Some(reference_address) = function_address.checked_add(offset) else {
                return Ok(false);
            };
            let Some(instruction_address) =
                self.containing_instruction(reference_address)
                    .filter(|start| {
                        self.analysis
                            .instruction_order
                            .get(start)
                            .is_none_or(|order| *order < self.location_count)
                    })
            else {
                return Ok(false);
            };

            if reference.name == "." {
                if self.data_xrefs_from.map_or_else(
                    || {
                        self.analysis
                            .data_xrefs
                            .values()
                            .any(|sources| sources.contains(&instruction_address))
                    },
                    |index| index.contains_key(&instruction_address),
                ) {
                    continue;
                }
                return Ok(false);
            }

            let targets = self.code_xrefs_from.map_or_else(
                || {
                    self.analysis
                        .code_xrefs
                        .iter()
                        .filter(|(_, sources)| sources.contains(&instruction_address))
                        .map(|(target, _)| *target)
                        .collect()
                },
                |index| index.get(&instruction_address).cloned().unwrap_or_default(),
            );
            let mut matched = false;
            for target in targets {
                if self.match_function(target)?.as_deref() == Some(reference.name.as_str()) {
                    matched = true;
                    break;
                }
            }
            if !matched {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn containing_instruction(&self, address: u64) -> Option<u64> {
        let (&start, instruction) = self.analysis.instructions.range(..=address).next_back()?;
        let end = start.checked_add(u64::try_from(instruction.bytes.len()).ok()?)?;
        (address < end).then_some(start)
    }

    fn apply_names(&mut self, base: u64, signature: &FlirtSignature) {
        for public in [false, true] {
            for symbol in &signature.names {
                let name = match (public, symbol) {
                    (false, Symbol::Local(name)) | (true, Symbol::Public(name)) => name,
                    _ => continue,
                };
                self.apply_name(base, name, !public);
            }
        }
    }

    fn apply_name(&mut self, base: u64, name: &Name, local: bool) {
        let address = if name.offset >= 0 {
            u64::try_from(name.offset)
                .ok()
                .and_then(|offset| base.checked_add(offset))
        } else {
            name.offset
                .checked_neg()
                .and_then(|offset| u64::try_from(offset).ok())
                .and_then(|offset| base.checked_sub(offset))
        };
        if let Some(address) = address {
            if local
                && !self.function_exists(address)
                && self.containing_instruction(address).is_none()
                && self.analysis.image.is_executable_address(address)
            {
                self.local_starts.insert(address);
            }
        }
        if let Some(address) = address.filter(|address| {
            self.function_exists(*address)
                || (self.analysis.functions.contains_key(address)
                    && self
                        .analysis
                        .function_order
                        .get(address)
                        .is_some_and(|order| {
                            self.analysis
                                .function_analysis_counts
                                .get(&base)
                                .is_some_and(|count| order < count)
                        }))
                || (local
                    && self.analysis.functions.contains_key(address)
                    && self
                        .containing_instruction(*address)
                        .and_then(|start| self.analysis.instruction_order.get(&start))
                        .is_some_and(|order| *order >= self.location_count))
        }) {
            self.recognized.insert(address, name.name.clone());
            self.cache
                .insert(address, CacheEntry::Complete(Some(name.name.clone())));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::extract::pe::extract_pe;
    use crate::extract::recovery::analyze;

    #[test]
    fn functions_without_tail_blocks_are_borrowed() {
        let analysis =
            super::super::analyze_shellcode_native(&[0x31, 0xc0, 0xc3], Architecture::X64).unwrap();
        let root = analysis.functions.values().next().unwrap();
        let function = function_with_tail_blocks(&analysis, root);
        assert!(matches!(function, Cow::Borrowed(borrowed) if std::ptr::eq(borrowed, root)));
    }

    #[test]
    fn tail_blocks_are_composed_once_without_changing_the_root() {
        use crate::extract::recovery::{BasicBlock, Edge};
        let mut analysis =
            super::super::analyze_shellcode_native(&[0xc3], Architecture::X64).unwrap();
        let function = |addr, target| Function {
            addr,
            blocks: vec![BasicBlock {
                addr,
                insns: Vec::new(),
                succs: vec![Edge {
                    target,
                    kind: EdgeKind::TailCall,
                }],
            }],
        };
        // A cycle and a missing target must not append duplicate blocks.
        let root = function(0, 16);
        analysis.functions.insert(16, function(16, 0));
        let composed = function_with_tail_blocks(&analysis, &root);
        assert!(matches!(composed, Cow::Owned(_)));
        assert_eq!(
            composed.blocks.iter().map(|b| b.addr).collect::<Vec<_>>(),
            [0, 16]
        );
        assert_eq!(root.blocks.len(), 1);
        analysis.functions.remove(&16);
        assert!(matches!(
            function_with_tail_blocks(&analysis, &root),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn embedded_signatures_are_shared_across_jobs_and_concurrent_callers() {
        use crate::parallel::Jobs;
        let signatures = std::thread::scope(|scope| {
            let handles: Vec<_> = [1, 2, 4]
                .into_iter()
                .map(|jobs| {
                    scope.spawn(move || {
                        let options = AnalysisOptions {
                            jobs: Jobs::new(jobs).unwrap(),
                            ..AnalysisOptions::SERIAL
                        };
                        Signatures::embedded_with_options(&options).unwrap()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        let serial = Signatures::embedded().unwrap();
        assert!(!serial.is_empty());
        for signatures in signatures {
            assert!(Arc::ptr_eq(&serial.databases, &signatures.databases));
        }
    }

    #[cfg(feature = "decompiler")]
    #[test]
    fn runtime_and_compatibility_share_the_crt_matcher() {
        let runtime = Signatures::decompiler_runtime().unwrap();
        let compatibility = Signatures::embedded().unwrap();
        assert!(Arc::ptr_eq(
            &runtime.databases[0],
            &compatibility.databases[0]
        ));
        assert_eq!(runtime.databases.len(), 2);
        assert_eq!(compatibility.databases.len(), 3);
        assert!(embedded_database("1_flare_msvc_rtf_32_64.sig", b"invalid").is_err());
    }

    #[test]
    fn custom_signature_paths_are_reloaded_after_changes() {
        let path =
            std::env::temp_dir().join(format!("binfera-flirt-{}-reload.pat", std::process::id()));
        let pat = |name| format!("558BEC{} 00 0000 0020 :0000 {name}\n---", ".".repeat(58));
        fs::write(&path, pat("first")).unwrap();
        let first = Signatures::from_path(&path).unwrap();
        fs::write(&path, pat("second")).unwrap();
        let second = Signatures::from_path(&path).unwrap();
        fs::write(&path, b"invalid signature").unwrap();
        assert!(Signatures::from_path(&path).is_err());
        fs::remove_file(&path).unwrap();
        assert!(matches!(
            Signatures::from_path(&path),
            Err(FlirtError::MissingPath { .. })
        ));
        let mut bytes = vec![0; 32];
        bytes[..3].copy_from_slice(&[0x55, 0x8b, 0xec]);
        assert_eq!(
            first.databases[0].matcher.r#match(&bytes)[0].get_name(),
            Some("first")
        );
        assert_eq!(
            second.databases[0].matcher.r#match(&bytes)[0].get_name(),
            Some("second")
        );
    }

    #[test]
    fn parses_pat_and_matches_a_tiny_signature() {
        let path = PathBuf::from("tiny.pat");
        let pat = format!("558BEC{} 00 0000 0020 :0000 tiny\n---", ".".repeat(58));
        let database = parse_database(path, pat.as_bytes()).expect("tiny PAT parses");
        let mut bytes = vec![0u8; 32];
        bytes[..3].copy_from_slice(&[0x55, 0x8b, 0xec]);
        let matches = database.matcher.r#match(&bytes);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].get_name(), Some("tiny"));
    }

    #[test]
    fn unsupported_single_file_is_an_error() {
        let path = std::env::temp_dir().join(format!(
            "binfera-flirt-{}-unsupported.txt",
            std::process::id()
        ));
        fs::write(&path, b"not a signature").expect("temporary file is writable");
        let result = Signatures::from_path(&path);
        let _ = fs::remove_file(&path);
        assert!(matches!(
            result,
            Err(FlirtError::UnsupportedExtension { .. })
        ));
    }

    #[test]
    fn secondary_public_names_require_existing_functions_but_local_names_can_create_them() {
        use crate::extract::image::SHELLCODE_BASE;
        use crate::extract::recovery::analyze_shellcode;

        let mut bytes = vec![0xe8, 27, 0, 0, 0, 0xe8, 54, 0, 0, 0, 0xc3];
        bytes.resize(96, 0xcc);
        bytes[32..35].copy_from_slice(&[0x31, 0xc0, 0xc3]);
        bytes[64..67].copy_from_slice(&[0x31, 0xc9, 0xc3]);
        let mut analysis = analyze_shellcode(&bytes, Architecture::X86).unwrap();
        analysis.image.format = ImageFormat::Pe;
        let first = SHELLCODE_BASE + 32;
        let second = SHELLCODE_BASE + 64;
        analysis.function_order = BTreeMap::from([(first, 0), (second, 1), (SHELLCODE_BASE, 2)]);
        analysis.function_location_counts.insert(first, 5);
        analysis.instruction_order.insert(second, 10);

        for (suffix, expected) in [("", false), ("@", true)] {
            let pattern = format!(
                "31C0C3{} 00 0000 0040 :0000 root :0020{suffix} secondary\n---",
                "..".repeat(29)
            );
            let signatures = Signatures {
                architecture: None,
                databases: vec![Arc::new(
                    parse_database(PathBuf::from("order.pat"), pattern.as_bytes()).unwrap(),
                )]
                .into(),
            };
            let libraries = identify_library_functions(&analysis, &signatures).unwrap();
            assert_eq!(libraries.get(&first).map(String::as_str), Some("root"));
            assert_eq!(libraries.contains_key(&second), expected);
        }
    }

    #[test]
    fn signature_references_cannot_use_instructions_discovered_later() {
        use crate::extract::image::SHELLCODE_BASE;
        use crate::extract::recovery::analyze_shellcode;

        // The entry creates the callee, root, then a later function whose
        // CALL happens to satisfy a reference beyond root's own return.
        let mut bytes = vec![
            0xe8, 91, 0, 0, 0, 0xe8, 22, 0, 0, 0, 0xe8, 49, 0, 0, 0, 0xc3,
        ];
        bytes.resize(128, 0xcc);
        bytes[32..35].copy_from_slice(&[0x31, 0xc0, 0xc3]);
        bytes[64..70].copy_from_slice(&[0xe8, 27, 0, 0, 0, 0xc3]);
        bytes[96..99].copy_from_slice(&[0x31, 0xc9, 0xc3]);
        let mut analysis = analyze_shellcode(&bytes, Architecture::X86).unwrap();
        analysis.image.format = ImageFormat::Pe;
        let pattern = format!(
            "31C0C3{} 00 0000 0040 :0000 root ^0021 callee\n31C9C3{} 00 0000 0020 :0000 callee\n---",
            "..".repeat(29), "..".repeat(29)
        );
        let signatures = Signatures {
            architecture: None,
            databases: vec![Arc::new(
                parse_database(PathBuf::from("visibility.pat"), pattern.as_bytes()).unwrap(),
            )]
            .into(),
        };
        let libraries = identify_library_functions(&analysis, &signatures).unwrap();
        assert_eq!(
            libraries.get(&(SHELLCODE_BASE + 96)).map(String::as_str),
            Some("callee")
        );
        assert!(!libraries.contains_key(&(SHELLCODE_BASE + 32)));
        // Once the later location exists, the exact same signature is valid.
        analysis
            .function_location_counts
            .insert(SHELLCODE_BASE + 32, usize::MAX);
        assert_eq!(
            identify_library_functions(&analysis, &signatures)
                .unwrap()
                .get(&(SHELLCODE_BASE + 32))
                .map(String::as_str),
            Some("root")
        );
    }

    #[test]
    fn recognized_function_is_named_and_removed_from_code_scopes() {
        use std::fmt::Write as _;

        let sample = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("tests/testfiles/Practical Malware Analysis Lab 01-01.exe_");
        let bytes = fs::read(sample).expect("pinned PE sample exists");
        let analysis = analyze(&bytes).expect("sample recovery succeeds");
        let (&address, _) = analysis
            .functions
            .iter()
            .find(|(address, _)| {
                analysis
                    .image
                    .bytes_at(**address, 32)
                    .is_some_and(|b| b.len() == 32)
            })
            .expect("sample has a 32-byte file-backed function");
        let function_bytes = analysis
            .image
            .bytes_at(address, 32)
            .expect("selected function bytes remain available");
        let mut pattern = String::new();
        for byte in function_bytes {
            write!(pattern, "{byte:02X}").expect("writing to String is infallible");
        }
        let pat = format!("{pattern} 00 0000 0020 :0000 __m5_test_library\n---");
        let signatures = Signatures {
            architecture: None,
            databases: vec![Arc::new(
                parse_database(PathBuf::from("test.pat"), pat.as_bytes())
                    .expect("generated PAT parses"),
            )]
            .into(),
        };

        let libraries = identify_library_functions(&analysis, &signatures)
            .expect("generated signature matches without error");
        assert_eq!(
            libraries.get(&address).map(String::as_str),
            Some("__m5_test_library")
        );

        let mut features = extract_pe(&bytes).expect("file features extract");
        enrich_static_features(
            &mut features,
            &analysis,
            &libraries,
            &AnalysisOptions::SERIAL,
        );
        assert!(!features.functions.contains_key(&Address::Absolute(address)));
        assert!(features.file_features.contains(&(
            Address::Absolute(address),
            Feature::FunctionName("__m5_test_library".to_string())
        )));
        assert!(features.file_features.contains(&(
            Address::Absolute(address),
            Feature::FunctionName("_m5_test_library".to_string())
        )));
    }
}
