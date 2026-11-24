//! Offline malware-family and trusted-software code matching (`BXFAM002` pack reader).
//!
//! Built directly on top of [`crate::diff::Fingerprint`], so matching uses only native code
//! recovery plus bundled FLIRT signatures (no decompiler or capa evaluation) and runs in
//! milliseconds in both native Rust and WebAssembly.

mod matcher;
mod pack;

use std::collections::BTreeSet;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::api::Format;
use crate::diff::{self, DiffError, Fingerprint, FingerprintOptions, FunctionRecord};
use crate::extract::image::{Architecture, ImageFormat};
use crate::extract::recovery::{
    self,
    flirt::{identify_library_functions, Signatures},
    RecoveryBackend,
};
use crate::parallel::AnalysisOptions;

pub use matcher::{
    CodeBreakdown, FamilyMatch, MatchConfig, MatchKind, MatchReport, MatchedFunction,
    TrustedSourceHit,
};
pub use pack::{
    BandRecord, FamilyMeta, FamilyPack, HashRecord, PackStats, SharedRecord, TrustedRecord,
};

/// Number of LSH bands derived from the 32-slot MinHash vector (8 bands of 4 slots).
pub const LSH_BANDS: usize = 8;
const SLOTS_PER_BAND: usize = 4;

#[derive(Debug, thiserror::Error)]
pub enum FamilyError {
    #[error("invalid family pack: {0}")]
    Pack(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Diff(#[from] DiffError),
}

/// Compact per-function summary extracted from a [`Fingerprint`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionEntry {
    pub address: u64,
    pub instructions: u32,
    pub blocks: u32,
    pub shape: u64,
    pub content: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bands: Option<[u64; LSH_BANDS]>,
    /// True when FLIRT or recovered symbols already identify this function as runtime/library code.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub library: bool,
}

/// Compact per-sample sketch matched against a [`FamilyPack`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampleSketch {
    pub sha256: String,
    pub family: String,
    pub path: String,
    pub format: String,
    pub arch: String,
    pub packed: bool,
    #[serde(default)]
    pub unpacked_dump: bool,
    pub functions: Vec<FunctionEntry>,
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0100_0000_01b3;

fn fnv1a_step(mut state: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        state = (state ^ u64::from(b)).wrapping_mul(FNV_PRIME);
    }
    state
}

/// Computes 8 domain-separated 64-bit LSH band hashes from a 32-slot MinHash vector.
pub fn minhash_bands(minhash: &[u32]) -> Option<[u64; LSH_BANDS]> {
    if minhash.len() < LSH_BANDS * SLOTS_PER_BAND {
        return None;
    }
    let mut out = [0_u64; LSH_BANDS];
    for (band_idx, slot_out) in out.iter_mut().enumerate() {
        let start = band_idx * SLOTS_PER_BAND;
        let chunk = minhash.get(start..start + SLOTS_PER_BAND)?;
        let mut h = fnv1a_step(FNV_OFFSET, &[band_idx as u8]);
        for &val in chunk {
            h = fnv1a_step(h, &val.to_le_bytes());
        }
        *slot_out = h;
    }
    Some(out)
}

/// Returns true when a recovered symbol name belongs to a known compiler runtime or standard library.
pub fn is_known_library_symbol(name: &str) -> bool {
    let trimmed = name.trim().trim_start_matches('.');
    if trimmed.is_empty() {
        return false;
    }
    const PREFIXES: &[&str] = &[
        "std::",
        "__gnu_cxx::",
        "__cxxabiv1::",
        "__cxa_",
        "__mingw",
        "_mingw",
        "__gcc",
        "__gxx_",
        "_Unwind_",
        "__udiv",
        "__umod",
        "__divdi",
        "__moddi",
        "__chkstk",
        "___chkstk",
        "__security_",
        "__report_gsfailure",
        "__scrt_",
        "__acrt_",
        "__vcrt_",
        "__crt",
        "_CRT_",
        "_crt_",
        "__libc_",
        "__GI_",
        "__musl_",
        "core::",
        "alloc::",
        "rustc_demangle::",
        "hashbrown::",
        "gimli::",
        "addr2line::",
        "object::",
        "runtime.",
        "runtime/",
        "internal/",
        "syscall.",
        "reflect.",
        "strconv.",
        "unicode/",
        "encoding/",
        "crypto/",
        "math/",
        "sync.",
        "sync/",
        "fmt.",
        "bytes.",
        "strings.",
        "bufio.",
        "sort.",
        "time.",
        "path/",
        "io.",
        "io/",
        "os.",
        "net.",
        "net/",
        "compress/",
        "boost::",
        "EVP_",
        "OPENSSL_",
        "ossl_",
        "CRYPTO_",
        "BN_",
        "RSA_",
        "EC_",
        "SSL_",
        "X509_",
        "ASN1_",
        "mbedtls_",
        "curl_",
        "Curl_",
        "zlib_",
        "deflate",
        "inflate",
        "sqlite3_",
    ];
    PREFIXES.iter().any(|p| trimmed.starts_with(p))
}

fn entry_from_record(rec: &FunctionRecord) -> FunctionEntry {
    let library = rec.display.as_deref().is_some_and(is_known_library_symbol)
        || rec.name.as_deref().is_some_and(is_known_library_symbol);
    FunctionEntry {
        address: rec.address,
        instructions: rec.instructions,
        blocks: rec.blocks,
        shape: rec.shape,
        content: rec.content,
        bands: minhash_bands(&rec.minhash),
        library,
    }
}

/// Converts an existing [`Fingerprint`] into a compact [`SampleSketch`].
pub fn sketch_from_fingerprint(
    fp: &Fingerprint,
    family: &str,
    path: &str,
    unpacked_dump: bool,
) -> SampleSketch {
    let packed = fp.header.packed.is_some();
    SampleSketch {
        sha256: fp.header.sha256.clone(),
        family: family.to_owned(),
        path: path.to_owned(),
        format: fp.header.format.clone(),
        arch: fp.header.arch.clone(),
        packed,
        unpacked_dump,
        functions: fp.functions.iter().map(entry_from_record).collect(),
    }
}

fn embedded_flirt() -> Option<&'static Signatures> {
    static SIGS: OnceLock<Option<Signatures>> = OnceLock::new();
    SIGS.get_or_init(|| Signatures::embedded_with_options(&AnalysisOptions::default()).ok())
        .as_ref()
}

/// Runs native code recovery, lists its functions as the decompiler does
/// ([`recovery::listing::list_functions`]), tags MSVC/ATL/MFC/common-library functions via bundled
/// FLIRT signatures on x86/x64 PEs, and returns a [`SampleSketch`] ready for
/// [`FamilyPack::match_sketch`].
pub fn sketch_bytes(
    bytes: &[u8],
    family: &str,
    path: &str,
    unpacked_dump: bool,
) -> Result<SampleSketch, FamilyError> {
    let options = FingerprintOptions {
        format: Format::Auto,
        arch: None,
        detail: false,
        name: path.to_owned(),
    };
    if crate::extract::dotnet::looks_like_dotnet_pe(bytes) || crate::freeze::is_freeze(bytes) {
        let fp = diff::fingerprint(bytes, &options)?;
        return Ok(sketch_from_fingerprint(&fp, family, path, unpacked_dump));
    }

    let repaired = crate::extract::elf::without_corrupt_section_headers(bytes);
    let image_bytes = repaired.as_deref().unwrap_or(bytes);
    let analysis = if crate::extract::looks_like_macho(bytes) {
        recovery::analyze_macho(bytes, None)
    } else {
        recovery::analyze_with_backend(image_bytes, RecoveryBackend::Native)
    }
    .map_err(DiffError::from)?;
    // Fingerprint the functions the decompiler lists, so an origin verdict names a function the
    // analyst can open and a pack is matched on the same starts it was built from.
    let (analysis, listed) = recovery::listing::list_functions(image_bytes, analysis);

    let flirt_addrs: BTreeSet<u64> = if analysis.image.format == ImageFormat::Pe
        && matches!(
            analysis.image.architecture,
            Architecture::X86 | Architecture::X64
        ) {
        embedded_flirt()
            .and_then(|sigs| identify_library_functions(&analysis, sigs).ok())
            .map(|libs| libs.into_keys().collect())
            .unwrap_or_default()
    } else {
        BTreeSet::new()
    };

    let fp = diff::from_analysis(image_bytes, bytes, &analysis, &options);
    let mut sketch = sketch_from_fingerprint(&fp, family, path, unpacked_dump);
    sketch.functions.retain(|f| listed.contains(&f.address));
    if !flirt_addrs.is_empty() {
        for f in &mut sketch.functions {
            if flirt_addrs.contains(&f.address) {
                f.library = true;
            }
        }
    }
    Ok(sketch)
}
