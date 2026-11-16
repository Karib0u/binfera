//! Compare two binaries: what changed in the file, its functions and its capabilities.
//!
//! [`fingerprint`] reduces one binary to the facts comparison needs; [`compare`] takes two of those
//! and, optionally, their [`crate::rd::ResultDocument`]s. The samples themselves are not needed
//! again, so a browser worker can hold one sample at a time. [`pair::diff_functions`] compares one
//! matched pair down to its blocks and instructions, on request.
use serde::{Deserialize, Serialize};

mod capability;
mod file;
mod fingerprint;
mod matcher;
pub mod pair;

pub use capability::{CapabilityDelta, RetargetedRule, RuleSummary};
pub use file::{ChangedItem, FileDelta, ListDelta};
pub use fingerprint::{
    fingerprint, is_fingerprint, DetailBlock, DetailEdge, DetailInstruction, ExportFact, FileFacts,
    Fingerprint, FingerprintOptions, FunctionDetail, FunctionRecord, Header, ImportFact,
    OverlayFact, Ref, ResourceFact, SectionFact, FINGERPRINT_VERSION,
};
pub use pair::{diff_functions, PairDiff};

use crate::rd::ResultDocument;

pub const DIFF_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum DiffError {
    #[error(transparent)]
    Analysis(#[from] crate::api::AnalysisError),
    #[error("recovering code: {0}")]
    Recovery(crate::extract::recovery::RecoveryError),
    #[error("a dynamic trace has no code to compare")]
    DynamicInput,
    #[error("fingerprint: {0}")]
    Json(serde_json::Error),
    #[error("fingerprint: {0}")]
    Io(std::io::Error),
    #[error("fingerprint has no header")]
    MissingHeader,
    #[error("fingerprint version {0} is not supported by this build")]
    Version(u32),
}

impl From<crate::extract::recovery::RecoveryError> for DiffError {
    fn from(error: crate::extract::recovery::RecoveryError) -> DiffError {
        DiffError::Recovery(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// The same bytes.
    Identical,
    /// Different bytes, and nothing this comparison looks at differs (a rebased copy, say).
    Equivalent,
    Changed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InfoSummary {
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub format: String,
    pub arch: String,
    pub image_base: u64,
    pub entry: Option<u64>,
    pub functions: usize,
    pub instructions: u64,
    pub packed: bool,
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Method {
    /// Same instructions, strings and imports; unique on both sides.
    Exact,
    /// Same instructions, different references; unique on both sides.
    Shape,
    /// Same symbol, confirmed by the content.
    Name,
    /// Next to a matched pair in the call graph.
    Propagated,
    /// Scored on features.
    Fuzzy,
    /// One of several identical functions, paired by position.
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeReason {
    /// The normalized instructions differ.
    Code,
    /// A referenced string differs.
    String,
    /// A referenced import differs.
    Import,
    /// A call goes to a function that is not the match of the old callee.
    Callee,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionMatch {
    pub evidence: Evidence,
    pub a_addr: u64,
    pub b_addr: u64,
    pub a_name: Option<String>,
    pub b_name: Option<String>,
    pub method: Method,
    /// How sure the pairing is, not how alike the functions are.
    pub confidence: f64,
    pub similarity: f64,
    pub changed: bool,
    pub reasons: Vec<ChangeReason>,
    pub a_instructions: u32,
    pub b_instructions: u32,
}

/// One thing the pairing score weighed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Signal {
    pub name: String,
    /// 0 to 1.
    pub value: f64,
    pub weight: f64,
}

/// What supports a pair and what differs in it, so its score can be checked rather than trusted.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub same_instructions: bool,
    pub same_cfg: bool,
    pub blocks: [u32; 2],
    pub edges: [u32; 2],
    /// Empty for an exact unchanged pair, where nothing needed weighing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<Signal>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strings_only_a: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strings_only_b: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub imports_only_a: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub imports_only_b: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constants_only_a: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constants_only_b: Vec<u64>,
    /// Functions A calls whose counterpart B does not call here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callees_only_a: Vec<FunctionRef>,
    /// Functions B calls that are not the counterpart of anything A calls here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callees_only_b: Vec<FunctionRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules_only_a: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules_only_b: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules_both: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FunctionRef {
    pub address: u64,
    pub name: Option<String>,
    pub instructions: u32,
    /// Rules that match in it, when capabilities were compared.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strings: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub imports: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Similarity {
    pub overall: f64,
    pub code: Option<f64>,
    pub imports: Option<f64>,
    pub strings: Option<f64>,
    pub capabilities: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiffDocument {
    pub schema_version: u32,
    pub tool_version: String,
    pub verdict: Verdict,
    pub inputs: [InfoSummary; 2],
    /// Conditions that limit what this comparison says, such as a packed input.
    pub warnings: Vec<String>,
    /// Whether functions were compared; files of different architectures are not.
    pub functions_compared: bool,
    pub file_delta: FileDelta,
    pub matches: Vec<FunctionMatch>,
    pub unmatched_a: Vec<FunctionRef>,
    pub unmatched_b: Vec<FunctionRef>,
    pub capability_delta: Option<CapabilityDelta>,
    pub similarity: Similarity,
}

fn summary(print: &Fingerprint) -> InfoSummary {
    InfoSummary {
        name: print.header.name.clone(),
        size: print.header.size,
        sha256: print.header.sha256.clone(),
        format: print.header.format.clone(),
        arch: print.header.arch.clone(),
        image_base: print.header.image_base,
        entry: print.header.entry,
        functions: print.functions.len(),
        instructions: print
            .functions
            .iter()
            .map(|function| u64::from(function.instructions))
            .sum(),
        packed: print.header.packed.is_some(),
        source: print.header.source.clone(),
    }
}

pub(crate) fn jaccard<T: Ord>(a: &[T], b: &[T]) -> Option<f64> {
    use std::collections::BTreeSet;
    let (a, b): (BTreeSet<_>, BTreeSet<_>) = (a.iter().collect(), b.iter().collect());
    if a.is_empty() && b.is_empty() {
        return None;
    }
    let shared = a.intersection(&b).count();
    Some(shared as f64 / (a.len() + b.len() - shared) as f64)
}

/// Weighs matched code by size, as an unchanged function says more the larger it is.
fn code_similarity(a: &Fingerprint, b: &Fingerprint, matches: &[FunctionMatch]) -> Option<f64> {
    let total = |print: &Fingerprint| {
        print
            .functions
            .iter()
            .map(|function| f64::from(function.instructions))
            .sum::<f64>()
    };
    let largest = total(a).max(total(b));
    (largest > 0.0).then(|| {
        matches.iter().fold(0.0, |sum, found| {
            sum + found.similarity * f64::from(found.a_instructions.max(found.b_instructions))
        }) / largest
    })
}

fn strings_of(print: &Fingerprint) -> Vec<&str> {
    print
        .functions
        .iter()
        .flat_map(|function| &function.refs)
        .filter_map(|reference| match reference {
            Ref::Str(text) => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

fn overall(similarity: &Similarity) -> f64 {
    let parts = [
        (similarity.code, 0.6),
        (similarity.capabilities, 0.2),
        (similarity.imports, 0.1),
        (similarity.strings, 0.1),
    ];
    let weight: f64 = parts
        .iter()
        .filter(|(v, _)| v.is_some())
        .map(|(_, w)| w)
        .sum();
    if weight == 0.0 {
        return 0.0;
    }
    parts
        .iter()
        .filter_map(|(value, part)| value.map(|value| value * part))
        .sum::<f64>()
        / weight
}

/// Which function in B each function in A was matched to, for [`pair::diff_functions`].
pub fn function_map(a: &Fingerprint, b: &Fingerprint) -> std::collections::BTreeMap<u64, u64> {
    matcher::match_functions(&a.functions, &b.functions)
        .matches
        .iter()
        .map(|found| (found.a_addr, found.b_addr))
        .collect()
}

/// Compare two fingerprints; `capabilities` adds the rule-level delta.
pub fn compare(
    a: &Fingerprint,
    b: &Fingerprint,
    capabilities: Option<(&ResultDocument, &ResultDocument)>,
) -> DiffDocument {
    let mut warnings: Vec<String> = a
        .header
        .warnings
        .iter()
        .chain(&b.header.warnings)
        .cloned()
        .collect();
    let functions_compared = a.header.arch == b.header.arch;
    if !functions_compared {
        warnings.push(format!(
            "functions were not compared: {} and {} are different architectures",
            a.header.arch, b.header.arch
        ));
    }
    if a.header.source != b.header.source {
        warnings.push(
            "one file has decoded code and the other only features, so most functions will not match"
                .to_string(),
        );
    }
    let mut outcome = if functions_compared {
        matcher::match_functions(&a.functions, &b.functions)
    } else {
        matcher::Outcome::unmatched(&a.functions, &b.functions)
    };
    let capability_delta = capabilities.map(|(left, right)| {
        capability::attach(left, right, a, b, &mut outcome);
        capability::compare(left, right, a, b, &outcome.matches, &mut warnings)
    });
    let file_delta = file::compare(&a.header.file, &b.header.file);
    let import_key = |print: &Fingerprint| {
        print
            .header
            .file
            .imports
            .iter()
            .map(|import| (import.dll.clone(), import.name.clone()))
            .collect::<Vec<_>>()
    };
    let mut similarity = Similarity {
        overall: 0.0,
        code: functions_compared
            .then(|| code_similarity(a, b, &outcome.matches))
            .flatten(),
        imports: jaccard(&import_key(a), &import_key(b)),
        strings: jaccard(&strings_of(a), &strings_of(b)),
        capabilities: capability_delta.as_ref().and_then(|delta| delta.similarity),
    };
    similarity.overall = overall(&similarity);
    let same_bytes = a.header.sha256 == b.header.sha256;
    if same_bytes {
        similarity.overall = 1.0;
    }
    let code_changed = !functions_compared
        || !outcome.unmatched_a.is_empty()
        || !outcome.unmatched_b.is_empty()
        || outcome.matches.iter().any(|found| found.changed);
    let verdict = if same_bytes {
        Verdict::Identical
    } else if code_changed
        || !file_delta.is_empty()
        || capability_delta
            .as_ref()
            .is_some_and(|delta| !delta.is_empty())
    {
        Verdict::Changed
    } else {
        Verdict::Equivalent
    };
    DiffDocument {
        schema_version: DIFF_SCHEMA_VERSION,
        tool_version: crate::version().to_string(),
        verdict,
        inputs: [summary(a), summary(b)],
        warnings,
        functions_compared,
        file_delta,
        matches: outcome.matches,
        unmatched_a: outcome.unmatched_a,
        unmatched_b: outcome.unmatched_b,
        capability_delta,
        similarity,
    }
}
