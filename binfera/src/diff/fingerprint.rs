//! One binary's comparable facts: [`Fingerprint`].
//!
//! Comparison needs two of these and never the samples, so each side can be produced in its own
//! process (a browser worker has one sample's memory, not two) and kept for later comparisons.
//!
//! Native code is read from native recovery: Freeze has no instruction bytes, operands or edges.
//! Managed code and static freeze files only have features, so their records are built from those.
//! Nothing here is tied to Function ID hashing, which is x86-only and pinned to Ghidra's output,
//! and which ignores the operand values a patch changes.
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Write};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::DiffError;
use crate::address::Address;
use crate::api::Format;
use crate::extract::decoder::{DecodedInstruction, Flow};
use crate::extract::image::{Architecture, LoadedImage};
use crate::extract::recovery::{self, Analysis, EdgeKind, Function, RecoveryBackend};
use crate::features::{Feature, StringFeature};
use crate::freeze::{Freeze, StaticFeatures};
use crate::parallel::AnalysisOptions;

pub const FINGERPRINT_VERSION: u32 = 2;
/// Minhash slots per function: 8 bands of 4 for candidate lookup.
pub(super) const MINHASH_SLOTS: usize = 32;
const MAX_CONSTANTS: usize = 64;
const MAX_STRING_CHARS: usize = 256;
/// An image based this low (a position-independent ELF, an object file) has addresses that look
/// like ordinary numbers, so only operands the decoder itself resolved count as addresses there.
const MIN_INFERRED_BASE: u64 = 0x1_0000;
const MIN_INFERRED_ADDRESS: u64 = 0x1000;

#[derive(Debug, Clone, Default)]
pub struct FingerprintOptions {
    pub format: Format,
    /// The universal Mach-O slice to read.
    pub arch: Option<String>,
    /// Keep each function's blocks and listing, needed to diff a pair of functions later.
    pub detail: bool,
    /// What `InfoSummary::name` should say; usually the file name.
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Fingerprint {
    pub header: Header,
    pub functions: Vec<FunctionRecord>,
    /// Keyed by function address; empty unless [`FingerprintOptions::detail`] was set.
    pub details: BTreeMap<u64, FunctionDetail>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Header {
    pub version: u32,
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub format: String,
    pub arch: String,
    pub image_base: u64,
    pub entry: Option<u64>,
    pub packed: Option<crate::packing::Packing>,
    /// `recovery` for decoded native code, `features` for managed code and freeze files.
    pub source: String,
    pub file: FileFacts,
    /// Conditions that limit what comparing this file can say.
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FileFacts {
    pub sections: Vec<SectionFact>,
    pub imports: Vec<ImportFact>,
    pub exports: Vec<ExportFact>,
    pub resources: Vec<ResourceFact>,
    pub overlay: Option<OverlayFact>,
    pub imphash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SectionFact {
    pub name: String,
    pub virtual_size: u64,
    pub size: u64,
    pub perms: String,
    pub entropy: f64,
    /// Over the file bytes with base relocation slots masked, so rebasing keeps it.
    pub hash: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ImportFact {
    pub dll: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExportFact {
    pub name: String,
    pub forward: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ResourceFact {
    pub kind: String,
    pub name: String,
    pub lang: String,
    pub size: u64,
    pub hash: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverlayFact {
    pub size: u64,
    pub entropy: f64,
    pub hash: u64,
}

/// A reference an instruction makes, resolved to something both files can agree on.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "k", content = "v", rename_all = "lowercase")]
pub enum Ref {
    Api(String),
    Str(String),
    /// A code address in this file; equal only through the function match.
    Call(u64),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionRecord {
    pub address: u64,
    pub name: Option<String>,
    /// Demangled, when the name is mangled.
    pub display: Option<String>,
    pub instructions: u32,
    pub bytes: u32,
    pub blocks: u32,
    pub edges: u32,
    /// Normalized instructions only: addresses are masked and references are not resolved.
    pub shape: u64,
    /// `shape` plus referenced strings and imports.
    pub content: u64,
    pub cfg: u64,
    /// Direct internal branch sources and destinations in normalized instruction order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch_hash: Option<u64>,
    pub refs: Vec<Ref>,
    pub constants: Vec<u64>,
    pub minhash: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetailInstruction {
    pub address: u64,
    pub bytes: String,
    pub text: String,
    /// `text` with addresses masked and strings and imports resolved: what instruction diffs
    /// compare.
    pub norm: String,
    /// The string or import this instruction refers to, for the reader.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The function it calls or jumps to. Masked in `norm`, so compared through the function match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call: Option<u64>,
    /// The destination block of a direct branch within this function.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetailEdge {
    pub target: u64,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetailBlock {
    pub address: u64,
    pub instructions: Vec<DetailInstruction>,
    pub successors: Vec<DetailEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionDetail {
    pub address: u64,
    pub name: Option<String>,
    pub blocks: Vec<DetailBlock>,
}

/// One line of the serialized form. Function by function, so a large file streams.
#[derive(Serialize, Deserialize)]
#[serde(tag = "record", rename_all = "lowercase")]
enum Line {
    Header(Box<Header>),
    Function(Box<FunctionRecord>),
    Detail(Box<FunctionDetail>),
}

/// Whether `bytes` is a serialized [`Fingerprint`] rather than a binary.
pub fn is_fingerprint(bytes: &[u8]) -> bool {
    bytes.starts_with(b"{\"record\":\"header\"")
}

impl Fingerprint {
    /// One JSON object per line: the header, then functions, then details.
    pub fn write_ndjson(&self, out: &mut dyn Write) -> Result<(), DiffError> {
        let mut line = |record: &Line| -> Result<(), DiffError> {
            serde_json::to_writer(&mut *out, record).map_err(DiffError::Json)?;
            out.write_all(b"\n").map_err(DiffError::Io)
        };
        line(&Line::Header(Box::new(self.header.clone())))?;
        for function in &self.functions {
            line(&Line::Function(Box::new(function.clone())))?;
        }
        for detail in self.details.values() {
            line(&Line::Detail(Box::new(detail.clone())))?;
        }
        Ok(())
    }

    pub fn read_ndjson(input: impl BufRead) -> Result<Fingerprint, DiffError> {
        let mut header = None;
        let mut functions = Vec::new();
        let mut details = BTreeMap::new();
        for line in input.lines() {
            let line: String = line.map_err(DiffError::Io)?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str(&line).map_err(DiffError::Json)? {
                Line::Header(found) => {
                    if found.version != FINGERPRINT_VERSION {
                        return Err(DiffError::Version(found.version));
                    }
                    header = Some(*found);
                }
                Line::Function(function) => functions.push(*function),
                Line::Detail(detail) => {
                    details.insert(detail.address, *detail);
                }
            }
        }
        let header = header.ok_or(DiffError::MissingHeader)?;
        Ok(Fingerprint {
            header,
            functions,
            details,
        })
    }
}

pub fn fingerprint(bytes: &[u8], options: &FingerprintOptions) -> Result<Fingerprint, DiffError> {
    let managed = matches!(options.format, Format::Dotnet | Format::Freeze)
        || (options.format == Format::Auto
            && (crate::extract::dotnet::looks_like_dotnet_pe(bytes)
                || crate::freeze::is_freeze(bytes)));
    if managed {
        return from_features(bytes, options);
    }
    let repaired = if matches!(options.format, Format::Sc32 | Format::Sc64) {
        None
    } else {
        crate::extract::elf::without_corrupt_section_headers(bytes)
    };
    let image_bytes = repaired.as_deref().unwrap_or(bytes);
    let analysis = match options.format {
        Format::Sc32 => recovery::analyze_shellcode_native(bytes, Architecture::X86),
        Format::Sc64 => recovery::analyze_shellcode_native(bytes, Architecture::X64),
        Format::Macho => recovery::analyze_macho(bytes, options.arch.as_deref()),
        _ if crate::extract::looks_like_macho(bytes) => {
            recovery::analyze_macho(bytes, options.arch.as_deref())
        }
        _ => recovery::analyze_with_backend(image_bytes, RecoveryBackend::Native),
    }?;
    Ok(from_analysis(image_bytes, bytes, &analysis, options))
}

pub(super) struct Fnv(u64);

impl Fnv {
    pub(super) fn new() -> Fnv {
        Fnv(0xcbf2_9ce4_8422_2325)
    }
    pub(super) fn bytes(&mut self, bytes: &[u8]) -> &mut Fnv {
        for byte in bytes {
            self.0 = (self.0 ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
        }
        self
    }
    pub(super) fn text(&mut self, text: &str) -> &mut Fnv {
        self.bytes(text.as_bytes()).bytes(&[0xff])
    }
    pub(super) fn number(&mut self, value: u64) -> &mut Fnv {
        self.bytes(&value.to_le_bytes())
    }
    pub(super) fn finish(&self) -> u64 {
        self.0
    }
}

pub(super) fn hash_text(text: &str) -> u64 {
    Fnv::new().text(text).finish()
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A numeric operand as printed: `0x10`, MASM's `10h`, or decimal.
fn parse_number(word: &str) -> Option<u64> {
    if let Some(hex) = word.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).ok();
    }
    if !word.as_bytes().first()?.is_ascii_digit() {
        return None;
    }
    if let Some(hex) = word.strip_suffix(['h', 'H']) {
        return u64::from_str_radix(hex, 16).ok();
    }
    word.parse().ok()
}

enum Token<'a> {
    Word(&'a str),
    Number(&'a str, u64),
    Other(&'a str),
}

fn tokens(text: &str) -> Vec<Token<'_>> {
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '.';
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(first) = rest.chars().next() {
        let word = is_word(first);
        let end = rest
            .find(|c: char| is_word(c) != word)
            .unwrap_or(rest.len());
        let (piece, tail) = rest.split_at(end);
        found.push(if word {
            match parse_number(piece) {
                Some(value) => Token::Number(piece, value),
                None => Token::Word(piece),
            }
        } else {
            Token::Other(piece)
        });
        rest = tail;
    }
    found
}

/// Instructions whose operand is half of an address the next instruction completes.
fn address_page(mnemonic: &str, value: u64) -> Option<u64> {
    match mnemonic {
        "adrp" | "auipc" => Some(value),
        "lui" => Some(value << 16),
        _ => None,
    }
}

struct Normal {
    text: String,
    constants: Vec<u64>,
    /// Addresses the operands name.
    targets: Vec<u64>,
}

/// Masks the operands that move when code or data moves, leaving registers, stack offsets and
/// real constants. Text is the one form every decoder here can give, so this is one normalizer
/// rather than one per architecture.
fn normalize(
    insn: &DecodedInstruction,
    image: &LoadedImage,
    pages: &mut BTreeMap<String, u64>,
) -> Normal {
    let text = insn
        .disassembly()
        .unwrap_or_else(|| "(unknown)".to_string());
    let infer = image.image_base >= MIN_INFERRED_BASE;
    let is_address = |value: u64| {
        Some(value) == insn.direct_target
            || Some(value) == insn.memory_target
            || (infer && value >= MIN_INFERRED_ADDRESS && image.section_containing(value).is_some())
    };
    let parts = tokens(&text);
    let mnemonic = text.split_whitespace().next().unwrap_or("").to_lowercase();
    let words: Vec<String> = parts
        .iter()
        .filter_map(|token| match token {
            Token::Word(word) => Some(word.to_lowercase()),
            _ => None,
        })
        .collect();
    // The register an address page was loaded into, used here with the low half of that address.
    let paged = words
        .iter()
        .skip(1)
        .find(|word| pages.contains_key(*word))
        .cloned();
    let last_number = parts
        .iter()
        .rposition(|token| matches!(token, Token::Number(..)));
    let mut out = String::with_capacity(text.len());
    let mut constants = Vec::new();
    let mut targets = Vec::new();
    let mut depth = 0_u32;
    let mut after_rip = false;
    for (index, token) in parts.iter().enumerate() {
        match *token {
            Token::Word(word) => {
                out.push_str(&word.to_lowercase());
                after_rip = word.eq_ignore_ascii_case("rip");
            }
            Token::Other(other) => {
                depth += other.matches(['[', '(']).count() as u32;
                depth = depth.saturating_sub(other.matches([']', ')']).count() as u32);
                out.push_str(other);
                after_rip = after_rip && other == "+";
            }
            Token::Number(raw, value) => {
                if let Some(page) = address_page(&mnemonic, value) {
                    out.push('@');
                    if let Some(register) = words.get(1) {
                        pages.insert(register.clone(), page);
                    }
                } else if let (Some(register), true) = (&paged, Some(index) == last_number) {
                    out.push('@');
                    let negative = matches!(parts.get(index.wrapping_sub(1)),
                        Some(Token::Other(sign)) if sign.ends_with('-'));
                    let page = pages.get(register).copied().unwrap_or(0);
                    targets.push(if negative {
                        page.wrapping_sub(value)
                    } else {
                        page.wrapping_add(value)
                    });
                } else if after_rip || is_address(value) {
                    out.push('@');
                    if !after_rip {
                        targets.push(value);
                    }
                } else {
                    out.push_str(&raw.to_lowercase());
                    if depth == 0 && value > 0xff {
                        constants.push(value);
                    }
                }
                after_rip = false;
            }
        }
    }
    if address_page(&mnemonic, 0).is_none() {
        if let Some(register) = &paged {
            pages.remove(register);
        }
        // Writing the register ends what it held.
        if let Some(first) = words.get(1) {
            pages.remove(first);
        }
    }
    Normal {
        text: out,
        constants,
        targets,
    }
}

fn function_instructions(function: &Function) -> Vec<&DecodedInstruction> {
    let mut all: Vec<_> = function
        .blocks
        .iter()
        .flat_map(|block| block.insns.iter())
        .collect();
    all.sort_by_key(|insn| insn.address);
    all.dedup_by_key(|insn| insn.address);
    all
}

fn internal_branch(insn: &DecodedInstruction, blocks: &BTreeSet<u64>) -> Option<u64> {
    insn.direct_target.filter(|target| {
        matches!(
            insn.flow,
            Flow::ConditionalBranch | Flow::UnconditionalBranch
        ) && blocks.contains(target)
    })
}

/// The variant of an import's name both files will share: the one without a library prefix.
fn import_name(bindings: &[String]) -> Option<String> {
    bindings.iter().min_by_key(|name| name.len()).cloned()
}

/// What a function that only jumps elsewhere stands for.
enum Thunk {
    Api(String),
    Code(u64),
}

fn thunk_of(analysis: &Analysis, function: &Function) -> Option<Thunk> {
    let image = &analysis.image;
    let body: Vec<_> = function_instructions(function)
        .into_iter()
        .filter(|insn| {
            !insn.is_alignment_filler()
                && !insn
                    .disassembly()
                    .is_some_and(|text| text.starts_with("endbr") || text == "nop")
        })
        .collect();
    let last = body.last()?;
    if !matches!(last.flow, Flow::UnconditionalBranch | Flow::IndirectBranch) || body.len() > 4 {
        return None;
    }
    if let Some(name) = [last.memory_target, last.direct_target]
        .iter()
        .flatten()
        .find_map(|target| image.external_bindings.get(target))
        .and_then(|names| import_name(names))
    {
        return Some(Thunk::Api(name));
    }
    (body.len() == 1).then_some(())?;
    last.direct_target
        .filter(|target| *target != function.addr && analysis.functions.contains_key(target))
        .map(Thunk::Code)
}

fn minhash(grams: &BTreeSet<u64>) -> Vec<u32> {
    (0..MINHASH_SLOTS as u64)
        .map(|slot| {
            let seed = (slot + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            grams
                .iter()
                .map(|gram| {
                    let mixed = (gram ^ seed).wrapping_mul(0xff51_afd7_ed55_8ccd);
                    ((mixed ^ (mixed >> 33)) >> 16) as u32
                })
                .min()
                .unwrap_or(u32::MAX)
        })
        .collect()
}

fn mnemonic_grams(mnemonics: &[u64]) -> BTreeSet<u64> {
    let mut grams = BTreeSet::new();
    if mnemonics.len() < 3 {
        grams.insert(
            mnemonics
                .iter()
                .fold(Fnv::new(), |mut hash, value| {
                    hash.number(*value);
                    hash
                })
                .finish(),
        );
    }
    for gram in mnemonics.windows(3) {
        let mut hash = Fnv::new();
        for value in gram {
            hash.number(*value);
        }
        grams.insert(hash.finish());
    }
    grams
}

/// A hash of the graph's shape that ignores addresses and block order: two rounds of
/// neighbourhood refinement, then the sorted labels.
fn cfg_hash(blocks: &[(u64, u32, Vec<u64>)]) -> (u64, u32) {
    let index: BTreeMap<u64, usize> = blocks
        .iter()
        .enumerate()
        .map(|(position, (address, ..))| (*address, position))
        .collect();
    let edges: Vec<Vec<usize>> = blocks
        .iter()
        .map(|(.., successors)| {
            successors
                .iter()
                .filter_map(|target| index.get(target).copied())
                .collect()
        })
        .collect();
    let mut predecessors = vec![Vec::new(); blocks.len()];
    for (from, targets) in edges.iter().enumerate() {
        for target in targets {
            if let Some(list) = predecessors.get_mut(*target) {
                list.push(from);
            }
        }
    }
    let mut labels: Vec<u64> = edges
        .iter()
        .zip(&predecessors)
        .map(|(out, into)| {
            Fnv::new()
                .number(out.len() as u64)
                .number(into.len() as u64)
                .finish()
        })
        .collect();
    for _ in 0..2 {
        let round = |list: &[usize], labels: &[u64]| {
            let mut found: Vec<u64> = list
                .iter()
                .filter_map(|at| labels.get(*at).copied())
                .collect();
            found.sort_unstable();
            found
        };
        labels = labels
            .iter()
            .zip(edges.iter().zip(&predecessors))
            .map(|(label, (out, into))| {
                let mut hash = Fnv::new();
                hash.number(*label);
                for value in round(out, &labels) {
                    hash.number(value);
                }
                hash.bytes(b"|");
                for value in round(into, &labels) {
                    hash.number(value);
                }
                hash.finish()
            })
            .collect();
    }
    labels.sort_unstable();
    let mut hash = Fnv::new();
    for label in &labels {
        hash.number(*label);
    }
    let count = edges.iter().map(Vec::len).sum::<usize>();
    (hash.finish(), count as u32)
}

fn edge_kind(kind: EdgeKind) -> &'static str {
    match kind {
        EdgeKind::Fallthrough => "fallthrough",
        EdgeKind::Branch => "branch",
        EdgeKind::TailCall => "tailcall",
        EdgeKind::JumpTable => "jumptable",
    }
}

fn names_of(
    analysis: &Analysis,
    info: Option<&crate::image_info::ImageInfo>,
) -> BTreeMap<u64, String> {
    let mut names: BTreeMap<u64, String> = BTreeMap::new();
    if let Some(go) = crate::golang::parse(&analysis.image) {
        for function in go.functions.functions {
            names.insert(function.entry, function.name);
        }
    }
    for export in info.into_iter().flat_map(|info| &info.exports) {
        if !export.name.is_empty() {
            names.insert(export.va, export.name.clone());
        }
    }
    for (address, aliases) in &analysis.elf_function_symbols {
        if let Some(name) = aliases.first() {
            names.entry(*address).or_insert_with(|| name.clone());
        }
    }
    names
}

pub(crate) fn from_analysis(
    bytes: &[u8],
    original: &[u8],
    analysis: &Analysis,
    options: &FingerprintOptions,
) -> Fingerprint {
    let image = &analysis.image;
    let info = crate::image_info::inspect(bytes, options.arch.as_deref()).ok();
    let names = names_of(analysis, info.as_ref());
    let thunks: BTreeMap<u64, Thunk> = analysis
        .functions
        .values()
        .filter_map(|function| thunk_of(analysis, function).map(|thunk| (function.addr, thunk)))
        .collect();
    // An import stub has no symbol of its own in most files, but it does stand for something.
    let mut names = names;
    for (address, thunk) in &thunks {
        if let Thunk::Api(name) = thunk {
            names.entry(*address).or_insert_with(|| name.clone());
        }
    }
    // A chain of thunks ends in an import or in the code it stands for.
    let resolve = |mut address: u64| -> Result<u64, String> {
        for _ in 0..16 {
            match thunks.get(&address) {
                Some(Thunk::Api(name)) => return Err(name.clone()),
                Some(Thunk::Code(next)) => address = *next,
                None => break,
            }
        }
        Ok(address)
    };
    let mut data_from: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for (target, sources) in &analysis.data_xrefs {
        for source in sources {
            data_from.entry(*source).or_default().push(*target);
        }
    }

    let mut functions = Vec::with_capacity(analysis.functions.len());
    let mut details = BTreeMap::new();
    for function in analysis.functions.values() {
        let own: BTreeSet<u64> = function.blocks.iter().map(|block| block.addr).collect();
        let instructions = function_instructions(function);
        let positions: Vec<_> = instructions
            .iter()
            .filter(|insn| !insn.is_alignment_filler())
            .map(|insn| insn.address)
            .collect();
        let mut shape = Fnv::new();
        let mut content = Fnv::new();
        let mut branch_hash = Fnv::new();
        let mut refs = Vec::new();
        let mut constants = BTreeSet::new();
        let mut mnemonics = Vec::new();
        let mut size = 0_u64;
        let mut count = 0_u32;
        let mut pages = BTreeMap::new();
        let mut read: BTreeMap<u64, (String, Option<String>, Option<u64>)> = BTreeMap::new();
        for insn in instructions {
            let normal = normalize(insn, image, &mut pages);
            if insn.is_alignment_filler() {
                if options.detail {
                    read.insert(insn.address, (normal.text, None, None));
                }
                continue;
            }
            let first_ref = refs.len();
            if let Some(target) = internal_branch(insn, &own) {
                // A target may start with alignment filler. Use the next normalized position.
                let destination = positions.partition_point(|&address| address < target);
                branch_hash
                    .number(u64::from(count))
                    .number(destination as u64);
            }
            count += 1;
            size += insn.bytes.len() as u64;
            shape.text(&normal.text);
            mnemonics.push(hash_text(
                normal.text.split_whitespace().next().unwrap_or(""),
            ));
            constants.extend(normal.constants.iter().copied());

            let mut targets: Vec<u64> = normal.targets;
            targets.extend(insn.memory_target);
            targets.extend(data_from.get(&insn.address).into_iter().flatten());
            let branch = insn.direct_target.filter(|target| {
                matches!(
                    insn.flow,
                    Flow::Call | Flow::UnconditionalBranch | Flow::ConditionalBranch
                ) && !own.contains(target)
            });
            targets.retain(|target| Some(*target) != insn.direct_target);
            targets.sort_unstable();
            targets.dedup();
            if let Some(target) = branch {
                if let Some(name) = image
                    .external_bindings
                    .get(&target)
                    .and_then(|names| import_name(names))
                {
                    refs.push(Ref::Api(name));
                } else if analysis.functions.contains_key(&target) {
                    refs.push(match resolve(target) {
                        Ok(code) => Ref::Call(code),
                        Err(name) => Ref::Api(name),
                    });
                }
            }
            for target in targets {
                if let Some(name) = image
                    .external_bindings
                    .get(&target)
                    .and_then(|names| import_name(names))
                {
                    refs.push(Ref::Api(name));
                } else if let Some(text) = image
                    .bytes_at(target, 2 * MAX_STRING_CHARS)
                    .and_then(crate::extract::strings::string_at)
                {
                    refs.push(Ref::Str(text.chars().take(MAX_STRING_CHARS).collect()));
                }
            }
            if options.detail {
                let mut notes = Vec::new();
                let mut call = None;
                for reference in refs.get(first_ref..).unwrap_or(&[]) {
                    match reference {
                        Ref::Api(name) => notes.push(name.clone()),
                        Ref::Str(text) => notes.push(format!("{text:?}")),
                        Ref::Call(target) => call = Some(*target),
                    }
                }
                let note = (!notes.is_empty()).then(|| notes.join(", "));
                read.insert(insn.address, (normal.text, note, call));
            }
        }
        let shape_hash = shape.finish();
        content.number(shape_hash);
        for reference in &refs {
            match reference {
                Ref::Api(name) => content.bytes(b"a").text(name),
                Ref::Str(text) => content.bytes(b"s").text(text),
                Ref::Call(_) => content.bytes(b"c"),
            };
        }
        let graph: Vec<(u64, u32, Vec<u64>)> = function
            .blocks
            .iter()
            .map(|block| {
                (
                    block.addr,
                    block.insns.len() as u32,
                    block.succs.iter().map(|edge| edge.target).collect(),
                )
            })
            .collect();
        let (cfg, edges) = cfg_hash(&graph);
        let name = names.get(&function.addr).cloned();
        if options.detail {
            let blocks = function
                .blocks
                .iter()
                .map(|block| DetailBlock {
                    address: block.addr,
                    instructions: block
                        .insns
                        .iter()
                        .map(|insn| {
                            let (norm, note, call) =
                                read.get(&insn.address).cloned().unwrap_or_default();
                            DetailInstruction {
                                address: insn.address,
                                bytes: insn.bytes.iter().map(|b| format!("{b:02x}")).collect(),
                                text: insn
                                    .disassembly()
                                    .unwrap_or_else(|| "(unknown)".to_string()),
                                norm: match &note {
                                    Some(note) => format!("{norm} ; {note}"),
                                    None => norm,
                                },
                                note,
                                call,
                                branch: internal_branch(insn, &own),
                            }
                        })
                        .collect(),
                    successors: block
                        .succs
                        .iter()
                        .map(|edge| DetailEdge {
                            target: edge.target,
                            kind: edge_kind(edge.kind).to_string(),
                        })
                        .collect(),
                })
                .collect();
            details.insert(
                function.addr,
                FunctionDetail {
                    address: function.addr,
                    name: name.clone(),
                    blocks,
                },
            );
        }
        functions.push(FunctionRecord {
            address: function.addr,
            display: name
                .as_deref()
                .and_then(crate::demangle::demangle)
                .map(|demangled| demangled.name),
            name,
            instructions: count,
            bytes: size.min(u64::from(u32::MAX)) as u32,
            blocks: function.blocks.len() as u32,
            edges,
            shape: shape_hash,
            content: content.finish(),
            cfg,
            branch_hash: Some(branch_hash.finish()),
            refs,
            constants: constants.into_iter().take(MAX_CONSTANTS).collect(),
            minhash: minhash(&mnemonic_grams(&mnemonics)),
        });
    }

    let packed = if crate::extract::looks_like_elf(bytes) {
        crate::packing::detect_elf(bytes)
    } else {
        crate::packing::detect(image, bytes)
    };
    let mut warnings: Vec<String> = Vec::new();
    if packed.is_some() {
        warnings.push(format!(
            "{} looks packed, so its code is mostly the unpacker's",
            options.name
        ));
    }
    Fingerprint {
        header: Header {
            version: FINGERPRINT_VERSION,
            name: options.name.clone(),
            size: original.len() as u64,
            sha256: sha256_hex(original),
            format: format!("{:?}", image.format).to_lowercase(),
            arch: image.architecture.name().to_string(),
            image_base: image.image_base,
            entry: image.entry_point,
            packed,
            source: "recovery".to_string(),
            file: info
                .as_ref()
                .map(|info| file_facts(bytes, info, &image.relocation_locations))
                .unwrap_or_default(),
            warnings,
        },
        functions,
        details,
    }
}

fn from_features(bytes: &[u8], options: &FingerprintOptions) -> Result<Fingerprint, DiffError> {
    let analysis_options = AnalysisOptions {
        format: options.format,
        arch: options.arch.clone(),
        ..AnalysisOptions::SERIAL
    };
    let mut timings = crate::api::PhaseTimings::default();
    let (loaded, format) = crate::api::load_input(bytes, &analysis_options, &mut timings)?;
    let Freeze::Static(features) = &loaded.freeze else {
        return Err(DiffError::DynamicInput);
    };
    let info = crate::image_info::inspect(bytes, options.arch.as_deref()).ok();
    let (functions, details) = records_from_features(features, options.detail);
    let arch = features
        .global_features
        .iter()
        .find_map(|feature| match feature {
            Feature::Arch(arch) => Some(arch.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "unknown".to_string());
    Ok(Fingerprint {
        header: Header {
            version: FINGERPRINT_VERSION,
            name: options.name.clone(),
            size: bytes.len() as u64,
            sha256: sha256_hex(bytes),
            format: format.to_string(),
            arch,
            image_base: address_value(&features.base_address).unwrap_or(0),
            entry: None,
            packed: None,
            source: "features".to_string(),
            file: info
                .as_ref()
                .map(|info| file_facts(bytes, info, &[]))
                .unwrap_or_default(),
            warnings: Vec::new(),
        },
        functions,
        details,
    })
}

pub(super) fn address_value(address: &Address) -> Option<u64> {
    match *address {
        Address::Absolute(value) | Address::Relative(value) | Address::File(value) => Some(value),
        Address::DnToken(token) => Some(u64::from(token)),
        Address::DnTokenOffset { token, .. } => Some(u64::from(token)),
        _ => None,
    }
}

/// Records for code known only through its features: the instruction text is whatever the
/// features say about each instruction, since the instructions themselves are not available.
fn records_from_features(
    features: &StaticFeatures,
    detail: bool,
) -> (Vec<FunctionRecord>, BTreeMap<u64, FunctionDetail>) {
    let mut records = Vec::with_capacity(features.functions.len());
    let mut details = BTreeMap::new();
    for (address, function) in &features.functions {
        let Some(address) = address_value(address) else {
            continue;
        };
        let mut shape = Fnv::new();
        let mut content = Fnv::new();
        let mut refs = Vec::new();
        let mut constants = BTreeSet::new();
        let mut mnemonics = Vec::new();
        let mut count = 0_u32;
        let mut name = None;
        for (at, feature) in &function.features {
            match feature {
                Feature::FunctionName(found) => name = Some(found.clone()),
                Feature::Characteristic(kind) if kind == "calls from" => {
                    refs.extend(address_value(at).map(Ref::Call));
                }
                _ => {}
            }
        }
        let mut blocks = Vec::new();
        let mut graph = Vec::new();
        for (block_address, block) in &function.basic_blocks {
            let block_at = address_value(block_address).unwrap_or(0);
            let mut instructions = Vec::new();
            for (insn_address, insn) in &block.instructions {
                let mut mnemonic = String::new();
                let mut rest = Vec::new();
                for (_, feature) in &insn.features {
                    match feature {
                        Feature::Mnemonic(text) => mnemonic = text.clone(),
                        Feature::Api(api) => {
                            refs.push(Ref::Api(api.clone()));
                            rest.push(api.clone());
                        }
                        Feature::String(StringFeature::Plain(text)) => {
                            refs.push(Ref::Str(text.clone()));
                            rest.push(format!("{text:?}"));
                        }
                        Feature::Number(number) => {
                            let printed = number.to_string();
                            if let Some(value) =
                                printed.parse::<i64>().ok().map(|value| value as u64)
                            {
                                constants.insert(value);
                            }
                            rest.push(printed);
                        }
                        Feature::Offset(offset) => rest.push(format!("+{offset}")),
                        _ => {}
                    }
                }
                rest.sort();
                rest.dedup();
                let text = format!("{mnemonic} {}", rest.join(", "))
                    .trim_end()
                    .to_string();
                count += 1;
                shape.text(&text);
                mnemonics.push(hash_text(&mnemonic));
                if detail {
                    instructions.push(DetailInstruction {
                        address: insn_address_value(insn_address),
                        bytes: String::new(),
                        norm: text.clone(),
                        text,
                        note: None,
                        call: None,
                        branch: None,
                    });
                }
            }
            graph.push((block_at, block.instructions.len() as u32, Vec::new()));
            blocks.push(DetailBlock {
                address: block_at,
                instructions,
                successors: Vec::new(),
            });
        }
        let shape_hash = shape.finish();
        content.number(shape_hash);
        for reference in &refs {
            if let Ref::Str(text) | Ref::Api(text) = reference {
                content.text(text);
            }
        }
        let (cfg, edges) = cfg_hash(&graph);
        if detail {
            details.insert(
                address,
                FunctionDetail {
                    address,
                    name: name.clone(),
                    blocks,
                },
            );
        }
        records.push(FunctionRecord {
            address,
            display: name
                .as_deref()
                .and_then(crate::demangle::demangle)
                .map(|demangled| demangled.name),
            name,
            instructions: count,
            bytes: 0,
            blocks: function.basic_blocks.len() as u32,
            edges,
            shape: shape_hash,
            content: content.finish(),
            cfg,
            branch_hash: None,
            refs,
            constants: constants.into_iter().take(MAX_CONSTANTS).collect(),
            minhash: minhash(&mnemonic_grams(&mnemonics)),
        });
    }
    (records, details)
}

fn insn_address_value(address: &Address) -> u64 {
    match *address {
        // A .NET instruction is a method token and an offset; the offset orders the listing.
        Address::DnTokenOffset { offset, .. } => u64::from(offset),
        _ => address_value(address).unwrap_or(0),
    }
}

/// Three decimals are all anyone reads, and they survive being written and read back exactly.
fn rounded(entropy: f64) -> f64 {
    (entropy * 1000.0).round() / 1000.0 + 0.0
}

fn file_facts(bytes: &[u8], info: &crate::image_info::ImageInfo, relocations: &[u64]) -> FileFacts {
    let slot = info.ptr_size.max(1) as u64;
    let to_offset = |va: u64| {
        info.regions
            .iter()
            .find(|region| va >= region.va && va - region.va < region.size)
            .map(|region| region.off + (va - region.va))
    };
    let mut masked: Vec<(u64, u64)> = relocations
        .iter()
        .filter_map(|va| to_offset(*va).map(|off| (off, off + slot)))
        .collect();
    masked.sort_unstable();
    let hash_range = |off: u64, size: u64| -> u64 {
        let (start, end) = (off, off.saturating_add(size).min(bytes.len() as u64));
        let mut hash = Fnv::new();
        let mut at = start;
        let first = masked.partition_point(|(_, stop)| *stop <= start);
        for (from, to) in masked.iter().skip(first) {
            if *from >= end {
                break;
            }
            if *from > at {
                hash.bytes(bytes.get(at as usize..*from as usize).unwrap_or(&[]));
            }
            at = at.max(*to);
        }
        if at < end {
            hash.bytes(bytes.get(at as usize..end as usize).unwrap_or(&[]));
        }
        hash.finish()
    };
    FileFacts {
        sections: info
            .sections
            .iter()
            .map(|section| SectionFact {
                name: section.name.clone(),
                virtual_size: section.vsize,
                size: section.size,
                perms: section.perms.clone(),
                entropy: rounded(section.entropy),
                // Headers hold the image base, timestamp and checksum: a rebuilt or rebased file
                // differs there whatever its contents, and the fields that matter are compared
                // in their own right.
                hash: if section.name == "PE_Header" {
                    0
                } else {
                    hash_range(section.off, section.size)
                },
            })
            .collect(),
        imports: info
            .imports
            .iter()
            .map(|import| ImportFact {
                dll: import.dll.to_lowercase(),
                name: import.name.clone(),
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        exports: info
            .exports
            .iter()
            .map(|export| ExportFact {
                name: export.name.clone(),
                forward: export.forward.clone(),
            })
            .collect(),
        resources: info
            .details
            .resources
            .iter()
            .map(|resource| ResourceFact {
                kind: resource.kind.clone(),
                name: resource.name.clone(),
                lang: resource.lang.clone(),
                size: resource.size,
                hash: resource.off.map(|off| hash_range(off, resource.size)),
            })
            .collect(),
        overlay: info.details.overlay.as_ref().map(|overlay| OverlayFact {
            size: overlay.size,
            entropy: rounded(overlay.entropy),
            hash: hash_range(overlay.off, overlay.size),
        }),
        imphash: info
            .details
            .facts
            .iter()
            .find(|fact| fact.label == "Imphash")
            .map(|fact| fact.value.clone()),
    }
}
