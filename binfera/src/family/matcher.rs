//! Matches a [`SampleSketch`] or [`Fingerprint`] against one or more loaded [`FamilyPack`]s
//! and produces an Intezer-style 4-way code breakdown (Trusted / Malware Family / Shared / Unique),
//! plus optional String Reuse evidence that never changes the code verdict.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use super::strings::{OriginString, StringEncoding};
use super::{sketch_from_fingerprint, FamilyPack, SampleSketch, LSH_BANDS};
use crate::diff::Fingerprint;

/// Distinct exclusive malware strings that must agree on one family before a
/// [`StringOnlyHint`] is reported for a binary whose code attribution abstained.
pub const MIN_STRING_HINT_STRINGS: usize = 3;
/// Most per-string attribution entries kept in a [`StringOriginReport`].
pub const MAX_STRING_ENTRIES: usize = 1_000;
/// Most characters of a string value kept in a [`StringMatch`].
pub const MAX_STRING_ENTRY_CHARS: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchConfig {
    /// Minimum instruction count for a query function to participate in matching.
    pub min_instructions: u32,
    /// Minimum basic-block count for a query function to participate in matching.
    pub min_blocks: u32,
    /// Minimum number of family-exclusive functions required to emit a family match
    /// (unless `min_large_exclusive_functions` with `>= large_function_instructions` match).
    pub min_exclusive_functions: usize,
    /// Alternative threshold for compact samples with fewer, larger exclusive functions.
    pub min_large_exclusive_functions: usize,
    pub large_function_instructions: u32,
    /// Minimum weighted score required to emit a family match.
    pub min_score: f64,
    /// Minimum fraction (`0.0..=1.0`) of non-trusted/non-shared functions matched by a family.
    pub min_coverage: f64,
    /// Minimum LSH band hits (out of 8) required to count a fuzzy function match.
    pub min_band_hits: u8,
    /// Minimum instruction count for fuzzy LSH matching.
    pub minhash_min_instructions: u32,
    /// Maximum number of top families returned in a report.
    pub max_families: usize,
}

impl Default for MatchConfig {
    fn default() -> Self {
        Self {
            min_instructions: 20,
            min_blocks: 2,
            min_exclusive_functions: 3,
            min_large_exclusive_functions: 2,
            large_function_instructions: 40,
            min_score: 3.0,
            min_coverage: 0.15,
            min_band_hits: 4,
            minhash_min_instructions: 25,
            max_families: 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    ExactContent,
    ExactShape,
    FuzzyBand { bands: u8 },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchedFunction {
    pub address: u64,
    pub instructions: u32,
    pub kind: MatchKind,
    pub exclusivity: u8,
    pub sample_count: u16,
    pub contribution: f64,
    /// Pack that contributed this match, when matching a named [`FamilyPackSet`](super::FamilyPackSet) layer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FamilyMatch {
    pub family: String,
    pub score: f64,
    pub exclusive_functions: usize,
    pub exact_content_hits: usize,
    pub exact_shape_hits: usize,
    pub fuzzy_hits: usize,
    pub matched_instructions: u64,
    pub coverage: f64,
    pub functions: Vec<MatchedFunction>,
}

/// Matched trusted/benign software or compiler runtime group (Intezer-style trusted genes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedSourceHit {
    pub source: String,
    pub functions: usize,
    pub instructions: u64,
    pub addresses: Vec<u64>,
}

/// 4-way percentage breakdown over all eligible functions in the binary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CodeBreakdown {
    pub trusted_pct: f64,
    pub malware_pct: f64,
    pub shared_pct: f64,
    pub unique_pct: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchReport {
    pub total_functions: usize,
    pub eligible_functions: usize,
    /// Functions matched to known benign/trusted binaries or stdlib symbols.
    pub trusted_functions: usize,
    /// Functions matched to non-trusted boilerplate shared across 3+ malware families.
    pub shared_malware_functions: usize,
    /// Distinct non-trusted, non-shared functions attributed to at least one qualifying malware family.
    pub family_matched_functions: usize,
    /// Eligible functions unseen in trusted, shared, or qualifying malware families (focus here!).
    pub unique_functions: usize,
    pub breakdown: CodeBreakdown,
    pub trusted_sources: Vec<TrustedSourceHit>,
    pub shared_addresses: Vec<u64>,
    pub unique_addresses: Vec<u64>,
    pub families: Vec<FamilyMatch>,
    /// Symbol names for Trusted functions, from `BXFAM003` packs, sorted by address.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_symbols: Vec<TrustedSymbolHit>,
    /// String Reuse evidence, present only when strings were supplied and a pack carries string
    /// data. It never changes [`families`](Self::families) or the code breakdown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strings: Option<StringOriginReport>,
}

/// Symbol name a pack records for a Trusted function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedSymbolHit {
    pub address: u64,
    pub trusted_symbol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_name: Option<String>,
}

/// 4-way String Reuse classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringOriginKind {
    /// Exclusive to one malware family.
    Malware,
    /// Seen in two or three malware families.
    Shared,
    /// Not in any loaded pack.
    Unique,
    /// In a Trusted string filter of any loaded pack.
    Trusted,
}

/// String Reuse percentages over all classified strings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StringBreakdown {
    pub trusted_pct: f64,
    pub malware_pct: f64,
    pub shared_pct: f64,
    pub unique_pct: f64,
}

/// Strings a malware family shares with this binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringFamilyHit {
    pub family: String,
    /// Strings exclusive to this family.
    pub exclusive_strings: usize,
    /// Strings this family shares with one or two other families.
    pub shared_strings: usize,
    /// True when code attribution also names this family.
    pub corroborates_code: bool,
}

/// One classified string (Trusted, Malware, or Shared). Unique strings are only counted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringMatch {
    /// Normalized value, truncated to [`MAX_STRING_ENTRY_CHARS`] characters.
    pub value: String,
    /// [`origin_string_hash`](super::origin_string_hash) as 16 lowercase hex digits.
    pub hash: String,
    pub kind: StringOriginKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub families: Vec<String>,
    pub encoding: StringEncoding,
    pub offset: u64,
}

/// Explicitly labeled family hint from strings alone, reported only when code attribution
/// abstained and at least [`MIN_STRING_HINT_STRINGS`] distinct exclusive malware strings name
/// one family more than any other. It is not a verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringOnlyHint {
    pub family: String,
    pub exclusive_strings: usize,
}

/// String Reuse evidence. Supporting evidence only: code attribution is computed first and
/// independently, and strings never add, remove, or rescore a [`FamilyMatch`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StringOriginReport {
    pub total_strings: usize,
    pub trusted_strings: usize,
    pub malware_strings: usize,
    pub shared_strings: usize,
    pub unique_strings: usize,
    pub breakdown: StringBreakdown,
    /// Families ranked by exclusive strings.
    pub families: Vec<StringFamilyHit>,
    /// Malware and Shared strings first, then Trusted, capped at [`MAX_STRING_ENTRIES`].
    pub entries: Vec<StringMatch>,
    /// True when classified strings were left out of `entries`.
    pub entries_truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub string_only_hint: Option<StringOnlyHint>,
}

struct FamilyAccum {
    score: f64,
    exclusive_functions: usize,
    large_exclusive_functions: usize,
    exact_content_hits: usize,
    exact_shape_hits: usize,
    fuzzy_hits: usize,
    matched_instructions: u64,
    functions: Vec<MatchedFunction>,
}

impl Default for FamilyAccum {
    fn default() -> Self {
        Self {
            score: 0.0,
            exclusive_functions: 0,
            large_exclusive_functions: 0,
            exact_content_hits: 0,
            exact_shape_hits: 0,
            fuzzy_hits: 0,
            matched_instructions: 0,
            functions: Vec::new(),
        }
    }
}

/// Smooth size multiplier: 15 insns -> ~0.85, 30 insns -> ~1.15, 100 insns -> ~1.8, capped at 2.5.
fn size_weight(instructions: u32) -> f64 {
    let insns = f64::from(instructions.max(1));
    (insns / 20.0).ln_1p().clamp(0.5, 2.5)
}

fn round_pct(num: usize, den: usize) -> f64 {
    if den == 0 {
        0.0
    } else {
        ((num as f64 / den as f64) * 10_000.0).round() / 100.0
    }
}

/// A pack participating in a match, with its display name.
#[derive(Clone, Copy)]
pub(crate) struct LayerRef<'a> {
    pub name: Option<&'a str>,
    pub pack: &'a FamilyPack,
}

impl FamilyPack {
    pub fn match_fingerprint(&self, fp: &Fingerprint, config: &MatchConfig) -> MatchReport {
        let sketch = sketch_from_fingerprint(fp, "", &fp.header.name, false);
        self.match_sketch(&sketch, config)
    }

    /// Matches a sketch's code against this pack alone. See
    /// [`FamilyPackSet::match_sample`](super::FamilyPackSet::match_sample) for strings and layering.
    pub fn match_sketch(&self, sketch: &SampleSketch, config: &MatchConfig) -> MatchReport {
        match_layers(
            &[LayerRef {
                name: None,
                pack: self,
            }],
            sketch,
            None,
            config,
        )
    }
}

/// Per-pack exact and fuzzy matches for one function, keyed by family id.
fn pack_function_matches(
    pack: &FamilyPack,
    func: &super::FunctionEntry,
    config: &MatchConfig,
) -> BTreeMap<u16, MatchedFunction> {
    let mut per_family: BTreeMap<u16, MatchedFunction> = BTreeMap::new();
    let sw = size_weight(func.instructions);
    let matched = |kind, exclusivity, sample_count, contribution| MatchedFunction {
        address: func.address,
        instructions: func.instructions,
        kind,
        exclusivity,
        sample_count,
        contribution,
        pack_name: None,
    };

    for rec in pack.lookup_content(func.content) {
        let weight = 1.25 * sw / f64::from(rec.exclusivity.max(1));
        per_family.insert(
            rec.family_id,
            matched(
                MatchKind::ExactContent,
                rec.exclusivity,
                rec.sample_count,
                weight,
            ),
        );
    }

    for rec in pack.lookup_shape(func.shape) {
        if per_family.contains_key(&rec.family_id) {
            continue;
        }
        let weight = 1.0 * sw / f64::from(rec.exclusivity.max(1));
        per_family.insert(
            rec.family_id,
            matched(
                MatchKind::ExactShape,
                rec.exclusivity,
                rec.sample_count,
                weight,
            ),
        );
    }

    if func.instructions >= config.minhash_min_instructions {
        if let Some(bands) = func.bands {
            let mut band_counts: HashMap<u16, (u8, u16)> = HashMap::new();
            for band_hash in bands {
                for rec in pack.lookup_band(band_hash) {
                    if per_family.contains_key(&rec.family_id) {
                        continue;
                    }
                    let entry = band_counts
                        .entry(rec.family_id)
                        .or_insert((0, rec.sample_count));
                    entry.0 = entry.0.saturating_add(1);
                    entry.1 = entry.1.max(rec.sample_count);
                }
            }
            let min_bands = config.min_band_hits.max(1);
            let qualifying: Vec<(u16, u8, u16)> = band_counts
                .into_iter()
                .filter(|(_, (count, _))| *count >= min_bands)
                .map(|(fam, (count, samples))| (fam, count, samples))
                .collect();
            let fuzzy_exclusivity = qualifying.len().clamp(1, usize::from(u8::MAX)) as u8;
            for (family_id, hit_bands, sample_count) in qualifying {
                let band_ratio = f64::from(hit_bands) / (LSH_BANDS as f64);
                let weight = 0.75 * band_ratio * sw / f64::from(fuzzy_exclusivity);
                per_family.insert(
                    family_id,
                    matched(
                        MatchKind::FuzzyBand { bands: hit_bands },
                        fuzzy_exclusivity,
                        sample_count,
                        weight,
                    ),
                );
            }
        }
    }
    per_family
}

/// Matches over packs ordered base first; later layers take precedence for Trusted sources and
/// symbols. A function or string Trusted by any layer is Trusted.
pub(crate) fn match_layers(
    layers: &[LayerRef<'_>],
    sketch: &SampleSketch,
    strings: Option<&[OriginString]>,
    config: &MatchConfig,
) -> MatchReport {
    let total_functions = sketch.functions.len();
    let mut eligible_functions = 0_usize;
    let mut trusted_functions = 0_usize;
    let mut shared_malware_functions = 0_usize;
    let mut trusted_acc: BTreeMap<String, (u64, Vec<u64>)> = BTreeMap::new();
    let mut trusted_symbols: Vec<TrustedSymbolHit> = Vec::new();
    let mut shared_addresses: Vec<u64> = Vec::new();
    let mut candidate_addresses: Vec<u64> = Vec::new();
    let mut acc: HashMap<&str, FamilyAccum> = HashMap::new();

    for func in &sketch.functions {
        if func.instructions < config.min_instructions || func.blocks < config.min_blocks {
            continue;
        }
        eligible_functions += 1;

        // 1. Trusted in any layer, preferring the highest-priority layer's source name.
        let trusted_source = layers
            .iter()
            .rev()
            .find_map(|l| l.pack.lookup_trusted(func.shape))
            .or(func.library.then_some("runtime-stdlib"));
        if let Some(src) = trusted_source {
            trusted_functions += 1;
            let entry = trusted_acc.entry(src.to_owned()).or_default();
            entry.0 += u64::from(func.instructions);
            entry.1.push(func.address);
            if let Some((symbol, layer)) = layers
                .iter()
                .rev()
                .find_map(|l| l.pack.lookup_trusted_symbol(func.shape).map(|s| (s, l)))
            {
                trusted_symbols.push(TrustedSymbolHit {
                    address: func.address,
                    trusted_symbol: symbol.name.to_owned(),
                    source: symbol.source.map(str::to_owned),
                    pack_name: layer.name.map(str::to_owned),
                });
            }
            continue;
        }

        // 2. Non-trusted boilerplate shared across many malware families in any layer.
        if layers
            .iter()
            .any(|l| l.pack.lookup_shared(func.shape).is_some())
        {
            shared_malware_functions += 1;
            shared_addresses.push(func.address);
            continue;
        }

        candidate_addresses.push(func.address);

        // 3. Family matches from every layer, merged by family name. A family matched by
        //    several layers counts the function once, with the strongest evidence.
        let mut per_family: BTreeMap<&str, MatchedFunction> = BTreeMap::new();
        for layer in layers {
            for (family_id, mut mf) in pack_function_matches(layer.pack, func, config) {
                let Some(name) = layer.pack.family_name(family_id) else {
                    continue;
                };
                mf.pack_name = layer.name.map(str::to_owned);
                match per_family.get(name) {
                    Some(best) if best.contribution >= mf.contribution => {}
                    _ => {
                        per_family.insert(name, mf);
                    }
                }
            }
        }

        for (family, mf) in per_family {
            let entry = acc.entry(family).or_default();
            entry.score += mf.contribution;
            if mf.exclusivity == 1 {
                entry.exclusive_functions += 1;
                if mf.instructions >= config.large_function_instructions {
                    entry.large_exclusive_functions += 1;
                }
            }
            match mf.kind {
                MatchKind::ExactContent => entry.exact_content_hits += 1,
                MatchKind::ExactShape => entry.exact_shape_hits += 1,
                MatchKind::FuzzyBand { .. } => entry.fuzzy_hits += 1,
            }
            entry.matched_instructions += u64::from(mf.instructions);
            entry.functions.push(mf);
        }
    }

    let candidate_denom = candidate_addresses.len().max(1) as f64;
    let mut families: Vec<FamilyMatch> = acc
        .into_iter()
        .filter_map(|(family, mut data)| {
            let meets_count = data.exclusive_functions >= config.min_exclusive_functions
                || data.large_exclusive_functions >= config.min_large_exclusive_functions;
            if !meets_count || data.score < config.min_score {
                return None;
            }
            data.functions.sort_by(|a, b| {
                b.instructions
                    .cmp(&a.instructions)
                    .then_with(|| a.address.cmp(&b.address))
            });
            let matched_count = data.functions.len();
            let raw_coverage = matched_count as f64 / candidate_denom;
            if raw_coverage < config.min_coverage {
                return None;
            }
            Some(FamilyMatch {
                family: family.to_owned(),
                score: (data.score * 100.0).round() / 100.0,
                exclusive_functions: data.exclusive_functions,
                exact_content_hits: data.exact_content_hits,
                exact_shape_hits: data.exact_shape_hits,
                fuzzy_hits: data.fuzzy_hits,
                matched_instructions: data.matched_instructions,
                coverage: (raw_coverage * 1000.0).round() / 1000.0,
                functions: data.functions,
            })
        })
        .collect();

    families.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| b.exclusive_functions.cmp(&a.exclusive_functions))
            .then_with(|| b.matched_instructions.cmp(&a.matched_instructions))
            .then_with(|| a.family.cmp(&b.family))
    });
    families.truncate(config.max_families);

    let matched_addrs: BTreeSet<u64> = families
        .iter()
        .flat_map(|f| f.functions.iter().map(|m| m.address))
        .collect();
    let mut unique_addresses: Vec<u64> = candidate_addresses
        .into_iter()
        .filter(|addr| !matched_addrs.contains(addr))
        .collect();
    unique_addresses.sort_unstable();
    shared_addresses.sort_unstable();
    trusted_symbols.sort_by_key(|s| s.address);

    let family_matched_functions = matched_addrs.len();
    let unique_functions = unique_addresses.len();

    let mut trusted_sources: Vec<TrustedSourceHit> = trusted_acc
        .into_iter()
        .map(|(source, (instructions, mut addresses))| {
            addresses.sort_unstable();
            TrustedSourceHit {
                source,
                functions: addresses.len(),
                instructions,
                addresses,
            }
        })
        .collect();
    trusted_sources.sort_by(|a, b| {
        b.functions
            .cmp(&a.functions)
            .then_with(|| a.source.cmp(&b.source))
    });

    let breakdown = CodeBreakdown {
        trusted_pct: round_pct(trusted_functions, eligible_functions),
        malware_pct: round_pct(family_matched_functions, eligible_functions),
        shared_pct: round_pct(shared_malware_functions, eligible_functions),
        unique_pct: round_pct(unique_functions, eligible_functions),
    };

    // String Reuse runs after, and independently of, the code verdict above.
    let strings = strings
        .filter(|_| layers.iter().any(|l| l.pack.has_string_data()))
        .map(|strings| match_strings(layers, strings, &families));

    MatchReport {
        total_functions,
        eligible_functions,
        trusted_functions,
        shared_malware_functions,
        family_matched_functions,
        unique_functions,
        breakdown,
        trusted_sources,
        shared_addresses,
        unique_addresses,
        families,
        trusted_symbols,
        strings,
    }
}

fn match_strings(
    layers: &[LayerRef<'_>],
    strings: &[OriginString],
    code_families: &[FamilyMatch],
) -> StringOriginReport {
    let mut counts: HashMap<StringOriginKind, usize> = HashMap::new();
    let mut per_family: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    let mut entries: Vec<StringMatch> = Vec::new();

    for s in strings {
        let mut names: Vec<&str> = Vec::new();
        let kind = if layers.iter().any(|l| l.pack.is_trusted_string(s.hash)) {
            StringOriginKind::Trusted
        } else {
            for layer in layers {
                if let Some(rec) = layer.pack.lookup_malware_string(s.hash) {
                    for &id in rec.family_ids() {
                        if let Some(name) = layer.pack.family_name(id) {
                            if !names.contains(&name) {
                                names.push(name);
                            }
                        }
                    }
                }
            }
            match names.len() {
                0 => StringOriginKind::Unique,
                1 => StringOriginKind::Malware,
                _ => StringOriginKind::Shared,
            }
        };
        *counts.entry(kind).or_default() += 1;
        for &name in &names {
            let entry = per_family.entry(name).or_default();
            if kind == StringOriginKind::Malware {
                entry.0 += 1;
            } else {
                entry.1 += 1;
            }
        }
        if kind != StringOriginKind::Unique {
            names.sort_unstable();
            entries.push(StringMatch {
                value: s.value.chars().take(MAX_STRING_ENTRY_CHARS).collect(),
                hash: format!("{:016x}", s.hash),
                kind,
                families: names.into_iter().map(str::to_owned).collect(),
                encoding: s.encoding,
                offset: s.offset,
            });
        }
    }

    let rank = |kind| match kind {
        StringOriginKind::Malware => 0,
        StringOriginKind::Shared => 1,
        StringOriginKind::Trusted => 2,
        StringOriginKind::Unique => 3,
    };
    entries.sort_by(|a, b| {
        rank(a.kind)
            .cmp(&rank(b.kind))
            .then_with(|| a.offset.cmp(&b.offset))
    });
    let entries_truncated = entries.len() > MAX_STRING_ENTRIES;
    entries.truncate(MAX_STRING_ENTRIES);

    let mut families: Vec<StringFamilyHit> = per_family
        .into_iter()
        .map(
            |(family, (exclusive_strings, shared_strings))| StringFamilyHit {
                family: family.to_owned(),
                exclusive_strings,
                shared_strings,
                corroborates_code: code_families.iter().any(|f| f.family == family),
            },
        )
        .collect();
    families.sort_by(|a, b| {
        b.exclusive_strings
            .cmp(&a.exclusive_strings)
            .then_with(|| b.shared_strings.cmp(&a.shared_strings))
            .then_with(|| a.family.cmp(&b.family))
    });

    // Hint only when code abstained and one family clearly leads on exclusive strings.
    let string_only_hint = match (code_families.is_empty(), families.as_slice()) {
        (true, [top, rest @ ..])
            if top.exclusive_strings >= MIN_STRING_HINT_STRINGS
                && rest
                    .first()
                    .is_none_or(|next| next.exclusive_strings < top.exclusive_strings) =>
        {
            Some(StringOnlyHint {
                family: top.family.clone(),
                exclusive_strings: top.exclusive_strings,
            })
        }
        _ => None,
    };
    families.truncate(10);

    let count = |kind| counts.get(&kind).copied().unwrap_or(0);
    let total = strings.len();
    StringOriginReport {
        total_strings: total,
        trusted_strings: count(StringOriginKind::Trusted),
        malware_strings: count(StringOriginKind::Malware),
        shared_strings: count(StringOriginKind::Shared),
        unique_strings: count(StringOriginKind::Unique),
        breakdown: StringBreakdown {
            trusted_pct: round_pct(count(StringOriginKind::Trusted), total),
            malware_pct: round_pct(count(StringOriginKind::Malware), total),
            shared_pct: round_pct(count(StringOriginKind::Shared), total),
            unique_pct: round_pct(count(StringOriginKind::Unique), total),
        },
        families,
        entries,
        entries_truncated,
        string_only_hint,
    }
}
