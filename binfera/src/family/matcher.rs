//! Matches a [`SampleSketch`] or [`Fingerprint`] against a loaded [`FamilyPack`]
//! and produces an Intezer-style 4-way code breakdown (Trusted / Malware Family / Shared / Unique).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use super::{sketch_from_fingerprint, FamilyPack, SampleSketch, LSH_BANDS};
use crate::diff::Fingerprint;

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

impl FamilyPack {
    pub fn match_fingerprint(&self, fp: &Fingerprint, config: &MatchConfig) -> MatchReport {
        let sketch = sketch_from_fingerprint(fp, "", &fp.header.name, false);
        self.match_sketch(&sketch, config)
    }

    pub fn match_sketch(&self, sketch: &SampleSketch, config: &MatchConfig) -> MatchReport {
        let total_functions = sketch.functions.len();
        let mut eligible_functions = 0_usize;
        let mut trusted_functions = 0_usize;
        let mut shared_malware_functions = 0_usize;
        let mut trusted_acc: BTreeMap<String, (u64, Vec<u64>)> = BTreeMap::new();
        let mut shared_addresses: Vec<u64> = Vec::new();
        let mut candidate_addresses: Vec<u64> = Vec::new();
        let mut acc: HashMap<u16, FamilyAccum> = HashMap::new();

        for func in &sketch.functions {
            if func.instructions < config.min_instructions || func.blocks < config.min_blocks {
                continue;
            }
            eligible_functions += 1;

            // 1. Trusted / benign software or known runtime symbol?
            let trusted_source = if let Some(src) = self.lookup_trusted(func.shape) {
                Some(src)
            } else if func.library {
                Some("runtime-stdlib")
            } else {
                None
            };
            if let Some(src) = trusted_source {
                trusted_functions += 1;
                let entry = trusted_acc.entry(src.to_owned()).or_default();
                entry.0 += u64::from(func.instructions);
                entry.1.push(func.address);
                continue;
            }

            // 2. Non-trusted boilerplate shared across >max_families_per_hash malware families?
            if self.lookup_shared(func.shape).is_some() {
                shared_malware_functions += 1;
                shared_addresses.push(func.address);
                continue;
            }

            candidate_addresses.push(func.address);

            // 3. Family-specific exact content, exact shape, or fuzzy LSH match.
            let mut per_family: BTreeMap<u16, MatchedFunction> = BTreeMap::new();
            let sw = size_weight(func.instructions);

            for rec in self.lookup_content(func.content) {
                let weight = 1.25 * sw / f64::from(rec.exclusivity.max(1));
                per_family.insert(
                    rec.family_id,
                    MatchedFunction {
                        address: func.address,
                        instructions: func.instructions,
                        kind: MatchKind::ExactContent,
                        exclusivity: rec.exclusivity,
                        sample_count: rec.sample_count,
                        contribution: weight,
                    },
                );
            }

            for rec in self.lookup_shape(func.shape) {
                if per_family.contains_key(&rec.family_id) {
                    continue;
                }
                let weight = 1.0 * sw / f64::from(rec.exclusivity.max(1));
                per_family.insert(
                    rec.family_id,
                    MatchedFunction {
                        address: func.address,
                        instructions: func.instructions,
                        kind: MatchKind::ExactShape,
                        exclusivity: rec.exclusivity,
                        sample_count: rec.sample_count,
                        contribution: weight,
                    },
                );
            }

            if func.instructions >= config.minhash_min_instructions {
                if let Some(bands) = func.bands {
                    let mut band_counts: HashMap<u16, (u8, u16)> = HashMap::new();
                    for band_hash in bands {
                        for rec in self.lookup_band(band_hash) {
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
                    let mut qualifying: Vec<(u16, u8, u16)> = band_counts
                        .into_iter()
                        .filter(|(_, (count, _))| *count >= min_bands)
                        .map(|(fam, (count, samples))| (fam, count, samples))
                        .collect();
                    let fuzzy_exclusivity = qualifying.len().clamp(1, usize::from(u8::MAX)) as u8;
                    for (family_id, hit_bands, sample_count) in qualifying.drain(..) {
                        let band_ratio = f64::from(hit_bands) / (LSH_BANDS as f64);
                        let weight = 0.75 * band_ratio * sw / f64::from(fuzzy_exclusivity);
                        per_family.insert(
                            family_id,
                            MatchedFunction {
                                address: func.address,
                                instructions: func.instructions,
                                kind: MatchKind::FuzzyBand { bands: hit_bands },
                                exclusivity: fuzzy_exclusivity,
                                sample_count,
                                contribution: weight,
                            },
                        );
                    }
                }
            }

            for (family_id, mf) in per_family {
                let entry = acc.entry(family_id).or_default();
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
            .filter_map(|(family_id, mut data)| {
                let meets_count = data.exclusive_functions >= config.min_exclusive_functions
                    || data.large_exclusive_functions >= config.min_large_exclusive_functions;
                if !meets_count || data.score < config.min_score {
                    return None;
                }
                let meta = self.families.get(usize::from(family_id))?;
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
                    family: meta.name.clone(),
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
        }
    }
}
