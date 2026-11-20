//! Per-start recovery evidence for the function-recovery benchmark (`--start-evidence`).
//!
//! The inventory lists starts without saying why each one exists. This exposes the seed kinds
//! recovery recorded for every seeded address, which also carry the binary's own function tables
//! (`.pdata`, incremental-link targets, `.eh_frame`, `LC_FUNCTION_STARTS`, `pclntab`), and the
//! chained x64 unwind fragments that seeding skips, so `scripts/bench/recovery.py` can score
//! recall against them without parsing the formats again.
use crate::extract::image::{Architecture, ImageFormat};
use crate::extract::recovery::{Analysis, SeedKind};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct StartEvidence {
    /// Every seeded address with the kinds of evidence recovery recorded for it, whether or not
    /// the address became a function: the listed analysis's seeds, merged with the native
    /// recovery's when the listing came from the compatibility pass.
    pub seeds: BTreeMap<u64, BTreeSet<SeedKind>>,
    /// x64 `.pdata` entries whose unwind info is chained (`UNW_FLAG_CHAININFO`): a separated
    /// block of another function, mapped to the primary entry the chain ends at.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub chained_unwind: BTreeMap<u64, u64>,
    /// Start to end of every extent the binary's own tables describe: x64 `.pdata` rows, ELF
    /// `.eh_frame` FDEs and `.ARM.exidx` entries.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub regions: BTreeMap<u64, u64>,
    /// Names of seeded table entries, when the image has them (to tell `.cold` parts apart).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub names: BTreeMap<u64, String>,
}

/// Seed kinds that come from a table of every function the toolchain emitted.
const TABLE_KINDS: [SeedKind; 6] = [
    SeedKind::Unwind,
    SeedKind::EhFrame,
    SeedKind::ArmExidx,
    SeedKind::MachoFunctionStarts,
    SeedKind::IncrementalTarget,
    SeedKind::GoFunctionTable,
];

impl StartEvidence {
    pub(super) fn collect(
        bytes: &[u8],
        analysis: &Analysis,
        native_seeds: Option<BTreeMap<u64, BTreeSet<SeedKind>>>,
        name: impl Fn(u64) -> Option<String>,
    ) -> Self {
        let mut seeds = native_seeds.unwrap_or_default();
        for (address, kinds) in &analysis.seeds {
            seeds.entry(*address).or_default().extend(kinds);
        }
        let mut regions = match analysis.image.format {
            ImageFormat::Elf => crate::extract::recovery::elf_unwind_ranges(bytes, &analysis.image),
            _ => BTreeMap::new(),
        };
        let mut chained_unwind = BTreeMap::new();
        x64_unwind(analysis, &mut regions, &mut chained_unwind);
        let names = seeds
            .iter()
            .filter(|(_, kinds)| TABLE_KINDS.iter().any(|kind| kinds.contains(kind)))
            .map(|(&address, _)| address)
            .chain(chained_unwind.keys().copied())
            .filter_map(|address| name(address).map(|name| (address, name)))
            .collect();
        Self {
            seeds,
            chained_unwind,
            regions,
            names,
        }
    }
}

/// Bound on chain depth, which also stops cycles.
const MAX_CHAIN: usize = 32;
const UNW_FLAG_CHAININFO: u8 = 0x4;

fn x64_unwind(
    analysis: &Analysis,
    regions: &mut BTreeMap<u64, u64>,
    chained: &mut BTreeMap<u64, u64>,
) {
    let image = &analysis.image;
    if image.architecture != Architecture::X64 {
        return;
    }
    let Some((directory, size)) = image.pe_exception_directory else {
        return;
    };
    let Some(rows) = image.bytes_at(directory, size as usize) else {
        return;
    };
    let word = |address: u64| -> Option<u32> {
        let bytes = image.bytes_at(address, 4)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    };
    let rva = |value: u32| image.image_base.checked_add(u64::from(value));
    for row in rows.as_chunks::<12>().0 {
        let field = |offset: usize| {
            row.get(offset..offset + 4)
                .and_then(|b| b.try_into().ok())
                .map(u32::from_le_bytes)
        };
        let (Some(begin), Some(end), Some(mut unwind)) =
            (field(0).and_then(rva), field(4).and_then(rva), field(8))
        else {
            continue;
        };
        if begin < end {
            regions.entry(begin).or_insert(end);
        }
        let mut primary = None;
        for _ in 0..MAX_CHAIN {
            let Some(info) = rva(unwind) else { break };
            let Some(&[version_flags, _, count, _]) = image.bytes_at(info, 4) else {
                break;
            };
            if version_flags >> 3 & UNW_FLAG_CHAININFO == 0 {
                break;
            }
            // The parent RUNTIME_FUNCTION follows the unwind codes, padded to an even count.
            let tail = info + 4 + u64::from(count).div_ceil(2) * 4;
            let (Some(parent), Some(next)) = (word(tail).and_then(rva), word(tail + 8)) else {
                break;
            };
            primary = Some(parent);
            unwind = next;
        }
        if let Some(primary) = primary.filter(|&primary| primary != begin) {
            chained.insert(begin, primary);
        }
    }
}
