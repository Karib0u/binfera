//! Starts that x64 unwind data proves are not function entries.
//!
//! The x64 Windows ABI gives every function that allocates stack, saves a nonvolatile register
//! or calls another function a `.pdata` row, and the row's `[begin, end)` bounds that function's
//! code (or one separated part of it, a funclet or a chained fragment, each with a row of its
//! own). The begin of every row is an entry. An address strictly inside a row that no row begins
//! at is therefore code of that row's function: a switch arm, a catch continuation, a `/GS`
//! cookie block, a local label of a library routine. Heuristic passes that see only a pointer, an
//! operand or a signature name such addresses; the rule here keeps them out of the function list.
//!
//! Only the binary's own metadata (an export, the entry point, a TLS callback, a symbol, the
//! incremental-link thunk table, Guard CF, MSVC exception or throw metadata) or a direct
//! `call` that lands on an instruction boundary can name an entry inside a row. That happens for hand-written
//! multi-entry routines and for a malformed `.pdata`. Such a start is kept and reported, never
//! dropped silently.
use super::*;

/// Seed kinds read from the image's own metadata that name a function entry by themselves.
const NAMED_ENTRY: [SeedKind; 9] = [
    SeedKind::EntryPoint,
    SeedKind::Export,
    SeedKind::TlsCallback,
    SeedKind::Symbol,
    SeedKind::IncrementalTarget,
    SeedKind::MsvcException,
    SeedKind::MsvcThrowMetadata,
    SeedKind::Dwarf,
    SeedKind::GuardCf,
];

/// Whether `address` lies strictly inside an unwind row of the sorted `unwound` extents (from
/// [`unwind_extents`]) and is the begin of none.
pub(crate) fn inside_unwind_row(unwound: &[(u64, u64)], address: u64) -> bool {
    inside_unwind_extent(unwound, address)
        && unwound
            .binary_search_by_key(&address, |&(begin, _)| begin)
            .is_err()
}

/// Function starts inside an x64 unwind row, split by whether evidence names them.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct InteriorStarts {
    /// Starts nothing authoritative names: blocks of the enclosing function.
    pub rejected: BTreeSet<u64>,
    /// Starts an export, image table or direct call names: kept, and worth reporting.
    pub kept: BTreeSet<u64>,
}

/// Sorts the `starts` of an x64 PE that lie strictly inside one of its unwind rows. `analysis`
/// supplies the seeds and the decoded instructions the evidence is read from; on other images,
/// or without unwind data, nothing is returned.
pub fn interior_unwind_starts(
    analysis: &Analysis,
    starts: impl IntoIterator<Item = u64>,
) -> InteriorStarts {
    let mut out = InteriorStarts::default();
    let image = &analysis.image;
    if image.format != ImageFormat::Pe || image.architecture != Architecture::X64 {
        return out;
    }
    let unwound = unwind_extents(image);
    let inside: BTreeSet<u64> = starts
        .into_iter()
        .filter(|&address| inside_unwind_row(&unwound, address))
        .collect();
    if inside.is_empty() {
        return out;
    }
    let called: BTreeSet<u64> = analysis
        .instructions
        .values()
        .filter(|insn| insn.flow == Flow::Call)
        .filter_map(|insn| insn.direct_target)
        .filter(|target| inside.contains(target))
        .collect();
    for address in inside {
        let named = analysis
            .seeds
            .get(&address)
            .is_some_and(|kinds| NAMED_ENTRY.iter().any(|kind| kinds.contains(kind)));
        if named || (called.contains(&address) && !mid_instruction(analysis, address)) {
            out.kept.insert(address);
        } else {
            out.rejected.insert(address);
        }
    }
    out
}

/// Whether a decoded instruction starts before `address` and runs past it.
fn mid_instruction(analysis: &Analysis, address: u64) -> bool {
    analysis
        .instructions
        .range(address.saturating_sub(15)..address)
        .any(|(_, insn)| insn.next_address > address)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn row_begins_are_not_inside_a_row() {
        let unwound = [(0x1000, 0x1080), (0x1080, 0x1100), (0x1200, 0x1210)];
        assert!(!inside_unwind_row(&unwound, 0x1000));
        assert!(inside_unwind_row(&unwound, 0x1001));
        assert!(inside_unwind_row(&unwound, 0x107f));
        // A chained fragment or funclet that begins where the previous row ends is an entry.
        assert!(!inside_unwind_row(&unwound, 0x1080));
        // Gaps between rows hold leaves; the end is exclusive.
        assert!(!inside_unwind_row(&unwound, 0x1100));
        assert!(!inside_unwind_row(&unwound, 0x1180));
        assert!(!inside_unwind_row(&unwound, 0x1210));
        assert!(!inside_unwind_row(&[], 0x1001));
    }
}
