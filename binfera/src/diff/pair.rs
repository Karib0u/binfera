//! One matched pair of functions, down to blocks and instructions.
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use super::fingerprint::{DetailBlock, DetailEdge, DetailInstruction, FunctionDetail};

/// Past this many cells, aligning two blocks is left to their common prefix and suffix.
const MAX_ALIGNMENT_CELLS: usize = 4_000_000;
/// Blocks below this similarity are not called the same block.
const BLOCK_THRESHOLD: f64 = 0.3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Same,
    Changed,
    Added,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionRow {
    pub status: Status,
    pub a: Option<DetailInstruction>,
    pub b: Option<DetailInstruction>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockRow {
    pub status: Status,
    pub a: Option<u64>,
    pub b: Option<u64>,
    pub similarity: f64,
    pub rows: Vec<InstructionRow>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from: u64,
    pub to: u64,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PairDiff {
    pub a: u64,
    pub b: u64,
    pub a_name: Option<String>,
    pub b_name: Option<String>,
    pub blocks: Vec<BlockRow>,
    pub a_edges: Vec<GraphEdge>,
    pub b_edges: Vec<GraphEdge>,
    pub similarity: f64,
}

fn norms(block: &DetailBlock) -> Vec<&str> {
    block
        .instructions
        .iter()
        .map(|insn| insn.norm.as_str())
        .collect()
}

/// The operations turning `a` into `b`, as (position in a, position in b).
fn align(a: &[&str], b: &[&str]) -> Vec<(Option<usize>, Option<usize>)> {
    let prefix = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let suffix = a[prefix..]
        .iter()
        .rev()
        .zip(b[prefix..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (mid_a, mid_b) = (&a[prefix..a.len() - suffix], &b[prefix..b.len() - suffix]);
    let mut out: Vec<(Option<usize>, Option<usize>)> =
        (0..prefix).map(|at| (Some(at), Some(at))).collect();
    let (n, m) = (mid_a.len(), mid_b.len());
    if n.saturating_mul(m) > MAX_ALIGNMENT_CELLS {
        out.extend((0..n).map(|at| (Some(prefix + at), None)));
        out.extend((0..m).map(|at| (None, Some(prefix + at))));
    } else {
        let width = m + 1;
        let mut table = vec![0_u32; (n + 1) * width];
        for i in (0..n).rev() {
            for j in (0..m).rev() {
                table[i * width + j] = if mid_a[i] == mid_b[j] {
                    table[(i + 1) * width + j + 1] + 1
                } else {
                    table[(i + 1) * width + j].max(table[i * width + j + 1])
                };
            }
        }
        let (mut i, mut j) = (0, 0);
        while i < n || j < m {
            if i < n && j < m && mid_a[i] == mid_b[j] {
                out.push((Some(prefix + i), Some(prefix + j)));
                i += 1;
                j += 1;
            } else if i < n && (j == m || table[(i + 1) * width + j] >= table[i * width + j + 1]) {
                out.push((Some(prefix + i), None));
                i += 1;
            } else {
                out.push((None, Some(prefix + j)));
                j += 1;
            }
        }
    }
    out.extend((0..suffix).map(|at| (Some(a.len() - suffix + at), Some(b.len() - suffix + at))));
    out
}

fn block_similarity(a: &DetailBlock, b: &DetailBlock) -> f64 {
    let (left, right) = (norms(a), norms(b));
    let largest = left.len().max(right.len());
    if largest == 0 {
        return 1.0;
    }
    let same = align(&left, &right)
        .iter()
        .filter(|(x, y)| x.is_some() && y.is_some())
        .count();
    same as f64 / largest as f64
}

/// Adjacent removals and additions of one mnemonic are one instruction with new operands.
fn rows(a: &DetailBlock, b: &DetailBlock, pairs: &BTreeMap<u64, u64>) -> Vec<InstructionRow> {
    let mut rows: Vec<InstructionRow> = Vec::new();
    let mut removed: Vec<DetailInstruction> = Vec::new();
    let mut added: Vec<DetailInstruction> = Vec::new();
    let flush = |rows: &mut Vec<InstructionRow>,
                 removed: &mut Vec<DetailInstruction>,
                 added: &mut Vec<DetailInstruction>| {
        let mnemonic = |insn: &DetailInstruction| insn.norm.split(' ').next().map(str::to_owned);
        let mut left = std::mem::take(removed).into_iter().peekable();
        let mut right = std::mem::take(added).into_iter().peekable();
        loop {
            match (left.peek(), right.peek()) {
                (Some(x), Some(y)) if mnemonic(x) == mnemonic(y) => rows.push(InstructionRow {
                    status: Status::Changed,
                    a: left.next(),
                    b: right.next(),
                }),
                (Some(_), _) => rows.push(InstructionRow {
                    status: Status::Removed,
                    a: left.next(),
                    b: None,
                }),
                (None, Some(_)) => rows.push(InstructionRow {
                    status: Status::Added,
                    a: None,
                    b: right.next(),
                }),
                (None, None) => break,
            }
        }
    };
    let (left, right) = (norms(a), norms(b));
    for step in align(&left, &right) {
        match step {
            (Some(x), Some(y)) => {
                flush(&mut rows, &mut removed, &mut added);
                let (a, b) = (a.instructions.get(x), b.instructions.get(y));
                let redirected = a
                    .and_then(|insn| insn.branch)
                    .and_then(|target| pairs.get(&target).copied())
                    .zip(b.and_then(|insn| insn.branch))
                    .is_some_and(|(mapped, actual)| mapped != actual);
                rows.push(InstructionRow {
                    status: if redirected {
                        Status::Changed
                    } else {
                        Status::Same
                    },
                    a: a.cloned(),
                    b: b.cloned(),
                });
            }
            (Some(x), None) => removed.extend(a.instructions.get(x).cloned()),
            (None, Some(y)) => added.extend(b.instructions.get(y).cloned()),
            (None, None) => {}
        }
    }
    flush(&mut rows, &mut removed, &mut added);
    rows
}

fn edges(function: &FunctionDetail) -> Vec<GraphEdge> {
    function
        .blocks
        .iter()
        .flat_map(|block| {
            block.successors.iter().map(|edge: &DetailEdge| GraphEdge {
                from: block.address,
                to: edge.target,
                kind: edge.kind.clone(),
            })
        })
        .collect()
}

/// Pairs blocks: the entry with the entry, blocks whose code is unique on both sides, then
/// outward along edges of the same kind, and last what remains in order of similarity.
fn pair_blocks(a: &FunctionDetail, b: &FunctionDetail) -> BTreeMap<u64, u64> {
    let by_a: BTreeMap<u64, &DetailBlock> = a.blocks.iter().map(|x| (x.address, x)).collect();
    let by_b: BTreeMap<u64, &DetailBlock> = b.blocks.iter().map(|x| (x.address, x)).collect();
    let mut pairs: BTreeMap<u64, u64> = BTreeMap::new();
    let mut taken: BTreeSet<u64> = BTreeSet::new();
    let mut queue = VecDeque::new();
    let mut take =
        |pairs: &mut BTreeMap<u64, u64>, x: u64, y: u64, queue: &mut VecDeque<(u64, u64)>| {
            if !pairs.contains_key(&x) && taken.insert(y) {
                pairs.insert(x, y);
                queue.push_back((x, y));
            }
        };
    if by_a.contains_key(&a.address) && by_b.contains_key(&b.address) {
        take(&mut pairs, a.address, b.address, &mut queue);
    }
    let code = |function: &FunctionDetail| {
        let mut groups: BTreeMap<Vec<String>, Vec<u64>> = BTreeMap::new();
        for block in &function.blocks {
            let key = norms(block).iter().map(|norm| norm.to_string()).collect();
            groups.entry(key).or_default().push(block.address);
        }
        groups
    };
    let right = code(b);
    for (key, ours) in code(a) {
        if let ([x], Some([y])) = (ours.as_slice(), right.get(&key).map(Vec::as_slice)) {
            take(&mut pairs, *x, *y, &mut queue);
        }
    }
    while let Some((x, y)) = queue.pop_front() {
        let (Some(left), Some(other)) = (by_a.get(&x), by_b.get(&y)) else {
            continue;
        };
        for edge in &left.successors {
            let peer = other.successors.iter().find(|candidate| {
                candidate.kind == edge.kind && by_b.contains_key(&candidate.target)
            });
            let (Some(peer), Some(from), true) = (
                peer,
                by_a.get(&edge.target),
                !pairs.contains_key(&edge.target),
            ) else {
                continue;
            };
            let Some(to) = by_b.get(&peer.target) else {
                continue;
            };
            if block_similarity(from, to) >= BLOCK_THRESHOLD {
                take(&mut pairs, edge.target, peer.target, &mut queue);
            }
        }
    }
    let mut rest = Vec::new();
    for (x, left) in &by_a {
        if pairs.contains_key(x) {
            continue;
        }
        for (y, other) in &by_b {
            if pairs.values().any(|used| used == y) {
                continue;
            }
            // Very large functions keep only what the graph established.
            if rest.len() > 100_000 {
                break;
            }
            let score = block_similarity(left, other);
            if score >= BLOCK_THRESHOLD {
                rest.push((score, *x, *y));
            }
        }
    }
    rest.sort_by(|p, q| {
        q.0.total_cmp(&p.0)
            .then_with(|| p.1.cmp(&q.1))
            .then_with(|| p.2.cmp(&q.2))
    });
    for (_, x, y) in rest {
        take(&mut pairs, x, y, &mut queue);
    }
    pairs
}

/// A copy whose `norm` also says where each call goes: in A's terms through the function match, so
/// a call to the counterpart of the old callee compares equal and any other does not.
fn with_callees(
    function: &FunctionDetail,
    side: char,
    forward: Option<&BTreeMap<u64, u64>>,
) -> FunctionDetail {
    let mut copy = function.clone();
    let Some(forward) = forward else {
        return copy;
    };
    for insn in copy
        .blocks
        .iter_mut()
        .flat_map(|block| &mut block.instructions)
    {
        let Some(call) = insn.call else {
            continue;
        };
        let target = match (side, forward.get(&call)) {
            ('a', Some(peer)) => format!("{peer:x}"),
            ('a', None) => format!("a{call:x}"),
            _ => format!("{call:x}"),
        };
        insn.norm = format!("{} -> {target}", insn.norm);
    }
    copy
}

/// Compares a pair. `forward` is the function match from A to B, when known; without it a call
/// is compared only by its masked text, so a redirected call would read as the same.
pub fn diff_functions(
    a: &FunctionDetail,
    b: &FunctionDetail,
    forward: Option<&BTreeMap<u64, u64>>,
) -> PairDiff {
    let (a, b) = (
        &with_callees(a, 'a', forward),
        &with_callees(b, 'b', forward),
    );
    let pairs = pair_blocks(a, b);
    let by_b: BTreeMap<u64, &DetailBlock> = b.blocks.iter().map(|x| (x.address, x)).collect();
    let paired: BTreeSet<u64> = pairs.values().copied().collect();
    let mut blocks = Vec::new();
    let (mut same, mut total) = (0_usize, 0_usize);
    let added_row = |insn: &DetailInstruction| InstructionRow {
        status: Status::Added,
        a: None,
        b: Some(insn.clone()),
    };
    for block in &a.blocks {
        let peer = pairs.get(&block.address).and_then(|y| by_b.get(y));
        let row = match peer {
            Some(peer) => {
                let rows = rows(block, peer, &pairs);
                let kept = rows.iter().filter(|r| r.status == Status::Same).count();
                same += kept;
                total += rows.len();
                BlockRow {
                    status: if kept == rows.len() {
                        Status::Same
                    } else {
                        Status::Changed
                    },
                    a: Some(block.address),
                    b: Some(peer.address),
                    similarity: if rows.is_empty() {
                        1.0
                    } else {
                        kept as f64 / rows.len() as f64
                    },
                    rows,
                }
            }
            None => {
                total += block.instructions.len();
                BlockRow {
                    status: Status::Removed,
                    a: Some(block.address),
                    b: None,
                    similarity: 0.0,
                    rows: block
                        .instructions
                        .iter()
                        .map(|insn| InstructionRow {
                            status: Status::Removed,
                            a: Some(insn.clone()),
                            b: None,
                        })
                        .collect(),
                }
            }
        };
        blocks.push(row);
    }
    for block in b.blocks.iter().filter(|x| !paired.contains(&x.address)) {
        total += block.instructions.len();
        blocks.push(BlockRow {
            status: Status::Added,
            a: None,
            b: Some(block.address),
            similarity: 0.0,
            rows: block.instructions.iter().map(added_row).collect(),
        });
    }
    PairDiff {
        a: a.address,
        b: b.address,
        a_name: a.name.clone(),
        b_name: b.name.clone(),
        blocks,
        a_edges: edges(a),
        b_edges: edges(b),
        similarity: if total == 0 {
            1.0
        } else {
            same as f64 / total as f64
        },
    }
}
