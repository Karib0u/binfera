//! Structured graph and references from recovery, independent of printed assembly.
use super::*;
use crate::extract::decoder::Flow;
use crate::extract::recovery::EdgeKind;

#[derive(Debug, Serialize)]
pub struct FunctionGraph {
    pub blocks: Vec<GraphBlock>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Debug, Serialize)]
pub struct GraphBlock {
    pub address: u64,
    pub instructions: Vec<u64>,
}

#[derive(Debug, Serialize)]
pub struct GraphEdge {
    pub from: u64,
    pub to: u64,
    pub kind: GraphEdgeKind,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GraphEdgeKind {
    True,
    False,
    Jump,
}

#[derive(Debug, Serialize)]
pub struct Reference {
    pub from: u64,
    pub to: u64,
}

pub(super) fn function_graph(
    analysis: &Analysis,
    address: u64,
    rows: &[InstructionRow],
) -> Option<FunctionGraph> {
    let function = analysis.functions.get(&address)?;
    let shown: BTreeSet<_> = rows.iter().map(|r| r.0).collect();
    let blocks: Vec<_> = function
        .blocks
        .iter()
        .filter_map(|block| {
            let instructions: Vec<_> = block
                .insns
                .iter()
                .filter(|i| shown.contains(&i.address))
                .map(|i| i.address)
                .collect();
            (!instructions.is_empty()).then_some(GraphBlock {
                address: block.addr,
                instructions,
            })
        })
        .collect();
    let covered: BTreeSet<_> = blocks
        .iter()
        .flat_map(|b| b.instructions.iter().copied())
        .collect();
    if !shown.is_subset(&covered) {
        return None;
    }
    let known: BTreeSet<_> = blocks.iter().map(|b| b.address).collect();
    let mut edges = Vec::new();
    for block in &function.blocks {
        if !known.contains(&block.addr) {
            continue;
        }
        let conditional = block
            .insns
            .last()
            .is_some_and(|i| i.flow == Flow::ConditionalBranch)
            || block.insns.iter().rev().nth(1).is_some_and(|i| {
                i.flow == Flow::ConditionalBranch && i.risc().is_some_and(|r| r.delay)
            });
        for edge in &block.succs {
            if !known.contains(&edge.target) {
                continue;
            }
            let kind = if conditional {
                if edge.kind == EdgeKind::Fallthrough {
                    GraphEdgeKind::False
                } else {
                    GraphEdgeKind::True
                }
            } else {
                GraphEdgeKind::Jump
            };
            edges.push(GraphEdge {
                from: block.addr,
                to: edge.target,
                kind,
            });
        }
    }
    Some(FunctionGraph { blocks, edges })
}

pub(super) fn calls(listing: &[&crate::extract::decoder::DecodedInstruction]) -> Vec<u64> {
    listing
        .iter()
        .filter(|i| matches!(i.flow, Flow::Call | Flow::UnconditionalBranch))
        .filter_map(|i| i.direct_target)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(super) fn reference_index(analysis: &Analysis) -> std::collections::BTreeMap<u64, Vec<u64>> {
    let mut by_source = std::collections::BTreeMap::<u64, Vec<u64>>::new();
    for (&to, sources) in &analysis.data_xrefs {
        for &from in sources {
            by_source.entry(from).or_default().push(to);
        }
    }
    by_source
}

pub(super) fn data_references(
    index: &std::collections::BTreeMap<u64, Vec<u64>>,
    rows: &[InstructionRow],
) -> Vec<Reference> {
    rows.iter()
        .flat_map(|row| {
            index
                .get(&row.0)
                .into_iter()
                .flatten()
                .map(move |&to| Reference { from: row.0, to })
        })
        .collect()
}
