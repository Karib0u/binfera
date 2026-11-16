//! Conservative caller stack-balance evidence for untyped Win32 imports.
use crate::extract::{decoder::Flow, recovery::Analysis};
use iced_x86::{Mnemonic, OpKind, Register};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn infer(analysis: &Analysis, known: &BTreeMap<u64, i32>) -> BTreeMap<u64, u32> {
    let mut evidence: BTreeMap<u64, BTreeSet<u32>> = BTreeMap::new();
    let mut conflicts = BTreeSet::new();
    for function in analysis.functions.values() {
        // A reset from EBP or a branch needs path-sensitive constraints. Do not guess there.
        if function.blocks.len() != 1 {
            continue;
        }
        let mut delta = 0i64;
        let mut unknown = None;
        for insn in &function.blocks[0].insns {
            let op = insn.x86_instruction();
            if matches!(insn.flow, Flow::Call | Flow::IndirectCall) {
                let target = insn.memory_target.or(insn.direct_target);
                let Some(target) = target else {
                    break;
                };
                if let Some(&purge) = known.get(&target).filter(|purge| **purge >= 0) {
                    delta += i64::from(purge);
                } else if analysis.image.import_locations.contains_key(&target) && unknown.is_none()
                {
                    unknown = Some(target);
                } else {
                    break;
                }
                continue;
            }
            if insn.flow == Flow::Return {
                if let Some(target) = unknown {
                    if (-1024..=0).contains(&delta) && delta % 4 == 0 {
                        evidence.entry(target).or_default().insert((-delta) as u32);
                    } else {
                        conflicts.insert(target);
                    }
                }
                break;
            }
            if insn.flow != Flow::Next || op.mnemonic() == Mnemonic::Leave {
                break;
            }
            if op.op0_kind() == OpKind::Register && op.op0_register() == Register::ESP {
                if !matches!(op.mnemonic(), Mnemonic::Add | Mnemonic::Sub) {
                    break;
                }
                let amount = match op.op1_kind() {
                    OpKind::Immediate8to32 => i64::from(op.immediate8to32()),
                    OpKind::Immediate32 => i64::from(op.immediate32() as i32),
                    _ => break,
                };
                delta += if op.mnemonic() == Mnemonic::Add {
                    amount
                } else {
                    -amount
                };
            } else if op.is_stack_instruction() {
                delta += i64::from(op.stack_pointer_increment());
            }
        }
    }
    evidence
        .into_iter()
        .filter_map(|(target, values)| {
            (values.len() == 1 && !conflicts.contains(&target))
                .then(|| values.first().map(|value| (target, *value)))
                .flatten()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::{image::Architecture, recovery};
    #[test]
    fn infers_one_unknown_purge_but_refuses_stack_resets() -> anyhow::Result<()> {
        let code = [0x6a, 1, 0x6a, 2, 0xff, 0x15, 0, 0x20, 0, 0, 0xc3];
        let mut analysis = recovery::analyze_shellcode(&code, Architecture::X86)?;
        analysis
            .image
            .import_locations
            .insert(0x2000, "test.Unknown".into());
        assert_eq!(infer(&analysis, &BTreeMap::new()).get(&0x2000), Some(&8));
        let code = [
            0x55, 0x8b, 0xec, 0x6a, 1, 0xff, 0x15, 0, 0x20, 0, 0, 0xc9, 0xc3,
        ];
        let mut analysis = recovery::analyze_shellcode(&code, Architecture::X86)?;
        analysis
            .image
            .import_locations
            .insert(0x2000, "test.Unknown".into());
        assert!(infer(&analysis, &BTreeMap::new()).is_empty());
        Ok(())
    }
}
