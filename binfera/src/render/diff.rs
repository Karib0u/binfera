//! Plain-text rendering of a [`DiffDocument`]: what changed, most useful first.
use std::fmt::Write;

use crate::diff::pair::{PairDiff, Status};
use crate::diff::{ChangeReason, DiffDocument, ListDelta, Method, Verdict};

const MAX_FUNCTIONS: usize = 40;

fn list(out: &mut String, title: &str, delta: &ListDelta) {
    if delta.added.is_empty() && delta.removed.is_empty() && delta.changed.is_empty() {
        return;
    }
    let _ = writeln!(out, "  {title}");
    for item in &delta.added {
        let _ = writeln!(out, "    + {item}");
    }
    for item in &delta.removed {
        let _ = writeln!(out, "    - {item}");
    }
    for item in &delta.changed {
        let _ = writeln!(out, "    ~ {}: {}", item.name, item.changes.join(", "));
    }
}

fn percent(value: f64) -> String {
    format!("{:.1}%", value * 100.0)
}

fn optional(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_string(), percent)
}

fn method(method: Method) -> &'static str {
    match method {
        Method::Exact => "exact",
        Method::Shape => "shape",
        Method::Name => "name",
        Method::Propagated => "propagated",
        Method::Fuzzy => "fuzzy",
        Method::Duplicate => "duplicate",
    }
}

fn reason(reason: ChangeReason) -> &'static str {
    match reason {
        ChangeReason::Code => "code",
        ChangeReason::String => "string",
        ChangeReason::Import => "import",
        ChangeReason::Callee => "callee",
    }
}

pub fn render(document: &DiffDocument) -> String {
    let mut out = String::new();
    let [a, b] = &document.inputs;
    let verdict = match document.verdict {
        Verdict::Identical => "identical",
        Verdict::Equivalent => "equivalent",
        Verdict::Changed => "changed",
    };
    let _ = writeln!(
        out,
        "A: {} ({} {}, {} functions)",
        a.name, a.format, a.arch, a.functions
    );
    let _ = writeln!(
        out,
        "B: {} ({} {}, {} functions)",
        b.name, b.format, b.arch, b.functions
    );
    let _ = writeln!(
        out,
        "verdict: {verdict}, similarity {} (code {}, imports {}, strings {}, capabilities {})",
        percent(document.similarity.overall),
        optional(document.similarity.code),
        optional(document.similarity.imports),
        optional(document.similarity.strings),
        optional(document.similarity.capabilities),
    );
    for warning in &document.warnings {
        let _ = writeln!(out, "warning: {warning}");
    }

    if let Some(delta) = &document.capability_delta {
        let _ = writeln!(
            out,
            "\ncapabilities: +{} -{} ~{} ={}",
            delta.added.len(),
            delta.removed.len(),
            delta.retargeted.len(),
            delta.unchanged
        );
        for rule in &delta.added {
            let _ = writeln!(out, "  + {}", rule.name);
        }
        for rule in &delta.removed {
            let _ = writeln!(out, "  - {}", rule.name);
        }
        for rule in &delta.retargeted {
            let _ = writeln!(
                out,
                "  ~ {} ({} lost, {} gained)",
                rule.name,
                rule.lost.len(),
                rule.gained.len()
            );
        }
        if !delta.attack_added.is_empty() {
            let _ = writeln!(out, "  ATT&CK gained: {}", delta.attack_added.join(", "));
        }
        if !delta.attack_removed.is_empty() {
            let _ = writeln!(out, "  ATT&CK lost: {}", delta.attack_removed.join(", "));
        }
        if delta.unmapped > 0 {
            let _ = writeln!(
                out,
                "  {} matches lie outside every recovered function",
                delta.unmapped
            );
        }
    }

    let file = &document.file_delta;
    if !file.is_empty() {
        let _ = writeln!(out, "\nfile:");
        list(&mut out, "sections", &file.sections);
        list(&mut out, "imports", &file.imports);
        list(&mut out, "exports", &file.exports);
        list(&mut out, "resources", &file.resources);
        if !file.overlay.is_empty() {
            let _ = writeln!(out, "  overlay: {}", file.overlay.join(", "));
        }
        if let Some([left, right]) = &file.imphash {
            let _ = writeln!(
                out,
                "  imphash: {} -> {}",
                left.as_deref().unwrap_or("none"),
                right.as_deref().unwrap_or("none")
            );
        }
    }

    if document.functions_compared {
        let changed: Vec<_> = document.matches.iter().filter(|m| m.changed).collect();
        let _ = writeln!(
            out,
            "\nfunctions: {} matched, {} changed, {} only in A, {} only in B",
            document.matches.len(),
            changed.len(),
            document.unmatched_a.len(),
            document.unmatched_b.len()
        );
        let mut changed = changed;
        changed.sort_by(|x, y| x.similarity.total_cmp(&y.similarity));
        for found in changed.iter().take(MAX_FUNCTIONS) {
            let reasons: Vec<_> = found.reasons.iter().map(|r| reason(*r)).collect();
            let _ = writeln!(
                out,
                "  ~ {:#x} -> {:#x} {} {} via {} ({})",
                found.a_addr,
                found.b_addr,
                found
                    .b_name
                    .as_deref()
                    .or(found.a_name.as_deref())
                    .unwrap_or("-"),
                percent(found.similarity),
                method(found.method),
                reasons.join(", ")
            );
        }
        if changed.len() > MAX_FUNCTIONS {
            let _ = writeln!(out, "  ... and {} more", changed.len() - MAX_FUNCTIONS);
        }
        for (sign, items) in [("-", &document.unmatched_a), ("+", &document.unmatched_b)] {
            for item in items.iter().take(MAX_FUNCTIONS) {
                let _ = writeln!(
                    out,
                    "  {sign} {:#x} {} ({} instructions)",
                    item.address,
                    item.name.as_deref().unwrap_or("-"),
                    item.instructions
                );
            }
            if items.len() > MAX_FUNCTIONS {
                let _ = writeln!(out, "  {sign} ... and {} more", items.len() - MAX_FUNCTIONS);
            }
        }
    }
    out
}

pub fn render_pair(diff: &PairDiff) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:#x} {} -> {:#x} {}, {}",
        diff.a,
        diff.a_name.as_deref().unwrap_or("-"),
        diff.b,
        diff.b_name.as_deref().unwrap_or("-"),
        percent(diff.similarity)
    );
    for block in &diff.blocks {
        let at = |value: Option<u64>| value.map_or_else(|| "-".to_string(), |v| format!("{v:#x}"));
        let _ = writeln!(out, "\nblock {} -> {}", at(block.a), at(block.b));
        for row in &block.rows {
            let sign = match row.status {
                Status::Same => ' ',
                Status::Changed => '~',
                Status::Added => '+',
                Status::Removed => '-',
            };
            let text = |insn: &Option<crate::diff::DetailInstruction>| {
                insn.as_ref()
                    .map_or_else(String::new, |insn| match &insn.note {
                        Some(note) => format!("{} ; {note}", insn.text),
                        None => insn.text.clone(),
                    })
            };
            if row.status == Status::Changed {
                let _ = writeln!(out, "{sign} {}  =>  {}", text(&row.a), text(&row.b));
            } else {
                let shown = if row.a.is_some() { &row.a } else { &row.b };
                let _ = writeln!(out, "{sign} {}", text(shown));
            }
        }
    }
    out
}
