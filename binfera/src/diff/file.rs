//! What differs in the containers: sections, imports, exports, resources and the overlay.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::fingerprint::{ExportFact, FileFacts, ImportFact, ResourceFact, SectionFact};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangedItem {
    pub name: String,
    /// Each thing that differs, short: `size 512 -> 1024`.
    pub changes: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ListDelta {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<ChangedItem>,
}

impl ListDelta {
    fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FileDelta {
    pub sections: ListDelta,
    pub imports: ListDelta,
    pub exports: ListDelta,
    pub resources: ListDelta,
    /// Each change to the overlay, empty when it is the same.
    pub overlay: Vec<String>,
    pub imphash: Option<[Option<String>; 2]>,
}

impl FileDelta {
    pub fn is_empty(&self) -> bool {
        self.sections.is_empty()
            && self.imports.is_empty()
            && self.exports.is_empty()
            && self.resources.is_empty()
            && self.overlay.is_empty()
            && self.imphash.is_none()
    }
}

/// Keys items so the Nth of a repeated name lines up with the Nth on the other side.
fn keyed<T>(items: &[T], name: impl Fn(&T) -> String) -> BTreeMap<String, &T> {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    items
        .iter()
        .map(|item| {
            let base = name(item);
            let count = seen.entry(base.clone()).or_default();
            *count += 1;
            let key = if *count == 1 {
                base
            } else {
                format!("{base} #{count}")
            };
            (key, item)
        })
        .collect()
}

fn delta<T>(
    a: &[T],
    b: &[T],
    name: impl Fn(&T) -> String,
    changes: impl Fn(&T, &T) -> Vec<String>,
) -> ListDelta {
    let (left, right) = (keyed(a, &name), keyed(b, &name));
    let mut out = ListDelta::default();
    for (key, item) in &left {
        match right.get(key) {
            None => out.removed.push(key.clone()),
            Some(other) => {
                let changes = changes(item, other);
                if !changes.is_empty() {
                    out.changed.push(ChangedItem {
                        name: key.clone(),
                        changes,
                    });
                }
            }
        }
    }
    out.added = right
        .keys()
        .filter(|key| !left.contains_key(*key))
        .cloned()
        .collect();
    out
}

fn section_changes(a: &SectionFact, b: &SectionFact) -> Vec<String> {
    let mut changes = Vec::new();
    if a.size != b.size {
        changes.push(format!("file size {} -> {}", a.size, b.size));
    }
    if a.virtual_size != b.virtual_size {
        changes.push(format!(
            "virtual size {} -> {}",
            a.virtual_size, b.virtual_size
        ));
    }
    if a.perms != b.perms {
        changes.push(format!("permissions {} -> {}", a.perms, b.perms));
    }
    if a.hash != b.hash {
        changes.push(format!(
            "content (entropy {:.2} -> {:.2})",
            a.entropy, b.entropy
        ));
    }
    changes
}

fn resource_changes(a: &ResourceFact, b: &ResourceFact) -> Vec<String> {
    let mut changes = Vec::new();
    if a.size != b.size {
        changes.push(format!("size {} -> {}", a.size, b.size));
    }
    if a.hash != b.hash {
        changes.push("content".to_string());
    }
    changes
}

pub(super) fn compare(a: &FileFacts, b: &FileFacts) -> FileDelta {
    let import = |item: &ImportFact| format!("{}!{}", item.dll, item.name);
    let export = |item: &ExportFact| item.name.clone();
    let resource = |item: &ResourceFact| format!("{}/{}/{}", item.kind, item.name, item.lang);
    let mut overlay = Vec::new();
    match (&a.overlay, &b.overlay) {
        (None, Some(found)) => overlay.push(format!("added, {} bytes", found.size)),
        (Some(found), None) => overlay.push(format!("removed, {} bytes", found.size)),
        (Some(left), Some(right)) => {
            if left.size != right.size {
                overlay.push(format!("size {} -> {}", left.size, right.size));
            }
            if left.hash != right.hash {
                overlay.push("content".to_string());
            }
        }
        (None, None) => {}
    }
    FileDelta {
        sections: delta(
            &a.sections,
            &b.sections,
            |s| s.name.clone(),
            section_changes,
        ),
        imports: delta(&a.imports, &b.imports, import, |_, _| Vec::new()),
        exports: delta(&a.exports, &b.exports, export, |left, right| {
            if left.forward == right.forward {
                Vec::new()
            } else {
                vec!["forwarder".to_string()]
            }
        }),
        resources: delta(&a.resources, &b.resources, resource, resource_changes),
        overlay,
        imphash: (a.imphash != b.imphash).then(|| [a.imphash.clone(), b.imphash.clone()]),
    }
}
