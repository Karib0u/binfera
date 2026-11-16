//! The PE resource tree, version information and manifest.
//! Layout reference: Microsoft PE format, ".rsrc Section", and VS_VERSIONINFO.
//! The tree is walked by hand so that cycles and shared nodes in hostile files stay bounded.
use std::collections::HashSet;

use super::{identify, is_executable, FileDetails, Property, Resource};

const MAX_ENTRIES: usize = 65_536;
/// Entries can all alias one large blob, so hashing shares a budget instead of scaling with them.
const MAX_ENTROPY_BYTES: u64 = 1 << 30;
const MAX_MANIFEST: usize = 64 * 1024;
const HIGH_BIT: u32 = 0x8000_0000;

const RT_VERSION: u32 = 16;
const RT_MANIFEST: u32 = 24;

/// A file offset for the RVA, from the section table.
pub(super) type RvaToOff<'a> = &'a dyn Fn(u32) -> Option<usize>;

struct Walk<'a> {
    bytes: &'a [u8],
    root: usize,
    rva_to_off: RvaToOff<'a>,
    image_base: u64,
    seen: HashSet<usize>,
    entries: usize,
    entropy_left: u64,
    truncated: bool,
}

fn le16(bytes: &[u8], at: usize) -> Option<u16> {
    let raw = bytes.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes(raw.try_into().ok()?))
}

fn le32(bytes: &[u8], at: usize) -> Option<u32> {
    let raw = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(raw.try_into().ok()?))
}

pub(super) fn collect(
    bytes: &[u8],
    root_rva: u32,
    image_base: u64,
    rva_to_off: RvaToOff<'_>,
    details: &mut FileDetails,
) {
    let Some(root) = rva_to_off(root_rva) else {
        details.info("The resource directory is not in the file", None);
        return;
    };
    let mut walk = Walk {
        bytes,
        root,
        rva_to_off,
        image_base,
        seen: HashSet::new(),
        entries: 0,
        entropy_left: MAX_ENTROPY_BYTES,
        truncated: false,
    };
    let mut leaves = Vec::new();
    walk.directory(0, 0, &mut [None, None], &mut leaves);
    if walk.truncated {
        details.info(
            "The resource tree is too large or malformed to read completely",
            None,
        );
    }
    for leaf in leaves {
        finish_leaf(bytes, &leaf, details);
        details.resources.push(leaf.resource);
    }
}

struct Leaf {
    resource: Resource,
    type_id: Option<u32>,
}

impl Walk<'_> {
    /// Reads one directory. The fixed three levels are type, name and language.
    fn directory(
        &mut self,
        offset: u32,
        depth: usize,
        path: &mut [Option<Key>; 2],
        leaves: &mut Vec<Leaf>,
    ) {
        let Some(at) = self.root.checked_add(offset as usize) else {
            self.truncated = true;
            return;
        };
        if depth > 2 || !self.seen.insert(at) {
            self.truncated = true;
            return;
        }
        let (Some(named), Some(ids)) = (
            le16(self.bytes, at.saturating_add(12)),
            le16(self.bytes, at.saturating_add(14)),
        ) else {
            self.truncated = true;
            return;
        };
        for index in 0..usize::from(named) + usize::from(ids) {
            self.entries += 1;
            if self.entries > MAX_ENTRIES {
                self.truncated = true;
                return;
            }
            let entry = at
                .saturating_add(16)
                .saturating_add(index.saturating_mul(8));
            let (Some(name), Some(target)) = (
                le32(self.bytes, entry),
                le32(self.bytes, entry.saturating_add(4)),
            ) else {
                self.truncated = true;
                return;
            };
            let key = self.key(name);
            if target & HIGH_BIT != 0 {
                let Some(slot) = path.get_mut(depth) else {
                    self.truncated = true;
                    return;
                };
                *slot = Some(key);
                self.directory(target & !HIGH_BIT, depth + 1, path, leaves);
            } else if depth == 2 {
                if let Some(leaf) = self.leaf(target, path, key) {
                    leaves.push(leaf);
                }
            } else {
                self.truncated = true;
            }
        }
    }

    fn key(&self, name: u32) -> Key {
        if name & HIGH_BIT == 0 {
            return Key::Id(name);
        }
        let text = self
            .root
            .checked_add((name & !HIGH_BIT) as usize)
            .and_then(|at| {
                let units = usize::from(le16(self.bytes, at)?);
                let raw = self.bytes.get(at + 2..at + 2 + units * 2)?;
                let wide: Vec<u16> = raw
                    .chunks_exact(2)
                    .map(|pair| {
                        pair.iter()
                            .rev()
                            .fold(0u16, |acc, &b| (acc << 8) | u16::from(b))
                    })
                    .collect();
                Some(String::from_utf16_lossy(&wide))
            });
        Key::Name(text.unwrap_or_else(|| "(unreadable)".into()))
    }

    fn leaf(&mut self, entry_off: u32, path: &[Option<Key>; 2], lang: Key) -> Option<Leaf> {
        let at = self.root.checked_add(entry_off as usize)?;
        let rva = le32(self.bytes, at)?;
        let size = le32(self.bytes, at.checked_add(4)?)?;
        let off = (self.rva_to_off)(rva);
        let data = off.and_then(|start| {
            let end = start.saturating_add(size as usize).min(self.bytes.len());
            self.bytes.get(start..end)
        });
        let entropy = data
            .filter(|data| (data.len() as u64) <= self.entropy_left && !data.is_empty())
            .map(|data| {
                self.entropy_left -= data.len() as u64;
                crate::packing::entropy(data)
            });
        let [type_key, name_key] = path;
        let type_id = match type_key {
            Some(Key::Id(id)) => Some(*id),
            _ => None,
        };
        Some(Leaf {
            type_id,
            resource: Resource {
                kind: type_key.as_ref().map_or_else(String::new, type_label),
                name: name_key.as_ref().map_or_else(String::new, Key::text),
                lang: match lang {
                    Key::Id(id) => lang_label(id),
                    Key::Name(name) => name,
                },
                va: self.image_base.saturating_add(u64::from(rva)),
                off: off.map(|start| start as u64),
                size: u64::from(size),
                entropy,
                detected: data.and_then(identify),
            },
        })
    }
}

enum Key {
    Id(u32),
    Name(String),
}

impl Key {
    fn text(&self) -> String {
        match self {
            Key::Id(id) => format!("#{id}"),
            Key::Name(name) => name.clone(),
        }
    }
}

fn type_label(key: &Key) -> String {
    const NAMES: &[(u32, &str)] = &[
        (1, "CURSOR"),
        (2, "BITMAP"),
        (3, "ICON"),
        (4, "MENU"),
        (5, "DIALOG"),
        (6, "STRING"),
        (7, "FONTDIR"),
        (8, "FONT"),
        (9, "ACCELERATOR"),
        (10, "RCDATA"),
        (11, "MESSAGETABLE"),
        (12, "GROUP_CURSOR"),
        (14, "GROUP_ICON"),
        (16, "VERSION"),
        (17, "DLGINCLUDE"),
        (19, "PLUGPLAY"),
        (20, "VXD"),
        (21, "ANICURSOR"),
        (22, "ANIICON"),
        (23, "HTML"),
        (24, "MANIFEST"),
    ];
    match key {
        Key::Id(id) => NAMES
            .iter()
            .find(|(known, _)| known == id)
            .map_or_else(|| format!("#{id}"), |(_, name)| (*name).to_string()),
        Key::Name(name) => name.clone(),
    }
}

fn lang_label(id: u32) -> String {
    const NAMES: &[(u32, &str)] = &[
        (0, "neutral"),
        (0x400, "user default"),
        (0x401, "ar-SA"),
        (0x402, "bg-BG"),
        (0x404, "zh-TW"),
        (0x405, "cs-CZ"),
        (0x407, "de-DE"),
        (0x408, "el-GR"),
        (0x409, "en-US"),
        (0x40a, "es-ES"),
        (0x40c, "fr-FR"),
        (0x40d, "he-IL"),
        (0x410, "it-IT"),
        (0x411, "ja-JP"),
        (0x412, "ko-KR"),
        (0x413, "nl-NL"),
        (0x415, "pl-PL"),
        (0x416, "pt-BR"),
        (0x418, "ro-RO"),
        (0x419, "ru-RU"),
        (0x41f, "tr-TR"),
        (0x422, "uk-UA"),
        (0x429, "fa-IR"),
        (0x804, "zh-CN"),
        (0x809, "en-GB"),
        (0x816, "pt-PT"),
    ];
    NAMES
        .iter()
        .find(|(known, _)| *known == id)
        .map_or_else(|| format!("{id:#06x}"), |(_, name)| (*name).to_string())
}

fn finish_leaf(bytes: &[u8], leaf: &Leaf, details: &mut FileDetails) {
    let resource = &leaf.resource;
    let data = resource.off.and_then(|off| {
        let start = usize::try_from(off).ok()?;
        let end = start
            .saturating_add(usize::try_from(resource.size).ok()?)
            .min(bytes.len());
        bytes.get(start..end)
    });
    if let Some(kind) = resource.detected.filter(|kind| is_executable(kind)) {
        details.warn(
            format!(
                "Resource {}/{} holds an embedded {kind}",
                resource.kind, resource.name
            ),
            Some(resource.va),
        );
    } else if resource.entropy.is_some_and(|e| e >= 7.5) && resource.size >= 1024 {
        // Compressed images are expected to look random; anything else may be a packed payload.
        if !matches!(resource.detected, Some("PNG" | "JPEG" | "GIF")) && resource.kind != "ICON" {
            details.warn(
                format!(
                    "Resource {}/{} has high entropy ({:.2})",
                    resource.kind,
                    resource.name,
                    resource.entropy.unwrap_or_default()
                ),
                Some(resource.va),
            );
        }
    }
    let Some(data) = data else {
        return;
    };
    match leaf.type_id {
        Some(RT_VERSION) if details.version_info.is_empty() => {
            details.version_info = version_info(data);
        }
        Some(RT_MANIFEST) if details.manifest.is_none() => {
            let shown = data.get(..data.len().min(MAX_MANIFEST)).unwrap_or(data);
            let text = String::from_utf8_lossy(shown);
            let text = text.trim_start_matches('\u{feff}').trim();
            if let Some(level) = execution_level(text) {
                details.fact("Identity", "Requested execution level", level);
            }
            details.manifest = Some(text.into());
        }
        _ => {}
    }
}

fn execution_level(manifest: &str) -> Option<String> {
    let at = manifest.find("requestedExecutionLevel")?;
    let rest = manifest.get(at..)?;
    let rest = rest.get(rest.find("level")?..)?;
    let rest = rest.get(rest.find(['"', '\''])?..)?;
    let mut chars = rest.chars();
    let quote = chars.next()?;
    let value = chars.as_str();
    value.get(..value.find(quote)?).map(str::to_owned)
}

/// One VS_VERSIONINFO-style node: its length, key and where its value starts.
struct Node<'a> {
    length: usize,
    value_length: usize,
    wide: bool,
    key: String,
    value: &'a [u8],
}

fn node(data: &[u8]) -> Option<Node<'_>> {
    let length = usize::from(le16(data, 0)?);
    if length < 6 || length > data.len() {
        return None;
    }
    let value_length = usize::from(le16(data, 2)?);
    let wide = le16(data, 4)? == 1;
    let mut units = Vec::new();
    let mut at = 6;
    while at + 2 <= length {
        let unit = le16(data, at)?;
        at += 2;
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    let value = align4(at);
    Some(Node {
        length,
        value_length,
        wide,
        key: String::from_utf16_lossy(&units),
        value: data.get(value.min(length)..length)?,
    })
}

fn align4(at: usize) -> usize {
    at.saturating_add(3) & !3
}

/// The child nodes stored after `skip` bytes of `data`.
fn children(data: &[u8], skip: usize) -> Vec<Node<'_>> {
    let mut out = Vec::new();
    let mut at = align4(skip);
    while let Some(child) = data.get(at..).and_then(node) {
        at = align4(at.saturating_add(child.length));
        out.push(child);
    }
    out
}

fn version_info(data: &[u8]) -> Vec<Property> {
    let Some(root) = node(data).filter(|root| root.key == "VS_VERSION_INFO") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if root.value_length >= 52 && le32(root.value, 0) == Some(0xfeef_04bd) {
        let mut version = |label: &str, at: usize| {
            if let (Some(high), Some(low)) = (le32(root.value, at), le32(root.value, at + 4)) {
                out.push(Property {
                    label: label.into(),
                    value: format!(
                        "{}.{}.{}.{}",
                        high >> 16,
                        high & 0xffff,
                        low >> 16,
                        low & 0xffff
                    ),
                });
            }
        };
        version("Fixed file version", 8);
        version("Fixed product version", 16);
    }
    for section in children(root.value, root.value_length) {
        if section.key != "StringFileInfo" {
            continue;
        }
        for table in children(section.value, 0) {
            for string in children(table.value, 0) {
                // wValueLength counts UTF-16 units for text values.
                let units: Vec<u16> = string
                    .value
                    .chunks_exact(2)
                    .take(if string.wide { string.value_length } else { 0 })
                    .map(|pair| {
                        pair.iter()
                            .rev()
                            .fold(0u16, |acc, &b| (acc << 8) | u16::from(b))
                    })
                    .take_while(|&unit| unit != 0)
                    .collect();
                let value = String::from_utf16_lossy(&units);
                if !value.trim().is_empty() && !out.iter().any(|p: &Property| p.label == string.key)
                {
                    out.push(Property {
                        label: string.key,
                        value,
                    });
                }
            }
        }
    }
    out
}
