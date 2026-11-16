//! Bounded readers for on-disk Objective-C 2 and Swift 5 metadata.
//! Layout references: Apple objc4 runtime/objc-runtime-new.h and
//! swift/include/swift/ABI/Metadata.h. Pointers are read after chained rebasing.
use std::collections::{BTreeMap, BTreeSet};

use super::image::LoadedImage;

const MAX_ENTRIES: usize = 65_536;

#[derive(Default)]
pub(crate) struct Metadata {
    pub functions: BTreeMap<u64, String>,
    pub signatures: BTreeMap<u64, String>,
    pub labels: BTreeMap<u64, String>,
    pub selectors: BTreeMap<u64, String>,
    /// `__cfstring` objects by label: the text each constant `CFSTR` holds.
    pub cfstrings: BTreeMap<String, String>,
    pub diagnostics: Vec<String>,
}

struct Reader<'a> {
    image: &'a LoadedImage,
    result: Metadata,
    remaining: usize,
}

impl Reader<'_> {
    fn u32(&self, at: u64) -> Option<u32> {
        Some(u32::from_le_bytes(
            self.image.bytes_at(at, 4)?.try_into().ok()?,
        ))
    }
    fn pointer(&self, at: u64) -> Option<u64> {
        Some(u64::from_le_bytes(
            self.image.bytes_at(at, 8)?.try_into().ok()?,
        ))
    }
    fn relative(&self, at: u64) -> Option<u64> {
        let offset = self.u32(at)? as i32;
        (offset != 0).then_some(())?;
        at.checked_add_signed(i64::from(offset))
    }
    fn string(&self, at: u64) -> Option<String> {
        let data = self.image.bytes_at(at, 4096)?;
        let end = data.iter().position(|b| *b == 0)?;
        let value = std::str::from_utf8(data.get(..end)?).ok()?;
        (!value.is_empty() && !value.chars().any(char::is_control)).then(|| value.to_owned())
    }
    fn take(&mut self) -> bool {
        if self.remaining == 0 {
            return false;
        }
        self.remaining -= 1;
        true
    }
    fn class_name(&self, class: u64) -> Option<String> {
        let ro = self.pointer(class.checked_add(32)?)? & !7;
        self.string(self.pointer(ro.checked_add(24)?)?)
    }
    fn methods(&mut self, list: u64, class: &str, kind: char) -> Option<()> {
        if list == 0 {
            return Some(());
        }
        let flags = self.u32(list)?;
        let count = self.u32(list.checked_add(4)?)? as usize;
        let relative = flags & 0x8000_0000 != 0;
        let stride = (flags & 0x0000_fffc) as u64;
        if stride < if relative { 12 } else { 24 } || count > MAX_ENTRIES {
            return None;
        }
        for i in 0..count {
            if !self.take() {
                return None;
            }
            let at = list
                .checked_add(8)?
                .checked_add((i as u64).checked_mul(stride)?)?;
            let (name, imp, types) = if relative {
                let name = self.relative(at)?;
                let name = if flags & 0x4000_0000 != 0 {
                    name
                } else {
                    self.pointer(name)?
                };
                (
                    self.string(name)?,
                    self.relative(at.checked_add(8)?)?,
                    self.relative(at.checked_add(4)?)
                        .and_then(|p| self.string(p)),
                )
            } else {
                (
                    self.string(self.pointer(at)?)?,
                    self.pointer(at.checked_add(16)?)?,
                    self.pointer(at.checked_add(8)?)
                        .and_then(|p| self.string(p)),
                )
            };
            if self.image.is_executable_address(imp) {
                if let Some(types) = types {
                    self.result.signatures.insert(imp, types);
                }
                self.result
                    .functions
                    .entry(imp)
                    .or_insert_with(|| format!("{kind}[{class} {name}]"));
            }
        }
        Some(())
    }
    fn class(&mut self, class: u64) -> Option<()> {
        let name = self.class_name(class)?;
        self.result
            .labels
            .insert(class, format!("OBJC_CLASS_{name}"));
        let ro = self.pointer(class.checked_add(32)?)? & !7;
        self.methods(self.pointer(ro.checked_add(32)?)?, &name, '-')?;
        let meta = self.pointer(class)?;
        let ro = self.pointer(meta.checked_add(32)?)? & !7;
        self.methods(self.pointer(ro.checked_add(32)?)?, &name, '+')
    }
    fn category(&mut self, category: u64) -> Option<()> {
        let name = self.string(self.pointer(category)?)?;
        let slot = category.checked_add(8)?;
        let class = self.class_name(self.pointer(slot)?).or_else(|| {
            let name = self.image.import_locations.get(&slot)?;
            Some(name.split("OBJC_CLASS_$_").nth(1)?.to_owned())
        })?;
        let name = format!("{class}({name})");
        self.methods(self.pointer(category.checked_add(16)?)?, &name, '-')?;
        self.methods(self.pointer(category.checked_add(24)?)?, &name, '+')
    }
    fn swift_name(&self, mut descriptor: u64) -> Option<String> {
        let mut seen = BTreeSet::new();
        let mut names = Vec::new();
        for _ in 0..32 {
            if !seen.insert(descriptor) {
                return None;
            }
            let kind = self.u32(descriptor)? & 0x1f;
            if !matches!(kind, 0 | 16..=18) {
                break;
            }
            names.push(self.string(self.relative(descriptor.checked_add(8)?)?)?);
            let parent = descriptor.checked_add(4)?;
            let offset = self.u32(parent)?;
            if offset == 0 {
                break;
            }
            let target = parent.checked_add_signed(i64::from((offset & !1) as i32))?;
            descriptor = if offset & 1 != 0 {
                self.pointer(target)?
            } else {
                target
            };
        }
        names.reverse();
        (!names.is_empty()).then(|| names.join("::"))
    }
    /// A constant `CFString` (CoreFoundation's `__CFString`): class, flags, characters, length.
    /// Flag `0x10` marks UTF-16 characters, otherwise they are ASCII or UTF-8.
    fn cfstring(&mut self, at: u64) -> Option<()> {
        let flags = self.u32(at.checked_add(8)?)?;
        let characters = self.pointer(at.checked_add(16)?)?;
        let length = usize::try_from(self.pointer(at.checked_add(24)?)?).ok()?;
        if length > 4096 {
            return None;
        }
        let text = if flags & 0x10 != 0 {
            let bytes = self.image.bytes_at(characters, length.checked_mul(2)?)?;
            if bytes.len() != length * 2 {
                return None;
            }
            let units: Vec<u16> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            String::from_utf16(&units).ok()?
        } else {
            let bytes = self.image.bytes_at(characters, length)?;
            if bytes.len() != length {
                return None;
            }
            std::str::from_utf8(bytes).ok()?.to_owned()
        };
        let label = format!("cfstr_{at:x}");
        self.result.labels.insert(at, label.clone());
        self.result.cfstrings.insert(label, text);
        Some(())
    }
    fn swift_type(&mut self, descriptor: u64) -> Option<()> {
        if !matches!(self.u32(descriptor)? & 0x1f, 16..=18) {
            return Some(());
        }
        let name = self.swift_name(descriptor)?;
        self.result
            .labels
            .insert(descriptor, format!("{name}::type_descriptor"));
        if let Some(accessor) = self.relative(descriptor.checked_add(12)?) {
            if self.image.is_executable_address(accessor) {
                self.result
                    .functions
                    .entry(accessor)
                    .or_insert_with(|| format!("{name}::metadata_accessor"));
            }
        }
        Some(())
    }
}

pub(crate) fn read(bytes: &[u8], image: &LoadedImage) -> Metadata {
    let mut reader = Reader {
        image,
        result: Metadata::default(),
        remaining: MAX_ENTRIES,
    };
    let Ok(macho) = goblin::mach::MachO::parse(bytes, 0) else {
        return reader.result;
    };
    for segment in &macho.segments {
        let Ok(sections) = segment.sections() else {
            continue;
        };
        for (section, _) in sections {
            let name = section.name().unwrap_or("");
            let width = match name {
                "__objc_classlist" | "__objc_nlclslist" | "__objc_catlist" | "__objc_nlcatlist"
                | "__objc_selrefs" => 8,
                "__swift5_types" => 4,
                "__cfstring" => 32,
                _ => continue,
            };
            let count = section.size / width;
            if count > MAX_ENTRIES as u64 || section.size % width != 0 {
                reader
                    .result
                    .diagnostics
                    .push(format!("Mach-O metadata: invalid {name} size"));
                continue;
            }
            for i in 0..count {
                if !reader.take() {
                    break;
                }
                let Some(at) = section.addr.checked_add(i * width) else {
                    break;
                };
                let parsed = match name {
                    "__objc_classlist" | "__objc_nlclslist" => {
                        reader.pointer(at).and_then(|p| reader.class(p))
                    }
                    "__objc_catlist" | "__objc_nlcatlist" => {
                        reader.pointer(at).and_then(|p| reader.category(p))
                    }
                    "__objc_selrefs" => {
                        reader
                            .pointer(at)
                            .and_then(|p| reader.string(p))
                            .map(|selector| {
                                reader
                                    .result
                                    .labels
                                    .insert(at, format!("sel_{}", selector.replace(':', "_")));
                                reader.result.selectors.insert(at, selector);
                            })
                    }
                    "__swift5_types" => reader.relative(at).and_then(|p| reader.swift_type(p)),
                    "__cfstring" => reader.cfstring(at),
                    _ => Some(()),
                };
                if parsed.is_none() {
                    reader
                        .result
                        .diagnostics
                        .push(format!("Mach-O metadata: invalid {name} entry at {at:#x}"));
                    break;
                }
            }
        }
    }
    if reader.remaining == 0 {
        reader
            .result
            .diagnostics
            .push("Mach-O metadata entry limit reached".into());
    }
    reader.result
}
