//! Delphi VMTs and classic RTTI in native PE images.
//!
//! Layout references: Embarcadero's Internal Data Formats (Delphi), and the table
//! descriptions in https://github.com/eset/DelphiHelper/tree/github/DelphiHelper/core.
//! Read only validated, file-backed records. In particular, never infer a data
//! range from the gap between two metadata pointers: that gap can contain code.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use crate::extract::image::{Architecture, ImageFormat, LoadedImage};

const MAX_ENTRIES: usize = 4096;
const MAX_CLASSES: usize = 16_384;
const MAX_METHODS: usize = 262_144;
const MAX_SCAN: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Class {
    pub name: String,
    /// Class reference (the first user virtual slot), not the negative header.
    pub vmt: u64,
    pub parent: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct Rtti {
    pub classes: Vec<Class>,
    pub methods: BTreeMap<u64, String>,
    pub function_starts: BTreeSet<u64>,
    /// Sorted, merged, half-open ranges of validated metadata.
    pub data_ranges: Vec<Range<u64>>,
}

struct Reader<'a> {
    image: &'a LoadedImage,
    ptr: u64,
    result: Rtti,
    methods: BTreeMap<u64, Vec<(usize, String, u8)>>,
    types: BTreeSet<u64>,
    method_count: usize,
}

impl Rtti {
    pub fn read(image: &LoadedImage) -> Self {
        if image.format != ImageFormat::Pe
            || !matches!(image.architecture, Architecture::X86 | Architecture::X64)
        {
            return Self::default();
        }
        Reader {
            image,
            ptr: if image.architecture == Architecture::X64 {
                8
            } else {
                4
            },
            result: Self::default(),
            methods: BTreeMap::new(),
            types: BTreeSet::new(),
            method_count: 0,
        }
        .read()
    }
}

impl Reader<'_> {
    fn bytes(&self, address: u64, size: u64) -> Option<&[u8]> {
        // Leave room for bounded record arithmetic even in a malicious PE
        // mapped at the very top of the address space.
        if address > u64::MAX - MAX_SCAN as u64 {
            return None;
        }
        let section = self.image.section_containing(address)?;
        if address.checked_add(size)? > section.address.checked_add(section.file_size)? {
            return None;
        }
        let bytes = self.image.bytes_at(address, usize::try_from(size).ok()?)?;
        (bytes.len() as u64 == size).then_some(bytes)
    }

    fn number(&self, address: u64, size: u64) -> Option<u64> {
        Some(
            self.bytes(address, size)?
                .iter()
                .enumerate()
                .fold(0, |n, (i, b)| n | (u64::from(*b) << (i * 8))),
        )
    }

    fn pointer(&self, address: u64) -> Option<u64> {
        self.number(address, self.ptr)
    }

    fn short_string(&self, address: u64) -> Option<(String, u64)> {
        let len = self.number(address, 1)?;
        let bytes = self.bytes(address + 1, len)?;
        if !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"_.$<> ,".contains(b))
        {
            return None;
        }
        Some((
            std::str::from_utf8(bytes).ok()?.to_owned(),
            address + 1 + len,
        ))
    }

    fn code(&self, address: u64) -> bool {
        self.image.is_primary_code_address(address)
            && self.image.is_executable_address(address)
            && self.bytes(address, 1).is_some()
    }

    fn range(&mut self, start: u64, end: u64) {
        if end > start && self.bytes(start, end - start).is_some() {
            self.result.data_ranges.push(start..end);
        }
    }

    fn method(&mut self, class: usize, address: u64, name: String, priority: u8) {
        if self.method_count < MAX_METHODS && self.code(address) {
            self.method_count += 1;
            self.methods
                .entry(address)
                .or_default()
                .push((class, name, priority));
        }
    }

    fn read(mut self) -> Rtti {
        let mut scanned = 0;
        let mut candidates = Vec::new();
        let mut type_candidates = Vec::new();
        for section in &self.image.sections {
            if section.address > u64::MAX - 2 * MAX_SCAN as u64 {
                continue;
            }
            let size = (section.file_size as usize).min(MAX_SCAN - scanned);
            let Some(bytes) = self.image.bytes_at(section.address, size) else {
                continue;
            };
            // RTTI self pointers need not be pointer-aligned.
            for (offset, raw) in bytes.windows(self.ptr as usize).enumerate() {
                let address = section.address + offset as u64;
                let target = raw
                    .iter()
                    .enumerate()
                    .fold(0, |n, (i, b)| n | (u64::from(*b) << (i * 8)));
                if target == address + self.ptr && type_candidates.len() < MAX_CLASSES * 4 {
                    type_candidates.push(target);
                }
                let Some(distance) = target.checked_sub(address) else {
                    continue;
                };
                // Delphi 4-2007: 19 words; newer Win32: 22; Win64: 25.
                if [19, 22, 25].contains(&(distance / self.ptr))
                    && distance % self.ptr == 0
                    && candidates.len() < MAX_CLASSES
                    && self.valid_vmt(address, target)
                {
                    candidates.push((address, target));
                }
            }
            scanned += size;
            if scanned == MAX_SCAN {
                break;
            }
        }
        for (header, vmt) in candidates {
            self.read_vmt(header, vmt);
        }
        // A self pointer alone is insufficient evidence in arbitrary PE code.
        if !self.result.classes.is_empty() {
            for address in type_candidates {
                self.read_type(address);
            }
        }
        self.result.data_ranges.sort_by_key(|range| range.start);
        let mut merged: Vec<Range<u64>> = Vec::new();
        for range in self.result.data_ranges.drain(..) {
            if let Some(last) = merged.last_mut().filter(|last| range.start <= last.end) {
                last.end = last.end.max(range.end);
            } else {
                merged.push(range);
            }
        }
        self.result.data_ranges = merged;
        let classes: BTreeMap<u64, usize> = self
            .result
            .classes
            .iter()
            .enumerate()
            .map(|(index, class)| (class.vmt, index))
            .collect();
        let ancestors: Vec<Vec<usize>> = (0..self.result.classes.len())
            .map(|class| self.ancestors(class, &classes))
            .collect();
        for (address, uses) in &self.methods {
            let data = &self.result.data_ranges;
            let i = data.partition_point(|range| range.end <= *address);
            if data.get(i).is_some_and(|range| range.contains(address)) {
                continue;
            }
            self.result.function_starts.insert(*address);
            // Prefer the declaring base over inherited copies. Unrelated shared
            // implementations have no unambiguous owner.
            let owners: BTreeSet<usize> = uses.iter().map(|(class, _, _)| *class).collect();
            let owner = owners
                .first()
                .and_then(|first| {
                    // The owner must be an ancestor of the first user. Walk that
                    // chain once instead of comparing every pair of users.
                    ancestors[*first]
                        .iter()
                        .copied()
                        .rev()
                        .find(|candidate| owners.contains(candidate))
                })
                .filter(|candidate| {
                    owners
                        .iter()
                        .all(|derived| ancestors[*derived].contains(candidate))
                });
            if let Some(owner) = owner {
                let priority = uses
                    .iter()
                    .filter(|(class, _, _)| *class == owner)
                    .map(|(_, _, priority)| *priority)
                    .max()
                    .unwrap_or(0);
                let names: BTreeSet<&str> = uses
                    .iter()
                    .filter(|(class, _, rank)| *class == owner && *rank == priority)
                    .map(|(_, name, _)| name.as_str())
                    .collect();
                let fallback = format!("FUN_{address:08x}");
                let name = if names.len() == 1 {
                    names.first().copied().unwrap_or(&fallback)
                } else {
                    &fallback
                };
                self.result.methods.insert(
                    *address,
                    format!("{}::{name}", self.result.classes[owner].name),
                );
            }
        }
        self.result
    }

    fn ancestors(&self, mut class: usize, index: &BTreeMap<u64, usize>) -> Vec<usize> {
        let mut chain = Vec::new();
        // Bound malformed cycles and deliberately deep hierarchies.
        for _ in 0..256 {
            if chain.contains(&class) {
                return Vec::new();
            }
            chain.push(class);
            let Some(parent) = self.result.classes[class]
                .parent
                .and_then(|vmt| index.get(&vmt))
            else {
                return chain;
            };
            class = *parent;
        }
        Vec::new()
    }

    fn valid_vmt(&self, header: u64, vmt: u64) -> bool {
        let Some(name_ptr) = self.pointer(header + 8 * self.ptr) else {
            return false;
        };
        let Some((name, _)) = self.short_string(name_ptr) else {
            return false;
        };
        if name.is_empty() || !name.as_bytes()[0].is_ascii_alphabetic() {
            return false;
        }
        let Some(size) = self.pointer(header + 9 * self.ptr) else {
            return false;
        };
        if !(self.ptr..=0x1000_0000).contains(&size) {
            return false;
        }
        if self.bytes(header, vmt - header).is_none() {
            return false;
        }
        // Every non-null metadata pointer must be backed by the file.
        for slot in (1..=7).chain(std::iter::once(10)) {
            let Some(pointer) = self.pointer(header + slot * self.ptr) else {
                return false;
            };
            if pointer != 0 && self.bytes(pointer, self.ptr).is_none() {
                return false;
            }
        }
        let mut functions = 0;
        for slot in (header + 11 * self.ptr..vmt).step_by(self.ptr as usize) {
            let Some(target) = self.pointer(slot) else {
                return false;
            };
            if target != 0 {
                if !self.code(target) {
                    return false;
                }
                functions += 1;
            }
        }
        functions >= 3
    }

    fn read_vmt(&mut self, header: u64, vmt: u64) {
        let p = self.ptr;
        let Some(name_ptr) = self.pointer(header + 8 * p) else {
            return;
        };
        let Some((name, name_end)) = self.short_string(name_ptr) else {
            return;
        };
        let parent_slot = self.pointer(header + 10 * p).unwrap_or(0);
        let parent = (parent_slot != 0)
            .then(|| self.pointer(parent_slot))
            .flatten();
        let class = self.result.classes.len();
        self.result.classes.push(Class { name, vmt, parent });
        self.range(header, vmt);
        self.range(name_ptr, name_end);
        if parent_slot != 0 {
            self.range(parent_slot, parent_slot + p);
        }
        let fixed = [
            "SafeCallException",
            "AfterConstruction",
            "BeforeDestruction",
            "Dispatch",
            "DefaultHandler",
            "NewInstance",
            "FreeInstance",
            "Destroy",
        ];
        for slot in (header + 11 * p..vmt).step_by(p as usize) {
            if let Some(target) = self.pointer(slot) {
                let index = ((vmt - slot) / p) as usize;
                let name = if index <= fixed.len() {
                    fixed[fixed.len() - index].to_owned()
                } else {
                    format!("FUN_{target:08x}")
                };
                self.method(class, target, name, u8::from(index <= fixed.len()));
            }
        }
        // Stop at the first metadata object or non-code pointer, including null.
        let end = (1..=8)
            .filter_map(|i| self.pointer(header + i * p))
            .filter(|address| *address >= vmt)
            .min()
            .unwrap_or(vmt + MAX_ENTRIES as u64 * p);
        let mut slot = vmt;
        for _ in 0..MAX_ENTRIES {
            if slot >= end {
                break;
            }
            let Some(target) = self.pointer(slot).filter(|target| self.code(*target)) else {
                break;
            };
            self.method(class, target, format!("FUN_{target:08x}"), 0);
            slot += p;
        }
        self.range(vmt, slot);
        if let Some(table) = self.pointer(header + p).filter(|t| *t != 0) {
            self.read_interfaces(class, table);
        }
        if let Some(table) = self.pointer(header + 6 * p).filter(|t| *t != 0) {
            self.read_methods(class, table);
        }
        if let Some(table) = self.pointer(header + 7 * p).filter(|t| *t != 0) {
            self.read_dynamic(class, table);
        }
        if let Some(table) = self.pointer(header + 5 * p).filter(|t| *t != 0) {
            self.read_fields(table);
        }
        if let Some(table) = self.pointer(header + 4 * p).filter(|t| *t != 0) {
            self.read_type(table);
        }
        if let Some(table) = self.pointer(header + 3 * p).filter(|t| *t != 0) {
            self.read_type(table);
        }
    }

    fn count(&self, address: u64, width: u64) -> Option<usize> {
        let count = usize::try_from(self.number(address, width)?).ok()?;
        (count <= MAX_ENTRIES).then_some(count)
    }

    fn read_methods(&mut self, class: usize, table: u64) -> Option<()> {
        let count = self.count(table, 2)?;
        let mut cursor = table + 2;
        let mut methods = Vec::new();
        for _ in 0..count {
            let len = self.number(cursor, 2)?;
            let target = self.pointer(cursor + 2)?;
            let (name, end) = self.short_string(cursor + 2 + self.ptr)?;
            if name.is_empty() || len < end - cursor || !self.code(target) {
                return None;
            }
            self.bytes(cursor, len)?;
            methods.push((target, name));
            cursor += len;
        }
        self.range(table, cursor);
        for (target, name) in methods {
            self.method(class, target, name, 3);
        }
        Some(())
    }

    fn read_dynamic(&mut self, class: usize, table: u64) -> Option<()> {
        let count = self.count(table, 2)? as u64;
        let end = table + 2 + count * (2 + self.ptr);
        self.bytes(table, end - table)?;
        let targets: Vec<u64> = (0..count)
            .map(|i| self.pointer(table + 2 + count * 2 + i * self.ptr))
            .collect::<Option<_>>()?;
        if !targets.iter().all(|target| self.code(*target)) {
            return None;
        }
        for (i, target) in targets.into_iter().enumerate() {
            let i = i as u64;
            let id = self.number(table + 2 + i * 2, 2)?;
            self.method(class, target, format!("Dynamic_{id:04x}"), 0);
        }
        self.range(table, end);
        Some(())
    }

    fn read_interfaces(&mut self, class: usize, table: u64) -> Option<()> {
        let count = self.count(table, self.ptr)? as u64;
        let end = table + self.ptr + count * (16 + 3 * self.ptr);
        self.bytes(table, end - table)?;
        self.range(table, end);
        for i in 0..count {
            let vmt = self.pointer(table + self.ptr + i * (16 + 3 * self.ptr) + 16)?;
            let mut slot = vmt;
            for _ in 0..MAX_ENTRIES {
                let Some(target) = self.pointer(slot).filter(|target| self.code(*target)) else {
                    break;
                };
                self.method(class, target, format!("FUN_{target:08x}"), 0);
                slot += self.ptr;
            }
            self.range(vmt, slot);
        }
        Some(())
    }

    fn read_fields(&mut self, table: u64) -> Option<()> {
        let count = self.count(table, 2)?;
        let classes = self.pointer(table + 2)?;
        let mut cursor = table + 2 + self.ptr;
        for _ in 0..count {
            cursor = self.short_string(cursor + 6)?.1;
        }
        self.range(table, cursor);
        if classes != 0 {
            if let Some(count) = self.count(classes, 2) {
                self.range(classes, classes + 2 + count as u64 * self.ptr);
            }
        }
        Some(())
    }

    fn read_type(&mut self, address: u64) -> Option<()> {
        if self.types.len() >= MAX_CLASSES * 4 || !self.types.insert(address) {
            return None;
        }
        let kind = self.number(address, 1)?;
        let (name, data) = self.short_string(address + 1)?;
        if name.is_empty() && kind != 14 {
            return None;
        }
        let p = self.ptr;
        let end = match kind {
            1 | 2 | 9 => data + 9, // OrdType, MinValue, MaxValue
            3 => {
                let min = self.number(data + 1, 4)? as u32 as i32;
                let max = self.number(data + 5, 4)? as u32 as i32;
                let count = i64::from(max) - i64::from(min) + 1;
                if !(0..=MAX_ENTRIES as i64).contains(&count) {
                    return None;
                }
                let base = self.pointer(data + 9)?;
                let mut cursor = data + 9 + p;
                if base != address.saturating_sub(p) && self.pointer(base) != Some(address) {
                    // A subrange references its base's names instead of repeating them.
                    cursor
                } else {
                    for _ in 0..count {
                        cursor = self.short_string(cursor)?.1;
                    }
                    self.short_string(cursor)?.1 // unit name
                }
            }
            4 => data + 1,     // FloatType
            5 => data + 1,     // short string capacity
            6 => data + 1 + p, // OrdType, CompType
            7 => {
                let vmt = self.pointer(data)?;
                let class = self
                    .result
                    .classes
                    .iter()
                    .position(|c| c.vmt == vmt && c.name == name)?;
                let mut cursor = self.short_string(data + 2 * p + 2)?.1;
                let count = self.count(cursor, 2)?;
                cursor += 2;
                let mut methods = Vec::new();
                for _ in 0..count {
                    let (property, end) = self.short_string(cursor + 4 * p + 10)?;
                    for (offset, prefix) in [(p, "Get"), (2 * p, "Set")] {
                        let target = self.pointer(cursor + offset)?;
                        // High bits encode a field offset or a virtual slot, not a VA.
                        if target >> (p * 8 - 2) == 0 && self.code(target) {
                            methods.push((target, format!("{prefix}{property}")));
                        }
                    }
                    cursor = end;
                }
                for (target, name) in methods {
                    self.method(class, target, name, 2);
                }
                cursor
            }
            8 => {
                let method_kind = self.number(data, 1)?;
                let count = self.count(data + 1, 1)?;
                let mut cursor = data + 2;
                for _ in 0..count {
                    cursor = self.short_string(cursor + 1)?.1; // flags, parameter name
                    cursor = self.short_string(cursor)?.1; // type name
                }
                if [1, 5, 7].contains(&method_kind) {
                    cursor = self.short_string(cursor)?.1;
                }
                cursor
            }
            10 | 11 | 12 | 18 => data, // string / variant, no classic payload
            13 => data + 8 + p,        // array size, element count, element type
            14 => {
                let count = self.count(data + 4, 4)? as u64;
                data + 8 + count * (2 * p) // managed record fields
            }
            15 => self.short_string(data + p + 1 + 16)?.1, // interface parent, flags, GUID, unit
            16 => data + 16,
            17 => self.short_string(data + 3 * p + 4)?.1, // dynamic array
            19 | 20 => data + p,
            _ => return None,
        };
        self.bytes(address, end - address)?;
        let start = address
            .checked_sub(p)
            .filter(|slot| self.pointer(*slot) == Some(address))
            .unwrap_or(address);
        self.range(start, end);
        Some(())
    }
}
