//! Microsoft Visual C++ run-time type information: classes, their bases and their virtual
//! function tables, read from the structures the compiler emits for `typeid` and `dynamic_cast`.
//!
//! The layout follows Ghidra 12.1.4's `RttiAnalyzer` and its data types (`TypeDescriptor`,
//! `RTTICompleteObjectLocator`, `RTTIClassHierarchyDescriptor`, `RTTIBaseClassDescriptor`), and the
//! method ownership rule follows `RecoverClassesFromRTTIScript`, which Ghidra calls a prototype:
//!
//! - A type descriptor is `{ type_info vftable, spare = 0, ".?AV<name>@@" }`; every descriptor in
//!   an image points at the same `type_info` table, so the commonest value selects them.
//! - A complete object locator is `{ signature, offset, cd_offset, type descriptor, hierarchy }`,
//!   plus its own address on x64, where the references are image-relative and the signature is 1.
//!   `offset` is where the table's pointer sits in the complete object.
//! - A virtual function table follows a pointer to its locator; its slots run while they point
//!   into executable code.
//! - A class hierarchy descriptor lists every base class, the class itself first, each with its
//!   displacement in the object.
//!
//! A function in several tables belongs to the class that is a base of all the others (an
//! inherited method that is not overridden). When the classes are unrelated (identical code
//! folding, `_purecall`), it belongs to none.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::demangle;
use crate::extract::image::{Architecture, LoadedImage};

/// Bounds against malformed images: no real hierarchy or table comes near them.
const MAX_BASES: u32 = 1024;
const MAX_SLOTS: usize = 1024;
const MAX_NAME: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Class {
    /// The demangled class name, `net::TcpChannel`.
    pub name: String,
    pub type_descriptor: u64,
    /// The type descriptor's mangled name, `.?AVTcpChannel@net@@`.
    pub mangled: String,
    /// Every base class, direct or not, as indices into [`Rtti::classes`].
    pub bases: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VfTable {
    /// The first slot.
    pub address: u64,
    pub locator: u64,
    pub class: usize,
    /// Where the table's pointer sits in the complete object; 0 for the primary table.
    pub offset: u32,
    /// For a table at a non-zero offset, the base class whose subobject it serves.
    pub base: Option<usize>,
    pub slots: Vec<u64>,
}

/// The class a virtual function belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Method {
    pub class: usize,
    /// The offset of the table it was found in, in that class: where `this` points.
    pub this_offset: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rtti {
    pub classes: Vec<Class>,
    pub vftables: Vec<VfTable>,
}

impl Rtti {
    /// Read the RTTI of a PE image. Empty for any other image or one built without RTTI.
    pub fn read(image: &LoadedImage) -> Rtti {
        Reader::new(image).map(Reader::read).unwrap_or_default()
    }

    /// True when `base` is one of `derived`'s base classes.
    pub fn is_base(&self, base: usize, derived: usize) -> bool {
        self.classes
            .get(derived)
            .is_some_and(|class| class.bases.contains(&base))
    }

    /// Each virtual function that belongs to one class, by address.
    pub fn methods(&self) -> BTreeMap<u64, Method> {
        let mut found: BTreeMap<u64, BTreeSet<(usize, u32)>> = BTreeMap::new();
        for table in &self.vftables {
            for slot in &table.slots {
                found
                    .entry(*slot)
                    .or_default()
                    .insert((table.class, table.offset));
            }
        }
        let mut methods = BTreeMap::new();
        for (address, uses) in found {
            let classes: BTreeSet<usize> = uses.iter().map(|(class, _)| *class).collect();
            let owner = classes.iter().copied().find(|candidate| {
                classes
                    .iter()
                    .all(|other| other == candidate || self.is_base(*candidate, *other))
            });
            if let Some(class) = owner {
                let this_offset = uses
                    .iter()
                    .filter(|(used, _)| *used == class)
                    .map(|(_, offset)| *offset)
                    .min()
                    .unwrap_or(0);
                methods.insert(address, Method { class, this_offset });
            }
        }
        methods
    }
}

struct Reader<'a> {
    image: &'a LoadedImage,
    wide: bool,
}

impl<'a> Reader<'a> {
    fn new(image: &'a LoadedImage) -> Option<Self> {
        if image.format != crate::extract::image::ImageFormat::Pe {
            return None;
        }
        let wide = match image.architecture {
            Architecture::X64 => true,
            Architecture::X86 => false,
            _ => return None,
        };
        Some(Self { image, wide })
    }

    fn pointer_size(&self) -> u64 {
        if self.wide {
            8
        } else {
            4
        }
    }

    fn u32_at(&self, address: u64) -> Option<u32> {
        let bytes = self.image.bytes_at(address, 4)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    }

    fn pointer_at(&self, address: u64) -> Option<u64> {
        if self.wide {
            let bytes = self.image.bytes_at(address, 8)?;
            Some(u64::from_le_bytes(bytes.try_into().ok()?))
        } else {
            self.u32_at(address).map(u64::from)
        }
    }

    /// A reference inside an RTTI structure: an address on x86, image-relative on x64.
    fn reference_at(&self, address: u64) -> Option<u64> {
        let value = u64::from(self.u32_at(address)?);
        if self.wide {
            self.image.image_base.checked_add(value)
        } else {
            Some(value)
        }
    }

    fn mapped(&self, address: u64) -> bool {
        self.image.bytes_at(address, 1).is_some()
    }

    /// The initialized sections other than code, where the compiler puts RTTI and tables. An
    /// image without the NX flag has every section executable, so code is the loader's own
    /// notion of it, not the permission.
    fn data_sections(&self) -> impl Iterator<Item = (u64, &'a [u8])> + '_ {
        self.image.sections.iter().filter_map(move |section| {
            if section.file_size == 0 || self.image.is_primary_code_address(section.address) {
                return None;
            }
            let size = usize::try_from(section.virtual_size).ok()?;
            Some((section.address, self.image.bytes_at(section.address, size)?))
        })
    }

    fn read(self) -> Rtti {
        let descriptors = self.type_descriptors();
        if descriptors.is_empty() {
            return Rtti::default();
        }
        let locators = self.locators(&descriptors);
        let mut rtti = Rtti::default();
        let mut index: HashMap<u64, usize> = HashMap::new();
        let mut class_of = |rtti: &mut Rtti, descriptor: u64| -> Option<usize> {
            if let Some(found) = index.get(&descriptor) {
                return Some(*found);
            }
            let mangled = descriptors.get(&descriptor)?;
            let name = demangle::type_descriptor_class(mangled)?;
            rtti.classes.push(Class {
                name,
                type_descriptor: descriptor,
                mangled: mangled.clone(),
                bases: Vec::new(),
            });
            index.insert(descriptor, rtti.classes.len() - 1);
            Some(rtti.classes.len() - 1)
        };
        // Hierarchies first, so every table can name the base it serves.
        let mut hierarchies: BTreeMap<u64, Vec<(usize, i32, i32)>> = BTreeMap::new();
        for locator in locators.values() {
            if hierarchies.contains_key(&locator.hierarchy) {
                continue;
            }
            let Some(bases) = self.hierarchy(locator.hierarchy) else {
                continue;
            };
            let mut resolved = Vec::new();
            for (descriptor, member, vbtable) in bases {
                if let Some(class) = class_of(&mut rtti, descriptor) {
                    resolved.push((class, member, vbtable));
                }
            }
            hierarchies.insert(locator.hierarchy, resolved);
        }
        let mut tables = Vec::new();
        for (address, locator) in self.table_locators(&locators) {
            let Some(class) = class_of(&mut rtti, locator.descriptor) else {
                continue;
            };
            let hierarchy = hierarchies.get(&locator.hierarchy);
            if let Some(entries) = hierarchy {
                // The class itself comes first; the rest are its bases.
                if entries.first().map(|(first, _, _)| *first) == Some(class) {
                    let bases: Vec<usize> = entries.iter().skip(1).map(|(c, _, _)| *c).collect();
                    let known = &mut rtti.classes[class].bases;
                    for base in bases {
                        if !known.contains(&base) {
                            known.push(base);
                        }
                    }
                }
            }
            // A non-virtual base at this displacement; the array is in pre-order, so the first
            // match is the most derived of the bases sharing it.
            let base = (locator.offset != 0)
                .then(|| {
                    hierarchy?
                        .iter()
                        .skip(1)
                        .find(|(_, member, vbtable)| {
                            *vbtable == -1 && i64::from(*member) == i64::from(locator.offset)
                        })
                        .map(|(base, _, _)| *base)
                })
                .flatten();
            let slots = self.slots(address, &locators);
            if slots.is_empty() {
                continue;
            }
            tables.push(VfTable {
                address,
                locator: locator.address,
                class,
                offset: locator.offset,
                base,
                slots,
            });
        }
        rtti.vftables = tables;
        rtti
    }

    /// Type descriptors of classes and structures, by address, with their mangled names.
    fn type_descriptors(&self) -> BTreeMap<u64, String> {
        let pointer = self.pointer_size();
        let mut candidates: Vec<(u64, u64, String)> = Vec::new();
        for (start, bytes) in self.data_sections() {
            let mut at = 0;
            while let Some(found) = find(&bytes[at..], b".?A") {
                let position = at + found;
                at = position + 1;
                if !matches!(bytes.get(position + 3), Some(b'V' | b'U')) {
                    continue;
                }
                let name_address = start + position as u64;
                let Some(descriptor) = name_address.checked_sub(2 * pointer) else {
                    continue;
                };
                if descriptor % pointer != 0 || descriptor < start {
                    continue;
                }
                let tail = &bytes[position..];
                let Some(end) = tail.iter().take(MAX_NAME).position(|b| *b == 0) else {
                    continue;
                };
                let Ok(name) = std::str::from_utf8(&tail[..end]) else {
                    continue;
                };
                if !name.ends_with("@@") || !name.bytes().all(|b| b.is_ascii_graphic()) {
                    continue;
                }
                let (Some(table), Some(0)) = (
                    self.pointer_at(descriptor),
                    self.pointer_at(descriptor + pointer),
                ) else {
                    continue;
                };
                candidates.push((descriptor, table, name.to_owned()));
            }
        }
        // Every descriptor points at `type_info`'s table; a stray string does not.
        let mut votes: BTreeMap<u64, usize> = BTreeMap::new();
        for (_, table, _) in &candidates {
            *votes.entry(*table).or_default() += 1;
        }
        let Some(type_info) = votes
            .iter()
            .max_by_key(|(table, count)| (**count, std::cmp::Reverse(**table)))
            .map(|(table, _)| *table)
        else {
            return BTreeMap::new();
        };
        candidates
            .into_iter()
            .filter(|(_, table, _)| *table == type_info)
            .map(|(descriptor, _, name)| (descriptor, name))
            .collect()
    }

    /// Complete object locators whose type descriptor is known, by address.
    fn locators(&self, descriptors: &BTreeMap<u64, String>) -> BTreeMap<u64, Locator> {
        let signature = u32::from(self.wide);
        let mut locators = BTreeMap::new();
        for (start, bytes) in self.data_sections() {
            let mut position = (start.wrapping_neg() % 4) as usize;
            while position + 24 <= bytes.len() {
                let address = start + position as u64;
                position += 4;
                if self.u32_at(address) != Some(signature) {
                    continue;
                }
                let Some(descriptor) = self.reference_at(address + 12) else {
                    continue;
                };
                if !descriptors.contains_key(&descriptor) {
                    continue;
                }
                if self.wide && self.reference_at(address + 20) != Some(address) {
                    continue;
                }
                let (Some(offset), Some(hierarchy)) =
                    (self.u32_at(address + 4), self.reference_at(address + 16))
                else {
                    continue;
                };
                if self.hierarchy(hierarchy).is_none() {
                    continue;
                }
                locators.insert(
                    address,
                    Locator {
                        address,
                        offset,
                        descriptor,
                        hierarchy,
                    },
                );
            }
        }
        locators
    }

    /// A class hierarchy descriptor's base classes: type descriptor, member displacement and
    /// virtual base table displacement (-1 for a non-virtual base), the class itself first.
    fn hierarchy(&self, address: u64) -> Option<Vec<(u64, i32, i32)>> {
        if self.u32_at(address)? != 0 {
            return None;
        }
        let count = self.u32_at(address + 8)?;
        if count == 0 || count > MAX_BASES {
            return None;
        }
        let array = self.reference_at(address + 12)?;
        let mut bases = Vec::with_capacity(count as usize);
        for index in 0..u64::from(count) {
            let descriptor = self.reference_at(array + 4 * index)?;
            let type_descriptor = self.reference_at(descriptor)?;
            let member = self.u32_at(descriptor + 8)? as i32;
            let vbtable = self.u32_at(descriptor + 12)? as i32;
            if !self.mapped(type_descriptor) {
                return None;
            }
            bases.push((type_descriptor, member, vbtable));
        }
        Some(bases)
    }

    /// The tables: each follows a pointer to its locator.
    fn table_locators<'l>(&self, locators: &'l BTreeMap<u64, Locator>) -> Vec<(u64, &'l Locator)> {
        let pointer = self.pointer_size();
        let mut tables = Vec::new();
        for (start, bytes) in self.data_sections() {
            let mut position = (start.wrapping_neg() % pointer) as usize;
            while position + 2 * pointer as usize <= bytes.len() {
                let address = start + position as u64;
                position += pointer as usize;
                if let Some(locator) = self
                    .pointer_at(address)
                    .and_then(|value| locators.get(&value))
                {
                    tables.push((address + pointer, locator));
                }
            }
        }
        tables
    }

    fn slots(&self, table: u64, locators: &BTreeMap<u64, Locator>) -> Vec<u64> {
        let pointer = self.pointer_size();
        let mut slots = Vec::new();
        let mut at = table;
        while slots.len() < MAX_SLOTS {
            let Some(target) = self.pointer_at(at) else {
                break;
            };
            if locators.contains_key(&target)
                || !self.image.is_primary_code_address(target)
                || !self.image.is_executable_address(target)
            {
                break;
            }
            slots.push(target);
            at += pointer;
        }
        slots
    }
}

#[derive(Clone, Copy, Debug)]
struct Locator {
    address: u64,
    offset: u32,
    descriptor: u64,
    hierarchy: u64,
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(bytes: &[u8]) -> Result<Rtti, crate::extract::image::ImageError> {
        Ok(Rtti::read(&LoadedImage::parse(bytes)?))
    }

    fn names(rtti: &Rtti) -> Vec<&str> {
        let mut names: Vec<&str> = rtti.classes.iter().map(|c| c.name.as_str()).collect();
        names.sort();
        names
    }

    #[test]
    fn reads_classes_tables_and_owners() -> Result<(), crate::extract::image::ImageError> {
        for bytes in [
            &include_bytes!("../tests/fixtures/cpp/rtti32.dll")[..],
            &include_bytes!("../tests/fixtures/cpp/rtti64.dll")[..],
        ] {
            let image = LoadedImage::parse(bytes)?;
            let pointer = image.architecture.pointer_width() as u32;
            let rtti = Rtti::read(&image);
            assert_eq!(
                names(&rtti),
                [
                    "IThing",
                    "Thing",
                    "net::Box<int>",
                    "net::Channel",
                    "net::Logger",
                    "net::LoggingChannel",
                    "net::TcpChannel"
                ]
            );
            let class = |name: &str| rtti.classes.iter().position(|c| c.name == name);
            let logging = class("net::LoggingChannel");
            let logger = class("net::Logger");
            let tcp = class("net::TcpChannel");
            let channel = class("net::Channel");
            assert!(rtti.is_base(channel.unwrap_or(99), logging.unwrap_or(99)));
            assert!(!rtti.is_base(logging.unwrap_or(99), channel.unwrap_or(99)));
            // The primary table and the one for the Logger subobject.
            let tables: Vec<(Option<usize>, u32, Option<usize>, usize)> = rtti
                .vftables
                .iter()
                .filter(|t| Some(t.class) == logging)
                .map(|t| (Some(t.class), t.offset, t.base, t.slots.len()))
                .collect();
            assert!(tables.contains(&(logging, 0, None, 3)), "{tables:?}");
            assert!(
                tables.contains(&(logging, 3 * pointer, logger, 2)),
                "{tables:?}"
            );
            // TcpChannel::send is TcpChannel's own; Channel::recv-overrides are not shared.
            let methods = rtti.methods();
            let tcp_table = rtti.vftables.iter().find(|t| Some(t.class) == tcp);
            let send = tcp_table.and_then(|t| t.slots.get(1)).copied().unwrap_or(0);
            assert_eq!(methods.get(&send).map(|m| m.class), tcp);
            // The compiler dropped the tables of the abstract classes, so Logger::level is found
            // only in LoggingChannel's table for its Logger part, and belongs to it there.
            let secondary = rtti
                .vftables
                .iter()
                .find(|t| Some(t.class) == logging && t.offset != 0);
            let level = secondary.and_then(|t| t.slots.get(1)).copied().unwrap_or(0);
            assert_eq!(
                methods.get(&level),
                Some(&Method {
                    class: logging.unwrap_or(99),
                    this_offset: 3 * pointer
                })
            );
        }
        Ok(())
    }

    #[test]
    fn other_images_have_none() -> Result<(), crate::extract::image::ImageError> {
        let rtti = read(include_bytes!("../tests/fixtures/cpp/rtti64.elf"))?;
        assert!(rtti.classes.is_empty() && rtti.vftables.is_empty());
        Ok(())
    }
}
