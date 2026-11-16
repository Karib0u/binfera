//! Bounded section layout and symbol resolution for native ELF relocatable objects.
use super::image::{Architecture, ImageError, LoadedImage, MappedSection, Permissions};
use goblin::elf::{reloc::*, section_header::*, sym::Sym, Elf};
use std::collections::BTreeSet;

const BASE: u64 = 0x10_0000;
const LIMIT: u64 = 256 << 20;

pub(super) fn layout(elf: &Elf<'_>) -> Result<Vec<Option<u64>>, ImageError> {
    let mut next = BASE;
    let mut addresses = vec![None; elf.section_headers.len()];
    for (index, section) in elf.section_headers.iter().enumerate() {
        if section.sh_flags & u64::from(SHF_ALLOC) == 0 || section.sh_size == 0 {
            continue;
        }
        let alignment = section.sh_addralign.max(1);
        if !alignment.is_power_of_two() {
            return Err(ImageError::Elf("invalid section alignment".into()));
        }
        next = next
            .checked_add(alignment - 1)
            .map(|n| n & !(alignment - 1))
            .ok_or_else(|| ImageError::Elf("section address overflow".into()))?;
        addresses[index] = Some(next);
        next = next
            .checked_add(section.sh_size)
            .filter(|n| *n - BASE <= LIMIT)
            .ok_or_else(|| ImageError::Elf("relocatable image exceeds mapping limit".into()))?;
    }
    Ok(addresses)
}

pub(crate) fn symbol_address(elf: &Elf<'_>, image: &LoadedImage, symbol: Sym) -> Option<u64> {
    if symbol.st_shndx == SHN_ABS as usize {
        return Some(symbol.st_value);
    }
    let section = elf.section_headers.get(symbol.st_shndx)?;
    if symbol.st_shndx == 0 || symbol.st_value >= section.sh_size {
        return None;
    }
    section_address(elf, image, symbol.st_shndx)?.checked_add(symbol.st_value)
}

pub(crate) fn section_address(elf: &Elf<'_>, image: &LoadedImage, index: usize) -> Option<u64> {
    let section = elf.section_headers.get(index)?;
    if elf.header.e_type != goblin::elf::header::ET_REL {
        return section.sh_addr.checked_add(image.load_bias);
    }
    image
        .sections
        .iter()
        .find(|s| {
            s.file_offset == section.sh_offset
                && s.name == elf.shdr_strtab.get_at(section.sh_name).unwrap_or("")
        })
        .map(|s| s.address)
}

pub(super) fn relocate(
    image: &mut LoadedImage,
    elf: &Elf<'_>,
    addresses: &[Option<u64>],
) -> Result<(), ImageError> {
    let end = image
        .sections
        .iter()
        .filter_map(MappedSection::end_address)
        .max()
        .unwrap_or(BASE);
    let external = (end + 15) & !15;
    let mut called = BTreeSet::new();
    for (index, relocations) in &elf.shdr_relocs {
        let Some(header) = elf.section_headers.get(*index) else {
            continue;
        };
        let Some(Some(base)) = addresses.get(header.sh_info as usize) else {
            continue;
        };
        if elf
            .section_headers
            .get(header.sh_link as usize)
            .is_none_or(|s| s.sh_type != SHT_SYMTAB)
        {
            return Err(ImageError::Elf(
                "relocation does not reference the symbol table".into(),
            ));
        }
        for relocation in relocations.iter() {
            if super::risc_rel::is_call(image.architecture, relocation.r_type) {
                called.insert(relocation.r_sym);
            }
            let site = base
                .checked_add(relocation.r_offset)
                .and_then(|a| a.checked_sub(1));
            if image.architecture.is_x86()
                && site.is_some_and(|a| {
                    image.is_executable_address(a)
                        && image
                            .bytes_at(a, 1)
                            .is_some_and(|b| matches!(b.first(), Some(0xe8 | 0xe9)))
                })
            {
                called.insert(relocation.r_sym);
            }
        }
    }
    let undefined = elf
        .syms
        .iter()
        .filter(|s| s.st_shndx == 0 && s.st_name != 0)
        .count();
    if undefined > 100_000 {
        return Err(ImageError::Elf("external symbol limit exceeded".into()));
    }
    let common_base = (external + undefined as u64 * 8 + 15) & !15;
    let mut common = Vec::new();
    let mut symbols = Vec::new();
    let mut slots = Vec::new();
    for (index, symbol) in elf.syms.iter().enumerate() {
        if symbol.st_shndx == 0 && symbol.st_name != 0 {
            let address = external + slots.len() as u64;
            let name = elf.strtab.get_at(symbol.st_name).unwrap_or("");
            image.add_external_binding(address, vec![name.to_owned()]);
            if slots.len() >= 8 * 100_000 {
                return Err(ImageError::Elf("external symbol limit exceeded".into()));
            }
            if called.contains(&index) || symbol.st_type() == goblin::elf::sym::STT_FUNC {
                image.import_locations.insert(address, format!("*.{name}"));
            }
            slots.extend_from_slice(&[0; 8]);
            symbols.push(Some(address));
        } else if symbol.st_shndx == SHN_COMMON as usize {
            let alignment = symbol.st_value.max(1);
            if !alignment.is_power_of_two() {
                return Err(ImageError::Elf("invalid common-symbol alignment".into()));
            }
            let start = common_base
                .checked_add(common.len() as u64)
                .and_then(|v| v.checked_add(alignment - 1))
                .map(|v| v & !(alignment - 1))
                .ok_or_else(|| ImageError::Elf("common-symbol address overflow".into()))?;
            let end = start
                .checked_add(symbol.st_size.max(1))
                .filter(|end| end.saturating_sub(BASE) <= LIMIT)
                .and_then(|end| end.checked_sub(common_base))
                .filter(|end| *end <= LIMIT)
                .ok_or_else(|| ImageError::Elf("common-symbol mapping exceeds limit".into()))?;
            common.resize(end as usize, 0);
            symbols.push(Some(start));
        } else {
            symbols.push(symbol_address(elf, image, symbol));
        }
    }
    if !common.is_empty() {
        image.sections.push(MappedSection {
            name: "COMMON".into(),
            address: common_base,
            virtual_size: common.len() as u64,
            file_offset: 0,
            file_size: 0,
            permissions: Permissions {
                read: true,
                write: true,
                execute: false,
            },
        });
        image.mapped_bytes.push(common);
    }
    if !slots.is_empty() {
        image.sections.push(MappedSection {
            name: "EXTERNAL".into(),
            address: external,
            virtual_size: slots.len() as u64,
            file_offset: 0,
            file_size: 0,
            permissions: Permissions {
                read: true,
                write: true,
                execute: false,
            },
        });
        image.mapped_bytes.push(slots);
    }
    if !image.architecture.is_x86() {
        return super::risc_rel::relocate(image, elf, addresses, &symbols);
    }
    for (index, relocations) in &elf.shdr_relocs {
        let Some(header) = elf.section_headers.get(*index) else {
            continue;
        };
        let Some(Some(base)) = addresses.get(header.sh_info as usize) else {
            continue;
        };
        for relocation in relocations.iter() {
            let kind = relocation.r_type;
            if kind == 0 {
                continue;
            }
            let address = base
                .checked_add(relocation.r_offset)
                .ok_or_else(|| ImageError::Elf("relocation address overflow".into()))?;
            let (width, relative, signed) = match (image.architecture, kind) {
                (Architecture::X64, R_X86_64_64) => (8, false, false),
                (Architecture::X64, R_X86_64_PC32 | R_X86_64_PLT32) => (4, true, true),
                (Architecture::X64, R_X86_64_32) | (Architecture::X86, R_386_32) => {
                    (4, false, false)
                }
                (Architecture::X64, R_X86_64_32S) => (4, false, true),
                (Architecture::X86, R_386_PC32 | R_386_PLT32) => (4, true, true),
                _ => {
                    image.load_diagnostics.push(format!(
                        "unsupported ET_REL relocation {kind} at {address:#x}"
                    ));
                    continue;
                }
            };
            let Some(symbol) = symbols.get(relocation.r_sym).copied().flatten() else {
                image
                    .load_diagnostics
                    .push(format!("unresolved ET_REL symbol at {address:#x}"));
                continue;
            };
            let Some(section_index) = image.sections.iter().position(|s| s.contains_va(address))
            else {
                return Err(ImageError::Elf("unmapped relocation".into()));
            };
            // A relocation may not spill into the next section, even if it is adjacent.
            let section = &image.sections[section_index];
            if Some(section.address) != Some(*base)
                || relocation
                    .r_offset
                    .checked_add(width as u64)
                    .is_none_or(|n| n > section.virtual_size)
            {
                return Err(ImageError::Elf("relocation exceeds section".into()));
            }
            let offset = (address - section.address) as usize;
            let dest = image.mapped_bytes[section_index]
                .get_mut(offset..offset + width)
                .ok_or_else(|| ImageError::Elf("truncated relocation".into()))?;
            let addend = relocation.r_addend.map(i128::from).unwrap_or_else(|| {
                let mut bytes = [0; 8];
                bytes[..width].copy_from_slice(dest);
                if width == 4 {
                    i128::from(i32::from_le_bytes(
                        bytes[..4].try_into().unwrap_or_default(),
                    ))
                } else {
                    i128::from(i64::from_le_bytes(bytes))
                }
            });
            let value =
                i128::from(symbol) + addend - if relative { i128::from(address) } else { 0 };
            if width == 4
                && if signed {
                    i32::try_from(value).is_err()
                } else {
                    u32::try_from(value).is_err()
                }
            {
                return Err(ImageError::Elf(format!(
                    "relocation overflow at {address:#x}"
                )));
            }
            dest.copy_from_slice(&(value as u64).to_le_bytes()[..width]);
            // Retpolines preserve the architectural branch, and the return thunk
            // is a return. Normalize only explicit relocations to these compiler
            // helpers, never matching arbitrary instruction bytes or sample names.
            if relative && width == 4 && relocation.r_addend == Some(-4) && offset > 0 {
                let name = elf
                    .syms
                    .get(relocation.r_sym)
                    .filter(|s| s.st_shndx == 0)
                    .and_then(|s| elf.strtab.get_at(s.st_name))
                    .unwrap_or("");
                let code = &mut image.mapped_bytes[section_index];
                let opcode = code[offset - 1];
                if opcode == 0xe9 && name == "__x86_return_thunk" {
                    code[offset - 1..offset + 4].copy_from_slice(&[0xc3, 0x90, 0x90, 0x90, 0x90]);
                } else if matches!(opcode, 0xe8 | 0xe9) {
                    if let Some(register) = name.strip_prefix("__x86_indirect_thunk_") {
                        let regs = [
                            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9",
                            "r10", "r11", "r12", "r13", "r14", "r15",
                        ];
                        if let Some(reg) = regs.iter().position(|r| *r == register) {
                            let operation =
                                (if opcode == 0xe8 { 0xd0 } else { 0xe0 }) + (reg % 8) as u8;
                            let replacement = if reg < 8 {
                                [0xff, operation, 0x90, 0x90, 0x90]
                            } else {
                                [0x41, 0xff, operation, 0x90, 0x90]
                            };
                            code[offset - 1..offset + 4].copy_from_slice(&replacement);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
