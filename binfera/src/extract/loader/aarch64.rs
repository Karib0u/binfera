//! Linked AArch64 ELF dynamic relocations, following Ghidra 12.1.4's
//! AARCH64_ElfRelocationHandler. Object-file instruction relocations require
//! an ET_REL section linker and are deliberately not treated as import slots.
use goblin::elf::{reloc::*, section_header::SHN_ABS, Elf};

use super::image::LoadedImage;

pub(super) fn relocate(image: &mut LoadedImage, elf: &Elf<'_>, relocation: Reloc) {
    let kind = relocation.r_type;
    if kind == R_AARCH64_NONE {
        return;
    }
    let Some(address) = relocation.r_offset.checked_add(image.load_bias) else {
        image
            .load_diagnostics
            .push("AArch64 relocation address overflow".into());
        return;
    };
    let symbol = elf.dynsyms.get(relocation.r_sym);
    let name = symbol
        .and_then(|s| elf.dynstrtab.get_at(s.st_name))
        .unwrap_or("");
    let width = match kind {
        R_AARCH64_ABS16 | R_AARCH64_PREL16 => 2,
        R_AARCH64_ABS32 | R_AARCH64_PREL32 => 4,
        R_AARCH64_ABS64 | R_AARCH64_PREL64 | R_AARCH64_RELATIVE | R_AARCH64_GLOB_DAT
        | R_AARCH64_JUMP_SLOT => 8,
        _ => {
            image.load_diagnostics.push(format!(
                "unsupported AArch64 ELF relocation {kind} at {address:#x} ({name})"
            ));
            return;
        }
    };
    if kind != R_AARCH64_RELATIVE && symbol.is_some_and(|s| s.st_shndx == 0) {
        if !name.is_empty()
            && matches!(
                kind,
                R_AARCH64_ABS64 | R_AARCH64_GLOB_DAT | R_AARCH64_JUMP_SLOT
            )
            && relocation.r_addend.unwrap_or(0) == 0
        {
            image.add_external_binding(address, vec![name.to_owned()]);
            image.import_locations.insert(address, format!("*.{name}"));
        } else {
            image.load_diagnostics.push(format!(
                "unresolved AArch64 ELF relocation {kind} at {address:#x} ({name})"
            ));
        }
        return;
    }
    let addend = match relocation.r_addend {
        Some(value) => value as u64,
        None => match image.bytes_at(address, width).filter(|b| b.len() == width) {
            Some(bytes) => bytes
                .iter()
                .enumerate()
                .fold(0u64, |v, (i, b)| v | (u64::from(*b) << (i * 8))),
            None => {
                image
                    .load_diagnostics
                    .push(format!("unmapped AArch64 relocation at {address:#x}"));
                return;
            }
        },
    };
    let base = if kind == R_AARCH64_RELATIVE {
        image.load_bias
    } else if let Some(symbol) = symbol {
        symbol
            .st_value
            .wrapping_add(if symbol.st_shndx == SHN_ABS as usize {
                0
            } else {
                image.load_bias
            })
    } else {
        image
            .load_diagnostics
            .push(format!("invalid AArch64 relocation symbol at {address:#x}"));
        return;
    };
    let mut value = base.wrapping_add(addend);
    if matches!(kind, R_AARCH64_PREL16 | R_AARCH64_PREL32 | R_AARCH64_PREL64) {
        value = value.wrapping_sub(address);
    }
    // Ghidra also reports overflow instead of silently truncating narrow relocations.
    let valid = match kind {
        R_AARCH64_ABS16 => (-32768..=65535).contains(&(value as i64)),
        R_AARCH64_ABS32 => (i64::from(i32::MIN)..=i64::from(u32::MAX)).contains(&(value as i64)),
        R_AARCH64_PREL16 => i16::try_from(value as i64).is_ok(),
        R_AARCH64_PREL32 => i32::try_from(value as i64).is_ok(),
        _ => true,
    };
    if !valid {
        image
            .load_diagnostics
            .push(format!("AArch64 relocation overflow at {address:#x}"));
        return;
    }
    let destination = image
        .sections
        .iter()
        .position(|s| s.contains_va(address))
        .and_then(|index| {
            let offset = usize::try_from(address - image.sections[index].address).ok()?;
            image
                .mapped_bytes
                .get_mut(index)?
                .get_mut(offset..offset.checked_add(width)?)
        });
    if let Some(destination) = destination {
        destination.copy_from_slice(&value.to_le_bytes()[..width]);
    } else {
        image
            .load_diagnostics
            .push(format!("unmapped AArch64 relocation at {address:#x}"));
    }
}
