//! ARM/Thumb, AArch64 and classic MIPS32 ET_REL fixups. Formulas follow the
//! pinned Ghidra ELF relocation handlers and Arm's aaelf32/aaelf64 ABI tables.
//! Section layout and external symbol allocation are shared with the x86 loader.
use super::image::{Architecture, ImageError, LoadedImage};
use goblin::elf::{reloc::*, section_header::SHT_SYMTAB, Elf};
use std::collections::BTreeMap;

// Goblin retains the historical name for relocation 10.
const R_ARM_THM_CALL: u32 = R_ARM_THM_PC22;

pub(super) fn is_call(arch: Architecture, kind: u32) -> bool {
    match arch {
        Architecture::Arm => matches!(
            kind,
            R_ARM_PC24
                | R_ARM_PLT32
                | R_ARM_CALL
                | R_ARM_JUMP24
                | R_ARM_THM_CALL
                | R_ARM_THM_JUMP24
        ),
        Architecture::AArch64 => matches!(kind, R_AARCH64_CALL26 | R_AARCH64_JUMP26),
        Architecture::Mips | Architecture::MipsBe => kind == R_MIPS_26,
        _ => false,
    }
}
fn diagnostic(image: &mut LoadedImage, message: String) {
    if image.load_diagnostics.len() < 256 {
        image.load_diagnostics.push(message);
    } else if image.load_diagnostics.len() == 256 {
        image
            .load_diagnostics
            .push("further ET_REL relocation diagnostics omitted".into());
    }
}
fn failure(address: u64, message: &str) -> ImageError {
    ImageError::Elf(format!("ET_REL relocation at {address:#x}: {message}"))
}
fn signed(value: i128, bits: u32, alignment: i128, address: u64) -> Result<i64, ImageError> {
    if value < -(1i128 << (bits - 1)) || value >= 1i128 << (bits - 1) || value % alignment != 0 {
        return Err(failure(address, "overflow or invalid alignment"));
    }
    Ok(value as i64)
}
fn read(image: &LoadedImage, address: u64, width: usize) -> Result<u64, ImageError> {
    let bytes = image
        .bytes_at(address, width)
        .filter(|b| b.len() == width)
        .ok_or_else(|| failure(address, "truncated field"))?;
    Ok(bytes.iter().enumerate().fold(0, |value, (index, byte)| {
        let shift = if image.architecture.little_endian() {
            index
        } else {
            width - 1 - index
        };
        value | (u64::from(*byte) << (8 * shift))
    }))
}
fn write(
    image: &mut LoadedImage,
    address: u64,
    width: usize,
    value: u64,
) -> Result<(), ImageError> {
    let little = image.architecture.little_endian();
    let index = image
        .sections
        .iter()
        .position(|s| s.contains_va(address))
        .ok_or_else(|| failure(address, "unmapped field"))?;
    let offset = (address - image.sections[index].address) as usize;
    let bytes = image.mapped_bytes[index]
        .get_mut(offset..offset + width)
        .ok_or_else(|| failure(address, "truncated field"))?;
    for (index, byte) in bytes.iter_mut().enumerate() {
        let shift = if little { index } else { width - 1 - index };
        *byte = (value >> (8 * shift)) as u8;
    }
    Ok(())
}
fn scalar(
    image: &mut LoadedImage,
    address: u64,
    width: usize,
    symbol: u64,
    addend: Option<i64>,
    relative: bool,
) -> Result<(), ImageError> {
    let stored = read(image, address, width)?;
    let addend = addend.map(i128::from).unwrap_or_else(|| {
        let shift = 64 - width * 8;
        i128::from(((stored << shift) as i64) >> shift)
    });
    let value = i128::from(symbol) + addend - if relative { i128::from(address) } else { 0 };
    let bits = width * 8;
    if bits < 64
        && (value < -(1i128 << (bits - 1))
            || value >= 1i128 << if relative { bits - 1 } else { bits })
    {
        return Err(failure(address, "scalar overflow"));
    }
    write(image, address, width, value as u64)
}

pub(super) fn relocate(
    image: &mut LoadedImage,
    elf: &Elf<'_>,
    addresses: &[Option<u64>],
    symbols: &[Option<u64>],
) -> Result<(), ImageError> {
    let mut count = 0usize;
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
        let target = &elf.section_headers[header.sh_info as usize];
        // All HI16 records for a symbol wait for its next LO16, including several
        // high halves sharing one low half. Pairing is local to a relocation table.
        let mut high: BTreeMap<usize, Vec<(u64, u32, Option<i64>)>> = BTreeMap::new();
        for relocation in relocations.iter() {
            count += 1;
            if count > 1_000_000 {
                return Err(ImageError::Elf("ET_REL relocation limit exceeded".into()));
            }
            let kind = relocation.r_type;
            if kind == 0 {
                continue;
            }
            let address = base
                .checked_add(relocation.r_offset)
                .ok_or_else(|| failure(*base, "address overflow"))?;
            let width = if image.architecture == Architecture::AArch64
                && matches!(kind, R_AARCH64_ABS64 | R_AARCH64_PREL64)
            {
                8
            } else if image.architecture == Architecture::AArch64
                && matches!(kind, R_AARCH64_ABS16 | R_AARCH64_PREL16)
            {
                2
            } else {
                4
            };
            if relocation
                .r_offset
                .checked_add(width as u64)
                .is_none_or(|end| end > target.sh_size)
            {
                return Err(failure(address, "field exceeds destination section"));
            }
            let Some(symbol) = symbols.get(relocation.r_sym).copied().flatten() else {
                diagnostic(image, format!("unresolved ET_REL symbol at {address:#x}"));
                continue;
            };
            let name = elf
                .syms
                .get(relocation.r_sym)
                .and_then(|s| elf.strtab.get_at(s.st_name))
                .unwrap_or("");
            if matches!(
                image.architecture,
                Architecture::Mips | Architecture::MipsBe
            ) && matches!(name, "_gp_disp" | "__gnu_local_gp")
            {
                diagnostic(
                    image,
                    format!(
                        "unsupported MIPS GP-dependent ET_REL relocation at {address:#x} ({name})"
                    ),
                );
                continue;
            }
            let value = read(image, address, width)?;
            let addend = relocation.r_addend;
            let applied = match image.architecture {
                Architecture::Arm => arm(image, relocation, address, symbol, value as u32)?,
                Architecture::AArch64 => aarch64(image, relocation, address, symbol, value)?,
                Architecture::Mips | Architecture::MipsBe => {
                    let word = value as u32;
                    match kind {
                        R_MIPS_32 | R_MIPS_REL32 => {
                            scalar(image, address, 4, symbol, addend, false)?;
                            true
                        }
                        R_MIPS_26 => {
                            if !matches!(word >> 26, 2 | 3) {
                                return Err(failure(address, "invalid MIPS jump encoding"));
                            }
                            let a = addend.unwrap_or(i64::from((word & 0x03ff_ffff) << 2));
                            let result = i128::from(symbol) + i128::from(a);
                            if result < 0
                                || result > i128::from(u32::MAX)
                                || result & 3 != 0
                                || ((result as u64) ^ (address + 4)) & 0xf000_0000 != 0
                            {
                                return Err(failure(
                                    address,
                                    "MIPS jump requires an out-of-region veneer",
                                ));
                            }
                            write(
                                image,
                                address,
                                4,
                                u64::from(
                                    (word & 0xfc00_0000) | ((result as u32 >> 2) & 0x03ff_ffff),
                                ),
                            )?;
                            true
                        }
                        R_MIPS_HI16 => {
                            if word >> 26 != 15 {
                                return Err(failure(address, "invalid MIPS HI16 encoding"));
                            }
                            high.entry(relocation.r_sym)
                                .or_default()
                                .push((address, word, addend));
                            true
                        }
                        R_MIPS_LO16 => {
                            let low = addend.unwrap_or(i64::from(word as u16 as i16));
                            if let Some(pending) = high.remove(&relocation.r_sym) {
                                for (site, old, explicit) in pending {
                                    let a =
                                        explicit.unwrap_or((i64::from(old & 0xffff) << 16) + low);
                                    let result =
                                        (i128::from(symbol) + i128::from(a) + 0x8000) >> 16;
                                    write(
                                        image,
                                        site,
                                        4,
                                        u64::from((old & 0xffff_0000) | (result as u32 & 0xffff)),
                                    )?;
                                }
                            }
                            let result = i128::from(symbol) + i128::from(low);
                            write(
                                image,
                                address,
                                4,
                                u64::from((word & 0xffff_0000) | (result as u32 & 0xffff)),
                            )?;
                            true
                        }
                        _ => false,
                    }
                }
                _ => false,
            };
            if !applied {
                diagnostic(
                    image,
                    format!(
                        "unsupported {} ET_REL relocation {kind} at {address:#x}",
                        image.architecture.name()
                    ),
                );
            } else {
                image.relocation_locations.push(address);
            }
        }
        for pending in high.values() {
            for (address, _, _) in pending {
                diagnostic(
                    image,
                    format!("unpaired MIPS HI16 relocation at {address:#x}"),
                );
            }
        }
    }
    image.relocation_locations.sort_unstable();
    image.relocation_locations.dedup();
    Ok(())
}

fn arm(image: &mut LoadedImage, r: Reloc, p: u64, s: u64, word: u32) -> Result<bool, ImageError> {
    let kind = r.r_type;
    let a = r.r_addend;
    match kind {
        R_ARM_ABS32 | R_ARM_TARGET1 | R_ARM_REL32 => {
            scalar(image, p, 4, s, a, kind == R_ARM_REL32)?
        }
        R_ARM_PREL31 => {
            let addend = a.unwrap_or(i64::from((word << 1) as i32 >> 1));
            let result = signed(i128::from(s) + i128::from(addend) - i128::from(p), 31, 1, p)?;
            write(
                image,
                p,
                4,
                u64::from((word & 0x8000_0000) | (result as u32 & 0x7fff_ffff)),
            )?;
        }
        R_ARM_MOVW_ABS_NC | R_ARM_MOVT_ABS | R_ARM_MOVW_PREL_NC | R_ARM_MOVT_PREL => {
            let immediate = ((word >> 4) & 0xf000) | (word & 0xfff);
            let addend = a.unwrap_or(i64::from(immediate as u16 as i16));
            let mut result = s.wrapping_add_signed(addend);
            if matches!(kind, R_ARM_MOVW_PREL_NC | R_ARM_MOVT_PREL) {
                result = result.wrapping_sub(p);
            }
            if matches!(kind, R_ARM_MOVT_ABS | R_ARM_MOVT_PREL) {
                result >>= 16;
            }
            let result =
                (word & 0xfff0_f000) | ((result as u32 & 0xf000) << 4) | (result as u32 & 0xfff);
            write(image, p, 4, u64::from(result))?;
        }
        R_ARM_THM_MOVW_ABS_NC
        | R_ARM_THM_MOVT_ABS
        | R_ARM_THM_MOVW_PREL_NC
        | R_ARM_THM_MOVT_PREL => {
            let first = word & 0xffff;
            let second = word >> 16;
            let immediate = ((first & 15) << 12)
                | ((first & 0x0400) << 1)
                | ((second & 0x7000) >> 4)
                | (second & 0xff);
            let addend = a.unwrap_or(i64::from(immediate as u16 as i16));
            let mut result = s.wrapping_add_signed(addend);
            if matches!(kind, R_ARM_THM_MOVW_PREL_NC | R_ARM_THM_MOVT_PREL) {
                result = result.wrapping_sub(p);
            }
            if matches!(kind, R_ARM_THM_MOVT_ABS | R_ARM_THM_MOVT_PREL) {
                result >>= 16;
            }
            let v = result as u32;
            let first = (first & 0xfbf0) | ((v >> 12) & 15) | ((v >> 1) & 0x0400);
            let second = (second & 0x8f00) | ((v << 4) & 0x7000) | (v & 0xff);
            write(image, p, 4, u64::from(first | (second << 16)))?;
        }
        R_ARM_PC24 | R_ARM_PLT32 | R_ARM_CALL | R_ARM_JUMP24 => {
            if word & 0x0e00_0000 != 0x0a00_0000 {
                return Err(failure(p, "invalid ARM branch encoding"));
            }
            let addend = a.unwrap_or(i64::from((word << 8) as i32 >> 6));
            let result = signed(
                i128::from(s & !1) + i128::from(addend) - i128::from(p),
                26,
                if s & 1 != 0 { 2 } else { 4 },
                p,
            )? as u32;
            let encoded = if s & 1 != 0 {
                if kind != R_ARM_CALL || word >> 28 != 14 {
                    return Err(failure(p, "ARM to Thumb branch requires a veneer"));
                }
                0xfa00_0000 | ((result & 2) << 23) | ((result >> 2) & 0x00ff_ffff)
            } else {
                (word & 0xff00_0000) | ((result >> 2) & 0x00ff_ffff)
            };
            write(image, p, 4, u64::from(encoded))?;
        }
        R_ARM_THM_CALL | R_ARM_THM_JUMP24 => {
            if word & 0xf800 != 0xf000 || (word >> 16) & 0x8000 == 0 {
                return Err(failure(p, "invalid Thumb branch encoding"));
            }
            let first = word & 0xffff;
            let second = word >> 16;
            let sign = (first >> 10) & 1;
            let j1 = (second >> 13) & 1;
            let j2 = (second >> 11) & 1;
            let encoded = (sign << 24)
                | ((!(j1 ^ sign) & 1) << 23)
                | ((!(j2 ^ sign) & 1) << 22)
                | ((first & 0x3ff) << 12)
                | ((second & 0x7ff) << 1);
            let addend = a.unwrap_or(i64::from((encoded << 7) as i32 >> 7));
            let undefined = image.import_locations.contains_key(&s);
            let thumb = s & 1 != 0 || undefined;
            if !thumb && kind != R_ARM_THM_CALL {
                return Err(failure(p, "Thumb to ARM jump requires a veneer"));
            }
            let base = if thumb { p } else { p & !3 };
            let result = signed(
                i128::from(s & !1) + i128::from(addend) - i128::from(base),
                25,
                if thumb { 2 } else { 4 },
                p,
            )? as u32;
            let sign = (result >> 24) & 1;
            let i1 = (result >> 23) & 1;
            let i2 = (result >> 22) & 1;
            let first = (first & 0xf800) | (sign << 10) | ((result >> 12) & 0x3ff);
            let opcode = if kind == R_ARM_THM_CALL {
                if thumb {
                    0xd000
                } else {
                    0xc000
                }
            } else {
                0x9000
            };
            let second = opcode
                | ((!(i1 ^ sign) & 1) << 13)
                | ((!(i2 ^ sign) & 1) << 11)
                | ((result >> 1) & 0x7ff);
            write(image, p, 4, u64::from(first | (second << 16)))?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}
fn aarch64(
    image: &mut LoadedImage,
    r: Reloc,
    p: u64,
    s: u64,
    raw: u64,
) -> Result<bool, ImageError> {
    let kind = r.r_type;
    let Some(addend) = r.r_addend else {
        return Err(failure(p, "AArch64 instruction relocations require RELA"));
    };
    let value = i128::from(s) + i128::from(addend);
    let word = raw as u32;
    let result = match kind {
        R_AARCH64_ABS64 | R_AARCH64_ABS32 | R_AARCH64_ABS16 | R_AARCH64_PREL64
        | R_AARCH64_PREL32 | R_AARCH64_PREL16 => {
            let width = match kind {
                R_AARCH64_ABS64 | R_AARCH64_PREL64 => 8,
                R_AARCH64_ABS16 | R_AARCH64_PREL16 => 2,
                _ => 4,
            };
            scalar(
                image,
                p,
                width,
                s,
                Some(addend),
                matches!(kind, R_AARCH64_PREL64 | R_AARCH64_PREL32 | R_AARCH64_PREL16),
            )?;
            return Ok(true);
        }
        R_AARCH64_CALL26 | R_AARCH64_JUMP26 => {
            let opcode = if kind == R_AARCH64_CALL26 {
                0x9400_0000
            } else {
                0x1400_0000
            };
            if word & 0xfc00_0000 != opcode {
                return Err(failure(p, "invalid AArch64 branch encoding"));
            }
            let v = signed(value - i128::from(p), 28, 4, p)? as u32;
            (word & 0xfc00_0000) | ((v >> 2) & 0x03ff_ffff)
        }
        R_AARCH64_ADR_PREL_PG_HI21 | R_AARCH64_ADR_PREL_PG_HI21_NC => {
            if word & 0x9f00_0000 != 0x9000_0000 {
                return Err(failure(p, "invalid ADRP encoding"));
            }
            let pages = ((value & !0xfff) - (i128::from(p) & !0xfff)) >> 12;
            let v = if kind == R_AARCH64_ADR_PREL_PG_HI21 {
                signed(pages, 21, 1, p)? as u32
            } else {
                pages as u32
            };
            (word & 0x9f00_001f) | ((v & 3) << 29) | ((v & 0x1f_fffc) << 3)
        }
        R_AARCH64_ADR_PREL_LO21 => {
            let v = signed(value - i128::from(p), 21, 1, p)? as u32;
            (word & 0x9f00_001f) | ((v & 3) << 29) | ((v & 0x1f_fffc) << 3)
        }
        R_AARCH64_ADD_ABS_LO12_NC => (word & !0x003f_fc00) | ((value as u32 & 0xfff) << 10),
        R_AARCH64_LDST8_ABS_LO12_NC
        | R_AARCH64_LDST16_ABS_LO12_NC
        | R_AARCH64_LDST32_ABS_LO12_NC
        | R_AARCH64_LDST64_ABS_LO12_NC
        | R_AARCH64_LDST128_ABS_LO12_NC => {
            let shift = match kind {
                R_AARCH64_LDST8_ABS_LO12_NC => 0,
                R_AARCH64_LDST16_ABS_LO12_NC => 1,
                R_AARCH64_LDST32_ABS_LO12_NC => 2,
                R_AARCH64_LDST64_ABS_LO12_NC => 3,
                _ => 4,
            };
            if value & ((1 << shift) - 1) != 0 {
                return Err(failure(p, "unaligned load/store target"));
            }
            (word & !0x003f_fc00) | (((value as u32 & 0xfff) >> shift) << 10)
        }
        _ => return Ok(false),
    };
    write(image, p, 4, u64::from(result))?;
    Ok(true)
}
