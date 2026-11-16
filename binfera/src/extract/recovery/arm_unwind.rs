//! ARM EHABI exception-index entries. Read PREL31 addresses from the mapped
//! image so linked images and relocated objects use the same coordinates.
use super::{
    image::{Architecture, LoadedImage},
    RecoveryDiagnostic,
};
use goblin::elf::{
    header::ET_REL,
    section_header::{SHF_ALLOC, SHF_EXECINSTR},
    Elf,
};
const ARM_EXIDX: u32 = 0x7000_0001;
const MAX_ENTRIES: u64 = 100_000;
#[derive(Default)]
pub(super) struct Table {
    pub entries: Vec<Entry>,
    pub diagnostics: Vec<RecoveryDiagnostic>,
}
pub(super) struct Entry {
    pub start: u64,
    pub end: u64,
    pub thumb: bool,
}
pub(super) fn read(bytes: &[u8], image: &LoadedImage) -> Table {
    let mut result = Table::default();
    if image.architecture != Architecture::Arm {
        return result;
    }
    let Ok(elf) = Elf::parse(bytes) else {
        return result;
    };
    let mut code = Vec::new();
    let mut tables = Vec::new();
    for (index, section) in elf.section_headers.iter().enumerate() {
        if section.sh_flags & u64::from(SHF_ALLOC) == 0 {
            continue;
        }
        let Some(base) = crate::extract::loader::elf_rel::section_address(&elf, image, index)
        else {
            continue;
        };
        if section.sh_flags & u64::from(SHF_EXECINSTR) != 0 {
            if let Some(end) = base.checked_add(section.sh_size) {
                code.push((base, end));
            }
        }
        if section.sh_type == ARM_EXIDX {
            tables.push((base, section.sh_size));
        }
    }
    if code.is_empty() && elf.header.e_type != ET_REL {
        code.extend_from_slice(image.primary_code_ranges());
    }
    if tables.is_empty() {
        for header in &elf.program_headers {
            if header.p_type == ARM_EXIDX {
                if let Some(base) = header.p_vaddr.checked_add(image.load_bias) {
                    tables.push((base, header.p_filesz));
                }
            }
        }
    }
    let mut remaining = MAX_ENTRIES;
    for (base, size) in tables {
        if !size.is_multiple_of(8) || size / 8 > remaining {
            result.diagnostics.push(RecoveryDiagnostic {
                address: base,
                message: "ARM .exidx: invalid size or entry limit exceeded".into(),
            });
            continue;
        }
        remaining -= size / 8;
        let mut entries = Vec::new();
        let mut previous = None;
        let mut valid = true;
        for offset in (0..size).step_by(8) {
            let Some(site) = base.checked_add(offset) else {
                valid = false;
                break;
            };
            if image.bytes_at(site, 8).is_none_or(|bytes| bytes.len() != 8) {
                valid = false;
                break;
            }
            let Some(raw) = image.read_pointer(site) else {
                valid = false;
                break;
            };
            if raw & 0x8000_0000 != 0 {
                valid = false;
                break;
            }
            let displacement = (((raw as u32) << 1) as i32 >> 1) as i64;
            let Some(target) = site.checked_add_signed(displacement) else {
                valid = false;
                break;
            };
            let start = target & !1;
            if previous.is_some_and(|old| start <= old) {
                valid = false;
                break;
            }
            previous = Some(start);
            let Some((_, end)) = code
                .iter()
                .find(|(begin, end)| *begin <= start && start <= *end)
                .copied()
            else {
                valid = false;
                break;
            };
            // The final CANTUNWIND sentinel describes the end, not another function.
            if start == end {
                continue;
            }
            let thumb = target & 1 != 0 || image.is_thumb(start);
            if !start.is_multiple_of(if thumb { 2 } else { 4 })
                || !image.is_executable_address(start)
            {
                valid = false;
                break;
            }
            entries.push(Entry { start, end, thumb });
        }
        if !valid {
            result.diagnostics.push(RecoveryDiagnostic {
                address: base,
                message: "ARM .exidx: invalid or unordered function addresses".into(),
            });
            continue;
        }
        for i in 0..entries.len().saturating_sub(1) {
            entries[i].end = entries[i].end.min(entries[i + 1].start);
        }
        result.entries.extend(entries);
    }
    result.entries.sort_by_key(|entry| entry.start);
    result.entries.dedup_by_key(|entry| entry.start);
    result
}
