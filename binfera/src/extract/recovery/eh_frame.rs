//! ELF function entries from exception-frame descriptions. Addresses are decoded in
//! link-time coordinates, then rebased once, including absolute encodings in PIEs.

use std::collections::{BTreeMap, BTreeSet};

use gimli::{BaseAddresses, CieOrFde, EhFrame, EhFrameHdr, Pointer, RunTimeEndian, UnwindSection};
use goblin::elf::{program_header::PT_GNU_EH_FRAME, section_header::SHF_ALLOC, Elf};

use super::image::{Architecture, LoadedImage};
use super::{RecoveryDiagnostic, SeedKind};

const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;
const MAX_CIES: usize = 4096;
const MAX_DIAGNOSTICS: usize = 16;

pub(super) fn collect(
    bytes: &[u8],
    image: &LoadedImage,
    seeds: &mut BTreeMap<u64, BTreeSet<SeedKind>>,
    diagnostics: &mut Vec<RecoveryDiagnostic>,
) {
    collect_inner(bytes, image, seeds, diagnostics, &mut |_, _| {});
}

pub(crate) fn ranges(bytes: &[u8], image: &LoadedImage) -> BTreeMap<u64, u64> {
    let mut ranges = BTreeMap::new();
    collect_inner(
        bytes,
        image,
        &mut BTreeMap::new(),
        &mut Vec::new(),
        &mut |start, end| {
            ranges
                .entry(start)
                .and_modify(|old: &mut u64| *old = (*old).max(end))
                .or_insert(end);
        },
    );
    ranges
}

fn collect_inner(
    bytes: &[u8],
    image: &LoadedImage,
    seeds: &mut BTreeMap<u64, BTreeSet<SeedKind>>,
    diagnostics: &mut Vec<RecoveryDiagnostic>,
    range: &mut impl FnMut(u64, u64),
) {
    let Ok(elf) = Elf::parse(bytes) else { return };
    let endian = if elf.little_endian {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    let mut bases = BaseAddresses::default();
    for (index, section) in elf.section_headers.iter().enumerate() {
        let address = if elf.header.e_type == goblin::elf::header::ET_REL {
            crate::extract::loader::elf_rel::section_address(&elf, image, index)
                .unwrap_or(section.sh_addr)
        } else {
            section.sh_addr
        };
        match elf.shdr_strtab.get_at(section.sh_name) {
            Some(".text") => bases = bases.set_text(address),
            Some(".got") => bases = bases.set_got(address),
            _ => {}
        }
    }
    let source = if let Some((index, section)) =
        elf.section_headers.iter().enumerate().find(|(_, s)| {
            s.sh_flags & u64::from(SHF_ALLOC) != 0
                && elf.shdr_strtab.get_at(s.sh_name) == Some(".eh_frame")
        }) {
        if elf.header.e_type == goblin::elf::header::ET_REL {
            crate::extract::loader::elf_rel::section_address(&elf, image, index)
                .and_then(|address| {
                    image
                        .bytes_at(
                            address,
                            section.sh_size.min(MAX_FRAME_BYTES as u64) as usize,
                        )
                        .map(|data| (address, data))
                })
                .ok_or("unmapped relocatable .eh_frame".to_string())
        } else {
            file_slice(bytes, section.sh_offset, section.sh_size)
                .map(|data| (section.sh_addr, data))
                .ok_or("invalid .eh_frame file range".to_string())
        }
    } else if let Some(header) = elf
        .program_headers
        .iter()
        .find(|p| p.p_type == PT_GNU_EH_FRAME)
    {
        // Stripping section headers does not remove the runtime unwind header.
        frame_from_header(
            bytes,
            image,
            header.p_offset,
            header.p_filesz,
            header.p_vaddr,
            endian,
            &bases,
        )
    } else {
        return;
    };
    let (address, data) = match source {
        Ok(source) => source,
        Err(message) => {
            diagnostics.push(RecoveryDiagnostic {
                address: image.image_base,
                message,
            });
            return;
        }
    };
    let diagnostic_start = diagnostics.len();
    let mut report = |message: String| {
        if diagnostics.len() - diagnostic_start < MAX_DIAGNOSTICS {
            diagnostics.push(RecoveryDiagnostic {
                address: address.saturating_add(image.load_bias),
                message: format!("ELF .eh_frame: {message}"),
            });
        }
    };
    if data.len() > MAX_FRAME_BYTES {
        report(format!("scan limited to {MAX_FRAME_BYTES} bytes"));
    }
    let mut frame = EhFrame::new(&data[..data.len().min(MAX_FRAME_BYTES)], endian);
    frame.set_address_size(image.architecture.pointer_width() as u8);
    let bases = bases.set_eh_frame(address);
    let mut entries = frame.entries(&bases);
    let mut cies: BTreeMap<
        usize,
        gimli::CommonInformationEntry<gimli::EndianSlice<'_, RunTimeEndian>>,
    > = BTreeMap::new();
    for _ in 0..MAX_ENTRIES {
        let entry = match entries.next() {
            Ok(Some(entry)) => entry,
            Ok(None) => return,
            Err(error) => {
                report(error.to_string());
                return;
            }
        };
        let partial = match entry {
            CieOrFde::Cie(cie) => {
                if cies.len() >= MAX_CIES {
                    report(format!("scan limited to {MAX_CIES} CIEs"));
                    return;
                }
                cies.insert(cie.offset(), cie);
                continue;
            }
            CieOrFde::Fde(partial) => partial,
        };
        // EH FDEs reference an earlier CIE. Cache only actual record boundaries,
        // so crafted offsets cannot repeatedly parse overlapping large records.
        let fde = match partial.parse(|_, _, offset| {
            cies.get(&offset.0)
                .cloned()
                .ok_or(gimli::Error::NoEntryAtGivenOffset)
        }) {
            Ok(fde) => fde,
            Err(error) => {
                report(error.to_string());
                continue;
            }
        };
        let Some(start) = fde.initial_address().checked_add(image.load_bias) else {
            continue;
        };
        // An FDE can describe a cold fragment, but never zero bytes, overflow, BSS, or data.
        if valid_range(image, start, fde.len()) {
            seeds.entry(start).or_default().insert(SeedKind::EhFrame);
            range(start, start + fde.len());
        }
    }
    report(format!("scan limited to {MAX_ENTRIES} entries"));
}

fn file_slice(bytes: &[u8], offset: u64, size: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let len = usize::try_from(size).ok()?;
    bytes.get(start..start.checked_add(len)?)
}

fn frame_from_header<'a>(
    bytes: &'a [u8],
    image: &LoadedImage,
    offset: u64,
    size: u64,
    address: u64,
    endian: RunTimeEndian,
    bases: &BaseAddresses,
) -> Result<(u64, &'a [u8]), String> {
    let raw = file_slice(bytes, offset, size).ok_or("invalid .eh_frame_hdr file range")?;
    let header = EhFrameHdr::new(raw, endian);
    let parsed = header
        .parse(
            &bases.clone().set_eh_frame_hdr(address),
            image.architecture.pointer_width() as u8,
        )
        .map_err(|error| format!("ELF .eh_frame_hdr: {error}"))?;
    let Pointer::Direct(frame_address) = parsed.eh_frame_ptr() else {
        return Err("indirect .eh_frame_hdr pointer is unsupported".into());
    };
    let loaded = frame_address
        .checked_add(image.load_bias)
        .ok_or(".eh_frame address overflow")?;
    let section = image
        .section_containing(loaded)
        .ok_or("unmapped .eh_frame pointer")?;
    let remaining = section
        .file_size
        .checked_sub(loaded - section.address)
        .filter(|size| *size != 0)
        .ok_or(".eh_frame pointer is not file backed")?;
    // Keep link-time bytes even if the loader relocated the mapped image.
    let file_offset = section
        .file_offset
        .checked_add(loaded - section.address)
        .ok_or(".eh_frame file offset overflow")?;
    let data = file_slice(bytes, file_offset, remaining).ok_or("invalid .eh_frame file range")?;
    Ok((frame_address, data))
}

fn valid_range(image: &LoadedImage, start: u64, size: u64) -> bool {
    let Some(end) = start.checked_add(size).filter(|_| size != 0) else {
        return false;
    };
    if image.architecture == Architecture::AArch64
        && (!start.is_multiple_of(4) || !size.is_multiple_of(4))
    {
        return false;
    }
    image.section_containing(start).is_some_and(|section| {
        section.permissions.execute
            && end
                .checked_sub(section.address)
                .is_some_and(|offset| offset <= section.file_size)
            && image.is_executable_address(start)
            && image.is_executable_address(end - 1)
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn runtime_header_fallback_reads_unrelocated_file_bytes() {
        let mut raw = vec![0x42; 64];
        raw[..8].copy_from_slice(&[1, 0x1b, 0xff, 0xff, 28, 0, 0, 0]);
        let mut relocated = raw.clone();
        relocated[32..].fill(0xaa);
        let mut image = LoadedImage::from_shellcode(&relocated, Architecture::X64);
        image.load_bias = image.image_base;
        let (address, data) = frame_from_header(
            &raw,
            &image,
            0,
            8,
            0,
            RunTimeEndian::Little,
            &BaseAddresses::default(),
        )
        .unwrap();
        assert_eq!(address, 32);
        assert_eq!(data, &raw[32..]);
        assert_ne!(
            Some(data),
            image.bytes_at(image.image_base + 32, data.len())
        );
    }
}
