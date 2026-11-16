//! Signs that a file is packed: its real code is compressed or encrypted and only unpacked at
//! run time, so what the decompiler sees is the unpacking stub and noise. Nothing here unpacks;
//! it only tells the reader why the output looks the way it does.

use serde::{Deserialize, Serialize};

use crate::extract::image::LoadedImage;

/// Section names packers leave behind, as (prefix, packer). Compared without case.
const PACKER_SECTIONS: &[(&str, &str)] = &[
    ("upx", "UPX"),
    (".aspack", "ASPack"),
    (".adata", "ASPack"),
    (".mpress", "MPRESS"),
    (".petite", "Petite"),
    (".nsp", "NsPack"),
    ("pec2", "PECompact"),
    ("pecompact", "PECompact"),
    (".themida", "Themida"),
    (".winlice", "WinLicense"),
    (".vmp", "VMProtect"),
    (".enigma", "Enigma Protector"),
    (".rlpack", "RLPack"),
    (".mew", "MEW"),
    ("fsg!", "FSG"),
    (".packed", "packer"),
    (".kkrunchy", "kkrunchy"),
    (".spack", "Simple Pack"),
    (".y0da", "yoda's Crypter"),
    (".yp", "yoda's Protector"),
];

/// Compressed or encrypted bytes are close to 8 bits of entropy per byte; compiled code sits
/// around 6, and even dense code stays under 7.
const HIGH_ENTROPY: f64 = 7.2;
/// A section smaller than this is too short for its entropy to mean much.
const MIN_ENTROPY_BYTES: u64 = 4096;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Packing {
    /// The packer, when its own marks name it.
    pub packer: Option<String>,
    /// What gave it away, one short phrase each.
    pub evidence: Vec<String>,
}

/// Bits of entropy per byte.
pub(crate) fn entropy(bytes: &[u8]) -> f64 {
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[usize::from(b)] += 1;
    }
    let total = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&n| n > 0)
        .map(|&n| {
            let p = n as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// The part of a section the checks read, so an image binfera can map and an ELF it can only
/// parse (a CPU it cannot decode) go through the same code.
struct SectionView {
    name: String,
    execute: bool,
    file_offset: u64,
    file_size: u64,
    virtual_size: u64,
}

/// `None` when nothing suggests the file is packed.
pub fn detect(image: &LoadedImage, bytes: &[u8]) -> Option<Packing> {
    let sections: Vec<_> = image
        .sections
        .iter()
        .map(|s| SectionView {
            name: s.name.clone(),
            execute: s.permissions.execute,
            file_offset: s.file_offset,
            file_size: s.file_size,
            virtual_size: s.virtual_size,
        })
        .collect();
    detect_sections(&sections, bytes)
}

/// [`detect`] for an ELF of any CPU, read from its headers alone. Executable sections come from
/// the section table, or from the executable `PT_LOAD` segments when the table is missing or
/// stripped, as in the packed IoT samples that carry no section headers at all.
pub fn detect_elf(bytes: &[u8]) -> Option<Packing> {
    use goblin::elf::{header::ET_REL, program_header::PT_LOAD, Elf};
    const SHF_EXECINSTR: u64 = 0x4;
    const PF_X: u32 = 0x1;
    let elf = Elf::parse(bytes).ok()?;
    let mut sections: Vec<_> = elf
        .section_headers
        .iter()
        .filter(|s| s.sh_type != goblin::elf::section_header::SHT_NULL)
        .map(|s| SectionView {
            name: elf.shdr_strtab.get_at(s.sh_name).unwrap_or("").to_owned(),
            execute: s.sh_flags & SHF_EXECINSTR != 0,
            file_offset: s.sh_offset,
            file_size: if s.sh_type == goblin::elf::section_header::SHT_NOBITS {
                0
            } else {
                s.sh_size
            },
            virtual_size: s.sh_size,
        })
        .collect();
    if elf.header.e_type != ET_REL && !sections.iter().any(|s| s.execute) {
        sections.extend(
            elf.program_headers
                .iter()
                .filter(|p| p.p_type == PT_LOAD && p.p_flags & PF_X != 0)
                .map(|p| SectionView {
                    name: String::new(),
                    execute: true,
                    file_offset: p.p_offset,
                    file_size: p.p_filesz,
                    virtual_size: p.p_memsz,
                }),
        );
    }
    detect_sections(&sections, bytes)
}

fn detect_sections(sections: &[SectionView], bytes: &[u8]) -> Option<Packing> {
    let mut packer = None;
    let mut evidence = Vec::new();
    for section in sections {
        let name = section.name.to_ascii_lowercase();
        if let Some((_, found)) = PACKER_SECTIONS
            .iter()
            .find(|(prefix, _)| name.starts_with(prefix))
        {
            packer.get_or_insert(*found);
            evidence.push(format!("{found} section {}", section.name));
        }
    }
    // UPX writes its "UPX!" header next to the file's own headers on every format, and keeps it
    // when the section names are changed to hide it.
    if bytes[..bytes.len().min(0x1000)]
        .windows(4)
        .any(|w| w == b"UPX!")
    {
        if packer.is_none() {
            evidence.push("UPX header".to_owned());
        }
        packer.get_or_insert("UPX");
    }
    let code: Vec<_> = sections.iter().filter(|s| s.execute).collect();
    for section in &code {
        let start = usize::try_from(section.file_offset).unwrap_or(usize::MAX);
        let end = start.saturating_add(usize::try_from(section.file_size).unwrap_or(usize::MAX));
        let Some(data) = bytes.get(start..end.min(bytes.len())) else {
            continue;
        };
        if data.len() as u64 >= MIN_ENTROPY_BYTES {
            let bits = entropy(data);
            if bits >= HIGH_ENTROPY {
                evidence.push(format!(
                    "executable section {} has {bits:.1} bits of entropy per byte",
                    display_name(&section.name)
                ));
            }
        }
    }
    // An executable section the file carries nothing for, next to other code: the space the stub
    // unpacks into (UPX0 and its kind).
    if code.len() > 1 {
        for section in &code {
            if section.file_size == 0 && section.virtual_size >= MIN_ENTROPY_BYTES {
                evidence.push(format!(
                    "executable section {} is empty on disk ({} KB in memory)",
                    display_name(&section.name),
                    section.virtual_size / 1024
                ));
            }
        }
    }
    (packer.is_some() || !evidence.is_empty()).then(|| Packing {
        packer: packer.map(str::to_owned),
        evidence,
    })
}

fn display_name(name: &str) -> String {
    if name.is_empty() {
        "(unnamed)".to_owned()
    } else {
        name.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_tells_noise_from_repetition() {
        assert_eq!(entropy(&[0u8; 4096]), 0.0);
        let all: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!((entropy(&all) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn names_upx_and_passes_a_plain_sample() -> Result<(), crate::extract::image::ImageError> {
        let bytes =
            include_bytes!("../../tests/testfiles/Practical Malware Analysis Lab 01-02.exe_");
        let packing = detect(&LoadedImage::parse(bytes)?, bytes);
        assert_eq!(
            packing.and_then(|p| p.packer).as_deref(),
            Some("UPX"),
            "Lab 01-02 is UPX-packed"
        );
        let plain =
            include_bytes!("../../tests/testfiles/Practical Malware Analysis Lab 01-01.exe_");
        assert_eq!(detect(&LoadedImage::parse(plain)?, plain), None);
        Ok(())
    }
}
