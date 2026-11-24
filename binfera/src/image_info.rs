//! File metadata shared by native callers and the browser workbench.
//!
//! Address mappings come from the same loaders as recovery. File offsets always
//! refer to the original input, including when a universal Mach-O slice is selected.
use serde::Serialize;

use crate::extract::image::{Architecture, ImageError, LoadedImage, MappedSection};

mod details;
mod elf;
mod macho;
mod pe;
mod shellcode;

pub use shellcode::{inspect_shellcode, ShellcodeInfo};

pub use details::{
    Anomaly, Certificate, Fact, Field, FileDetails, Overlay, Property, Resource, Signature,
    Structure,
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageInfo {
    pub format: String,
    pub arch: Option<String>,
    /// The optional Function ID database required by this image.
    pub fid_arch: Option<String>,
    pub entry: Option<u64>,
    pub ptr_size: usize,
    pub little_endian: bool,
    pub warnings: Vec<String>,
    pub sections: Vec<Section>,
    pub regions: Vec<Region>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub details: FileDetails,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shellcode: Option<ShellcodeInfo>,
}

#[derive(Debug, Serialize)]
pub struct Section {
    pub name: String,
    pub va: u64,
    pub vsize: u64,
    pub off: u64,
    pub size: u64,
    pub perms: String,
    pub entropy: f64,
}

#[derive(Debug, Serialize)]
pub struct Region {
    pub off: u64,
    pub size: u64,
    pub va: u64,
}

#[derive(Debug, Serialize)]
pub struct Import {
    pub dll: String,
    pub name: String,
    pub va: u64,
    /// A variable, not a function: an ELF executable's copy of a shared library's data
    /// (`stdout`, `optarg`), placed in its `.bss` by a copy relocation. `va` is that copy.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub data: bool,
}

#[derive(Debug, Serialize)]
pub struct Export {
    pub name: String,
    pub va: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forward: Option<String>,
}

/// Inspect headers without recovering or decompiling code, or loading signatures and rules.
pub fn inspect(bytes: &[u8], arch: Option<&str>) -> Result<ImageInfo, ImageError> {
    if crate::extract::looks_like_elf(bytes) {
        let repaired = crate::extract::elf::without_corrupt_section_headers(bytes);
        elf::inspect(repaired.as_deref().unwrap_or(bytes))
    } else if crate::extract::looks_like_macho(bytes) {
        macho::inspect(bytes, arch)
    } else {
        pe::inspect(bytes)
    }
}

fn from_image(bytes: &[u8], image: &LoadedImage, offset: u64) -> ImageInfo {
    ImageInfo {
        format: match image.format {
            crate::extract::image::ImageFormat::Pe => "pe",
            crate::extract::image::ImageFormat::Elf => "elf",
            crate::extract::image::ImageFormat::Macho => "macho",
            crate::extract::image::ImageFormat::Sc => "sc",
        }
        .into(),
        arch: Some(image.architecture.name().into()),
        fid_arch: None,
        entry: image.entry_point,
        ptr_size: image.architecture.pointer_width(),
        little_endian: image.architecture.little_endian(),
        warnings: image.load_diagnostics.clone(),
        sections: image
            .sections
            .iter()
            .map(|s| section(bytes, s, offset))
            .collect(),
        regions: image
            .sections
            .iter()
            .map(|s| Region {
                off: s.file_offset.saturating_add(offset),
                size: s.file_size,
                va: s.address,
            })
            .collect(),
        imports: image
            .import_locations
            .iter()
            .map(|(&va, location)| {
                let symbol = image
                    .external_bindings
                    .get(&va)
                    .and_then(|names| names.first());
                let (dll, name) = symbol
                    .and_then(|name| {
                        location
                            .strip_suffix(name.as_str())
                            .and_then(|prefix| prefix.strip_suffix('.'))
                            .map(|dll| (dll, name.as_str()))
                    })
                    .or_else(|| location.rsplit_once('.'))
                    .unwrap_or(("", location));
                Import {
                    dll: if dll == "*" {
                        String::new()
                    } else {
                        dll.into()
                    },
                    name: name.into(),
                    va,
                    data: false,
                }
            })
            .collect(),
        exports: Vec::new(),
        details: FileDetails::default(),
        shellcode: None,
    }
}

fn section(bytes: &[u8], section: &MappedSection, offset: u64) -> Section {
    let off = section.file_offset.saturating_add(offset);
    let data = usize::try_from(section.file_offset)
        .ok()
        .and_then(|start| {
            let size = usize::try_from(section.file_size).ok()?;
            bytes.get(start..start.saturating_add(size).min(bytes.len()))
        })
        .unwrap_or_default();
    let p = section.permissions;
    Section {
        name: section.name.clone(),
        va: section.address,
        vsize: section.virtual_size,
        off,
        size: section.file_size,
        perms: format!(
            "{}{}{}",
            if p.read { 'r' } else { '-' },
            if p.write { 'w' } else { '-' },
            if p.execute { 'x' } else { '-' }
        ),
        entropy: crate::packing::entropy(data),
    }
}

pub(crate) fn unsupported_elf_cpu(bytes: &[u8]) -> Option<&'static str> {
    const EM_SPARC: u16 = 2;
    const EM_386: u16 = 3;
    const EM_MIPS: u16 = 8;
    const EM_PPC: u16 = 20;
    const EM_PPC64: u16 = 21;
    const EM_S390: u16 = 22;
    const EM_ARM: u16 = 40;
    const EM_SH: u16 = 42;
    const EM_SPARCV9: u16 = 43;
    const EM_X86_64: u16 = 62;
    const EM_AARCH64: u16 = 183;
    const EM_RISCV: u16 = 243;
    if !crate::extract::looks_like_elf(bytes) {
        return None;
    }
    let little = *bytes.get(5)? == 1;
    let raw: [u8; 2] = bytes.get(18..20)?.try_into().ok()?;
    let machine = if little {
        u16::from_le_bytes(raw)
    } else {
        u16::from_be_bytes(raw)
    };
    match machine {
        EM_386 | EM_X86_64 | EM_AARCH64 => None,
        EM_ARM => {
            if bytes.get(4) == Some(&1) && little {
                None
            } else {
                Some("ARM variant")
            }
        }
        EM_MIPS => {
            if bytes.get(4) != Some(&1) {
                return Some("MIPS64");
            }
            let raw: [u8; 4] = bytes.get(36..40)?.try_into().ok()?;
            let flags = if little {
                u32::from_le_bytes(raw)
            } else {
                u32::from_be_bytes(raw)
            };
            if !crate::extract::risc::supported_mips_flags(flags) {
                Some("MIPS ISA/ABI variant")
            } else {
                None
            }
        }
        EM_PPC | EM_PPC64 => Some("PowerPC"),
        EM_SH => Some("SuperH"),
        EM_SPARC | EM_SPARCV9 => Some("SPARC"),
        EM_RISCV => Some("RISC-V"),
        EM_S390 => Some("s390"),
        _ => Some("this CPU"),
    }
}
