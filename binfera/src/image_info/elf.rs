//! ELF section and symbol metadata, including CPUs available only as data.
use super::*;
use crate::extract::image::{ImageFormat, Permissions};
use goblin::elf::{
    header::{EM_386, EM_AARCH64, EM_ARM, EM_MIPS, EM_PPC, EM_X86_64, ET_REL},
    program_header::{PF_R, PF_W, PF_X, PT_LOAD},
    reloc::{R_386_COPY, R_AARCH64_COPY, R_ARM_COPY, R_MIPS_COPY, R_PPC_COPY, R_X86_64_COPY},
    section_header::SHN_UNDEF,
    section_header::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS},
    Elf,
};

pub(super) fn inspect(bytes: &[u8]) -> Result<ImageInfo, ImageError> {
    let elf = Elf::parse(bytes).map_err(|e| ImageError::Elf(e.to_string()))?;
    let loaded = if super::unsupported_elf_cpu(bytes).is_none() {
        Some(LoadedImage::from_elf(bytes)?)
    } else {
        None
    };
    let bias = loaded.as_ref().map_or_else(
        || crate::extract::image::elf_load_bias(&elf),
        |image| image.load_bias,
    );
    let address = |va: u64| {
        va.checked_add(bias).ok_or(ImageError::AddressOverflow {
            format: ImageFormat::Elf,
            context: "metadata address",
        })
    };
    let mut info = if let Some(image) = &loaded {
        from_image(bytes, image, 0)
    } else {
        ImageInfo {
            format: "elf".into(),
            arch: None,
            fid_arch: None,
            entry: (elf.entry != 0).then(|| address(elf.entry)).transpose()?,
            ptr_size: if elf.is_64 { 8 } else { 4 },
            little_endian: elf.little_endian,
            warnings: Vec::new(),
            sections: Vec::new(),
            regions: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            details: FileDetails::default(),
            shellcode: None,
        }
    };
    info.ptr_size = if elf.is_64 { 8 } else { 4 };
    info.little_endian = elf.little_endian;
    if loaded.is_none() {
        for p in elf.program_headers.iter().filter(|p| p.p_type == PT_LOAD) {
            if p.p_filesz > p.p_memsz
                || p.p_offset
                    .checked_add(p.p_filesz)
                    .is_none_or(|end| end > bytes.len() as u64)
            {
                return Err(ImageError::Elf("invalid file-backed segment".into()));
            }
            address(
                p.p_vaddr
                    .checked_add(p.p_memsz)
                    .ok_or_else(|| ImageError::Elf("segment address overflow".into()))?,
            )?;
            let mapped = MappedSection {
                name: format!("LOAD_{:x}", p.p_vaddr),
                address: address(p.p_vaddr)?,
                virtual_size: p.p_memsz,
                file_offset: p.p_offset,
                file_size: p.p_filesz,
                permissions: Permissions {
                    read: p.p_flags & PF_R != 0,
                    write: p.p_flags & PF_W != 0,
                    execute: p.p_flags & PF_X != 0,
                },
            };
            info.sections.push(section(bytes, &mapped, 0));
            info.regions.push(Region {
                off: p.p_offset,
                size: p.p_filesz,
                va: address(p.p_vaddr)?,
            });
        }
    }
    if elf.header.e_type != ET_REL {
        let sections = elf
            .section_headers
            .iter()
            .filter(|s| s.sh_flags & u64::from(SHF_ALLOC) != 0 && s.sh_size != 0)
            .map(|s| {
                let mapped = MappedSection {
                    name: elf.shdr_strtab.get_at(s.sh_name).unwrap_or("").into(),
                    address: address(s.sh_addr)?,
                    virtual_size: s.sh_size,
                    file_offset: s.sh_offset,
                    file_size: if s.sh_type == SHT_NOBITS {
                        0
                    } else {
                        s.sh_size
                    },
                    permissions: Permissions {
                        read: true,
                        write: s.sh_flags & u64::from(SHF_WRITE) != 0,
                        execute: s.sh_flags & u64::from(SHF_EXECINSTR) != 0,
                    },
                };
                Ok(section(bytes, &mapped, 0))
            })
            .collect::<Result<Vec<_>, ImageError>>()?;
        if !sections.is_empty() {
            info.sections = sections;
        }
    }
    // A copy relocation makes a library's variable look defined here: the executable holds the copy
    // the library itself uses. It is an import of data, not something the file exports.
    let copy_type = match elf.header.e_machine {
        EM_X86_64 => Some(R_X86_64_COPY),
        EM_386 => Some(R_386_COPY),
        EM_AARCH64 => Some(R_AARCH64_COPY),
        EM_ARM => Some(R_ARM_COPY),
        EM_MIPS => Some(R_MIPS_COPY),
        EM_PPC => Some(R_PPC_COPY),
        _ => None,
    };
    let copied: std::collections::HashSet<usize> = copy_type
        .map(|kind| {
            elf.dynrelas
                .iter()
                .chain(elf.dynrels.iter())
                .filter(|r| r.r_type == kind)
                .map(|r| r.r_sym)
                .collect()
        })
        .unwrap_or_default();
    for (index, sym) in elf.dynsyms.iter().enumerate() {
        let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        if sym.st_shndx == SHN_UNDEF as usize {
            if !info.imports.iter().any(|i| i.name == name) {
                info.imports.push(Import {
                    dll: String::new(),
                    name: name.into(),
                    va: 0,
                    data: false,
                });
            }
        } else if copied.contains(&index) && sym.st_value != 0 {
            // The loader may already list it from its relocation; mark that entry rather than add a second.
            let va = address(sym.st_value)?;
            match info.imports.iter_mut().find(|i| i.name == name) {
                Some(existing) => {
                    existing.data = true;
                    if existing.va == 0 {
                        existing.va = va;
                    }
                }
                None => info.imports.push(Import {
                    dll: String::new(),
                    name: name.into(),
                    va,
                    data: true,
                }),
            }
        } else if sym.st_value != 0 && sym.st_type() <= 2 {
            info.exports.push(Export {
                name: name.into(),
                va: address(sym.st_value)?,
                forward: None,
            });
        }
    }
    info.details = details::elf::collect(bytes, &elf, bias);
    Ok(info)
}
