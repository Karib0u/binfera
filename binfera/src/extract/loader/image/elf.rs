//! ELF image loading and relocation policy.
use super::*;

impl LoadedImage {
    pub fn from_elf(bytes: &[u8]) -> Result<Self, ImageError> {
        Self::from_elf_with_import_policy(bytes, false)
    }

    pub(crate) fn from_elf_with_import_policy(
        bytes: &[u8],
        vivisect_compat: bool,
    ) -> Result<Self, ImageError> {
        let elf = Elf::parse(bytes).map_err(|error| ImageError::Elf(error.to_string()))?;
        let architecture = match elf.header.e_machine {
            EM_386 => Architecture::X86,
            EM_X86_64 => Architecture::X64,
            EM_AARCH64 => Architecture::AArch64,
            goblin::elf::header::EM_ARM if elf.little_endian && !elf.is_64 => Architecture::Arm,
            goblin::elf::header::EM_MIPS if !elf.is_64 => {
                if !crate::extract::risc::supported_mips_flags(elf.header.e_flags) {
                    return Err(ImageError::UnsupportedVariant {
                        format: ImageFormat::Elf,
                        description: "MIPS requires classic MIPS32 or MIPS I/II with the o32 ABI"
                            .into(),
                    });
                }
                if elf.little_endian {
                    Architecture::Mips
                } else {
                    Architecture::MipsBe
                }
            }
            machine => {
                return Err(ImageError::UnsupportedArchitecture {
                    format: ImageFormat::Elf,
                    machine,
                });
            }
        };

        if architecture == Architecture::AArch64
            && (!elf.little_endian || !elf.is_64 || !matches!(elf.header.e_type, 1..=3))
        {
            return Err(ImageError::Elf(
                "AArch64 requires a little-endian ELF64 executable, shared image or object".into(),
            ));
        }

        if elf.header.e_type == goblin::elf::header::ET_REL {
            if elf
                .program_headers
                .iter()
                .any(|header| header.p_type == PT_LOAD)
            {
                return Err(ImageError::Elf(
                    "relocatable objects cannot contain executable load segments".into(),
                ));
            }
            let addresses = super::super::elf_rel::layout(&elf)?;
            let mut image = Self::from_shellcode_at(&[], architecture, 0x10_0000);
            image.format = ImageFormat::Elf;
            image.entry_point = None;
            image.sections.clear();
            image.mapped_bytes.clear();
            image.primary_code.clear();
            for (index, address) in addresses.iter().enumerate() {
                let Some(address) = *address else {
                    continue;
                };
                let section = &elf.section_headers[index];
                let file_size = if section.sh_type == goblin::elf::section_header::SHT_NOBITS {
                    0
                } else {
                    section.sh_size
                };
                let data = mapped_region(
                    bytes,
                    section.sh_offset,
                    file_size,
                    section.sh_size,
                    ImageFormat::Elf,
                )?;
                let execute =
                    section.sh_flags & u64::from(goblin::elf::section_header::SHF_EXECINSTR) != 0;
                if execute {
                    image
                        .primary_code
                        .push((address, address + section.sh_size));
                }
                image.sections.push(MappedSection {
                    name: elf
                        .shdr_strtab
                        .get_at(section.sh_name)
                        .unwrap_or("")
                        .to_owned(),
                    address,
                    virtual_size: section.sh_size,
                    file_offset: section.sh_offset,
                    file_size,
                    permissions: Permissions {
                        read: true,
                        write: section.sh_flags & u64::from(goblin::elf::section_header::SHF_WRITE)
                            != 0,
                        execute,
                    },
                });
                image.mapped_bytes.push(data);
            }
            super::super::elf_rel::relocate(&mut image, &elf, &addresses)?;
            configure_arm_context(&mut image, &elf, Some(&addresses));
            return Ok(image);
        }

        let raw_image_base = elf
            .program_headers
            .iter()
            .filter(|header| header.p_type == PT_LOAD)
            .map(|header| header.p_vaddr)
            .min()
            .unwrap_or(0);
        let load_bias = elf_load_bias(&elf);
        let image_base =
            raw_image_base
                .checked_add(load_bias)
                .ok_or(ImageError::AddressOverflow {
                    format: ImageFormat::Elf,
                    context: "image base",
                })?;
        let entry_point = if elf.entry == 0 {
            None
        } else {
            Some(
                elf.entry
                    .checked_add(load_bias)
                    .ok_or(ImageError::AddressOverflow {
                        format: ImageFormat::Elf,
                        context: "entry point",
                    })?,
            )
        };
        let mut sections = Vec::new();
        let mut mapped_bytes = Vec::new();
        let mut primary_code = Vec::new();
        for (index, header) in elf
            .program_headers
            .iter()
            .enumerate()
            .filter(|(_, header)| header.p_type == PT_LOAD)
        {
            let available = u64::try_from(bytes.len())
                .unwrap_or(u64::MAX)
                .saturating_sub(header.p_offset);
            let file_size = header.p_filesz.min(available);
            let data = mapped_region(
                bytes,
                header.p_offset,
                file_size,
                file_size,
                ImageFormat::Elf,
            )?;
            let address =
                header
                    .p_vaddr
                    .checked_add(load_bias)
                    .ok_or(ImageError::AddressOverflow {
                        format: ImageFormat::Elf,
                        context: "segment address",
                    })?;
            sections.push(MappedSection {
                name: format!("PT_LOAD[{index}]"),
                address,
                virtual_size: header.p_memsz.max(header.p_filesz),
                file_offset: header.p_offset,
                file_size,
                permissions: Permissions {
                    read: header.p_flags & PF_R != 0,
                    write: header.p_flags & PF_W != 0,
                    execute: header.p_flags & PF_X != 0,
                },
            });
            mapped_bytes.push(data);
            if header.p_flags & PF_X != 0 {
                primary_code.push((address, address.saturating_add(header.p_memsz)));
            }
        }

        let mut image = Self {
            format: ImageFormat::Elf,
            architecture,
            image_base,
            load_bias,
            entry_point,
            arm_context: BTreeMap::new(),
            global_pointer: None,
            sections,
            external_bindings: BTreeMap::new(),
            import_locations: BTreeMap::new(),
            load_diagnostics: Vec::new(),
            imports_skipped: false,
            relocation_locations: Vec::new(),
            elf_plt_ranges: Vec::new(),
            dead_data: Vec::new(),
            pe_exception_directory: None,
            code_exclusions: Vec::new(),
            function_ranges: Vec::new(),
            uninitialized: Vec::new(),
            primary_code,
            mapped_bytes,
        };
        configure_arm_context(&mut image, &elf, None);
        // elfplt.getPLTs uses section names even though executable mappings
        // come from PT_LOAD segments. Its .rela.plt entries are already typed
        // relocation structures, so that range contains no undefined code.
        for section in &elf.section_headers {
            let Some(name) = elf.shdr_strtab.get_at(section.sh_name) else {
                continue;
            };
            if name.starts_with(".plt") {
                let start =
                    section
                        .sh_addr
                        .checked_add(load_bias)
                        .ok_or(ImageError::AddressOverflow {
                            format: ImageFormat::Elf,
                            context: "PLT section address",
                        })?;
                let end =
                    start
                        .checked_add(section.sh_size)
                        .ok_or(ImageError::AddressOverflow {
                            format: ImageFormat::Elf,
                            context: "PLT section size",
                        })?;
                image.elf_plt_ranges.push((start, end));
            }
        }
        for relocation in elf
            .dynrelas
            .iter()
            .chain(elf.dynrels.iter())
            .chain(elf.pltrelocs.iter())
        {
            if architecture.is_risc32() {
                super::super::super::risc::relocate(&mut image, &elf, relocation);
                continue;
            }
            if architecture == Architecture::AArch64 {
                super::super::aarch64::relocate(&mut image, &elf, relocation);
                continue;
            }
            // parsers/elf.py applies unnamed R_386_RELATIVE and
            // R_X86_64_RELATIVE from the stored word, including RELA records.
            // Native loading follows ELF: RELA supplies the addend, REL stores it.
            if matches!(architecture, Architecture::X86 | Architecture::X64)
                && relocation.r_sym == 0
                && relocation.r_type == goblin::elf::reloc::R_X86_64_RELATIVE
            {
                let address = relocation.r_offset.checked_add(load_bias).ok_or(
                    ImageError::AddressOverflow {
                        format: ImageFormat::Elf,
                        context: "relative relocation address",
                    },
                )?;
                let width = architecture.pointer_width();
                let stored = image.bytes_at(address, width).and_then(|bytes| {
                    if width == 8 {
                        bytes.try_into().ok().map(u64::from_le_bytes)
                    } else {
                        bytes.try_into().ok().map(u32::from_le_bytes).map(u64::from)
                    }
                });
                let value = if vivisect_compat {
                    stored
                } else {
                    relocation.r_addend.map(|addend| addend as u64).or(stored)
                };
                if let Some(value) = value {
                    let base = if vivisect_compat {
                        image_base
                    } else {
                        load_bias
                    };
                    let relocated = value.wrapping_add(base).to_le_bytes();
                    let destination = image
                        .sections
                        .iter()
                        .enumerate()
                        .find(|(_, section)| section.contains_va(address))
                        .and_then(|(index, section)| {
                            let offset = usize::try_from(address - section.address).ok()?;
                            image
                                .mapped_bytes
                                .get_mut(index)?
                                .get_mut(offset..offset.checked_add(width)?)
                        });
                    if let (Some(destination), Some(source)) = (destination, relocated.get(..width))
                    {
                        destination.copy_from_slice(source);
                    } else {
                        image
                            .load_diagnostics
                            .push(format!("unmapped ELF relative relocation at {address:#x}"));
                    }
                } else {
                    image
                        .load_diagnostics
                        .push(format!("unmapped ELF relative relocation at {address:#x}"));
                }
            }
            let Some(symbol) = elf.dynsyms.get(relocation.r_sym) else {
                continue;
            };
            let Some(name) = elf.dynstrtab.get_at(symbol.st_name) else {
                continue;
            };
            if !name.is_empty() {
                let address = relocation.r_offset.checked_add(load_bias).ok_or(
                    ImageError::AddressOverflow {
                        format: ImageFormat::Elf,
                        context: "relocation binding",
                    },
                )?;
                // Vivisect 1.3.2 `parsers/elf.py:parseRelocs` creates imports
                // only for these relocation types on both x86 architectures.
                // Other named relocations remain symbols/relocations, not API
                // bindings. Native and AArch64 analysis retain all bindings.
                if vivisect_compat
                    && matches!(architecture, Architecture::X86 | Architecture::X64)
                    && !matches!(
                        relocation.r_type,
                        R_386_JMP_SLOT | R_X86_64_GLOB_DAT | R_X86_64_IRELATIVE
                    )
                {
                    image.load_diagnostics.push(format!(
                        "named ELF relocation type {} at {address:#x} ({name}) is not an import in the compatibility backend",
                        relocation.r_type
                    ));
                    continue;
                }
                image.add_external_binding(address, vec![name.to_string()]);
                // `vivisect/parsers/elf.py` passes `"*"` as the library name
                // for every dynamic relocation import (elf.py:844 and friends),
                // and `makeImport` leaves `"*"` un-normalised.
                image.import_locations.insert(address, format!("*.{name}"));
            }
        }

        image.global_pointer = elf
            .syms
            .iter()
            .find(|s| elf.strtab.get_at(s.st_name) == Some("_gp"))
            .map(|s| s.st_value.wrapping_add(load_bias));
        super::super::super::risc::mips_got(&mut image, &elf);
        Ok(image)
    }
}

/// Shared ET_DYN placement for recovery and file metadata.
pub(crate) fn elf_load_bias(elf: &Elf<'_>) -> u64 {
    let raw_image_base = elf
        .program_headers
        .iter()
        .filter(|p| p.p_type == PT_LOAD)
        .map(|p| p.p_vaddr)
        .min()
        .unwrap_or(0);
    if elf.header.e_type == ET_DYN {
        let dyn_base = if elf.header.e_machine == EM_AARCH64 {
            GHIDRA_AARCH64_ELF_DYN_BASE
        } else {
            VIV_ELF_DYN_BASE
        };
        dyn_base.saturating_sub(raw_image_base)
    } else {
        0
    }
}

// `capa/loader.py:get_workspace` delegates ET_DYN placement to the pinned
// Vivisect loader, which uses this base for PIEs and shared objects.
const VIV_ELF_DYN_BASE: u64 = 0x0200_0000;
// Native AArch64 ELF has no Vivisect baseline to reproduce -- its oracle is
// Ghidra's BinExport2, and Ghidra's own default AArch64 ET_DYN image base
// is this value, not `VIV_ELF_DYN_BASE`. Confirmed empirically against the
// pinned corpus (`tests/testfiles/aarch64/`, paired with
// `tests/testfiles/binexport2/*.ghidra.BinExport`): every function address
// the upstream fixture table names resolves under this base and none under
// `VIV_ELF_DYN_BASE`. Using the wrong base doesn't fail loudly -- recovery
// still succeeds, just at addresses that can never line up with the paired
// BinExport2 file, which is why this was caught by task 4's feature-parity
// table rather than task 3's recovery-only acceptance.
const GHIDRA_AARCH64_ELF_DYN_BASE: u64 = 0x0010_0000;

fn configure_arm_context(
    image: &mut LoadedImage,
    elf: &Elf<'_>,
    addresses: Option<&[Option<u64>]>,
) {
    let load_bias = image.load_bias;
    let symbol_address = |symbol: goblin::elf::sym::Sym| {
        addresses
            .and_then(|a| a.get(symbol.st_shndx).copied().flatten())
            .unwrap_or(load_bias)
            .saturating_add(symbol.st_value)
    };
    if image.architecture == Architecture::Arm {
        for section in &image.sections {
            image.arm_context.insert(section.address, 0);
        }
        for symbol in elf.syms.iter().chain(elf.dynsyms.iter()) {
            if symbol.st_shndx == 0 {
                continue;
            }
            let address = symbol_address(symbol);
            if symbol.is_function() {
                image.set_thumb(address, address & 1 != 0);
            }
        }
        for (symbols, strings) in [(&elf.syms, &elf.strtab), (&elf.dynsyms, &elf.dynstrtab)] {
            for symbol in symbols.iter() {
                let name = strings.get_at(symbol.st_name).unwrap_or_default();
                let name = name.split('.').next().unwrap_or_default();
                if name == "$a" || name == "$t" {
                    image.set_thumb(symbol_address(symbol), name == "$t");
                }
                if name == "$d" {
                    let start = symbol_address(symbol);
                    let end = symbols
                        .iter()
                        .filter(|s| s.st_shndx == symbol.st_shndx && s.st_value > symbol.st_value)
                        .filter(|s| {
                            strings.get_at(s.st_name).is_some_and(|n| {
                                n.starts_with("$a") || n.starts_with("$t") || n.starts_with("$d")
                            })
                        })
                        .map(&symbol_address)
                        .min()
                        .or_else(|| {
                            elf.section_headers
                                .get(symbol.st_shndx)
                                .and_then(|section| {
                                    let base = addresses
                                        .and_then(|a| a.get(symbol.st_shndx).copied().flatten())
                                        .unwrap_or(section.sh_addr.saturating_add(load_bias));
                                    base.checked_add(section.sh_size)
                                })
                        });
                    if let Some(end) = end {
                        if start < end {
                            image.code_exclusions.push(start..end);
                        }
                    }
                }
            }
        }
        if let Some(entry) = image.entry_point {
            image.set_thumb(entry, entry & 1 != 0);
            image.entry_point = Some(entry & !1);
        }
        image.code_exclusions.sort_by_key(|r| r.start);
        let mut merged: Vec<std::ops::Range<u64>> = Vec::new();
        for range in image.code_exclusions.drain(..) {
            if let Some(last) = merged.last_mut().filter(|last| range.start <= last.end) {
                last.end = last.end.max(range.end);
            } else {
                merged.push(range);
            }
        }
        image.code_exclusions = merged;
    }
}
