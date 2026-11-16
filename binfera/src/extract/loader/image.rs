//! The format-neutral loaded-image and instruction-decode model.
//!
//! PE sections and ELF `PT_LOAD` segments are represented using the same
//! address, file-backing, and permission fields. Recovery code can therefore
//! stay independent of the container format and cannot read beyond a mapped
//! executable region.

use std::borrow::Cow;
use std::collections::BTreeMap;

use goblin::elf::header::{EM_386, EM_AARCH64, EM_X86_64, ET_DYN};
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_LOAD};
use goblin::elf::reloc::{R_386_JMP_SLOT, R_X86_64_GLOB_DAT, R_X86_64_IRELATIVE};
use goblin::elf::Elf;
use goblin::mach::constants::cputype::CPU_TYPE_X86_64;
use goblin::mach::constants::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
use goblin::mach::fat::FAT_MAGIC;
use goblin::mach::header::{MH_CIGAM_64, MH_MAGIC_64};
use goblin::mach::load_command::{CommandVariant, SIZEOF_SECTION_64, SIZEOF_SEGMENT_COMMAND_64};
use goblin::mach::MachO;
use goblin::pe::header::{COFF_MACHINE_ARM64, COFF_MACHINE_X86, COFF_MACHINE_X86_64};
use goblin::pe::options::{ParseMode, ParseOptions};
use goblin::pe::section_table::{
    IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};
use goblin::pe::PE;
use iced_x86::{Decoder, DecoderOptions, Instruction};

use super::helpers::generate_symbols;

mod decode;
mod elf;
mod macho;
mod pe;
pub(crate) use elf::elf_load_bias;
pub use macho::select_macho_slice;
pub(crate) use pe::tolerate_rich_header;

const MAX_MAPPED_IMAGE_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "decompiler", derive(serde::Serialize, serde::Deserialize))]
pub enum ImageFormat {
    Pe,
    Elf,
    /// `-f sc32`/`sc64`: a raw code blob with no container format at all.
    Sc,
    /// `-f macho`: a binfera extension -- pinned capa 10.0.0 has
    /// no raw Mach-O input, so this is never a parity claim, only capa's own
    /// feature semantics applied to a format upstream does not accept.
    Macho,
}

/// `viv_utils.SHELLCODE_BASE` (pinned via `flare-capa==9.4.0`'s `viv_utils`
/// dependency, `.venv/lib/*/site-packages/viv_utils/__init__.py`):
/// `capa/loader.py:get_workspace`'s `FORMAT_SC32`/`FORMAT_SC64` branches call
/// `viv_utils.getShellcodeWorkspaceFromFile(path, arch=..., analyze=False)`,
/// whose `base`/`entry_point` defaults place the whole buffer at this fixed
/// address with the entry point at its first byte -- *not* address 0.
pub const SHELLCODE_BASE: u64 = 0x0069_0000;

/// `AArch64` decodes through `disarm64` instead of `iced-x86`
/// (see `decode_at` and `super::decoder::from_aarch64`). `from_elf` maps
/// `EM_AARCH64` to it (task 3); every x86-only recovery heuristic reachable
/// from the ELF path (`libc_start_main`, `golang`, `noreturn.rs`) is either
/// architecture-gated or, for `noreturn.rs`, rewritten against the generic
/// `Flow` boundary, so none of them can reach
/// [`super::decoder::DecodedInstruction::x86_instruction`] (which panics by
/// design for this variant) against an AArch64 image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "decompiler", derive(serde::Serialize, serde::Deserialize))]
pub enum Architecture {
    X86,
    X64,
    AArch64,
    Arm,
    Mips,
    MipsBe,
}

impl Architecture {
    pub fn bitness(self) -> u32 {
        match self {
            Self::X86 | Self::Arm | Self::Mips | Self::MipsBe => 32,
            Self::X64 | Self::AArch64 => 64,
        }
    }

    /// Native pointer/GPR width in bytes -- `bitness() / 8`, named for the
    /// several call sites in `recovery.rs` (relocation/init-array/jump-table
    /// pointer reads) that used to spell this `== Architecture::X64` before
    /// AArch64 existed, silently reading 32-bit halves of a 64-bit pointer
    /// had it ever reached one.
    pub fn pointer_width(self) -> usize {
        (self.bitness() / 8) as usize
    }

    pub fn is_x86(self) -> bool {
        matches!(self, Self::X86 | Self::X64)
    }

    pub fn is_risc32(self) -> bool {
        matches!(self, Self::Arm | Self::Mips | Self::MipsBe)
    }

    pub fn little_endian(self) -> bool {
        self != Self::MipsBe
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X64 => "x64",
            Self::AArch64 => "aarch64",
            Self::Arm => "arm",
            Self::Mips => "mipsel",
            Self::MipsBe => "mips",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "decompiler", derive(serde::Serialize, serde::Deserialize))]
pub struct Permissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "decompiler", derive(serde::Serialize, serde::Deserialize))]
pub struct MappedSection {
    pub name: String,
    pub address: u64,
    pub virtual_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub permissions: Permissions,
}

impl MappedSection {
    pub fn end_address(&self) -> Option<u64> {
        self.address.checked_add(self.virtual_size)
    }

    pub fn contains_va(&self, address: u64) -> bool {
        address
            .checked_sub(self.address)
            .is_some_and(|offset| offset < self.virtual_size)
    }

    pub fn contains_file_offset(&self, offset: u64) -> bool {
        offset
            .checked_sub(self.file_offset)
            .is_some_and(|relative| relative < self.file_size)
    }
}

pub use super::decoder::DecodedInstruction;

#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    #[error("unsupported input format")]
    UnsupportedFormat,
    #[error("unsupported {format:?} machine type {machine:#x}")]
    UnsupportedArchitecture { format: ImageFormat, machine: u16 },
    #[error("unsupported {format:?} processor variant: {description}")]
    UnsupportedVariant {
        format: ImageFormat,
        description: String,
    },
    #[error("parsing PE image: {0}")]
    Pe(String),
    #[error("parsing ELF image: {0}")]
    Elf(String),
    #[error("mapping {format:?} image: {context}")]
    Mapping {
        format: ImageFormat,
        context: String,
    },
    #[error("{format:?} address computation overflow: {context}")]
    AddressOverflow {
        format: ImageFormat,
        context: &'static str,
    },
    #[error("address {address:#x} is not file-backed mapped data")]
    AddressNotMapped { address: u64 },
    #[error("address {address:#x} is not in an executable mapping")]
    AddressNotExecutable { address: u64 },
    #[error("invalid or truncated instruction at {address:#x}: {reason}")]
    InvalidInstruction { address: u64, reason: String },
    #[error("malformed PE delay import data at RVA {rva:#x}: {context}")]
    DelayImport { rva: u64, context: String },
    #[error("parsing Mach-O image: {0}")]
    Macho(String),
    #[error(
        "no {requested} slice in this Mach-O: available architectures are [{}]",
        .available.join(", ")
    )]
    NoCompatibleMachoSlice {
        requested: String,
        available: Vec<String>,
    },
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "decompiler", derive(serde::Serialize, serde::Deserialize))]
pub struct LoadedImage {
    pub format: ImageFormat,
    pub architecture: Architecture,
    pub image_base: u64,
    pub load_bias: u64,
    pub entry_point: Option<u64>,
    /// ARM mapping symbols and discovered interworking targets. Bit 0 selects Thumb;
    /// bit 1 marks an instruction predicated by a preceding Thumb IT instruction.
    pub(crate) arm_context: BTreeMap<u64, u8>,
    pub(crate) global_pointer: Option<u64>,
    pub sections: Vec<MappedSection>,
    /// Maps IAT/GOT addresses to capa API-name variants.
    pub external_bindings: BTreeMap<u64, Vec<String>>,
    /// Maps the same IAT/GOT addresses to Vivisect's *import location* name --
    /// the `tinfo` string `VivWorkspace.makeImport` stores, i.e.
    /// `"{normFileName(libname)}.{impname}"` for PE and `"*.{impname}"` for
    /// ELF (`vivisect/__init__.py:919-927`). This is the exact string
    /// `addNoReturnApi`/`addNoReturnApiRegex` match against, so it is kept
    /// verbatim alongside the capa-flavoured `external_bindings` variants
    /// rather than reconstructed from them.
    pub import_locations: BTreeMap<u64, String>,
    /// Recoverable malformed optional-directory conditions encountered while
    /// loading. Code recovery exposes these without rejecting the sample.
    pub load_diagnostics: Vec<String>,
    /// Set by [`LoadedImage::parse_partial`] when a malformed import directory
    /// was dropped, so the image has no import bindings.
    pub(crate) imports_skipped: bool,
    /// PE relocation slots, retained as pointer locations during recovery.
    pub(crate) relocation_locations: Vec<u64>,
    /// ELF PLT section ranges, separate from the PT_LOAD memory mappings.
    pub(crate) elf_plt_ranges: Vec<(u64, u64)>,
    /// Vivisect's PE loader marks directory sections and sections without
    /// code, execute, or write characteristics as dead data. The end address
    /// is inclusive because `VivWorkspace.isDeadData()` uses `<= end`.
    dead_data: Vec<(u64, u64)>,
    /// Address and byte size of the PE exception directory.
    pub(crate) pe_exception_directory: Option<(u64, u32)>,
    /// Sorted, merged compiler metadata ranges, populated by native recovery.
    pub(crate) code_exclusions: Vec<std::ops::Range<u64>>,
    /// Linker-provided function extents used to keep fallback discovery out of bodies.
    pub(crate) function_ranges: Vec<(u64, u64)>,
    /// Regions carrying Vivisect's `MM_UNINIT` permission. Code flow must not
    /// enter these even if another loader rule also made the map executable.
    uninitialized: Vec<(u64, u64)>,
    /// Regions identified as code before Vivisect's pre-Vista NX fallback
    /// broadens executable permission to every readable PE section.
    primary_code: Vec<(u64, u64)>,
    /// Bytes as mapped into virtual memory, parallel to `sections`. PE entries
    /// include loader-created zero fill and file-alignment padding.
    pub(super) mapped_bytes: Vec<Vec<u8>>,
}

impl LoadedImage {
    pub fn is_thumb(&self, address: u64) -> bool {
        self.architecture == Architecture::Arm
            && self
                .arm_context
                .range(..=address)
                .next_back()
                .is_some_and(|(_, mode)| mode & 1 != 0)
    }

    pub(crate) fn set_thumb(&mut self, address: u64, thumb: bool) {
        if self.architecture == Architecture::Arm {
            self.arm_context.insert(address & !1, u8::from(thumb));
        }
    }

    pub(crate) fn write_pointer(&mut self, address: u64, value: u64) {
        let width = self.architecture.pointer_width();
        let bytes = if self.architecture.little_endian() {
            value.to_le_bytes()
        } else {
            (value << 32).to_be_bytes()
        };
        if let Some(index) = self.sections.iter().position(|s| s.contains_va(address)) {
            let offset = (address - self.sections[index].address) as usize;
            if let Some(dst) =
                self.mapped_bytes[index].get_mut(offset..offset.saturating_add(width))
            {
                dst.copy_from_slice(&bytes[..width]);
            }
        }
    }
    pub fn read_pointer(&self, address: u64) -> Option<u64> {
        let bytes = self.bytes_at(address, self.architecture.pointer_width())?;
        match (
            self.architecture.pointer_width(),
            self.architecture.little_endian(),
        ) {
            (4, true) => Some(u64::from(u32::from_le_bytes(bytes.try_into().ok()?))),
            (4, false) => Some(u64::from(u32::from_be_bytes(bytes.try_into().ok()?))),
            (8, true) => Some(u64::from_le_bytes(bytes.try_into().ok()?)),
            _ => None,
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, ImageError> {
        if bytes.starts_with(b"MZ") {
            Self::from_pe(bytes)
        } else if bytes.starts_with(b"\x7fELF") {
            Self::from_elf(bytes)
        } else if super::looks_like_macho(bytes) {
            Self::from_macho(bytes, None)
        } else {
            Err(ImageError::UnsupportedFormat)
        }
    }

    /// Like [`parse`](Self::parse), but a PE whose import or delay import
    /// directory cannot be parsed loads without any imports and records a
    /// diagnostic instead of being refused. Validated flat Go memory images
    /// use virtual section offsets. Capability analysis keeps using strict `parse`.
    pub fn parse_partial(bytes: &[u8]) -> Result<Self, ImageError> {
        let memory_image = bytes
            .starts_with(b"MZ")
            .then(|| pe::normalize_go_memory_pe(bytes))
            .flatten();
        let bytes = memory_image.as_deref().unwrap_or(bytes);
        let result = match Self::parse(bytes) {
            Err(error @ (ImageError::Pe(_) | ImageError::DelayImport { .. }))
                if bytes.starts_with(b"MZ") =>
            {
                let Ok(mut image) = Self::from_pe_with_imports(bytes, false) else {
                    return Err(error);
                };
                image
                    .load_diagnostics
                    .push(format!("import directory ignored: {error}"));
                Ok(image)
            }
            other => other,
        };
        result.map(|mut image| {
            if memory_image.is_some() {
                image.load_diagnostics.push("Go memory image: sections use virtual offsets; on-disk section offsets were ignored.".into());
            }
            image
        })
    }

    /// `viv_utils.getShellcodeWorkspace`: the whole buffer becomes one
    /// `MM_RWX` memory map/segment named `shellcode_0x{base:x}`, loaded at
    /// [`SHELLCODE_BASE`] with the entry point at that same address
    /// (`entry_point=0`, relative to `base`). No imports/exports/relocations
    /// exist for a raw blob, so `external_bindings` stays empty.
    pub fn from_shellcode(bytes: &[u8], architecture: Architecture) -> Self {
        Self::from_shellcode_at(bytes, architecture, SHELLCODE_BASE)
    }

    /// Raw code mapped at an explicit address, without changing capability defaults.
    pub fn from_shellcode_at(bytes: &[u8], architecture: Architecture, base: u64) -> Self {
        let size = bytes.len() as u64;
        Self {
            format: ImageFormat::Sc,
            architecture,
            image_base: base,
            load_bias: 0,
            entry_point: Some(base),
            arm_context: BTreeMap::new(),
            global_pointer: None,
            sections: vec![MappedSection {
                name: format!("shellcode_0x{base:x}"),
                address: base,
                virtual_size: size,
                file_offset: 0,
                file_size: size,
                permissions: Permissions {
                    read: true,
                    write: true,
                    execute: true,
                },
            }],
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
            primary_code: vec![(base, base.saturating_add(size))],
            mapped_bytes: vec![bytes.to_vec()],
        }
    }

    pub fn section_containing(&self, address: u64) -> Option<&MappedSection> {
        self.sections
            .iter()
            .find(|section| section.contains_va(address))
    }

    pub fn is_dead_data(&self, address: u64) -> bool {
        self.dead_data
            .iter()
            .any(|(start, end)| address >= *start && address <= *end)
    }

    pub fn is_uninitialized(&self, address: u64) -> bool {
        self.uninitialized
            .iter()
            .any(|(start, end)| address >= *start && address < *end)
    }

    pub(crate) fn primary_code_ranges(&self) -> &[(u64, u64)] {
        &self.primary_code
    }

    pub(crate) fn is_primary_code_address(&self, address: u64) -> bool {
        self.primary_code
            .iter()
            .any(|(start, end)| address >= *start && address < *end)
    }

    pub fn is_code_excluded(&self, address: u64) -> bool {
        let i = self
            .code_exclusions
            .partition_point(|range| range.end <= address);
        self.code_exclusions
            .get(i)
            .is_some_and(|range| range.contains(&address))
    }

    pub fn is_executable_address(&self, address: u64) -> bool {
        self.section_containing(address)
            .is_some_and(|section| section.permissions.execute)
            && !self.is_uninitialized(address)
            && !self.is_code_excluded(address)
            && self.bytes_at(address, 1).is_some()
    }

    pub fn va_to_file_offset(&self, address: u64) -> Option<u64> {
        self.sections.iter().find_map(|section| {
            let relative = address.checked_sub(section.address)?;
            (relative < section.file_size).then(|| section.file_offset.checked_add(relative))?
        })
    }

    pub fn file_offset_to_va(&self, offset: u64) -> Option<u64> {
        self.sections.iter().find_map(|section| {
            let relative = offset.checked_sub(section.file_offset)?;
            (relative < section.file_size).then(|| section.address.checked_add(relative))?
        })
    }

    /// Returns at most `max_len` bytes without crossing the containing mapped
    /// region. PE zero-fill and file-alignment padding are visible here just
    /// as they are through Vivisect's memory maps.
    /// The bytes mapped for section `index`, which may be shorter than its virtual size.
    pub fn section_bytes(&self, index: usize) -> Option<&[u8]> {
        self.mapped_bytes.get(index).map(Vec::as_slice)
    }

    /// Like [`Self::bytes_at`], but stops at the end of the section's file data, so
    /// the loader's zero fill (and a truncated file's missing tail) is never returned.
    pub(crate) fn file_backed_at(&self, address: u64, max_len: usize) -> Option<&[u8]> {
        let (index, section) = self
            .sections
            .iter()
            .enumerate()
            .find(|(_, section)| section.contains_va(address))?;
        let start = usize::try_from(address.checked_sub(section.address)?).ok()?;
        let backed = usize::try_from(section.file_size).unwrap_or(usize::MAX);
        let len = max_len.min(backed.checked_sub(start)?);
        self.mapped_bytes
            .get(index)?
            .get(start..start.checked_add(len)?)
    }

    pub fn bytes_at(&self, address: u64, max_len: usize) -> Option<&[u8]> {
        let (index, section) = self
            .sections
            .iter()
            .enumerate()
            .find(|(_, section)| section.contains_va(address))?;
        let relative = address.checked_sub(section.address)?;
        let start = usize::try_from(relative).ok()?;
        let data = self.mapped_bytes.get(index)?;
        let section_remaining = data.len().checked_sub(start)?;
        let len = max_len.min(section_remaining);
        let end = start.checked_add(len)?;
        data.get(start..end)
    }
}

/// Test-only constructor for other test modules (feature
/// extraction) that need a hand-built image rather than a real PE/ELF byte
/// buffer -- e.g. several disjoint code/data sections at addresses chosen
/// to make a specific extractor's inputs obvious.
#[cfg(test)]
impl LoadedImage {
    pub(crate) fn for_test(
        format: ImageFormat,
        architecture: Architecture,
        image_base: u64,
        sections: Vec<MappedSection>,
        external_bindings: BTreeMap<u64, Vec<String>>,
        bytes: Vec<u8>,
    ) -> Self {
        let mapped_bytes = sections
            .iter()
            .map(|section| {
                let start = usize::try_from(section.file_offset).unwrap_or(usize::MAX);
                let len = usize::try_from(section.file_size).unwrap_or(0);
                let end = start.saturating_add(len);
                bytes.get(start..end).unwrap_or_default().to_vec()
            })
            .collect();
        let primary_code = sections
            .iter()
            .filter(|section| section.permissions.execute)
            .filter_map(|section| Some((section.address, section.end_address()?)))
            .collect();
        Self {
            format,
            architecture,
            image_base,
            load_bias: 0,
            entry_point: Some(image_base),
            arm_context: BTreeMap::new(),
            global_pointer: None,
            sections,
            external_bindings,
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
        }
    }

    /// Register an IAT/GOT slot under the Vivisect `makeImport` name form, so
    /// a hand-built image can exercise import-driven analysis (no-return APIs,
    /// thunk classification) without a real import directory.
    pub(crate) fn with_import_location(mut self, address: u64, name: &str) -> Self {
        self.import_locations.insert(address, name.to_string());
        self
    }
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    if alignment == 0 {
        return Some(value);
    }
    value
        .checked_add(alignment.checked_sub(1)?)
        .map(|sum| sum / alignment * alignment)
}

fn mapped_region(
    bytes: &[u8],
    file_offset: u64,
    file_size: u64,
    mapped_size: u64,
    format: ImageFormat,
) -> Result<Vec<u8>, ImageError> {
    let mapped_len = usize::try_from(mapped_size).map_err(|_| ImageError::Mapping {
        format,
        context: format!("region size {mapped_size:#x} does not fit in memory"),
    })?;
    if mapped_len > MAX_MAPPED_IMAGE_BYTES {
        return Err(ImageError::Mapping {
            format,
            context: format!(
                "region size {mapped_size:#x} exceeds limit {MAX_MAPPED_IMAGE_BYTES:#x}"
            ),
        });
    }
    let start = usize::try_from(file_offset).unwrap_or(usize::MAX);
    let requested = usize::try_from(file_size).unwrap_or(usize::MAX);
    let available = bytes.len().saturating_sub(start);
    let copy_len = requested.min(available).min(mapped_len);
    let mut mapped = vec![0; mapped_len];
    if copy_len != 0 {
        let source_end = start.saturating_add(copy_len);
        if let (Some(source), Some(destination)) =
            (bytes.get(start..source_end), mapped.get_mut(..copy_len))
        {
            destination.copy_from_slice(source);
        }
    }
    Ok(mapped)
}

fn account_mapping(total: &mut usize, size: usize) -> Result<(), ImageError> {
    *total = total
        .checked_add(size)
        .ok_or_else(|| ImageError::Pe("mapped image size overflow".to_string()))?;
    if *total > MAX_MAPPED_IMAGE_BYTES {
        return Err(ImageError::Pe(format!(
            "mapped image size {total:#x} exceeds limit {MAX_MAPPED_IMAGE_BYTES:#x}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;

impl LoadedImage {
    pub(crate) fn add_external_binding(&mut self, address: u64, names: Vec<String>) {
        let bindings = self.external_bindings.entry(address).or_default();
        for name in names {
            if !bindings.contains(&name) {
                bindings.push(name);
            }
        }
    }
}
