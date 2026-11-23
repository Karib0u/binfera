//! Mach-O image loading.
use super::*;

impl LoadedImage {
    /// Load a thin or fat Mach-O, selecting `arch` (`Some("arm64")`) or,
    /// when `None` ("`--arch auto`"), the first slice in
    /// [`SUPPORTED_MACHO_ARCHES`] in fat-header order -- host-independent by
    /// construction, since it never consults the running machine's own
    /// architecture.
    pub fn from_macho(bytes: &[u8], arch: Option<&str>) -> Result<Self, ImageError> {
        let (slice, resolved_arch) = select_macho_slice(bytes, arch)?;
        let macho = MachO::parse(slice, 0).map_err(|error| ImageError::Macho(error.to_string()))?;
        if !macho.is_64 {
            return Err(ImageError::Macho(
                "32-bit Mach-O is not supported".to_string(),
            ));
        }
        if !macho.little_endian || macho.header.filetype == goblin::mach::header::MH_OBJECT {
            return Err(ImageError::Macho(
                "requires a linked little-endian Mach-O image; object relocation is unsupported"
                    .into(),
            ));
        }
        // `select_macho_slice` already restricted `resolved_arch` to
        // `SUPPORTED_MACHO_ARCHES`; this only maps that name to the
        // `Architecture` recovery/decode dispatch on -- both `arm64` and
        // `arm64e` decode through `disarm64` identically (see
        // `SUPPORTED_MACHO_ARCHES`'s doc comment).
        let architecture = match resolved_arch {
            "x86_64" => Architecture::X64,
            "arm64" | "arm64e" => Architecture::AArch64,
            other => {
                return Err(ImageError::Macho(format!(
                    "internal error: select_macho_slice returned unsupported arch {other}"
                )));
            }
        };
        validate_macho_load_commands(&macho, slice)?;

        // (segname, vmaddr, vmsize, fileoff, filesize, initprot), in
        // load-command order -- collected once so both the overlap check
        // and the mapping loop below share one validated view.
        let mut segments: Vec<(String, u64, u64, u64, u64, u32)> = Vec::new();
        for command in &macho.load_commands {
            let CommandVariant::Segment64(seg) = command.command else {
                continue;
            };
            let expected_cmdsize = u32::try_from(SIZEOF_SEGMENT_COMMAND_64)
                .ok()
                .and_then(|base| {
                    seg.nsects
                        .checked_mul(u32::try_from(SIZEOF_SECTION_64).ok()?)
                        .and_then(|sections_size| base.checked_add(sections_size))
                })
                .ok_or_else(|| ImageError::Macho("segment nsects overflows cmdsize".to_string()))?;
            if expected_cmdsize != seg.cmdsize {
                return Err(ImageError::Macho(format!(
                    "segment {} declares {} sections, inconsistent with cmdsize {}",
                    cstr16(&seg.segname),
                    seg.nsects,
                    seg.cmdsize
                )));
            }
            // Go emits a file-only __DWARF segment with vmsize zero. It is
            // read by the debug importer, never mapped into the runtime image.
            let file_only_debug =
                cstr16(&seg.segname) == "__DWARF" && seg.vmsize == 0 && seg.initprot == 0;
            if seg.filesize > seg.vmsize && !file_only_debug {
                return Err(ImageError::Macho(format!(
                    "segment {} filesize {:#x} exceeds vmsize {:#x}",
                    cstr16(&seg.segname),
                    seg.filesize,
                    seg.vmsize
                )));
            }
            let fileoff = usize::try_from(seg.fileoff).map_err(|_| {
                ImageError::Macho(format!(
                    "segment {} fileoff does not fit in memory",
                    cstr16(&seg.segname)
                ))
            })?;
            let filesize = usize::try_from(seg.filesize).map_err(|_| {
                ImageError::Macho(format!(
                    "segment {} filesize does not fit in memory",
                    cstr16(&seg.segname)
                ))
            })?;
            let in_bounds = fileoff
                .checked_add(filesize)
                .is_some_and(|end| end <= slice.len());
            if !in_bounds {
                return Err(ImageError::Macho(format!(
                    "segment {} file range [{:#x}, {:#x}+{:#x}) is past the end of the file",
                    cstr16(&seg.segname),
                    seg.fileoff,
                    seg.fileoff,
                    seg.filesize
                )));
            }
            segments.push((
                cstr16(&seg.segname),
                seg.vmaddr,
                seg.vmsize,
                seg.fileoff,
                seg.filesize,
                seg.initprot,
            ));
        }
        validate_no_overlapping_macho_segments(&segments)?;

        let image_base = segments
            .iter()
            .find(|(name, ..)| name == "__TEXT")
            .map(|(_, vmaddr, ..)| *vmaddr)
            .or_else(|| segments.iter().map(|(_, vmaddr, ..)| *vmaddr).min())
            .unwrap_or(0);

        let mut sections = Vec::with_capacity(segments.len());
        let mut mapped_bytes = Vec::with_capacity(segments.len());
        let mut primary_code = Vec::new();
        let mut mapped_total = 0usize;
        for (name, vmaddr, vmsize, fileoff, filesize, initprot) in &segments {
            if name == "__PAGEZERO" || (*vmsize == 0 && name == "__DWARF") {
                // Unreadable, not 4 GiB of zero fill: never mapped at all, so
                // `section_containing`/`bytes_at` correctly treat every
                // address inside it as unmapped rather than serving
                // synthesized zero bytes for a region that was never backed
                // by anything -- `__PAGEZERO` maps unreadable.
                continue;
            }
            let data = mapped_region(slice, *fileoff, *filesize, *vmsize, ImageFormat::Macho)?;
            account_mapping(&mut mapped_total, data.len())?;
            let read = initprot & VM_PROT_READ != 0;
            let write = initprot & VM_PROT_WRITE != 0;
            let execute = initprot & VM_PROT_EXECUTE != 0;
            sections.push(MappedSection {
                name: name.clone(),
                address: *vmaddr,
                virtual_size: *vmsize,
                file_offset: *fileoff,
                file_size: (*filesize).min(*vmsize),
                permissions: Permissions {
                    read,
                    write,
                    execute,
                },
            });
            mapped_bytes.push(data);
            if execute {
                primary_code.push((*vmaddr, vmaddr.saturating_add(*vmsize)));
            }
        }

        let entry_point = (macho.entry != 0).then_some(macho.entry);

        let mut image = Self {
            format: ImageFormat::Macho,
            architecture,
            image_base,
            load_bias: 0,
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

        let mut code = Vec::new();
        for segment in &macho.segments {
            if segment.vmsize == 0 && segment.name().ok() == Some("__DWARF") {
                continue;
            }
            for section in segment
                .sections()
                .map_err(|e| ImageError::Macho(e.to_string()))?
            {
                let section = section.0;
                let end = section
                    .addr
                    .checked_add(section.size)
                    .ok_or_else(|| ImageError::Macho("section address overflow".into()))?;
                if section.addr < segment.vmaddr
                    || end > segment.vmaddr.saturating_add(segment.vmsize)
                {
                    return Err(ImageError::Macho("section lies outside its segment".into()));
                }
                if section.flags & 0x80000400 != 0 || section.flags & 0xff == 8 {
                    code.push((section.addr, end));
                    if section.flags & 0xff == 8 {
                        image.elf_plt_ranges.push((section.addr, end));
                    }
                }
            }
        }
        code.sort_unstable();
        image.primary_code = code.clone();
        for segment in image.sections.iter().filter(|s| s.permissions.execute) {
            let end = segment.address.saturating_add(segment.virtual_size);
            let mut cursor = segment.address;
            for &(start, stop) in &code {
                if stop <= cursor || start >= end {
                    continue;
                }
                if start > cursor {
                    image.code_exclusions.push(cursor..start);
                }
                cursor = cursor.max(stop.min(end));
            }
            if cursor < end {
                image.code_exclusions.push(cursor..end);
            }
        }
        image.code_exclusions.sort_by_key(|range| range.start);
        load_macho_imports(&macho, slice, &mut image);
        load_macho_indirect_symbols(&macho, slice, &mut image);

        Ok(image)
    }
}

/// Bind/rebase chain walk step cap, mirroring this file's other untrusted-
/// input loop bounds (`MAX_DELAY_IMPORTS` etc.) -- a real chain is at most
/// one entry per pointer-sized slot in a segment, which for any fixture or
/// realistic sample is orders of magnitude below this.
const MAX_MACHO_CHAIN_STEPS: usize = 1_000_000;

/// `x86_64`/`arm64`/`arm64e`/... names for [`ImageError::NoCompatibleMachoSlice`]
/// and `--arch` matching. `x86_64`, `arm64` and `arm64e`
/// are *supported* slices ([`SUPPORTED_MACHO_ARCHES`]) -- this still names
/// the others so a fat binary's error lists what it actually contains.
fn macho_cputype_name(cputype: u32) -> &'static str {
    use goblin::mach::constants::cputype::{CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_I386};
    match cputype {
        CPU_TYPE_X86_64 => "x86_64",
        CPU_TYPE_ARM64 => "arm64",
        CPU_TYPE_ARM => "arm",
        CPU_TYPE_I386 => "i386",
        _ => "unknown",
    }
}

/// The architecture names the loader accepts for `--arch` and auto-selection;
/// anything else (`arm`, `i386`, `arm64_32`, ...) is named in
/// an error message but never selected. `arm64`/`arm64e` are cputype
/// `CPU_TYPE_ARM64` distinguished only by cpusubtype --
/// pinned Vivisect never loaded Mach-O at all, so both decode identically
/// through `disarm64` (`Architecture::AArch64`); pac*/aut* instructions are
/// flow-neutral either way (no cryptographic modelling).
const SUPPORTED_MACHO_ARCHES: [&str; 3] = ["x86_64", "arm64", "arm64e"];

/// Name the CPU and subtype after masking the feature flags stored in both
/// universal and thin headers.
fn macho_arch_name(cputype: u32, cpusubtype: u32) -> &'static str {
    use goblin::mach::constants::cputype::{get_arch_name_from_types, CPU_SUBTYPE_MASK};
    get_arch_name_from_types(cputype, cpusubtype & !CPU_SUBTYPE_MASK)
        .unwrap_or_else(|| macho_cputype_name(cputype))
}

fn cstr16(raw: &[u8; 16]) -> String {
    let end = raw.iter().position(|byte| *byte == 0).unwrap_or(16);
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

/// Peeks `mach_header_64.cputype` without a full [`MachO::parse`], for slice
/// selection (which must happen *before* deciding whether the rest of the
/// header is even a supported (64-bit, x86_64) Mach-O). `magic_be` is the
/// first 4 bytes read big-endian, as [`select_macho_slice`] already
/// computed: `MH_CIGAM_64` means the file is little-endian on disk (the
/// common case for every real x86_64/arm64 Mach-O), `MH_MAGIC_64` means
/// big-endian.
fn peek_macho_cputype(bytes: &[u8], magic_be: u32) -> Result<u32, ImageError> {
    let raw = bytes
        .get(4..8)
        .and_then(|value| <[u8; 4]>::try_from(value).ok())
        .ok_or_else(|| ImageError::Macho("truncated Mach-O header".to_string()))?;
    Ok(if magic_be == MH_CIGAM_64 {
        u32::from_le_bytes(raw)
    } else {
        u32::from_be_bytes(raw)
    })
}

/// Same pre-parse peek as [`peek_macho_cputype`], for `mach_header_64`'s
/// very next field (`cpusubtype`, offset 8) -- needed to distinguish
/// `arm64` from `arm64e` (both `CPU_TYPE_ARM64`) before slice selection
/// decides whether the rest of the header is even worth parsing.
fn peek_macho_cpusubtype(bytes: &[u8], magic_be: u32) -> Result<u32, ImageError> {
    let raw = bytes
        .get(8..12)
        .and_then(|value| <[u8; 4]>::try_from(value).ok())
        .ok_or_else(|| ImageError::Macho("truncated Mach-O header".to_string()))?;
    Ok(if magic_be == MH_CIGAM_64 {
        u32::from_le_bytes(raw)
    } else {
        u32::from_be_bytes(raw)
    })
}

/// Deterministic, host-independent Mach-O slice selection. `arch` explicit
/// (`Some("arm64")`)
/// picks that architecture by name; `None` ("`--arch auto`") takes the
/// first slice in [`SUPPORTED_MACHO_ARCHES`] **in fat-header order** --
/// never by host architecture, so a fat binary selects identically on an M1
/// and an x86 runner, and never by a preference among supported
/// architectures either (a fat binary listing `arm64` before `x86_64`
/// auto-selects `arm64`). A thin (non-fat) input is its own only "slice".
/// Returns the selected slice's raw bytes plus its resolved architecture
/// name, for [`LoadedImage::from_macho`] and the file/global feature
/// extractor (`extract/macho.rs`) to share one selection.
pub fn select_macho_slice<'a>(
    bytes: &'a [u8],
    arch: Option<&str>,
) -> Result<(&'a [u8], &'static str), ImageError> {
    let arch = match arch {
        Some("auto") | None => None,
        Some("amd64") => Some("x86_64"),
        Some("aarch64") => Some("arm64"),
        other => other,
    };
    if bytes.len() < 4 {
        return Err(ImageError::Macho(
            "file is too short for a Mach-O magic number".to_string(),
        ));
    }
    let magic_be = u32::from_be_bytes(bytes[0..4].try_into().unwrap_or_default());
    if matches!(magic_be, FAT_MAGIC | 0xbebafeca | 0xcafebabf | 0xbfbafeca) {
        select_fat_macho_slice(bytes, arch)
    } else if magic_be == MH_MAGIC_64 || magic_be == MH_CIGAM_64 {
        let cputype = peek_macho_cputype(bytes, magic_be)?;
        let cpusubtype = peek_macho_cpusubtype(bytes, magic_be)?;
        let name = macho_arch_name(cputype, cpusubtype);
        let supported = SUPPORTED_MACHO_ARCHES.contains(&name);
        if !supported || arch.is_some_and(|requested| requested != name) {
            return Err(ImageError::NoCompatibleMachoSlice {
                requested: arch.unwrap_or("auto").to_string(),
                available: vec![name.to_string()],
            });
        }
        Ok((bytes, name))
    } else {
        Err(ImageError::UnsupportedFormat)
    }
}

/// Universal headers use either fat_arch (32-bit offsets) or fat_arch_64.
fn select_fat_macho_slice<'a>(
    bytes: &'a [u8],
    arch: Option<&str>,
) -> Result<(&'a [u8], &'static str), ImageError> {
    let fail = |message: &str| ImageError::Macho(format!("fat Mach-O: {message}"));
    let magic = bytes.get(..4).ok_or_else(|| fail("truncated header"))?;
    let little = matches!(magic, [0xbe, 0xba, 0xfe, 0xca] | [0xbf, 0xba, 0xfe, 0xca]);
    let wide = matches!(magic, [0xca, 0xfe, 0xba, 0xbf] | [0xbf, 0xba, 0xfe, 0xca]);
    let u32_at = |at: usize| -> Result<u32, ImageError> {
        let raw: [u8; 4] = bytes
            .get(at..at.saturating_add(4))
            .and_then(|raw| raw.try_into().ok())
            .ok_or_else(|| fail("truncated fat_arch"))?;
        Ok(if little {
            u32::from_le_bytes(raw)
        } else {
            u32::from_be_bytes(raw)
        })
    };
    let u64_at = |at: usize| -> Result<u64, ImageError> {
        let raw: [u8; 8] = bytes
            .get(at..at.saturating_add(8))
            .and_then(|raw| raw.try_into().ok())
            .ok_or_else(|| fail("truncated fat_arch_64"))?;
        Ok(if little {
            u64::from_le_bytes(raw)
        } else {
            u64::from_be_bytes(raw)
        })
    };
    let count = u32_at(4)? as usize;
    let stride = if wide { 32 } else { 20 };
    if count > bytes.len().saturating_sub(8) / stride {
        return Err(fail("architecture table is outside file"));
    }
    let mut available = Vec::new();
    let mut selected = None;
    for i in 0..count {
        let at = 8 + i * stride;
        let name = macho_arch_name(u32_at(at)?, u32_at(at + 4)?);
        let offset = if wide {
            u64_at(at + 8)?
        } else {
            u64::from(u32_at(at + 8)?)
        };
        let size = if wide {
            u64_at(at + 16)?
        } else {
            u64::from(u32_at(at + 12)?)
        };
        let end = offset
            .checked_add(size)
            .filter(|end| *end <= bytes.len() as u64)
            .ok_or_else(|| fail("slice is past the end of the file"))?;
        if offset < (8 + count * stride) as u64 {
            return Err(fail("slice overlaps fat header"));
        }
        available.push(name.to_owned());
        if selected.is_none()
            && SUPPORTED_MACHO_ARCHES.contains(&name)
            && arch.is_none_or(|requested| requested == name)
        {
            selected = Some((offset as usize, end as usize, name));
        }
    }
    let Some((start, end, name)) = selected else {
        return Err(ImageError::NoCompatibleMachoSlice {
            requested: arch.unwrap_or("auto").into(),
            available,
        });
    };
    let slice = bytes.get(start..end).ok_or_else(|| fail("invalid slice"))?;
    if !matches!(
        slice.get(..4),
        Some([0xcf, 0xfa, 0xed, 0xfe] | [0xfe, 0xed, 0xfa, 0xcf])
    ) {
        return Err(fail("selected slice is not a thin 64-bit Mach-O"));
    }
    select_macho_slice(slice, Some(name))
}

/// `goblin`'s own `MachO::parse` bounds `ncmds` against the whole
/// buffer (`ncmds > sizeofcmds / 8 || sizeofcmds > bytes.len()`) but does not
/// cross-check that the commands it actually reads stay inside
/// `header_size + sizeofcmds` -- the `bad-ncmds` fixture (declared `ncmds`
/// doubled, `sizeofcmds` unchanged) parses without error under that check
/// alone. This closes the gap: every command must immediately follow the
/// previous one (a nonzero, 4-byte-aligned `cmdsize`, advancing validation),
/// and the last one must end at or before the declared boundary.
fn validate_macho_load_commands(macho: &MachO, slice: &[u8]) -> Result<(), ImageError> {
    let limit = MACHO_HEADER_64_SIZE
        .checked_add(u64::from(macho.header.sizeofcmds))
        .ok_or_else(|| ImageError::Macho("sizeofcmds overflow".to_string()))?;
    let mut expected_offset = MACHO_HEADER_64_SIZE;
    for command in &macho.load_commands {
        let offset = u64::try_from(command.offset).unwrap_or(u64::MAX);
        let size = u64::try_from(command.command.cmdsize()).unwrap_or(u64::MAX);
        if size == 0 {
            return Err(ImageError::Macho(format!(
                "load command at offset {offset:#x} has cmdsize 0"
            )));
        }
        if !size.is_multiple_of(4) {
            return Err(ImageError::Macho(format!(
                "load command at offset {offset:#x} has unaligned cmdsize {size}"
            )));
        }
        if offset != expected_offset {
            return Err(ImageError::Macho(format!(
                "load command at offset {offset:#x} does not immediately follow the previous command (expected {expected_offset:#x})"
            )));
        }
        let end = offset
            .checked_add(size)
            .ok_or_else(|| ImageError::Macho("load command offset+cmdsize overflow".to_string()))?;
        if end > limit {
            return Err(ImageError::Macho(format!(
                "load command at offset {offset:#x} ends at {end:#x}, past the sizeofcmds boundary {limit:#x}"
            )));
        }
        expected_offset = end;
    }
    if usize::try_from(limit).unwrap_or(usize::MAX) > slice.len() {
        return Err(ImageError::Macho(
            "file is shorter than the declared load-command region".to_string(),
        ));
    }
    Ok(())
}

/// Second check: no two `LC_SEGMENT_64`s' `[fileoff, fileoff +
/// filesize)` ranges may overlap (the `overlapping-segments` fixture moves
/// `__DATA_CONST.fileoff` inside `__TEXT`'s range; `goblin` accepts it
/// without complaint).
fn validate_no_overlapping_macho_segments(
    segments: &[(String, u64, u64, u64, u64, u32)],
) -> Result<(), ImageError> {
    for (i, (name_a, _, _, fileoff_a, filesize_a, _)) in segments.iter().enumerate() {
        if *filesize_a == 0 {
            continue;
        }
        let end_a = fileoff_a.checked_add(*filesize_a).ok_or_else(|| {
            ImageError::Macho(format!("segment {name_a} fileoff+filesize overflows"))
        })?;
        for (name_b, _, _, fileoff_b, filesize_b, _) in &segments[i.saturating_add(1)..] {
            if *filesize_b == 0 {
                continue;
            }
            let end_b = fileoff_b.checked_add(*filesize_b).ok_or_else(|| {
                ImageError::Macho(format!("segment {name_b} fileoff+filesize overflows"))
            })?;
            if *fileoff_a < end_b && *fileoff_b < end_a {
                return Err(ImageError::Macho(format!(
                    "segments {name_a} and {name_b} have overlapping file ranges"
                )));
            }
        }
    }
    Ok(())
}

/// Populates `image.import_locations`/`external_bindings` from whichever
/// dyld binding mechanism the slice actually used -- `LC_DYLD_INFO(_ONLY)`
/// classic bind opcodes (which `goblin::mach::MachO::imports()` already
/// decodes) or `LC_DYLD_CHAINED_FIXUPS` (which it does not; see
/// [`parse_macho_chained_fixups`]). A given binary uses exactly one of the
/// two, never both, so trying the classic path first and falling back is
/// enough rather than needing to detect which one up front.
fn load_macho_imports(macho: &MachO, slice: &[u8], image: &mut LoadedImage) {
    if let Ok(imports) = macho.imports() {
        if !imports.is_empty() {
            for import in &imports {
                register_macho_import(image, import.address, import.dylib, import.name);
            }
        }
    }
    for command in &macho.load_commands {
        if let CommandVariant::DyldChainedFixups(linkedit) = command.command {
            match parse_macho_chained_fixups(
                image,
                slice,
                &macho.libs,
                linkedit.dataoff,
                linkedit.datasize,
            ) {
                Ok(fixups) => {
                    for (address, dylib, symbol) in &fixups.binds {
                        register_macho_import(image, *address, dylib, symbol);
                    }
                    for (address, value) in fixups.rebases {
                        if let Some((index, section)) = image
                            .sections
                            .iter()
                            .enumerate()
                            .find(|(_, section)| section.contains_va(address))
                        {
                            let offset =
                                usize::try_from(address - section.address).unwrap_or(usize::MAX);
                            if let Some(target) = image
                                .mapped_bytes
                                .get_mut(index)
                                .and_then(|data| data.get_mut(offset..offset.saturating_add(8)))
                            {
                                target.copy_from_slice(&value.to_le_bytes());
                            }
                        }
                    }
                }
                Err(diagnostic) => image.load_diagnostics.push(diagnostic.to_string()),
            }
        }
    }
}

/// Older linkers describe stubs and lazy/non-lazy pointers through LC_DYSYMTAB.
/// Keep their addresses even when there is no dyld bind stream.
fn load_macho_indirect_symbols(macho: &MachO, slice: &[u8], image: &mut LoadedImage) {
    let Some(symbols) = &macho.symbols else {
        return;
    };
    let Some(table) = macho.load_commands.iter().find_map(|c| match c.command {
        CommandVariant::Dysymtab(table) => Some(table),
        _ => None,
    }) else {
        return;
    };
    let count = macho
        .load_commands
        .iter()
        .find_map(|c| match c.command {
            CommandVariant::Symtab(table) => Some(table.nsyms),
            _ => None,
        })
        .unwrap_or(0);
    for segment in &macho.segments {
        let Ok(sections) = segment.sections() else {
            continue;
        };
        let Some(command) = macho.load_commands.iter().find(|command| matches!(command.command,
            CommandVariant::Segment64(header) if header.vmaddr == segment.vmaddr && header.fileoff == segment.fileoff)) else { continue; };
        for (section_index, (section, _)) in sections.into_iter().enumerate() {
            // goblin's normalized Section omits the reserved fields.
            let at = command
                .offset
                .saturating_add(72)
                .saturating_add(section_index * 80);
            let (Ok(reserved1), Ok(reserved2)) = (
                read_macho_u32(slice, at + 68, "reserved1"),
                read_macho_u32(slice, at + 72, "reserved2"),
            ) else {
                continue;
            };
            let width = match section.flags & 0xff {
                8 if reserved2 != 0 => u64::from(reserved2),
                6 | 7 | 0x10 => 8,
                _ => continue,
            };
            let entries = section.size / width;
            if entries > u64::from(table.nindirectsyms.saturating_sub(reserved1)) {
                image
                    .load_diagnostics
                    .push("Mach-O indirect symbol section exceeds table".into());
                continue;
            }
            for index in 0..entries {
                let at = (table.indirectsymoff as usize)
                    .saturating_add((reserved1 as usize + index as usize).saturating_mul(4));
                let Ok(index) = read_macho_u32(slice, at, "indirect symbol") else {
                    image
                        .load_diagnostics
                        .push("Mach-O indirect symbol table is truncated".into());
                    break;
                };
                if index >= count {
                    continue;
                } // Includes INDIRECT_SYMBOL_LOCAL/ABS.
                let Ok((name, symbol)) = symbols.get(index as usize) else {
                    continue;
                };
                if symbol.is_stab() || symbol.get_type() != goblin::mach::symbols::N_UNDF {
                    continue;
                }
                let ordinal = (symbol.n_desc >> 8) as u8;
                let library = macho_chained_lib_name(
                    &macho.libs,
                    if ordinal > 0xf0 {
                        ordinal as i8 as i32
                    } else {
                        ordinal as i32
                    },
                );
                // Recover the slot number separately from the symbol index.
                let slot_index = (at - table.indirectsymoff as usize) / 4 - reserved1 as usize;
                let Some(address) = section.addr.checked_add(slot_index as u64 * width) else {
                    continue;
                };
                if !image.import_locations.contains_key(&address) {
                    register_macho_import(image, address, &library, name);
                }
            }
        }
    }
}

fn register_macho_import(image: &mut LoadedImage, address: u64, dylib: &str, symbol: &str) {
    let symbol = symbol.strip_prefix('_').unwrap_or(symbol);
    let dylib = macho_dylib_short_name(dylib);
    image.add_external_binding(address, vec![symbol.to_string()]);
    image
        .import_locations
        .insert(address, format!("{dylib}.{symbol}"));
}

/// Basename minus a trailing `.dylib`/`.framework` extension. Mach-O has no
/// upstream capa naming convention to match (this format has no Python
/// oracle at all -- see the module-level honesty-constraint doc); this
/// mirrors this file's PE `norm_file_name` in spirit (basename, extension
/// stripped) without adopting its Windows-specific lowercasing.
fn macho_dylib_short_name(path: &str) -> String {
    let base = path.rsplit('/').next().unwrap_or(path);
    let base = base.strip_suffix(".dylib").unwrap_or(base);
    base.strip_suffix(".framework").unwrap_or(base).to_string()
}

fn macho_chained_lib_name(libs: &[&str], ordinal: i32) -> String {
    match ordinal {
        -1 => "main_executable".into(),
        -2 => "flat_lookup".into(),
        -3 => "weak_lookup".into(),
        n if n >= 0 => libs.get(n as usize).copied().unwrap_or("unknown").into(),
        _ => format!("special_{ordinal}"),
    }
}

fn read_macho_u16(data: &[u8], offset: usize, context: &str) -> Result<u16, ImageError> {
    data.get(offset..offset.saturating_add(2))
        .and_then(|raw| <[u8; 2]>::try_from(raw).ok())
        .map(u16::from_le_bytes)
        .ok_or_else(|| ImageError::Macho(format!("truncated chained-fixups {context}")))
}

fn read_macho_u32(data: &[u8], offset: usize, context: &str) -> Result<u32, ImageError> {
    data.get(offset..offset.saturating_add(4))
        .and_then(|raw| <[u8; 4]>::try_from(raw).ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| ImageError::Macho(format!("truncated chained-fixups {context}")))
}

fn read_macho_u64(data: &[u8], offset: usize, context: &str) -> Result<u64, ImageError> {
    data.get(offset..offset.saturating_add(8))
        .and_then(|raw| <[u8; 8]>::try_from(raw).ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| ImageError::Macho(format!("truncated chained-fixups {context}")))
}

/// Apple mach-o/fixup-chains.h: imports (1/2/3), 64-bit pointers (2/6),
/// and arm64e userland pointers (1/9/12). Resolve rebases in mapped memory so
/// metadata and constant pointers have their runtime values before analysis.
#[derive(Default)]
struct MachoFixups {
    binds: Vec<(u64, String, String)>,
    rebases: Vec<(u64, u64)>,
}

fn parse_macho_chained_fixups(
    image: &LoadedImage,
    slice: &[u8],
    libs: &[&str],
    dataoff: u32,
    datasize: u32,
) -> Result<MachoFixups, ImageError> {
    let fail = |message: &str| ImageError::Macho(format!("chained-fixups {message}"));
    let start = dataoff as usize;
    let data = slice
        .get(start..start.saturating_add(datasize as usize))
        .ok_or_else(|| fail("payload is outside file"))?;
    if read_macho_u32(data, 0, "version")? != 0 {
        return Err(fail("unsupported version"));
    }
    let starts = read_macho_u32(data, 4, "starts_offset")? as usize;
    let imports = read_macho_u32(data, 8, "imports_offset")? as usize;
    let symbols = read_macho_u32(data, 12, "symbols_offset")? as usize;
    let count = read_macho_u32(data, 16, "imports_count")? as usize;
    let format = read_macho_u32(data, 20, "imports_format")?;
    if read_macho_u32(data, 24, "symbols_format")? != 0 {
        return Err(fail("compressed symbols are unsupported"));
    }
    let width = match format {
        1 => 4usize,
        2 => 8,
        3 => 16,
        _ => return Err(fail("unsupported import format")),
    };
    if count > MAX_MACHO_CHAIN_STEPS
        || imports > data.len()
        || count > data.len().saturating_sub(imports) / width
        || symbols > data.len()
    {
        return Err(fail("import table is outside payload"));
    }
    let resolve = |ordinal: usize| -> Result<(String, String), ImageError> {
        if ordinal >= count {
            return Err(fail("bind ordinal is outside import table"));
        }
        let at = imports + ordinal * width;
        let (library, name_offset) = if format == 3 {
            let value = read_macho_u64(data, at, "import64")?;
            let ordinal = (value & 0xffff) as u16;
            (
                if ordinal > 0xfff0 {
                    ordinal as i16 as i32
                } else {
                    ordinal as i32
                },
                (value >> 32) as usize,
            )
        } else {
            let value = read_macho_u32(data, at, "import")?;
            let ordinal = (value & 0xff) as u8;
            (
                if ordinal > 0xf0 {
                    ordinal as i8 as i32
                } else {
                    ordinal as i32
                },
                (value >> 9) as usize,
            )
        };
        let at = symbols
            .checked_add(name_offset)
            .ok_or_else(|| fail("name overflow"))?;
        let name = data
            .get(at..)
            .and_then(|tail| {
                let end = tail.iter().take(4096).position(|b| *b == 0)?;
                std::str::from_utf8(&tail[..end]).ok()
            })
            .ok_or_else(|| fail("unterminated import name"))?;
        Ok((macho_chained_lib_name(libs, library), name.into()))
    };
    let segments = read_macho_u32(data, starts, "segment count")?;
    if segments > MAX_MACHO_FIXUP_SEGMENTS {
        return Err(fail("segment count exceeds limit"));
    }
    let mut result = MachoFixups::default();
    let mut steps = 0;
    for index in 0..segments as usize {
        let offset =
            read_macho_u32(data, starts.saturating_add(4 + index * 4), "segment offset")? as usize;
        if offset == 0 {
            continue;
        }
        let at = starts
            .checked_add(offset)
            .ok_or_else(|| fail("segment offset overflow"))?;
        let size = read_macho_u32(data, at, "segment size")? as usize;
        let segment = data
            .get(at..at.saturating_add(size))
            .ok_or_else(|| fail("segment outside payload"))?;
        let page_size = read_macho_u16(segment, 4, "page size")? as u64;
        let pointer_format = read_macho_u16(segment, 6, "pointer format")?;
        let segment_offset = read_macho_u64(segment, 8, "segment offset")?;
        let pages = read_macho_u16(segment, 20, "page count")? as usize;
        if !matches!(page_size, 4096 | 16384) {
            return Err(fail("invalid page size"));
        }
        if !matches!(pointer_format, 1 | 2 | 6 | 9 | 12) {
            return Err(fail(&format!(
                "unsupported pointer format {pointer_format}"
            )));
        }
        for page in 0..pages {
            let first = read_macho_u16(segment, 22 + page * 2, "page start")?;
            if first == 0xffff {
                continue;
            }
            let mut chain_starts = Vec::new();
            if first & 0x8000 != 0 {
                let mut index = (first & 0x7fff) as usize;
                loop {
                    let value = read_macho_u16(segment, 22 + index * 2, "overflow start")?;
                    chain_starts.push(value & 0x7fff);
                    index += 1;
                    if value & 0x8000 != 0 {
                        break;
                    }
                }
            } else {
                chain_starts.push(first);
            }
            let page_base = image
                .image_base
                .checked_add(segment_offset)
                .and_then(|base| base.checked_add(page as u64 * page_size))
                .ok_or_else(|| fail("page address overflow"))?;
            let page_end = page_base
                .checked_add(page_size)
                .ok_or_else(|| fail("page end overflow"))?;
            for first in chain_starts {
                let mut va = page_base
                    .checked_add(first as u64)
                    .ok_or_else(|| fail("chain address overflow"))?;
                loop {
                    steps += 1;
                    if steps > MAX_MACHO_CHAIN_STEPS {
                        return Err(fail("walk exceeded step limit"));
                    }
                    if va < page_base || va.checked_add(8).is_none_or(|end| end > page_end) {
                        return Err(fail("chain escapes its page"));
                    }
                    let raw = image
                        .bytes_at(va, 8)
                        .and_then(|raw| <[u8; 8]>::try_from(raw).ok())
                        .ok_or_else(|| fail("unmapped chain pointer"))?;
                    let value = u64::from_le_bytes(raw);
                    let arm = matches!(pointer_format, 1 | 9 | 12);
                    let bind = if arm {
                        value >> 62 & 1 != 0
                    } else {
                        value >> 63 != 0
                    };
                    let next = if arm {
                        (value >> 51) & 0x7ff
                    } else {
                        (value >> 51) & 0xfff
                    };
                    if bind {
                        let mask = if arm && pointer_format != 12 {
                            0xffff
                        } else {
                            0xffffff
                        };
                        let (library, name) = resolve((value & mask) as usize)?;
                        result.binds.push((va, library, name));
                    } else {
                        let target = if arm && value >> 63 != 0 {
                            image.image_base.checked_add(value & 0xffffffff)
                        } else {
                            let (low, high) = if arm {
                                (value & ((1 << 43) - 1), ((value >> 43) & 0xff) << 56)
                            } else {
                                (value & ((1 << 36) - 1), ((value >> 36) & 0xff) << 56)
                            };
                            if matches!(pointer_format, 6 | 9 | 12) {
                                image.image_base.checked_add(low | high)
                            } else {
                                Some(low | high)
                            }
                        }
                        .ok_or_else(|| fail("rebase target overflow"))?;
                        result.rebases.push((va, target));
                    }
                    if next == 0 {
                        break;
                    }
                    va = va
                        .checked_add(next * if arm { 8 } else { 4 })
                        .ok_or_else(|| fail("chain address overflow"))?;
                }
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests;

/// `mach_header_64`: magic, cputype, cpusubtype, filetype, ncmds,
/// sizeofcmds, flags, reserved -- eight `u32` fields (`mach-o/loader.h`).
const MACHO_HEADER_64_SIZE: u64 = 32;
/// `dyld_chained_starts_in_image.seg_count` is a `u32`; a real image never
/// has more than a handful of `LC_SEGMENT_64`s, so this is a generous but
/// finite bound against a malformed count driving an unbounded read loop.
const MAX_MACHO_FIXUP_SEGMENTS: u32 = 256;
