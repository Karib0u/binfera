//! PE image loading.
use super::*;

impl LoadedImage {
    pub fn from_pe(bytes: &[u8]) -> Result<Self, ImageError> {
        Self::from_pe_with_imports(bytes, true)
    }

    pub(super) fn from_pe_with_imports(
        bytes: &[u8],
        parse_imports: bool,
    ) -> Result<Self, ImageError> {
        let mut options = ParseOptions::default();
        options.parse_mode = ParseMode::Permissive;
        options.parse_imports = parse_imports;
        options.parse_tls_data = false;
        options.parse_resources = false;
        options.parse_attribute_certificates = false;
        let parsed = tolerate_rich_header(bytes);
        let bytes: &[u8] = &parsed;
        let pe = PE::parse_with_opts(bytes, &options)
            .map_err(|error| ImageError::Pe(error.to_string()))?;

        let architecture = match pe.header.coff_header.machine {
            COFF_MACHINE_X86 => Architecture::X86,
            COFF_MACHINE_X86_64 => Architecture::X64,
            // `IMAGE_FILE_MACHINE_ARM64`. Every mapping/import/
            // export/relocation path below this match is already format-
            // generic (RVA-based, no x86-specific assumption) -- verified
            // against the `tests/fixtures/aarch64-pe/` corpus rather than
            // reimplemented; see `aarch64_pe_features.rs`.
            // `aarch64_pe_features.rs`.
            COFF_MACHINE_ARM64 => Architecture::AArch64,
            0x1c0 | 0x1c2 | 0x1c4 => Architecture::Arm,
            machine => {
                return Err(ImageError::UnsupportedArchitecture {
                    format: ImageFormat::Pe,
                    machine,
                });
            }
        };
        if architecture == Architecture::Arm && pe.is_64 {
            return Err(ImageError::Pe("ARM32 requires PE32, not PE32+".into()));
        }
        let entry_point = if pe.entry == 0 {
            None
        } else {
            Some(pe.image_base.checked_add(u64::from(pe.entry)).ok_or(
                ImageError::AddressOverflow {
                    format: ImageFormat::Pe,
                    context: "entry point",
                },
            )?)
        };

        let optional_header = pe
            .header
            .optional_header
            .as_ref()
            .ok_or_else(|| ImageError::Pe("missing optional header".to_string()))?;
        let section_alignment = u64::from(optional_header.windows_fields.section_alignment);
        if section_alignment == 0 {
            return Err(ImageError::Pe("section alignment is zero".to_string()));
        }
        let file_alignment = u64::from(optional_header.windows_fields.file_alignment);
        let mut sections = Vec::with_capacity(pe.sections.len().saturating_add(1));
        let mut mapped_bytes = Vec::with_capacity(pe.sections.len().saturating_add(1));
        let mut dead_data = Vec::new();
        let mut uninitialized = Vec::new();
        let mut primary_code = Vec::new();
        let mut mapped_total = 0usize;

        // Port of pinned Vivisect 1.3.2 `vivisect/parsers/pe.py:185-216`.
        // SizeOfHeaders is spoofable, so Vivisect maps the bytes through the
        // section table and pads that mapping to SectionAlignment.
        let header_size = u64::from(pe.header.dos_header.pe_pointer)
            .checked_add(PE_SIGNATURE_SIZE)
            .and_then(|value| value.checked_add(PE_COFF_HEADER_SIZE))
            .and_then(|value| {
                value.checked_add(u64::from(pe.header.coff_header.size_of_optional_header))
            })
            .and_then(|value| {
                value.checked_add(
                    u64::from(pe.header.coff_header.number_of_sections)
                        .checked_mul(PE_SECTION_HEADER_SIZE)?,
                )
            })
            .ok_or(ImageError::AddressOverflow {
                format: ImageFormat::Pe,
                context: "header mapping",
            })?;
        let header_file_size = header_size.min(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if header_file_size != header_size {
            return Err(ImageError::Pe("truncated PE header".to_string()));
        }
        let header_map_size =
            align_up(header_size, section_alignment).ok_or(ImageError::AddressOverflow {
                format: ImageFormat::Pe,
                context: "aligned header mapping",
            })?;
        let mut header =
            mapped_region(bytes, 0, header_file_size, header_map_size, ImageFormat::Pe)?;
        account_mapping(&mut mapped_total, header.len())?;
        sections.push(MappedSection {
            name: "PE_Header".to_string(),
            address: pe.image_base,
            virtual_size: header_map_size,
            file_offset: 0,
            file_size: header_file_size,
            permissions: Permissions {
                read: true,
                write: false,
                execute: false,
            },
        });
        mapped_bytes.push(std::mem::take(&mut header));

        let entry_rva = u64::from(pe.entry);
        let code_start = optional_header.standard_fields.base_of_code;
        let code_end = code_start.saturating_add(optional_header.standard_fields.size_of_code);
        let dead_directory_rvas: Vec<u32> = optional_header
            .data_directories
            .data_directories
            .iter()
            .filter_map(Option::as_ref)
            .map(|(_, directory)| directory.virtual_address)
            .filter(|rva| *rva != 0)
            .collect();

        for (index, section) in pe.sections.iter().enumerate() {
            // `vivisect/parsers/pe.py` strips only leading/trailing NULs.
            // Embedded NULs are part of the workspace segment name.
            let name = String::from_utf8_lossy(&section.name)
                .trim_matches('\0')
                .to_string();
            let address = pe
                .image_base
                .checked_add(u64::from(section.virtual_address))
                .ok_or(ImageError::AddressOverflow {
                    format: ImageFormat::Pe,
                    context: "section address",
                })?;
            let characteristics = section.characteristics;
            // capa loads through viv_utils.getWorkspace, which sets
            // viv.parsers.pe.loadresources = True. Resource-directory
            // sections are mapped too; their normal permissions decide
            // whether code flow can enter them.

            let section_rva = u64::from(section.virtual_address);
            let declared_virtual_size = u64::from(section.virtual_size);
            let declared_raw_size = u64::from(section.size_of_raw_data);
            let file_offset = u64::from(section.pointer_to_raw_data);
            let (virtual_size, read_size, align_mapping) = if declared_virtual_size == 0
                || declared_raw_size == 0
            {
                let Some(next) = pe.sections.get(index.saturating_add(1)) else {
                    continue;
                };
                let gap = u64::from(next.virtual_address)
                    .checked_sub(section_rva)
                    .ok_or_else(|| {
                        ImageError::Pe(format!("section {name} ends after the following section"))
                    })?;
                (gap, 0, false)
            } else {
                // `pe.py:337-354` reads min(RawSize, VirtualSize), pads to
                // VirtualSize, then addMemoryMap pads to FileAlignment.
                if declared_raw_size < declared_virtual_size
                    && declared_raw_size > u64::try_from(bytes.len()).unwrap_or(u64::MAX)
                {
                    continue;
                }
                (
                    declared_virtual_size,
                    declared_raw_size.min(declared_virtual_size),
                    true,
                )
            };
            let map_size = if align_mapping && file_alignment != 0 {
                align_up(virtual_size, file_alignment).ok_or(ImageError::AddressOverflow {
                    format: ImageFormat::Pe,
                    context: "aligned section mapping",
                })?
            } else {
                virtual_size
            };
            if map_size == 0 {
                continue;
            }
            let available = u64::try_from(bytes.len())
                .unwrap_or(u64::MAX)
                .saturating_sub(file_offset);
            let file_size = read_size.min(available);
            let data = mapped_region(bytes, file_offset, file_size, map_size, ImageFormat::Pe)?;
            account_mapping(&mut mapped_total, data.len())?;

            let mut primary = characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE) != 0;
            if section_rva >= code_start && section_rva < code_end {
                primary = true;
            }
            if section_rva <= entry_rva
                && entry_rva < section_rva.saturating_add(declared_virtual_size)
            {
                primary = true;
            }
            // `vivisect/parsers/pe.py:278` and `:309-311` grant execute to any
            // readable section of a pre-Vista non-NX image -- but both are
            // guarded by `not vw.config.viv.parsers.pe.nx`, and the pinned
            // reference sets `nx = True` (`viv_utils/__init__.py:102`), so
            // neither ever fires. Verified against the pinned workspace:
            // `Practical Malware Analysis Lab 03-02.dll_` is a pre-Vista
            // non-NX image whose `.data` map is `MM_READ|MM_WRITE`, with no
            // `MM_EXEC`. Execute therefore comes only from the flags, the
            // BaseOfCode range, and the entry-point section.
            let execute = primary;
            let read = characteristics & IMAGE_SCN_MEM_READ != 0;
            sections.push(MappedSection {
                name,
                address,
                virtual_size: map_size,
                file_offset,
                file_size,
                permissions: Permissions {
                    read,
                    write: characteristics & IMAGE_SCN_MEM_WRITE != 0,
                    execute,
                },
            });
            mapped_bytes.push(data);

            let raw_map_end = address.saturating_add(virtual_size);
            if dead_directory_rvas.contains(&section.virtual_address)
                || characteristics
                    & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE)
                    == 0
            {
                dead_data.push((address, raw_map_end));
            }
            if characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
                uninitialized.push((address, address.saturating_add(map_size)));
            }
            if primary {
                primary_code.push((address, address.saturating_add(map_size)));
            }
        }

        let mut image = Self {
            format: ImageFormat::Pe,
            architecture,
            image_base: pe.image_base,
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
            dead_data,
            pe_exception_directory: None,
            code_exclusions: Vec::new(),
            function_ranges: Vec::new(),
            uninitialized,
            primary_code,
            mapped_bytes,
        };
        image.pe_exception_directory = pe
            .header
            .optional_header
            .as_ref()
            .and_then(|header| header.data_directories.get_exception_table())
            .and_then(|directory| {
                Some((
                    pe.image_base
                        .checked_add(u64::from(directory.virtual_address))?,
                    directory.size,
                ))
            });
        mark_embedded_pe_data(bytes, &pe, &mut image);
        collect_pe_relocation_locations(&pe, &mut image);

        let mut terminated_import_ranges = Vec::new();
        for data in pe.import_data.iter().flat_map(|data| &data.import_data) {
            let directory = &data.import_directory_entry;
            if directory.import_lookup_table_rva == 0 {
                continue;
            }
            // PE.parseImportTable uses OriginalFirstThunk whenever nonzero,
            // including RVAs in the headers. Goblin can fall back to the IAT
            // when its section-only RVA lookup misses that table. Do not
            // manufacture API bindings beyond the declared table's terminator.
            let lookup = image
                .image_base
                .checked_add(u64::from(directory.import_lookup_table_rva))
                .ok_or(ImageError::AddressOverflow {
                    format: ImageFormat::Pe,
                    context: "import lookup table",
                })?;
            let width = image.architecture.pointer_width();
            let count = data.import_lookup_table.as_ref().map_or(0, Vec::len);
            for index in 0..count {
                let slot = lookup.saturating_add(index.saturating_mul(width) as u64);
                if image.bytes_at(slot, width).is_some_and(|bytes| {
                    bytes.len() == width && bytes.iter().all(|byte| *byte == 0)
                }) {
                    let iat = u64::from(directory.import_address_table_rva);
                    terminated_import_ranges.push(
                        iat.saturating_add(index.saturating_mul(width) as u64)
                            ..iat.saturating_add(count.saturating_mul(width) as u64),
                    );
                    image.load_diagnostics.push(format!(
                        "import lookup table for {} terminates at {slot:#x}; ignoring fallback IAT bindings",
                        data.name
                    ));
                    break;
                }
            }
        }
        for import in &pe.imports {
            if terminated_import_ranges
                .iter()
                .any(|range| range.contains(&(import.offset as u64)))
            {
                continue;
            }
            let address = pe
                .image_base
                .checked_add(u64::try_from(import.offset).map_err(|_| {
                    ImageError::AddressOverflow {
                        format: ImageFormat::Pe,
                        context: "IAT address",
                    }
                })?)
                .ok_or(ImageError::AddressOverflow {
                    format: ImageFormat::Pe,
                    context: "IAT address",
                })?;
            let symbol = import.name.strip_prefix("ORDINAL ").map_or_else(
                || import.name.to_string(),
                |ordinal| {
                    ordinal
                        .parse::<u16>()
                        .ok()
                        .and_then(|ordinal| resolve_pe_ordinal(import.dll, ordinal))
                        .map_or_else(|| format!("#{ordinal}"), str::to_string)
                },
            );
            // `viv/insn.py:extract_insn_api_features` calls
            // `generate_symbols(dll, symbol)` (`include_dll` defaults
            // `False`) for the insn-scope `api:` feature -- unlike
            // `pefile.py`'s *file*-scope `Import` feature, which passes
            // `include_dll=True`. `external_bindings` only ever feeds the
            // former (`insn_features.rs::push_api_names`); the file-scope
            // Import feature is built independently in this file's own
            // `extract_file_import_names`, so this doesn't affect it.
            image.add_external_binding(address, generate_symbols(import.dll, &symbol, false));
            image
                .import_locations
                .insert(address, import_location_name(import.dll, &symbol));
        }
        if parse_imports {
            image.load_pe_delay_imports(&pe)?;
        } else {
            image.imports_skipped = true;
        }

        if architecture == Architecture::Arm {
            let thumb = pe.header.coff_header.machine != 0x1c0
                || image.entry_point.is_some_and(|v| v & 1 != 0);
            for section in &image.sections {
                image.arm_context.insert(section.address, u8::from(thumb));
            }
            image.entry_point = image.entry_point.map(|v| v & !1);
            for export in &pe.exports {
                let address = image.image_base + export.rva as u64;
                if address & 1 != 0 {
                    image.set_thumb(address, true);
                }
            }
        }
        Ok(image)
    }
}

/// `PE/carve.py` and `vivisect/parsers/pe.py:parseFile` mark embedded
/// plaintext or single-byte-XOR PE files as dead data for pointer analysis.
/// This does not prevent explicit code flow into those mappings.
fn mark_embedded_pe_data(bytes: &[u8], pe: &PE<'_>, image: &mut LoadedImage) {
    // Local scan/candidate limits, not upstream constants.
    const MAX_CARVED_HEADERS: usize = 1024;
    let scan = bytes
        .get(..bytes.len().min(MAX_MAPPED_IMAGE_BYTES))
        .unwrap_or_default();
    let mut candidates = 0;
    for (offset, pair) in scan.windows(2).enumerate().skip(1) {
        let Some((&first, rest)) = pair.split_first() else {
            continue;
        };
        let key = first ^ b'M';
        if rest.first().copied().map(|byte| byte ^ key) != Some(b'Z') {
            continue;
        }
        let Some(candidate) = bytes.get(offset..) else {
            continue;
        };
        let Some(nt) = xor_number(candidate, 0x3c, 4, key).map(|value| value as usize) else {
            continue;
        };
        // `PE/carve.py:MAX_OFFSET_PE_AFTER_MZ`.
        if nt > 0x200 || xor_number(candidate, nt, 2, key) != Some(0x4550) {
            continue;
        }
        candidates += 1;
        if candidates > MAX_CARVED_HEADERS {
            image
                .load_diagnostics
                .push("embedded PE scan exceeded 1024 candidate headers".into());
            break;
        }
        let Some(size) = carved_pe_size(candidate, nt, key) else {
            image.load_diagnostics.push(format!(
                "invalid embedded PE header at file offset {offset:#x}"
            ));
            continue;
        };
        // `PE.offsetToRva` returns zero for an overlay. Preserve that loader
        // behavior, including its image-base dead-data range for such files.
        let alignment = pe.header.optional_header.as_ref().map_or(1, |header| {
            u64::from(header.windows_fields.section_alignment).max(1)
        });
        let max_rva = pe
            .sections
            .iter()
            .map(|section| {
                let end = u64::from(section.virtual_address) + u64::from(section.virtual_size);
                (end / alignment + 1) * alignment
            })
            .max()
            .unwrap_or(0);
        let rva = pe
            .sections
            .iter()
            .find_map(|section| {
                let raw = u64::from(section.pointer_to_raw_data);
                let span = if raw + u64::from(section.size_of_raw_data) > max_rva {
                    section.virtual_size
                } else {
                    section.virtual_size.max(section.size_of_raw_data)
                };
                let relative = (offset as u64).checked_sub(raw)?;
                (relative < u64::from(span)).then(|| relative + u64::from(section.virtual_address))
            })
            .unwrap_or(0);
        if let Some(start) = image.image_base.checked_add(rva) {
            if let Some(end) = start.checked_add(size.min(candidate.len() as u64)) {
                image.dead_data.push((start, end));
            }
        }
    }
    if bytes.len() > scan.len() {
        image.load_diagnostics.push(format!(
            "embedded PE scan stopped at {MAX_MAPPED_IMAGE_BYTES} bytes"
        ));
    }
}

fn xor_number(bytes: &[u8], offset: usize, size: usize, key: u8) -> Option<u64> {
    let raw = bytes.get(offset..offset.checked_add(size)?)?;
    Some(raw.iter().enumerate().fold(0, |value, (index, byte)| {
        value | (u64::from(byte ^ key) << (8 * index))
    }))
}

#[allow(clippy::chunks_exact_to_as_chunks)] // Keep the Rust 1.87 MSRV.
pub(super) fn carved_pe_size(bytes: &[u8], nt: usize, key: u8) -> Option<u64> {
    // PE structure offsets used by `PE.PE.parseSections`. That parser locates
    // sections using NumberOfRvaAndSizes rather than SizeOfOptionalHeader.
    let sections = usize::try_from(xor_number(bytes, nt.checked_add(6)?, 2, key)?).ok()?;
    let optional = nt.checked_add(24)?;
    let standard = match xor_number(bytes, optional, 2, key)? {
        0x10b => 96usize,
        0x20b => 112usize,
        _ => return None,
    };
    let directories = usize::try_from(xor_number(
        bytes,
        optional.checked_add(standard - 4)?,
        4,
        key,
    )?)
    .ok()?;
    let table = optional
        .checked_add(standard)?
        .checked_add(directories.checked_mul(8)?)?;
    let raw = bytes.get(table..table.checked_add(sections.checked_mul(40)?)?)?;
    let mut size = 0;
    for section in raw.chunks_exact(40) {
        let offset = xor_number(section, 20, 4, key)?;
        let len = xor_number(section, 16, 4, key)?;
        size = size.max(offset.checked_add(len)?);
    }
    (sections != 0).then_some(size)
}

fn collect_pe_relocation_locations(pe: &PE<'_>, image: &mut LoadedImage) {
    let Some(relocations) = &pe.relocation_data else {
        return;
    };
    for block in relocations.blocks() {
        let block = match block {
            Ok(block) => block,
            Err(error) => {
                image
                    .load_diagnostics
                    .push(format!("stopped parsing malformed PE relocations: {error}"));
                break;
            }
        };
        for word in block.words() {
            let word = match word {
                Ok(word) => word,
                Err(error) => {
                    image.load_diagnostics.push(format!(
                        "stopped parsing malformed PE relocation block at RVA {:#x}: {error}",
                        block.rva
                    ));
                    break;
                }
            };
            if word.reloc_type() == 0 {
                continue;
            }
            if let Some(location) = image
                .image_base
                .checked_add(u64::from(block.rva))
                .and_then(|address| address.checked_add(u64::from(word.offset())))
            {
                image.relocation_locations.push(location);
            }
        }
    }
    image.relocation_locations.sort_unstable();
    image.relocation_locations.dedup();
}

/// Resolve the ordinal-only imports that the pinned Vivisect backend names
/// from its *own* vendored ordinal database (`PE/ordlookup/`, the `PE`
/// package vivisect ships), not from pefile's. The two disagree: pefile
/// keeps a separate, newer `wsock32` table where ordinal 10 is `inet_addr`,
/// while `PE/ordlookup/__init__.py` maps `wsock32.dll` at the same
/// `ws2_32.ord_names` table, making ordinal 10 `ioctlsocket`. capa's viv
/// backend reads `vw.getImports()`, so vivisect's table is the reference.
/// Unknown ordinals keep their original `#N` form, as capa does for ordinal
/// imports it cannot name.
///
/// The socket and automation tables are transcribed. `PE/ordlookup` also ships
/// `mfc42`, `oledlg`, `msvbvm60` and `comctl32`; no corpus
/// sample has needed them yet, and each is a large table best added when a
/// measurement asks for it.
pub(super) fn resolve_pe_ordinal(dll: &str, ordinal: u16) -> Option<&'static str> {
    let dll = dll
        .get(..dll.len().saturating_sub(4))
        .filter(|_| dll.to_ascii_lowercase().ends_with(".dll"))
        .unwrap_or(dll);
    if dll.eq_ignore_ascii_case("oleaut32") {
        return super::super::oleaut32_ordinals::lookup(ordinal);
    }
    // `PE/ordlookup/__init__.py`: `'ws2_32.dll'` and `'wsock32.dll'` both
    // resolve against `ws2_32.ord_names`.
    if dll.eq_ignore_ascii_case("ws2_32") || dll.eq_ignore_ascii_case("wsock32") {
        return match ordinal {
            1 => Some("accept"),
            2 => Some("bind"),
            3 => Some("closesocket"),
            4 => Some("connect"),
            5 => Some("getpeername"),
            6 => Some("getsockname"),
            7 => Some("getsockopt"),
            8 => Some("htonl"),
            9 => Some("htons"),
            10 => Some("ioctlsocket"),
            11 => Some("inet_addr"),
            12 => Some("inet_ntoa"),
            13 => Some("listen"),
            14 => Some("ntohl"),
            15 => Some("ntohs"),
            16 => Some("recv"),
            17 => Some("recvfrom"),
            18 => Some("select"),
            19 => Some("send"),
            20 => Some("sendto"),
            21 => Some("setsockopt"),
            22 => Some("shutdown"),
            23 => Some("socket"),
            24 => Some("GetAddrInfoW"),
            25 => Some("GetNameInfoW"),
            26 => Some("WSApSetPostRoutine"),
            27 => Some("FreeAddrInfoW"),
            28 => Some("WPUCompleteOverlappedRequest"),
            29 => Some("WSAAccept"),
            30 => Some("WSAAddressToStringA"),
            31 => Some("WSAAddressToStringW"),
            32 => Some("WSACloseEvent"),
            33 => Some("WSAConnect"),
            34 => Some("WSACreateEvent"),
            35 => Some("WSADuplicateSocketA"),
            36 => Some("WSADuplicateSocketW"),
            37 => Some("WSAEnumNameSpaceProvidersA"),
            38 => Some("WSAEnumNameSpaceProvidersW"),
            39 => Some("WSAEnumNetworkEvents"),
            40 => Some("WSAEnumProtocolsA"),
            41 => Some("WSAEnumProtocolsW"),
            42 => Some("WSAEventSelect"),
            43 => Some("WSAGetOverlappedResult"),
            44 => Some("WSAGetQOSByName"),
            45 => Some("WSAGetServiceClassInfoA"),
            46 => Some("WSAGetServiceClassInfoW"),
            47 => Some("WSAGetServiceClassNameByClassIdA"),
            48 => Some("WSAGetServiceClassNameByClassIdW"),
            49 => Some("WSAHtonl"),
            50 => Some("WSAHtons"),
            51 => Some("gethostbyaddr"),
            52 => Some("gethostbyname"),
            53 => Some("getprotobyname"),
            54 => Some("getprotobynumber"),
            55 => Some("getservbyname"),
            56 => Some("getservbyport"),
            57 => Some("gethostname"),
            58 => Some("WSAInstallServiceClassA"),
            59 => Some("WSAInstallServiceClassW"),
            60 => Some("WSAIoctl"),
            61 => Some("WSAJoinLeaf"),
            62 => Some("WSALookupServiceBeginA"),
            63 => Some("WSALookupServiceBeginW"),
            64 => Some("WSALookupServiceEnd"),
            65 => Some("WSALookupServiceNextA"),
            66 => Some("WSALookupServiceNextW"),
            67 => Some("WSANSPIoctl"),
            68 => Some("WSANtohl"),
            69 => Some("WSANtohs"),
            70 => Some("WSAProviderConfigChange"),
            71 => Some("WSARecv"),
            72 => Some("WSARecvDisconnect"),
            73 => Some("WSARecvFrom"),
            74 => Some("WSARemoveServiceClass"),
            75 => Some("WSAResetEvent"),
            76 => Some("WSASend"),
            77 => Some("WSASendDisconnect"),
            78 => Some("WSASendTo"),
            79 => Some("WSASetEvent"),
            80 => Some("WSASetServiceA"),
            81 => Some("WSASetServiceW"),
            82 => Some("WSASocketA"),
            83 => Some("WSASocketW"),
            84 => Some("WSAStringToAddressA"),
            85 => Some("WSAStringToAddressW"),
            86 => Some("WSAWaitForMultipleEvents"),
            87 => Some("WSCDeinstallProvider"),
            88 => Some("WSCEnableNSProvider"),
            89 => Some("WSCEnumProtocols"),
            90 => Some("WSCGetProviderPath"),
            91 => Some("WSCInstallNameSpace"),
            92 => Some("WSCInstallProvider"),
            93 => Some("WSCUnInstallNameSpace"),
            94 => Some("WSCUpdateProvider"),
            95 => Some("WSCWriteNameSpaceOrder"),
            96 => Some("WSCWriteProviderOrder"),
            97 => Some("freeaddrinfo"),
            98 => Some("getaddrinfo"),
            99 => Some("getnameinfo"),
            101 => Some("WSAAsyncSelect"),
            102 => Some("WSAAsyncGetHostByAddr"),
            103 => Some("WSAAsyncGetHostByName"),
            104 => Some("WSAAsyncGetProtoByNumber"),
            105 => Some("WSAAsyncGetProtoByName"),
            106 => Some("WSAAsyncGetServByPort"),
            107 => Some("WSAAsyncGetServByName"),
            108 => Some("WSACancelAsyncRequest"),
            109 => Some("WSASetBlockingHook"),
            110 => Some("WSAUnhookBlockingHook"),
            111 => Some("WSAGetLastError"),
            112 => Some("WSASetLastError"),
            113 => Some("WSACancelBlockingCall"),
            114 => Some("WSAIsBlocking"),
            115 => Some("WSAStartup"),
            116 => Some("WSACleanup"),
            151 => Some("__WSAFDIsSet"),
            500 => Some("WEP"),
            _ => None,
        };
    }
    None
}

/// Port of `VivWorkspace.normFileName` (`vivisect/__init__.py:2958-2977`):
/// take the basename, lowercase it, drop the last dot-separated component and
/// join the rest with `_`, then replace every character outside
/// `[A-Za-z0-9_]` with `_`.
fn norm_file_name(filename: &str) -> String {
    // `os.path.basename` on the reference (POSIX) platform splits on `/` only.
    let base = filename
        .rsplit('/')
        .next()
        .unwrap_or(filename)
        .to_lowercase();
    let stem = match base.rfind('.') {
        Some(index) => base[..index].replace('.', "_"),
        None => base,
    };
    stem.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// The `tinfo` string `VivWorkspace.makeImport` records for a PE import
/// (`vivisect/__init__.py:919-927`), which is what the no-return API lists in
/// `vivisect/parsers/pe.py` are matched against.
fn import_location_name(dll: &str, symbol: &str) -> String {
    format!("{}.{symbol}", norm_file_name(dll))
}

impl LoadedImage {
    fn load_pe_delay_imports(&mut self, pe: &PE<'_>) -> Result<(), ImageError> {
        let Some(optional_header) = pe.header.optional_header.as_ref() else {
            return Ok(());
        };
        let Some(directory) = optional_header
            .data_directories
            .get_delay_import_descriptor()
        else {
            return Ok(());
        };
        if directory.virtual_address == 0 || directory.size == 0 {
            return Ok(());
        }

        let descriptor_count = usize::try_from(directory.size)
            .unwrap_or(usize::MAX)
            .checked_div(DELAY_DESCRIPTOR_SIZE)
            .unwrap_or(0);
        if usize::try_from(directory.size).unwrap_or(usize::MAX) % DELAY_DESCRIPTOR_SIZE != 0 {
            // pefile's permissive parser processes every complete descriptor
            // and records a warning for the trailing bytes. Do the same so a
            // malformed optional directory cannot suppress analysis of the
            // rest of an otherwise loadable PE.
            self.load_diagnostics.push(format!(
                "delay import directory at RVA {:#x} has size {}, which is not a multiple of {DELAY_DESCRIPTOR_SIZE}; ignoring trailing bytes",
                directory.virtual_address, directory.size
            ));
        }
        if descriptor_count > MAX_DELAY_DESCRIPTORS {
            return Err(ImageError::DelayImport {
                rva: u64::from(directory.virtual_address),
                context: format!(
                    "descriptor count {descriptor_count} exceeds limit {MAX_DELAY_DESCRIPTORS}"
                ),
            });
        }
        for index in 0..descriptor_count {
            let descriptor_rva = u64::from(directory.virtual_address)
                .checked_add(
                    u64::try_from(index)
                        .ok()
                        .and_then(|value| value.checked_mul(DELAY_DESCRIPTOR_SIZE as u64))
                        .ok_or(ImageError::AddressOverflow {
                            format: ImageFormat::Pe,
                            context: "delay import descriptor",
                        })?,
                )
                .ok_or(ImageError::AddressOverflow {
                    format: ImageFormat::Pe,
                    context: "delay import descriptor",
                })?;
            let raw = self.read_array_at_rva::<32>(descriptor_rva)?;
            if raw.iter().all(|byte| *byte == 0) {
                break;
            }
            let attrs = read_u32_field(&raw, 0, descriptor_rva)?;
            let uses_rvas = attrs & 1 != 0;
            let name_rva =
                self.delay_field_to_rva(read_u32_field(&raw, 4, descriptor_rva)?, uses_rvas)?;
            let iat_rva =
                self.delay_field_to_rva(read_u32_field(&raw, 12, descriptor_rva)?, uses_rvas)?;
            let int_rva =
                self.delay_field_to_rva(read_u32_field(&raw, 16, descriptor_rva)?, uses_rvas)?;
            if name_rva == 0 || iat_rva == 0 || int_rva == 0 {
                return Err(ImageError::DelayImport {
                    rva: descriptor_rva,
                    context: "descriptor has a zero name, IAT, or INT address".to_string(),
                });
            }
            let dll = self.read_ascii_cstr_at_rva(name_rva)?.to_string();
            let pointer_size = if self.architecture == Architecture::X64 {
                8
            } else {
                4
            };

            let mut terminated = false;
            for import_index in 0..MAX_DELAY_IMPORTS {
                let relative = u64::try_from(import_index)
                    .ok()
                    .and_then(|value| value.checked_mul(pointer_size))
                    .ok_or(ImageError::AddressOverflow {
                        format: ImageFormat::Pe,
                        context: "delay import thunk",
                    })?;
                let thunk_rva =
                    int_rva
                        .checked_add(relative)
                        .ok_or(ImageError::AddressOverflow {
                            format: ImageFormat::Pe,
                            context: "delay import thunk",
                        })?;
                let value = self.read_pointer_at_rva(thunk_rva)?;
                if value == 0 {
                    terminated = true;
                    break;
                }
                let ordinal_mask = if pointer_size == 8 {
                    1u64 << 63
                } else {
                    1u64 << 31
                };
                let symbol = if value & ordinal_mask != 0 {
                    // Same ordinal database the main import table is named
                    // from: vivisect's PE parser resolves delay-load ordinals
                    // through `PE/ordlookup` exactly as it does bound ones, so
                    // a delay-imported `ws2_32` ordinal 6 is `getsockname`
                    // upstream, not `#6`. Naming only the main table left
                    // every `api:` feature behind a delay-loaded ordinal
                    // import unresolvable.
                    let ordinal = u16::try_from(value & 0xffff).unwrap_or(u16::MAX);
                    resolve_pe_ordinal(&dll, ordinal)
                        .map_or_else(|| format!("#{ordinal}"), str::to_string)
                } else {
                    let hint_name_rva = self.delay_field_to_rva(value, uses_rvas)?;
                    self.read_ascii_cstr_at_rva(hint_name_rva.checked_add(2).ok_or(
                        ImageError::AddressOverflow {
                            format: ImageFormat::Pe,
                            context: "delay import hint/name",
                        },
                    )?)?
                    .to_string()
                };
                let binding_rva =
                    iat_rva
                        .checked_add(relative)
                        .ok_or(ImageError::AddressOverflow {
                            format: ImageFormat::Pe,
                            context: "delay IAT binding",
                        })?;
                let address = self.image_base.checked_add(binding_rva).ok_or(
                    ImageError::AddressOverflow {
                        format: ImageFormat::Pe,
                        context: "delay IAT binding",
                    },
                )?;
                // see the main-import binding site above: `include_dll:
                // false` matches `viv/insn.py`'s insn-scope `api:` feature,
                // not the file-scope `Import` feature.
                self.add_external_binding(address, generate_symbols(&dll, &symbol, false));
                self.import_locations
                    .insert(address, import_location_name(&dll, &symbol));
            }
            if !terminated {
                return Err(ImageError::DelayImport {
                    rva: int_rva,
                    context: format!(
                        "import thunk count exceeds limit {MAX_DELAY_IMPORTS} without a terminator"
                    ),
                });
            }
        }
        Ok(())
    }

    fn delay_field_to_rva(&self, value: u64, uses_rvas: bool) -> Result<u64, ImageError> {
        if uses_rvas {
            Ok(value)
        } else {
            value
                .checked_sub(self.image_base)
                .ok_or_else(|| ImageError::DelayImport {
                    rva: value,
                    context: "VA lies below the image base".to_string(),
                })
        }
    }

    fn read_pointer_at_rva(&self, rva: u64) -> Result<u64, ImageError> {
        if self.architecture == Architecture::X64 {
            Ok(u64::from_le_bytes(self.read_array_at_rva::<8>(rva)?))
        } else {
            Ok(u64::from(u32::from_le_bytes(
                self.read_array_at_rva::<4>(rva)?,
            )))
        }
    }

    fn read_array_at_rva<const N: usize>(&self, rva: u64) -> Result<[u8; N], ImageError> {
        let address = self
            .image_base
            .checked_add(rva)
            .ok_or(ImageError::AddressOverflow {
                format: ImageFormat::Pe,
                context: "RVA read",
            })?;
        let bytes = self
            .bytes_at(address, N)
            .ok_or_else(|| ImageError::DelayImport {
                rva,
                context: format!("cannot read {N} mapped bytes"),
            })?;
        bytes.try_into().map_err(|_| ImageError::DelayImport {
            rva,
            context: format!("expected {N} bytes, found {}", bytes.len()),
        })
    }

    fn read_ascii_cstr_at_rva(&self, rva: u64) -> Result<&str, ImageError> {
        let address = self
            .image_base
            .checked_add(rva)
            .ok_or(ImageError::AddressOverflow {
                format: ImageFormat::Pe,
                context: "string RVA",
            })?;
        let section = self
            .section_containing(address)
            .ok_or(ImageError::DelayImport {
                rva,
                context: "string is outside mapped sections".to_string(),
            })?;
        let relative = address
            .checked_sub(section.address)
            .ok_or(ImageError::AddressOverflow {
                format: ImageFormat::Pe,
                context: "string section offset",
            })?;
        let remaining =
            usize::try_from(section.file_size.saturating_sub(relative)).unwrap_or(usize::MAX);
        let bytes = self
            .bytes_at(address, remaining)
            .ok_or(ImageError::DelayImport {
                rva,
                context: "string is not file-backed".to_string(),
            })?;
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(ImageError::DelayImport {
                rva,
                context: "unterminated string".to_string(),
            })?;
        let value = std::str::from_utf8(bytes.get(..end).ok_or(ImageError::DelayImport {
            rva,
            context: "invalid string range".to_string(),
        })?)
        .map_err(|error| ImageError::DelayImport {
            rva,
            context: format!("non-UTF-8 string: {error}"),
        })?;
        if !value.is_ascii() {
            return Err(ImageError::DelayImport {
                rva,
                context: "non-ASCII string".to_string(),
            });
        }
        Ok(value)
    }
}

fn read_u32_field(raw: &[u8; 32], offset: usize, rva: u64) -> Result<u64, ImageError> {
    let end = offset.checked_add(4).ok_or(ImageError::DelayImport {
        rva,
        context: "descriptor field offset overflow".to_string(),
    })?;
    let bytes = raw.get(offset..end).ok_or(ImageError::DelayImport {
        rva,
        context: "descriptor field is truncated".to_string(),
    })?;
    Ok(u64::from(u32::from_le_bytes(bytes.try_into().map_err(
        |_| ImageError::DelayImport {
            rva,
            context: "descriptor field has the wrong width".to_string(),
        },
    )?)))
}

const DELAY_DESCRIPTOR_SIZE: usize = 32;

const MAX_DELAY_DESCRIPTORS: usize = 4_096;

const MAX_DELAY_IMPORTS: usize = 65_536;

const PE_SECTION_HEADER_SIZE: u64 = 40;

const PE_COFF_HEADER_SIZE: u64 = 20;

const PE_SIGNATURE_SIZE: u64 = 4;

/// goblin refuses a whole PE, even in permissive mode, when the DOS stub holds a `Rich`
/// marker whose `DanS` start does not decode. The loader never reads the stub, so such a
/// file is parsed from a copy with that marker cleared, which goblin reads as no Rich header.
pub(crate) fn tolerate_rich_header(bytes: &[u8]) -> Cow<'_, [u8]> {
    const RICH: &[u8] = b"Rich";
    if goblin::pe::header::RichHeader::parse(bytes).is_ok() || bytes.len() < 0x40 {
        return Cow::Borrowed(bytes);
    }
    let lfanew = u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    // goblin scans from the end of the DOS header plus four bytes up to the PE header.
    let Some(stub) = bytes.get(0x44..lfanew.min(bytes.len())) else {
        return Cow::Borrowed(bytes);
    };
    let Some(marker) = stub.windows(RICH.len()).position(|window| window == RICH) else {
        return Cow::Borrowed(bytes);
    };
    let mut copy = bytes.to_vec();
    copy[0x44 + marker..0x44 + marker + RICH.len()].fill(0);
    Cow::Owned(copy)
}

/// A flat Go memory dump can retain its original on-disk section offsets.
/// Require SizeOfImage and an independently located build-ID function whose
/// pclntab entry equals its virtual file offset. Normal PE files do not match.
pub(super) fn normalize_go_memory_pe(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() > MAX_MAPPED_IMAGE_BYTES {
        return None;
    }
    let u32_at = |at: usize| -> Option<u32> {
        Some(u32::from_le_bytes(
            bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
        ))
    };
    let nt = u32_at(0x3c)? as usize;
    let optional = nt.checked_add(24)?;
    let image_size = usize::try_from(u32_at(optional.checked_add(56)?)?).ok()?;
    let alignment = usize::try_from(u32_at(optional.checked_add(32)?)?).ok()?;
    if image_size == 0 || bytes.len() < image_size || bytes.len() - image_size > alignment {
        return None;
    }
    let marker = b"\xff Go build ID: ";
    let build_id = bytes
        .windows(marker.len())
        .position(|part| part == marker)?;
    let mut options = ParseOptions::default();
    options.parse_mode = ParseMode::Permissive;
    options.parse_imports = false;
    options.parse_tls_data = false;
    options.parse_resources = false;
    options.parse_attribute_certificates = false;
    let pe = PE::parse_with_opts(bytes, &options).ok()?;
    if !pe.sections.iter().any(|section| {
        section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
            && section.pointer_to_raw_data != section.virtual_address
            && u64::from(section.virtual_address) <= build_id as u64
            && (build_id as u64)
                < u64::from(section.virtual_address) + u64::from(section.virtual_size)
    }) {
        return None;
    }
    let pointer = if pe.is_64 { 8 } else { 4 };
    let word = |at: usize| -> Option<u64> {
        let raw = bytes.get(at..at.checked_add(pointer)?)?;
        Some(if pointer == 8 {
            u64::from_le_bytes(raw.try_into().ok()?)
        } else {
            u64::from(u32::from_le_bytes(raw.try_into().ok()?))
        })
    };
    let entry = pe.image_base.checked_add(build_id as u64)?;
    // Go 1.2 through 1.15 use absolute entries. The first function is the
    // build ID for ordinary Go executables; external-linker layouts stay alone.
    let confirmed = bytes.windows(8).enumerate().any(|(at, header)| {
        let check = || -> Option<()> {
            if header != [0xfb, 0xff, 0xff, 0xff, 0, 0, 1, pointer as u8] {
                return None;
            }
            let count = usize::try_from(word(at.checked_add(8)?)?).ok()?;
            if count == 0 || count > 2_000_000 {
                return None;
            }
            let table = at.checked_add(8 + pointer)?;
            bytes
                .get(table..table.checked_add(count.checked_add(1)?.checked_mul(2 * pointer)?)?)?;
            if word(table)? != entry {
                return None;
            }
            let record = at.checked_add(usize::try_from(word(table + pointer)?).ok()?)?;
            if word(record)? != entry {
                return None;
            }
            let name = at.checked_add(u32_at(record.checked_add(pointer)?)? as usize)?;
            let raw = bytes.get(name..name.checked_add(11)?)?;
            (raw == b"go.buildid\0" || raw == b"go:buildid\0").then_some(())
        };
        check().is_some()
    });
    if !confirmed {
        return None;
    }
    let section_table =
        optional.checked_add(usize::from(pe.header.coff_header.size_of_optional_header))?;
    let mut normalized = bytes.to_vec();
    for (index, section) in pe.sections.iter().enumerate() {
        let end = u64::from(section.virtual_address) + u64::from(section.virtual_size);
        if end > bytes.len() as u64 {
            return None;
        }
        let header = section_table.checked_add(index.checked_mul(40)?)?;
        normalized
            .get_mut(header + 16..header + 20)?
            .copy_from_slice(&section.virtual_size.to_le_bytes());
        normalized
            .get_mut(header + 20..header + 24)?
            .copy_from_slice(&section.virtual_address.to_le_bytes());
    }
    Some(normalized)
}

#[cfg(test)]
mod go_memory_pe_tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut bytes = vec![0; 0x3000];
        bytes[..2].copy_from_slice(b"MZ");
        let put = |bytes: &mut [u8], at: usize, value: u32| {
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        };
        put(&mut bytes, 0x3c, 0x80);
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        bytes[0x96..0x98].copy_from_slice(&0x22u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        put(&mut bytes, 0x98 + 16, 0x1020);
        bytes[0xb0..0xb8].copy_from_slice(&0x400000u64.to_le_bytes());
        for (offset, value) in [
            (32, 0x1000),
            (36, 0x200),
            (56, 0x3000),
            (60, 0x200),
            (108, 16),
        ] {
            put(&mut bytes, 0x98 + offset, value);
        }
        for (at, name, virtual_address, size, raw, flags) in [
            (0x188, b".text\0\0\0", 0x1000, 0x200, 0x200, 0x60000020),
            (0x1b0, b".rdata\0\0", 0x2000, 0x400, 0x400, 0x40000040),
        ] {
            bytes[at..at + 8].copy_from_slice(name);
            for (offset, value) in [
                (8, size),
                (12, virtual_address),
                (16, size),
                (20, raw),
                (36, flags),
            ] {
                put(&mut bytes, at + offset, value);
            }
        }
        bytes[0x1000..0x100f].copy_from_slice(b"\xff Go build ID: ");
        bytes[0x1020] = 0xc3;
        bytes[0x2000..0x2008].copy_from_slice(&[0xfb, 0xff, 0xff, 0xff, 0, 0, 1, 8]);
        for (offset, value) in [
            (8, 1u64),
            (16, 0x401000),
            (24, 0x80),
            (32, 0x401030),
            (0x80, 0x401000),
        ] {
            bytes[0x2000 + offset..0x2008 + offset].copy_from_slice(&value.to_le_bytes());
        }
        put(&mut bytes, 0x2088, 0xc0);
        bytes[0x20c0..0x20cb].copy_from_slice(b"go.buildid\0");
        bytes
    }

    #[test]
    fn flat_go_memory_image_uses_virtual_offsets() -> anyhow::Result<()> {
        for padding in [0, 0x1000] {
            let mut bytes = fixture();
            bytes.resize(bytes.len() + padding, 0);
            let strict = LoadedImage::from_pe(&bytes)?;
            assert_ne!(
                strict.bytes_at(0x401000, 15),
                Some(b"\xff Go build ID: ".as_slice())
            );
            let image = LoadedImage::parse_partial(&bytes)?;
            assert_eq!(
                image.bytes_at(0x401000, 15),
                Some(b"\xff Go build ID: ".as_slice())
            );
            assert_eq!(image.bytes_at(0x401020, 1), Some([0xc3].as_slice()));
            assert!(image
                .load_diagnostics
                .iter()
                .any(|d| d.contains("Go memory image")));
        }
        Ok(())
    }

    #[test]
    fn raw_files_and_unconfirmed_memory_layouts_are_unchanged() {
        let mut raw = fixture();
        let code = raw[0x1000..0x1200].to_vec();
        raw[0x200..0x400].copy_from_slice(&code);
        raw[0x1000..0x1200].fill(0);
        assert!(normalize_go_memory_pe(&raw).is_none());
        let mut mismatched = fixture();
        mismatched[0x2010..0x2018].copy_from_slice(&0x401010u64.to_le_bytes());
        assert!(normalize_go_memory_pe(&mismatched).is_none());
        let mut truncated = fixture();
        truncated.truncate(0x2000);
        assert!(normalize_go_memory_pe(&truncated).is_none());
    }
}
