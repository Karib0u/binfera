//! Container metadata and fallback function entry seeds.
use super::*;

pub(super) type SeedMap = BTreeMap<u64, BTreeSet<SeedKind>>;
pub(super) type FunctionSymbolMap = BTreeMap<u64, Vec<String>>;

pub(super) fn collect_seeds(
    bytes: &[u8],
    image: &LoadedImage,
    backend: RecoveryBackend,
) -> Result<(SeedMap, FunctionSymbolMap, Vec<RecoveryDiagnostic>), RecoveryError> {
    let mut seeds = BTreeMap::new();
    let mut elf_function_symbols = BTreeMap::new();
    let mut diagnostics = image
        .load_diagnostics
        .iter()
        .map(|message| RecoveryDiagnostic {
            address: image.image_base,
            message: message.clone(),
        })
        .collect();
    if let Some(entry) = image.entry_point {
        add_seed(image, &mut seeds, entry, SeedKind::EntryPoint);
    }
    match image.format {
        ImageFormat::Pe => collect_pe_seeds(
            bytes,
            image,
            backend,
            &mut seeds,
            &mut elf_function_symbols,
            &mut diagnostics,
        )?,
        ImageFormat::Elf => {
            collect_elf_seeds(bytes, image, backend, &mut seeds, &mut elf_function_symbols)?;
            if backend == RecoveryBackend::Native {
                super::super::eh_frame::collect(bytes, image, &mut seeds, &mut diagnostics);
            }
        }
        // no exports/TLS/relocations/symbol tables to seed from -- see
        // `analyze_shellcode`'s doc comment.
        ImageFormat::Sc => {}
        ImageFormat::Macho => {
            collect_macho_seeds(bytes, image, &mut seeds, &mut elf_function_symbols)?;
            let metadata = crate::extract::loader::macho_metadata::read(bytes, image);
            for (address, name) in metadata.functions {
                add_seed(image, &mut seeds, address, SeedKind::Symbol);
                elf_function_symbols.entry(address).or_default().push(name);
            }
            diagnostics.extend(metadata.diagnostics.into_iter().map(|message| {
                RecoveryDiagnostic {
                    address: image.image_base,
                    message,
                }
            }));
        }
    }
    Ok((seeds, elf_function_symbols, diagnostics))
}

/// `LC_FUNCTION_STARTS` (a high-quality, linker-emitted seed table), exported
/// symbols (via the export trie), and `LC_SYMTAB`'s
/// `N_SECT` symbols landing in an executable mapping. `function_symbols`
/// (named `elf_function_symbols` on [`Analysis`] for historical reasons --
/// it now also carries Mach-O's `LC_SYMTAB` names, the same "address to
/// function-name feature" role `capa.features.extractors.elf.SymTab` plays
/// for ELF) feeds `function_features.rs`'s `FunctionName` feature exactly as
/// it does for ELF.
pub(super) fn collect_macho_seeds(
    bytes: &[u8],
    image: &LoadedImage,
    seeds: &mut SeedMap,
    function_symbols: &mut FunctionSymbolMap,
) -> Result<(), RecoveryError> {
    let (slice, _resolved_arch) =
        super::super::image::select_macho_slice(bytes, None).map_err(|error| {
            RecoveryError::Seeds {
                format: ImageFormat::Macho,
                context: error.to_string(),
            }
        })?;
    let macho = MachO::parse(slice, 0).map_err(|error| RecoveryError::Seeds {
        format: ImageFormat::Macho,
        context: error.to_string(),
    })?;

    // Flat section list (address, size), independent of segment/n_sect
    // numbering -- needed below to reject `__mh_execute_header`, which
    // every Mach-O executable's `LC_SYMTAB` *and* export trie both carry:
    // an `Extern`/`N_SECT` symbol whose value is the image's load address
    // (`__TEXT`'s `vmaddr`), which sits in the Mach header and load
    // commands, *not* inside any actual section's range -- a standard
    // linker convention, not a malformed input. The AArch64 decoder has
    // no invalid-encoding fallback the way x86 does (fixed-width, dense
    // opcode space -- almost any 4 bytes decode to *something*), so seeding
    // a function there let recovery fall/branch out of the header and load
    // commands and directly into real code, manufacturing a second,
    // overlapping "function" over legitimate instructions and a spurious
    // duplicate rule match (found empirically in the AArch64 Mach-O fixture
    // acceptance, `thin-arm64-exe`, recovered a 9-block function at the
    // image base that duplicated `_main`'s own `api: malloc` match). Every
    // legitimate function/data symbol and export *does* fall inside a real
    // section, so this check costs nothing for them.
    let mut macho_sections: Vec<(u64, u64)> = Vec::new();
    for segment in &macho.segments {
        if let Ok(sections) = segment.sections() {
            for (section, _data) in sections {
                macho_sections.push((section.addr, section.size));
            }
        }
    }
    let in_a_macho_section = |address: u64| {
        macho_sections
            .iter()
            .any(|(addr, size)| address >= *addr && address < addr.saturating_add(*size))
    };

    if let Ok(exports) = macho.exports() {
        for export in &exports {
            if let Some(address) = image.image_base.checked_add(export.offset) {
                if in_a_macho_section(address) {
                    add_seed(image, seeds, address, SeedKind::Export);
                    if image.is_executable_address(address) {
                        function_symbols.entry(address).or_default().push(
                            export
                                .name
                                .strip_prefix('_')
                                .unwrap_or(&export.name)
                                .to_owned(),
                        );
                    }
                }
            }
        }
    }

    for (name, nlist) in macho.symbols().flatten() {
        if nlist.is_stab() || nlist.get_type() != goblin::mach::symbols::N_SECT {
            continue;
        }
        if in_a_macho_section(nlist.n_value) {
            add_seed(image, seeds, nlist.n_value, SeedKind::Symbol);
        }
        // Strip the Mach-O C-symbol convention's leading `_`, matching
        // `image.rs::register_macho_import`'s import/export names -- a
        // rule author writing `function-name: add` should not have to know
        // this format prefixes every C symbol with an underscore. The name
        // is still recorded even when the symbol falls outside every
        // section, so a function independently recovered at this address
        // (e.g. the entry point) can still carry whatever name the symbol
        // table offers.
        let name = name.strip_prefix('_').unwrap_or(name);
        if name.is_empty() {
            continue;
        }
        let names = function_symbols.entry(nlist.n_value).or_default();
        if !names.iter().any(|existing| existing == name) {
            names.push(name.to_string());
        }
    }

    for command in &macho.load_commands {
        if let CommandVariant::FunctionStarts(linkedit) = command.command {
            collect_macho_function_starts(
                slice,
                image.image_base,
                linkedit.dataoff,
                linkedit.datasize,
                image,
                seeds,
            );
        }
    }
    Ok(())
}

/// `LC_FUNCTION_STARTS`' payload is a sequence of ULEB128-encoded deltas,
/// cumulative from `__TEXT`'s load address (`image_base`), terminated by a
/// `0x00` byte or the end of the declared region -- `mach-o/loader.h`'s
/// `linkedit_data_command` payload for this command.
pub(super) fn collect_macho_function_starts(
    slice: &[u8],
    image_base: u64,
    dataoff: u32,
    datasize: u32,
    image: &LoadedImage,
    seeds: &mut SeedMap,
) {
    let base = usize::try_from(dataoff).unwrap_or(usize::MAX);
    let size = usize::try_from(datasize).unwrap_or(usize::MAX);
    let Some(data) = base.checked_add(size).and_then(|end| slice.get(base..end)) else {
        return;
    };
    let mut address = image_base;
    let mut offset = 0usize;
    'table: while offset < data.len() {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            let Some(&byte) = data.get(offset) else {
                return;
            };
            offset += 1;
            result |= u64::from(byte & 0x7f).checked_shl(shift).unwrap_or(0);
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift >= 64 {
                return;
            }
        }
        if result == 0 {
            // A zero delta only ever appears as the table's own terminator
            // (alignment padding after the real entries).
            break 'table;
        }
        address = address.saturating_add(result);
        add_seed(image, seeds, address, SeedKind::MachoFunctionStarts);
    }
}

// The fixed-size chunk iterators intentionally leave malformed trailing bytes out.
pub(super) fn collect_pe_seeds(
    bytes: &[u8],
    image: &LoadedImage,
    backend: RecoveryBackend,
    seeds: &mut BTreeMap<u64, BTreeSet<SeedKind>>,
    function_symbols: &mut FunctionSymbolMap,
    diagnostics: &mut Vec<RecoveryDiagnostic>,
) -> Result<(), RecoveryError> {
    let mut options = ParseOptions::default();
    options.parse_mode = ParseMode::Permissive;
    options.parse_resources = false;
    options.parse_attribute_certificates = false;
    options.parse_tls_data = true;
    options.parse_imports = !image.imports_skipped;
    let parsed = crate::extract::loader::image::tolerate_rich_header(bytes);
    let bytes: &[u8] = &parsed;
    let pe = PE::parse_with_opts(bytes, &options).map_err(|error| RecoveryError::Seeds {
        format: ImageFormat::Pe,
        context: error.to_string(),
    })?;
    // Vivisect does not consume this table. Keep its feature/recovery contract unchanged.
    if backend == RecoveryBackend::Native {
        match crate::extract::loader::coff::function_symbols(bytes, &pe, image) {
            Ok(symbols) => {
                for address in symbols.keys() {
                    add_seed(image, seeds, *address, SeedKind::Symbol);
                }
                function_symbols.extend(symbols);
            }
            Err(message) => diagnostics.push(RecoveryDiagnostic {
                address: image.image_base,
                message: format!("malformed PE COFF symbol table: {message}"),
            }),
        }
    }
    for export in &pe.exports {
        // vivisect/parsers/pe.py records forwarded exports as strings. Their
        // RVA names another DLL's symbol, so it is not a function entry.
        if export.reexport.is_some() {
            continue;
        }
        if let Some(address) = image.image_base.checked_add(export.rva as u64) {
            add_seed(image, seeds, address, SeedKind::Export);
        }
    }
    if let Some(tls) = &pe.tls_data {
        for callback in &tls.callbacks {
            add_seed(image, seeds, *callback, SeedKind::TlsCallback);
        }
    }
    if let Some(load_config) = &pe.load_config_data {
        if let (Some(table), Some(count)) = (
            load_config.directory.se_handler_table,
            load_config.directory.se_handler_count,
        ) {
            collect_safe_seh_seeds(bytes.len(), image, table, count, seeds, diagnostics);
        }
    }
    if let Some(directory) = pe
        .header
        .optional_header
        .as_ref()
        .and_then(|header| header.data_directories.get_exception_table())
    {
        // Parse this optional directory directly (rather than through
        // goblin 0.10.7's `ExceptionData::functions()`, which slices with
        // unchecked PE-provided bounds and can panic on malformed input).
        // AMD64 and ARM64 both call this the "exception table"/`.pdata`,
        // but its entry layout is architecture-specific -- `RUNTIME_FUNCTION`
        // (12 bytes: three RVAs) for AMD64, `IMAGE_ARM64_RUNTIME_FUNCTION_
        // ENTRY` (8 bytes: `BeginAddress` + `UnwindData`) for ARM64 --
        // so which loop below runs is gated on `image.architecture`, not
        // format alone.
        let directory_address = image
            .image_base
            .saturating_add(u64::from(directory.virtual_address));
        let requested = usize::try_from(directory.size).unwrap_or(usize::MAX);
        let raw = image.bytes_at(directory_address, requested).unwrap_or(&[]);
        if image.architecture == Architecture::X64 {
            if raw.len() != requested || !raw.len().is_multiple_of(12) {
                diagnostics.push(RecoveryDiagnostic {
                    address: directory_address,
                    message: format!(
                        "malformed x64 exception directory: declared {} bytes, {} file-backed bytes",
                        directory.size,
                        raw.len()
                    ),
                });
            }
            // Port of vivisect/parsers/pe.py's `.pdata` walk (pe.py:513-548): seed
            // a function per AMD64 RUNTIME_FUNCTION *entry*, but skip function
            // *blocks* -- chained fragments (`UNW_FLAG_CHAININFO`) whose
            // BeginAddress is interior to the parent function. Vivisect only calls
            // `addEntryPoint()` on non-chained entries; seeding the chained ones
            // (as this code previously did) manufactures a spurious function start
            // inside every real function that has multiple unwind fragments, which
            // then truncates the real function at that address. Vivisect also
            // *bails on the whole directory* (`break`) the moment an entry's
            // UNWIND_INFO pointer is unmapped or its version is not 1, so replicate
            // that rather than skipping the single entry.
            // UNW_FLAG_CHAININFO = 0x4 (PE/__init__.py:162); the VerFlags version
            // (`& 0x7`) / flags (`>> 3`) split and break semantics are pe.py:529-548.
            const UNW_FLAG_CHAININFO: u8 = 0x4;
            // Vivisect gives up on the whole directory at the first entry it
            // cannot read. Native recovery keeps going: every non-chained
            // `BeginAddress` is a function start whatever its neighbours hold.
            let bail = backend == RecoveryBackend::VivisectCompat;
            for entry in raw.as_chunks::<12>().0 {
                let (Some(begin), Some(unwind_info_rva)) = (
                    entry
                        .get(..4)
                        .and_then(|value| <[u8; 4]>::try_from(value).ok())
                        .map(u32::from_le_bytes),
                    entry
                        .get(8..12)
                        .and_then(|value| <[u8; 4]>::try_from(value).ok())
                        .map(u32::from_le_bytes),
                ) else {
                    continue;
                };
                let ver_flags = image
                    .image_base
                    .checked_add(u64::from(unwind_info_rva))
                    .and_then(|unwind_info_va| image.bytes_at(unwind_info_va, 1))
                    .and_then(|bytes| bytes.first().copied());
                // vivisect: `if not vw.isValidPointer(baseaddr + UnwindInfoAddress): break`
                let Some(ver_flags) = ver_flags else {
                    if bail {
                        break;
                    }
                    if let Some(address) = image.image_base.checked_add(u64::from(begin)) {
                        add_seed(image, seeds, address, SeedKind::Unwind);
                    }
                    continue;
                };
                if bail && ver_flags & 0x7 != 1 {
                    // Unwind Info Version != 1 -> vivisect bails on the whole `.pdata`.
                    break;
                }
                if ver_flags >> 3 & UNW_FLAG_CHAININFO != 0 {
                    // A function *block*, not a function *entry* -> not a start.
                    continue;
                }
                if let Some(address) = image.image_base.checked_add(u64::from(begin)) {
                    add_seed(image, seeds, address, SeedKind::Unwind);
                }
            }
        } else if image.architecture == Architecture::AArch64 {
            if raw.len() != requested || !raw.len().is_multiple_of(8) {
                diagnostics.push(RecoveryDiagnostic {
                    address: directory_address,
                    message: format!(
                        "malformed arm64 exception directory: declared {} bytes, {} file-backed bytes",
                        directory.size,
                        raw.len()
                    ),
                });
            }
            // `IMAGE_ARM64_RUNTIME_FUNCTION_ENTRY` (winnt.h): `BeginAddress`
            // (RVA, u32) then `UnwindData` (u32 -- either packed unwind info
            // or, when its low 2 bits are 0, an RVA into `.xdata`). Unlike
            // AMD64, the ARM64 Windows ABI has no function-fragment/chaining
            // concept (every entry stands for exactly one whole function --
            // Microsoft's ARM64 exception-handling docs), so this needs
            // none of the AMD64 branch's `UNW_FLAG_CHAININFO`/version-bail
            // logic: every entry's `BeginAddress` is an authoritative
            // function start, full stop.
            for entry in raw.as_chunks::<8>().0 {
                let Some(begin) = entry
                    .get(..4)
                    .and_then(|value| <[u8; 4]>::try_from(value).ok())
                    .map(u32::from_le_bytes)
                else {
                    continue;
                };
                if let Some(address) = image.image_base.checked_add(u64::from(begin)) {
                    add_seed(image, seeds, address, SeedKind::Unwind);
                }
            }
        }
    }
    // Targets remain candidates until pointer classification has the current
    // location map. The loader also retains the source slots as typed data.
    for &location in &image.relocation_locations {
        if backend == RecoveryBackend::Native && location > 0 {
            if let Ok(push) = image.decode_at(location - 1) {
                if super::super::idioms::delphi_handler(image, &push)
                    || super::super::idioms::delphi_finally(image, &push).is_some()
                {
                    continue;
                }
            }
        }
        if let Some(target) = read_pointer(image, location) {
            add_seed(image, seeds, target, SeedKind::Relocation);
        }
    }
    Ok(())
}

pub(super) fn collect_safe_seh_seeds(
    file_size: usize,
    image: &LoadedImage,
    table: u64,
    count: u64,
    seeds: &mut SeedMap,
    diagnostics: &mut Vec<RecoveryDiagnostic>,
) {
    if table == 0 || count == 0 {
        return;
    }
    // Faithful port of pinned Vivisect 1.3.2
    // `vivisect/parsers/pe.py:465-485`. Its sanity check is strictly
    // `SEHandlerCount * 4 < pe.filesize`, even though the subsequent `P`
    // format uses the workspace pointer width.
    let Some(sanity_size) = count.checked_mul(4) else {
        return;
    };
    if sanity_size >= u64::try_from(file_size).unwrap_or(u64::MAX)
        || image.bytes_at(table, 1).is_none()
    {
        return;
    }
    // SafeSEH is a 32/64-bit PE/x86 Windows exception-handling mechanism;
    // AArch64 PE uses `.pdata`/exception-directory unwind info
    // instead, so this table never applies there.
    let pointer_width = match image.architecture {
        Architecture::X86 => 4usize,
        Architecture::X64 => 8usize,
        _ => return,
    };
    let Some(byte_len) = usize::try_from(count)
        .ok()
        .and_then(|value| value.checked_mul(pointer_width))
    else {
        diagnostics.push(RecoveryDiagnostic {
            address: table,
            message: "SafeSEH table byte length overflows the host size".to_string(),
        });
        return;
    };
    let Some(raw) = image.bytes_at(table, byte_len) else {
        diagnostics.push(RecoveryDiagnostic {
            address: table,
            message: "SafeSEH table is not mapped".to_string(),
        });
        return;
    };
    if raw.len() != byte_len {
        diagnostics.push(RecoveryDiagnostic {
            address: table,
            message: format!(
                "SafeSEH table is truncated: expected {byte_len} bytes, found {}",
                raw.len()
            ),
        });
        return;
    }
    for entry in raw.chunks_exact(pointer_width) {
        let handler_rva = if pointer_width == 8 {
            let Some(value) = entry.get(..8).and_then(|value| value.try_into().ok()) else {
                return;
            };
            u64::from_le_bytes(value)
        } else {
            let Some(value) = entry.get(..4).and_then(|value| value.try_into().ok()) else {
                return;
            };
            u64::from(u32::from_le_bytes(value))
        };
        if let Some(handler) = image.image_base.checked_add(handler_rva) {
            add_seed(image, seeds, handler, SeedKind::SafeSeh);
        }
    }
}

pub(super) fn plausible_relocation_function(image: &LoadedImage, address: u64) -> bool {
    // `generic.pointers` rejects free-hanging pointer targets marked by the
    // PE loader as dead data. Applying the same guard prevents legacy
    // relocation compensation from turning zero-filled `.rdata` into code.
    if image.is_dead_data(address) || !image.is_primary_code_address(address) {
        return false;
    }
    let Ok(first) = image.decode_at(address) else {
        return false;
    };
    if first.x86_instruction().mnemonic() == Mnemonic::Push {
        if first.x86_instruction().op0_kind() == OpKind::Register {
            return true;
        }
        // Pinned Vivisect 1.3.2's `analysis/i386/__init__.py` registers
        // `push imm8; push imm32; call rel32` as an i386 function-entry
        // signature for Microsoft's SEH setup sequence. Its relocation
        // analysis follows pointers to matching executable locations.
        return image.architecture == Architecture::X86
            && image
                .bytes_at(address, 8)
                .is_some_and(matches_x86_seh_entry_signature);
    }
    matches!(
        first.x86_instruction().mnemonic(),
        Mnemonic::Mov
            | Mnemonic::Sub
            | Mnemonic::Xor
            | Mnemonic::Jmp
            | Mnemonic::Lea
            | Mnemonic::Cmp
            | Mnemonic::Test
            | Mnemonic::Call
            | Mnemonic::Endbr32
            | Mnemonic::Endbr64
    )
}

pub(super) fn plausible_sweep_function(image: &LoadedImage, address: u64) -> bool {
    image.decode_at(address).is_ok_and(|first| {
        first.x86_instruction().mnemonic() == Mnemonic::Push
            || plausible_relocation_function(image, address)
    })
}

pub(super) fn collect_elf_seeds(
    bytes: &[u8],
    image: &LoadedImage,
    backend: RecoveryBackend,
    seeds: &mut BTreeMap<u64, BTreeSet<SeedKind>>,
    function_symbols: &mut BTreeMap<u64, Vec<String>>,
) -> Result<(), RecoveryError> {
    let elf = Elf::parse(bytes).map_err(|error| RecoveryError::Seeds {
        format: ImageFormat::Elf,
        context: error.to_string(),
    })?;
    if elf.header.e_type == goblin::elf::header::ET_REL {
        for symbol in elf
            .syms
            .iter()
            .filter(|s| matches!(st_type(s.st_info), STT_FUNC | STT_GNU_IFUNC))
        {
            if let Some(address) =
                crate::extract::loader::elf_rel::symbol_address(&elf, image, symbol)
            {
                let address = if image.architecture == Architecture::Arm {
                    address & !1
                } else {
                    address
                };
                add_seed(image, seeds, address, SeedKind::Symbol);
                if let Some(name) = elf.strtab.get_at(symbol.st_name).filter(|n| !n.is_empty()) {
                    function_symbols
                        .entry(address)
                        .or_default()
                        .push(name.to_owned());
                }
            }
        }
        // Kernel tracing records point at each instrumented function's first call.
        for section in image.sections.iter().filter(|s| s.name == "__mcount_loc") {
            let width = image.architecture.pointer_width() as u64;
            for offset in (0..section.virtual_size.min(1 << 20)).step_by(width as usize) {
                if let Some(address) = read_pointer(image, section.address + offset) {
                    add_seed(image, seeds, address, SeedKind::Symbol);
                }
            }
        }
        return Ok(());
    }
    collect_function_symbols(image, elf.syms.iter(), &elf.strtab, seeds, function_symbols);
    collect_function_symbols(
        image,
        elf.dynsyms.iter(),
        &elf.dynstrtab,
        seeds,
        function_symbols,
    );
    // `generic.emucode.analyze` also tries named undefined addresses. A
    // non-function symbol is a candidate, never an authoritative function.
    if matches!(image.architecture, Architecture::X86 | Architecture::X64) {
        for symbol in elf.syms.iter().chain(elf.dynsyms.iter()) {
            if symbol.st_shndx != 0
                && symbol.st_value != 0
                && symbol.st_name != 0
                && !matches!(st_type(symbol.st_info), STT_FUNC | STT_GNU_IFUNC)
            {
                if let Some(address) = symbol.st_value.checked_add(image.load_bias) {
                    add_seed(image, seeds, address, SeedKind::Emulated);
                }
            }
        }
    }
    for relocation in elf
        .dynrelas
        .iter()
        .chain(elf.dynrels.iter())
        .chain(elf.pltrelocs.iter())
    {
        let location = relocation.r_offset.saturating_add(image.load_bias);
        // Only the *unnamed* relocation branch of `vivisect/parsers/elf.py`
        // dereferences the slot (`R_386_RELATIVE`, elf.py:865-869: "ptr =
        // vw.readMemoryPtr(rlva)"). A *named* `JMP_SLOT`/`GLOB_DAT` becomes an
        // import instead (elf.py:842-845), and upstream guards the paths that
        // do read the slot with `isPLT`, whose comment is exactly this case:
        // "some toolchains like to point the GOT back at it's PLT entry".
        // Dereferencing it here seeds a function at `plt_entry + 6`, the middle
        // of the stub, instead of at the stub.
        if image.import_locations.contains_key(&location) {
            continue;
        }
        // A `0` slot means the relocation hasn't been applied to the raw file
        // bytes at all (an `R_AARCH64_RELATIVE`/`R_X86_64_RELATIVE` target
        // with no static addend baked into the slot itself, common for a
        // PIE's data/GOT entries this loader never runtime-relocates -- see
        // `run_aarch64_plt_wave`'s doc comment on the same non-relocation).
        // Rebasing a bare `0` by `load_bias` produces `load_bias` itself,
        // i.e. the image base -- almost always mapped and executable, so
        // `add_seed` would otherwise happily accept it as a real function
        // start and the CFG walk would then fall/branch through however much
        // of the image is reachable from address zero. Skip it rather than
        // rebase a value that was never a real pointer to begin with.
        if let Some(target) = read_pointer(image, location).filter(|&target| target != 0) {
            let target = if image.load_bias != 0 && !is_executable(image, target) {
                target.saturating_add(image.load_bias)
            } else {
                target
            };
            add_seed(image, seeds, target, SeedKind::Relocation);
        }
        // vivisect/parsers/elf.py:loadElfRelocs reads the stored pointer
        // for R_386_RELATIVE / R_X86_64_RELATIVE (both type 8). It does
        // not substitute the RELA addend, even when the slot is zero.
        if backend == RecoveryBackend::VivisectCompat
            && matches!(image.architecture, Architecture::X86 | Architecture::X64)
            && relocation.r_type == goblin::elf::reloc::R_X86_64_RELATIVE
        {
            continue;
        }
        if let Some(addend) = relocation
            .r_addend
            .and_then(|value| u64::try_from(value).ok())
        {
            let target = addend.saturating_add(image.load_bias);
            add_seed(image, seeds, target, SeedKind::Relocation);
        }
    }
    if let Some(main) = libc_start_main::main_address(image) {
        add_seed(image, seeds, main, SeedKind::LibcMain);
    }
    // `vivisect/parsers/elf.py:447-463` walks the *section* table as well as
    // the dynamic table: `.init`/`.fini` become functions by name, and
    // `.init_array`/`.fini_array` go through `makeFunctionTable`, which makes
    // a function of every pointer in the array. A statically linked ELF has no
    // `PT_DYNAMIC` at all, so the `DT_INIT_ARRAY` path below never fires for
    // one and these constructors are reachable only from the section headers.
    // `2f7f5fb5…elf_` is exactly that: ET_EXEC, no `.dynamic`, and a
    // 0x138-byte `.init_array` whose entries the reference names
    // `init_function_N`.
    for shdr in &elf.section_headers {
        let Some(name) = elf.shdr_strtab.get_at(shdr.sh_name) else {
            continue;
        };
        let address = shdr.sh_addr.saturating_add(image.load_bias);
        match name {
            ".init" => add_seed(image, seeds, address, SeedKind::Init),
            ".fini" => add_seed(image, seeds, address, SeedKind::Fini),
            ".init_array" => add_pointer_array_seeds(
                image,
                seeds,
                Some(address),
                shdr.sh_size,
                SeedKind::InitArray,
            )?,
            ".fini_array" => add_pointer_array_seeds(
                image,
                seeds,
                Some(address),
                shdr.sh_size,
                SeedKind::FiniArray,
            )?,
            _ => {}
        }
    }
    if let Some(dynamic) = &elf.dynamic {
        let mut init_array = None;
        let mut init_array_size = 0u64;
        let mut fini_array = None;
        let mut fini_array_size = 0u64;
        for entry in &dynamic.dyns {
            match entry.d_tag {
                DT_INIT => add_seed(
                    image,
                    seeds,
                    entry.d_val.saturating_add(image.load_bias),
                    SeedKind::Init,
                ),
                DT_FINI => add_seed(
                    image,
                    seeds,
                    entry.d_val.saturating_add(image.load_bias),
                    SeedKind::Fini,
                ),
                DT_INIT_ARRAY => init_array = Some(entry.d_val.saturating_add(image.load_bias)),
                DT_INIT_ARRAYSZ => init_array_size = entry.d_val,
                DT_FINI_ARRAY => fini_array = Some(entry.d_val.saturating_add(image.load_bias)),
                DT_FINI_ARRAYSZ => fini_array_size = entry.d_val,
                _ => {}
            }
        }
        add_pointer_array_seeds(
            image,
            seeds,
            init_array,
            init_array_size,
            SeedKind::InitArray,
        )?;
        add_pointer_array_seeds(
            image,
            seeds,
            fini_array,
            fini_array_size,
            SeedKind::FiniArray,
        )?;
    }
    Ok(())
}

pub(super) fn add_pointer_array_seeds(
    image: &LoadedImage,
    seeds: &mut BTreeMap<u64, BTreeSet<SeedKind>>,
    address: Option<u64>,
    size: u64,
    kind: SeedKind,
) -> Result<(), RecoveryError> {
    let Some(address) = address else {
        return Ok(());
    };
    let width = image.architecture.pointer_width() as u64;
    if !size.is_multiple_of(width) || size / width > 65_536 {
        return Err(RecoveryError::Seeds {
            format: ImageFormat::Elf,
            context: format!("invalid pointer-array size {size:#x} at {address:#x}"),
        });
    }
    for index in 0..size / width {
        let Some(slot) = address.checked_add(index.saturating_mul(width)) else {
            continue;
        };
        let Some(target) = image.read_pointer(slot) else {
            continue;
        };
        // See the matching guard in `collect_elf_seeds`'s relocation loop: a
        // bare `0` slot is an unrelocated PIE pointer, not a real address,
        // and rebasing it by `load_bias` would otherwise land squarely on
        // the (usually mapped, executable) image base.
        if target == 0 {
            continue;
        }
        let target = if image.load_bias != 0 && !is_executable(image, target) {
            target.saturating_add(image.load_bias)
        } else {
            target
        };
        add_seed(image, seeds, target, kind);
    }
    Ok(())
}

pub(super) fn add_seed(
    image: &LoadedImage,
    seeds: &mut BTreeMap<u64, BTreeSet<SeedKind>>,
    address: u64,
    kind: SeedKind,
) {
    let address = if image.architecture == Architecture::Arm {
        address & !1
    } else {
        address
    };
    if image.architecture == Architecture::AArch64
        && image.format == ImageFormat::Pe
        && kind == SeedKind::Relocation
        && !plausible_aarch64_pointer(image, address)
    {
        return;
    }
    if is_executable(image, address) {
        seeds.entry(address).or_default().insert(kind);
    }
}

/// Weak data pointers need a short, recognized code sequence ending in real flow.
pub(super) fn plausible_aarch64_pointer(image: &LoadedImage, mut address: u64) -> bool {
    if !address.is_multiple_of(4) {
        return false;
    }
    for index in 0..16 {
        let Ok(insn) = image.decode_at(address) else {
            return false;
        };
        let Some(text) = insn.disassembly() else {
            return false;
        };
        if text.starts_with("udf") || insn.flow == Flow::Terminal {
            return false;
        }
        match insn.flow {
            Flow::Return => return true,
            Flow::UnconditionalBranch | Flow::Call | Flow::ConditionalBranch => {
                return insn
                    .direct_target
                    .is_some_and(|target| image.is_executable_address(target))
            }
            Flow::IndirectBranch | Flow::IndirectCall => return index > 0,
            _ => {}
        }
        address = insn.next_address;
    }
    false
}

/// Seeds function starts from `STT_FUNC`/`STT_GNU_IFUNC` symbols and records
/// their names, mirroring `capa.features.extractors.elf.SymTab`'s combined
/// `.symtab`/`.dynsym` view (each table's `st_name` is only meaningful
/// against its *own* string table, so this is called once per table rather
/// than over a chained iterator).
pub(super) fn collect_function_symbols(
    image: &LoadedImage,
    syms: impl Iterator<Item = goblin::elf::sym::Sym>,
    strtab: &goblin::strtab::Strtab<'_>,
    seeds: &mut BTreeMap<u64, BTreeSet<SeedKind>>,
    function_symbols: &mut BTreeMap<u64, Vec<String>>,
) {
    for symbol in syms {
        if symbol.st_shndx == 0
            || symbol.st_value == 0
            || !matches!(st_type(symbol.st_info), STT_FUNC | STT_GNU_IFUNC)
        {
            continue;
        }
        let address = symbol.st_value.saturating_add(image.load_bias);
        let address = if image.architecture == Architecture::Arm {
            address & !1
        } else {
            address
        };
        add_seed(image, seeds, address, SeedKind::Symbol);
        let Some(name) = strtab.get_at(symbol.st_name) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let names = function_symbols.entry(address).or_default();
        if !names.iter().any(|existing| existing == name) {
            names.push(name.to_string());
        }
    }
}
