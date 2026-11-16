//! PE headers, compiler traces, resources and Authenticode signatures.
//! Layout reference: Microsoft PE format. Imphash follows pefile's definition,
//! and the Rich checksum follows the linker's published-by-reversing algorithm.
use goblin::pe::PE;

use super::Ty::{Bytes, Text, U16, U32, U64, U8};
use super::{
    flags, now, ordinals, pkcs7, resources, size_text, utc, FileDetails, Signature, Spec, Tables,
};

const DOS_HEADER: &[Spec] = &[
    ("e_magic", U16),
    ("e_cblp", U16),
    ("e_cp", U16),
    ("e_crlc", U16),
    ("e_cparhdr", U16),
    ("e_minalloc", U16),
    ("e_maxalloc", U16),
    ("e_ss", U16),
    ("e_sp", U16),
    ("e_csum", U16),
    ("e_ip", U16),
    ("e_cs", U16),
    ("e_lfarlc", U16),
    ("e_ovno", U16),
    ("e_res", Bytes(8)),
    ("e_oemid", U16),
    ("e_oeminfo", U16),
    ("e_res2", Bytes(20)),
    ("e_lfanew", U32),
];

const FILE_HEADER: &[Spec] = &[
    ("Signature", U32),
    ("Machine", U16),
    ("NumberOfSections", U16),
    ("TimeDateStamp", U32),
    ("PointerToSymbolTable", U32),
    ("NumberOfSymbols", U32),
    ("SizeOfOptionalHeader", U16),
    ("Characteristics", U16),
];

const OPTIONAL_32: &[Spec] = &[
    ("Magic", U16),
    ("MajorLinkerVersion", U8),
    ("MinorLinkerVersion", U8),
    ("SizeOfCode", U32),
    ("SizeOfInitializedData", U32),
    ("SizeOfUninitializedData", U32),
    ("AddressOfEntryPoint", U32),
    ("BaseOfCode", U32),
    ("BaseOfData", U32),
    ("ImageBase", U32),
    ("SectionAlignment", U32),
    ("FileAlignment", U32),
    ("MajorOperatingSystemVersion", U16),
    ("MinorOperatingSystemVersion", U16),
    ("MajorImageVersion", U16),
    ("MinorImageVersion", U16),
    ("MajorSubsystemVersion", U16),
    ("MinorSubsystemVersion", U16),
    ("Win32VersionValue", U32),
    ("SizeOfImage", U32),
    ("SizeOfHeaders", U32),
    ("CheckSum", U32),
    ("Subsystem", U16),
    ("DllCharacteristics", U16),
    ("SizeOfStackReserve", U32),
    ("SizeOfStackCommit", U32),
    ("SizeOfHeapReserve", U32),
    ("SizeOfHeapCommit", U32),
    ("LoaderFlags", U32),
    ("NumberOfRvaAndSizes", U32),
];

const OPTIONAL_64: &[Spec] = &[
    ("Magic", U16),
    ("MajorLinkerVersion", U8),
    ("MinorLinkerVersion", U8),
    ("SizeOfCode", U32),
    ("SizeOfInitializedData", U32),
    ("SizeOfUninitializedData", U32),
    ("AddressOfEntryPoint", U32),
    ("BaseOfCode", U32),
    ("ImageBase", U64),
    ("SectionAlignment", U32),
    ("FileAlignment", U32),
    ("MajorOperatingSystemVersion", U16),
    ("MinorOperatingSystemVersion", U16),
    ("MajorImageVersion", U16),
    ("MinorImageVersion", U16),
    ("MajorSubsystemVersion", U16),
    ("MinorSubsystemVersion", U16),
    ("Win32VersionValue", U32),
    ("SizeOfImage", U32),
    ("SizeOfHeaders", U32),
    ("CheckSum", U32),
    ("Subsystem", U16),
    ("DllCharacteristics", U16),
    ("SizeOfStackReserve", U64),
    ("SizeOfStackCommit", U64),
    ("SizeOfHeapReserve", U64),
    ("SizeOfHeapCommit", U64),
    ("LoaderFlags", U32),
    ("NumberOfRvaAndSizes", U32),
];

const SECTION_HEADER: &[Spec] = &[
    ("Name", Text(8)),
    ("VirtualSize", U32),
    ("VirtualAddress", U32),
    ("SizeOfRawData", U32),
    ("PointerToRawData", U32),
    ("PointerToRelocations", U32),
    ("PointerToLinenumbers", U32),
    ("NumberOfRelocations", U16),
    ("NumberOfLinenumbers", U16),
    ("Characteristics", U32),
];

const DIRECTORIES: &[&str] = &[
    "Export",
    "Import",
    "Resource",
    "Exception",
    "Security",
    "BaseRelocation",
    "Debug",
    "Architecture",
    "GlobalPtr",
    "TLS",
    "LoadConfig",
    "BoundImport",
    "IAT",
    "DelayImport",
    "CLR",
    "Reserved",
];

const CHARACTERISTICS: &[(u64, &str)] = &[
    (0x0001, "RELOCS_STRIPPED"),
    (0x0002, "EXECUTABLE_IMAGE"),
    (0x0004, "LINE_NUMS_STRIPPED"),
    (0x0008, "LOCAL_SYMS_STRIPPED"),
    (0x0020, "LARGE_ADDRESS_AWARE"),
    (0x0100, "32BIT_MACHINE"),
    (0x0200, "DEBUG_STRIPPED"),
    (0x1000, "SYSTEM"),
    (0x2000, "DLL"),
];

const DLL_CHARACTERISTICS: &[(u64, &str)] = &[
    (0x0020, "HIGH_ENTROPY_VA"),
    (0x0040, "DYNAMIC_BASE"),
    (0x0080, "FORCE_INTEGRITY"),
    (0x0100, "NX_COMPAT"),
    (0x0200, "NO_ISOLATION"),
    (0x0400, "NO_SEH"),
    (0x0800, "NO_BIND"),
    (0x1000, "APPCONTAINER"),
    (0x2000, "WDM_DRIVER"),
    (0x4000, "GUARD_CF"),
    (0x8000, "TERMINAL_SERVER_AWARE"),
];

const SECTION_FLAGS: &[(u64, &str)] = &[
    (0x20, "CODE"),
    (0x40, "INITIALIZED_DATA"),
    (0x80, "UNINITIALIZED_DATA"),
    (0x0200_0000, "DISCARDABLE"),
    (0x1000_0000, "SHARED"),
    (0x2000_0000, "EXECUTE"),
    (0x4000_0000, "READ"),
    (0x8000_0000, "WRITE"),
];

const SECTION_EXECUTE: u64 = 0x2000_0000;
const SECTION_WRITE: u64 = 0x8000_0000;

fn machine_name(machine: u64) -> &'static str {
    match machine {
        0x14c => "x86",
        0x8664 => "x64",
        0xaa64 => "ARM64",
        0x1c0 | 0x1c4 => "ARM",
        0x200 => "IA-64",
        _ => "unknown",
    }
}

fn subsystem_name(subsystem: u64) -> &'static str {
    match subsystem {
        1 => "Native",
        2 => "Windows GUI",
        3 => "Windows console",
        5 => "OS/2 console",
        7 => "POSIX console",
        9 => "Windows CE GUI",
        10 => "EFI application",
        11 => "EFI boot service driver",
        12 => "EFI runtime driver",
        13 => "EFI ROM",
        14 => "Xbox",
        16 => "Windows boot application",
        _ => "unknown",
    }
}

struct SectionRow {
    name: String,
    rva: u64,
    vsize: u64,
    raw_off: u64,
    raw_size: u64,
    characteristics: u64,
}

pub(in crate::image_info) fn collect(bytes: &[u8], pe: &PE<'_>) -> FileDetails {
    let mut details = FileDetails::default();
    details.hashes(bytes);
    let mut t = Tables::new(bytes, true, 0);
    let Some(dos) = t.add("IMAGE_DOS_HEADER", 0, DOS_HEADER) else {
        return details;
    };
    t.note(dos, "e_magic", "\"MZ\"");
    let lfanew = t.value(dos, "e_lfanew").unwrap_or(0) as usize;
    let image_base = pe.image_base;
    t.note(dos, "e_lfanew", "offset of IMAGE_NT_HEADERS");
    t.target(dos, "e_lfanew", image_base.saturating_add(lfanew as u64));
    rich_header(bytes, lfanew, &mut t, &mut details);

    let Some(file) = t.add("IMAGE_NT_HEADERS", lfanew, FILE_HEADER) else {
        t.finish(&mut details, |_| None);
        return details;
    };
    annotate_file_header(&mut t, file, &mut details);
    let optional_at = lfanew.saturating_add(24);
    let magic = t.u16(optional_at).unwrap_or(0);
    let (optional_name, optional_specs) = if magic == 0x20b {
        ("IMAGE_OPTIONAL_HEADER64", OPTIONAL_64)
    } else {
        ("IMAGE_OPTIONAL_HEADER32", OPTIONAL_32)
    };
    let optional = t.add(optional_name, optional_at, optional_specs);
    let optional_end = optional
        .and_then(|index| t.list.get(index))
        .map_or(optional_at, |s| optional_at.saturating_add(s.size as usize));
    if let Some(optional) = optional {
        annotate_optional(&mut t, optional, image_base, &mut details);
    }

    let optional_size = t.value(file, "SizeOfOptionalHeader").unwrap_or(0) as usize;
    let declared = optional
        .and_then(|index| t.value(index, "NumberOfRvaAndSizes"))
        .unwrap_or(0) as usize;
    if declared != 16 && optional.is_some() {
        details.info(format!("NumberOfRvaAndSizes is {declared}, not 16"), None);
    }
    let room = optional_at
        .saturating_add(optional_size)
        .saturating_sub(optional_end)
        / 8;
    let directories: Vec<Spec> = DIRECTORIES
        .iter()
        .take(declared.min(room))
        .flat_map(|name| {
            let rva: &'static str = dir_label(name, "VirtualAddress");
            let size: &'static str = dir_label(name, "Size");
            [(rva, U32), (size, U32)]
        })
        .collect();
    let directory = t.add("IMAGE_DATA_DIRECTORY[]", optional_end, &directories);
    if let Some(directory) = directory {
        for name in DIRECTORIES {
            let field = dir_label(name, "VirtualAddress");
            if let Some(rva) = t.value(directory, field).filter(|&rva| rva != 0) {
                // The Security directory alone holds a file offset, not an RVA.
                if *name == "Security" {
                    t.note(directory, field, "file offset");
                } else {
                    t.target(directory, field, image_base.saturating_add(rva));
                }
            }
        }
    }

    let sections_at = optional_at.saturating_add(optional_size);
    let count = t.value(file, "NumberOfSections").unwrap_or(0) as usize;
    let mut sections = Vec::new();
    for index in 0..count {
        let at = sections_at.saturating_add(index.saturating_mul(40));
        let Some(row) = t.add(format!("IMAGE_SECTION_HEADER[{index}]"), at, SECTION_HEADER) else {
            break;
        };
        let rva = t.value(row, "VirtualAddress").unwrap_or(0);
        let characteristics = t.value(row, "Characteristics").unwrap_or(0);
        t.note(
            row,
            "Characteristics",
            flags(characteristics, SECTION_FLAGS),
        );
        t.target(row, "VirtualAddress", image_base.saturating_add(rva));
        let name = pe
            .sections
            .get(index)
            .and_then(|s| s.name().ok())
            .unwrap_or("")
            .to_owned();
        if let Some(found) = t.list.get_mut(row) {
            found.name = format!("IMAGE_SECTION_HEADER {name}");
        }
        sections.push(SectionRow {
            name,
            rva,
            vsize: t.value(row, "VirtualSize").unwrap_or(0),
            raw_off: t.value(row, "PointerToRawData").unwrap_or(0),
            raw_size: t.value(row, "SizeOfRawData").unwrap_or(0),
            characteristics,
        });
    }
    let headers_end = sections_at.saturating_add(count.saturating_mul(40)) as u64;
    let entry_of = |name: &str| -> Option<(u64, u64)> {
        let index = directory?;
        Some((
            t.value(index, dir_label(name, "VirtualAddress"))?,
            t.value(index, dir_label(name, "Size"))?,
        ))
    };
    let security = entry_of("Security").filter(|&(off, size)| off != 0 && size != 0);
    let resource_rva = entry_of("Resource")
        .map(|(rva, _)| rva)
        .filter(|&rva| rva != 0);
    let import = entry_of("Import");
    let debug = entry_of("Debug").filter(|&(rva, size)| rva != 0 && size != 0);
    let symbols_end = symbol_table_end(&t, file);
    t.finish(&mut details, |off| {
        (off < headers_end).then(|| image_base.saturating_add(off))
    });

    identity_facts(pe, &mut details);
    section_anomalies(&sections, pe, image_base, &mut details);
    let rva_to_off = |rva: u32| {
        let rva = u64::from(rva);
        if rva < headers_end {
            return usize::try_from(rva).ok();
        }
        sections.iter().find_map(|s| {
            let delta = rva.checked_sub(s.rva)?;
            if delta >= s.raw_size {
                return None;
            }
            usize::try_from(s.raw_off.checked_add(delta)?).ok()
        })
    };
    if let Some(root) = resource_rva.and_then(|rva| u32::try_from(rva).ok()) {
        resources::collect(bytes, root, image_base, &rva_to_off, &mut details);
    }
    if let Some(hash) = imphash(bytes, &rva_to_off, import, magic == 0x20b, headers_end) {
        details.fact("Hashes", "Imphash", hash);
    }
    if optional.is_some() {
        checksum(bytes, optional_at, &mut details);
    }
    for section in sections
        .iter()
        .filter(|s| s.raw_off.saturating_add(s.raw_size) > bytes.len() as u64)
    {
        details.warn(
            format!(
                "Section {} runs past the end of the file, so the file may be truncated",
                section.name
            ),
            Some(image_base.saturating_add(section.rva)),
        );
    }
    let image_end = debug_data_end(bytes, debug, &rva_to_off).max(symbols_end);
    overlay(
        bytes,
        &sections,
        headers_end.max(image_end),
        security,
        &mut details,
    );
    if let Some((off, size)) = security {
        authenticode(bytes, off, size, optional_at, optional_end, &mut details);
    }
    details
}

/// Where the COFF symbol and string tables end; MinGW leaves them after the last section.
fn symbol_table_end(t: &Tables<'_>, file: usize) -> u64 {
    let (Some(start), Some(count)) = (
        t.value(file, "PointerToSymbolTable"),
        t.value(file, "NumberOfSymbols"),
    ) else {
        return 0;
    };
    if start == 0 {
        return 0;
    }
    let strings = start.saturating_add(count.saturating_mul(18));
    let length = usize::try_from(strings)
        .ok()
        .and_then(|at| t.u32(at))
        .unwrap_or(0);
    // Packers leave garbage here, which must not swallow a real overlay.
    Some(strings.saturating_add(length))
        .filter(|&end| end <= t.bytes.len() as u64)
        .unwrap_or(0)
}

/// Where the raw data named by debug directory entries ends; it often follows the last section.
fn debug_data_end(
    bytes: &[u8],
    debug: Option<(u64, u64)>,
    rva_to_off: &dyn Fn(u32) -> Option<usize>,
) -> u64 {
    const ENTRY: usize = 28;
    let Some((rva, size)) = debug else {
        return 0;
    };
    let table = u32::try_from(rva)
        .ok()
        .and_then(rva_to_off)
        .and_then(|start| bytes.get(start..start.saturating_add(size as usize).min(bytes.len())))
        .unwrap_or_default();
    let field = |entry: &[u8], at: usize| {
        entry
            .get(at..at + 4)
            .and_then(|raw| <[u8; 4]>::try_from(raw).ok())
            .map_or(0, |raw| u64::from(u32::from_le_bytes(raw)))
    };
    table
        .chunks_exact(ENTRY)
        .map(|entry| field(entry, 24).saturating_add(field(entry, 16)))
        .filter(|&end| end <= bytes.len() as u64)
        .max()
        .unwrap_or(0)
}

/// A static `Directory.Field` label, matched against `DIRECTORIES`.
fn dir_label(directory: &str, field: &str) -> &'static str {
    const VIRTUAL: &[&str] = &[
        "Export.VirtualAddress",
        "Import.VirtualAddress",
        "Resource.VirtualAddress",
        "Exception.VirtualAddress",
        "Security.VirtualAddress",
        "BaseRelocation.VirtualAddress",
        "Debug.VirtualAddress",
        "Architecture.VirtualAddress",
        "GlobalPtr.VirtualAddress",
        "TLS.VirtualAddress",
        "LoadConfig.VirtualAddress",
        "BoundImport.VirtualAddress",
        "IAT.VirtualAddress",
        "DelayImport.VirtualAddress",
        "CLR.VirtualAddress",
        "Reserved.VirtualAddress",
    ];
    const SIZES: &[&str] = &[
        "Export.Size",
        "Import.Size",
        "Resource.Size",
        "Exception.Size",
        "Security.Size",
        "BaseRelocation.Size",
        "Debug.Size",
        "Architecture.Size",
        "GlobalPtr.Size",
        "TLS.Size",
        "LoadConfig.Size",
        "BoundImport.Size",
        "IAT.Size",
        "DelayImport.Size",
        "CLR.Size",
        "Reserved.Size",
    ];
    let index = DIRECTORIES
        .iter()
        .position(|d| *d == directory)
        .unwrap_or(15);
    let table = if field == "Size" { SIZES } else { VIRTUAL };
    table.get(index).copied().unwrap_or("Reserved.Size")
}

fn annotate_file_header(t: &mut Tables<'_>, file: usize, details: &mut FileDetails) {
    t.note(file, "Signature", "\"PE\\0\\0\"");
    let machine = t.value(file, "Machine").unwrap_or(0);
    let name = machine_name(machine);
    t.note(file, "Machine", name);
    details.fact("Identity", "Machine", name);
    let characteristics = t.value(file, "Characteristics").unwrap_or(0);
    t.note(
        file,
        "Characteristics",
        flags(characteristics, CHARACTERISTICS),
    );
    details.fact(
        "Identity",
        "Image type",
        if characteristics & 0x2000 != 0 {
            "DLL"
        } else if characteristics & 0x1000 != 0 {
            "System file"
        } else {
            "Executable"
        },
    );
    let stamp = t.value(file, "TimeDateStamp").unwrap_or(0);
    let date = utc(stamp as i64);
    t.note(file, "TimeDateStamp", date.clone());
    details.fact(
        "Identity",
        "Compile timestamp",
        format!("{date} ({stamp:#x})"),
    );
    if stamp == 0 {
        details.info("The compile timestamp is zero", None);
    } else if now().is_some_and(|now| stamp as i64 > now) {
        details.warn(
            format!("The compile timestamp is in the future: {date}"),
            None,
        );
    }
}

fn annotate_optional(
    t: &mut Tables<'_>,
    optional: usize,
    image_base: u64,
    details: &mut FileDetails,
) {
    t.note(
        optional,
        "Magic",
        if t.value(optional, "Magic") == Some(0x20b) {
            "PE32+"
        } else {
            "PE32"
        },
    );
    let entry = t.value(optional, "AddressOfEntryPoint").unwrap_or(0);
    if entry != 0 {
        t.target(
            optional,
            "AddressOfEntryPoint",
            image_base.saturating_add(entry),
        );
    }
    let subsystem = t.value(optional, "Subsystem").unwrap_or(0);
    t.note(optional, "Subsystem", subsystem_name(subsystem));
    details.fact("Identity", "Subsystem", subsystem_name(subsystem));
    details.fact("Identity", "Image base", format!("{image_base:#x}"));
    if let (Some(major), Some(minor)) = (
        t.value(optional, "MajorLinkerVersion"),
        t.value(optional, "MinorLinkerVersion"),
    ) {
        details.fact("Build", "Linker version", format!("{major}.{minor}"));
    }
    if let (Some(major), Some(minor)) = (
        t.value(optional, "MajorSubsystemVersion"),
        t.value(optional, "MinorSubsystemVersion"),
    ) {
        details.fact("Build", "Minimum OS", format!("{major}.{minor}"));
    }
    let dll = t.value(optional, "DllCharacteristics").unwrap_or(0);
    t.note(
        optional,
        "DllCharacteristics",
        flags(dll, DLL_CHARACTERISTICS),
    );
    for (bit, label) in [
        (0x40u64, "ASLR"),
        (0x20, "High-entropy ASLR"),
        (0x100, "DEP"),
        (0x4000, "Control Flow Guard"),
        (0x80, "Forced integrity checks"),
    ] {
        details.fact("Security", label, if dll & bit != 0 { "yes" } else { "no" });
    }
    if dll & 0x400 != 0 {
        details.fact("Security", "SEH", "disabled by NO_SEH");
    }
}

fn identity_facts(pe: &PE<'_>, details: &mut FileDetails) {
    if let Some(clr) = &pe.clr_data {
        details.fact(
            "Build",
            ".NET runtime header",
            format!(
                "{}.{}",
                clr.cor20_header.major_runtime_version, clr.cor20_header.minor_runtime_version
            ),
        );
    }
    if let Some(debug) = &pe.debug_data {
        if let Some(pdb) = &debug.codeview_pdb70_debug_info {
            let end = pdb
                .filename
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(pdb.filename.len());
            let name = pdb.filename.get(..end).unwrap_or_default();
            details.fact("Build", "PDB path", String::from_utf8_lossy(name));
            details.fact(
                "Build",
                "PDB GUID",
                format!("{}{:X}", guid(&pdb.signature), pdb.age),
            );
        }
    }
    if let Some(config) = &pe.load_config_data {
        let directory = &config.directory;
        if directory.security_cookie.is_some_and(|cookie| cookie != 0) {
            details.fact("Security", "Stack cookie (/GS)", "yes");
        }
        if let Some(count) = directory.se_handler_count.filter(|&count| count != 0) {
            details.fact("Security", "SafeSEH handlers", count.to_string());
        }
    }
    if let Some(tls) = &pe.tls_data {
        for (index, &callback) in tls.callbacks.iter().enumerate() {
            details.fact_at(
                "Build",
                &format!("TLS callback {index}"),
                format!("{callback:#x}"),
                callback,
            );
        }
        if !tls.callbacks.is_empty() {
            details.warn(
                format!(
                    "{} TLS callback(s) run before the entry point",
                    tls.callbacks.len()
                ),
                tls.callbacks.first().copied(),
            );
        }
    }
}

/// A CodeView GUID in the form symbol servers use: the first three groups little-endian.
fn guid(raw: &[u8; 16]) -> String {
    let mut out = String::new();
    for &index in &[3usize, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15] {
        if let Some(byte) = raw.get(index) {
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

fn section_anomalies(
    sections: &[SectionRow],
    pe: &PE<'_>,
    image_base: u64,
    details: &mut FileDetails,
) {
    for section in sections {
        let va = image_base.saturating_add(section.rva);
        if section.characteristics & SECTION_EXECUTE != 0
            && section.characteristics & SECTION_WRITE != 0
        {
            details.warn(
                format!("Section {} is both writable and executable", section.name),
                Some(va),
            );
        }
        if section.raw_size == 0 && section.characteristics & SECTION_EXECUTE != 0 {
            details.warn(
                format!(
                    "Executable section {} has no file data, so it is filled at run time",
                    section.name
                ),
                Some(va),
            );
        }
        if !section.name.chars().all(|c| c.is_ascii_graphic()) {
            details.info(
                format!("Section name {:?} has unusual characters", section.name),
                Some(va),
            );
        }
    }
    let entry = u64::from(pe.entry);
    if entry == 0 {
        return;
    }
    let va = image_base.saturating_add(entry);
    let holder = sections
        .iter()
        .find(|s| entry >= s.rva && entry < s.rva.saturating_add(s.vsize.max(s.raw_size)));
    match holder {
        None => details.warn("The entry point is outside every section", Some(va)),
        Some(section) if section.characteristics & SECTION_EXECUTE == 0 => details.warn(
            format!(
                "The entry point is in non-executable section {}",
                section.name
            ),
            Some(va),
        ),
        Some(section)
            if sections.len() > 1
                && sections
                    .last()
                    .is_some_and(|last| std::ptr::eq(section, last)) =>
        {
            details.info(
                format!("The entry point is in the last section, {}", section.name),
                Some(va),
            )
        }
        _ => {}
    }
}

/// Decodes the XOR-masked Rich header in the DOS stub, as a structure and two facts.
fn rich_header(bytes: &[u8], lfanew: usize, t: &mut Tables<'_>, details: &mut FileDetails) {
    let Some(stub) = bytes.get(..lfanew.min(bytes.len())) else {
        return;
    };
    let Some(marker) = stub.windows(4).position(|w| w == b"Rich") else {
        return;
    };
    let Some(key) = stub
        .get(marker + 4..marker + 8)
        .and_then(|raw| <[u8; 4]>::try_from(raw).ok())
        .map(u32::from_le_bytes)
    else {
        return;
    };
    let word = |at: usize| {
        stub.get(at..at + 4)
            .and_then(|raw| <[u8; 4]>::try_from(raw).ok())
            .map(|raw| u32::from_le_bytes(raw) ^ key)
    };
    let mut start = marker;
    let found = loop {
        if start < 4 {
            break false;
        }
        start -= 4;
        if word(start) == Some(0x536e_6144) {
            break true;
        }
    };
    if !found {
        details.info("The Rich header has no start marker", None);
        return;
    }
    let mut clear = Vec::with_capacity(marker - start);
    let mut at = start;
    while at < marker {
        clear.extend_from_slice(&word(at).unwrap_or(0).to_le_bytes());
        at += 4;
    }
    details.fact(
        "Hashes",
        "Rich header hash",
        super::pkcs7::digest("MD5", &[&clear]).unwrap_or_default(),
    );

    // The checksum covers the DOS stub with e_lfanew blanked, then each entry.
    let mut sum = start as u32;
    for (index, &byte) in stub.iter().take(start).enumerate() {
        if !(0x3c..0x40).contains(&index) {
            sum = sum.wrapping_add(u32::from(byte).rotate_left(index as u32 % 32));
        }
    }
    let entries_at = start + 16;
    let mut entries = 0;
    let mut at = entries_at;
    while at + 8 <= marker {
        let (Some(id), Some(count)) = (word(at), word(at + 4)) else {
            break;
        };
        sum = sum.wrapping_add(id.rotate_left(count % 32));
        entries += 1;
        at += 8;
    }
    details.fact("Build", "Rich header entries", entries.to_string());
    if sum != key {
        details.warn(
            "The Rich header checksum does not match, so it may be forged or copied from another file",
            None,
        );
    }
    let mut fields = Vec::new();
    let mut at = entries_at;
    for index in 0..entries {
        let (Some(id), Some(count)) = (word(at), word(at + 4)) else {
            break;
        };
        let decoded = [
            (
                format!("compid[{index}]"),
                at,
                id,
                format!("product {} build {}", id >> 16, id & 0xffff),
            ),
            (
                format!("count[{index}]"),
                at + 4,
                count,
                format!("{count} objects"),
            ),
        ];
        for (name, field_at, value, note) in decoded {
            if let Some(mut field) = t.field(&name, field_at, U32) {
                field.value = format!("{value:08X}h");
                field.note = Some(note);
                fields.push(field);
            }
        }
        at += 8;
    }
    t.add_fields("RICH_HEADER (XOR-decoded)", entries_at, fields);
}

/// pefile's imphash: lowercase `dll.name` pairs in import-table order.
fn imphash(
    bytes: &[u8],
    rva_to_off: &dyn Fn(u32) -> Option<usize>,
    directory: Option<(u64, u64)>,
    wide: bool,
    headers_end: u64,
) -> Option<String> {
    const MAX_DLLS: usize = 8192;
    const MAX_IMPORTS: usize = 262_144;
    let read32 = |at: usize| -> Option<u32> {
        let raw = bytes.get(at..at.checked_add(4)?)?;
        Some(u32::from_le_bytes(raw.try_into().ok()?))
    };
    let read64 = |at: usize| -> Option<u64> {
        let raw = bytes.get(at..at.checked_add(8)?)?;
        Some(u64::from_le_bytes(raw.try_into().ok()?))
    };
    let (rva, _) = directory.filter(|&(rva, _)| rva != 0)?;
    let table = rva_to_off(u32::try_from(rva).ok()?)?;
    let mut parts: Vec<String> = Vec::new();
    for index in 0..MAX_DLLS {
        let at = table.checked_add(index.checked_mul(20)?)?;
        let lookup = read32(at)?;
        let name_rva = read32(at.checked_add(12)?)?;
        let thunk = read32(at.checked_add(16)?)?;
        if lookup == 0 && name_rva == 0 && thunk == 0 {
            break;
        }
        let Some(dll) = rva_to_off(name_rva).and_then(|off| super::c_string(bytes, off, 256))
        else {
            continue;
        };
        let dll = dll.to_lowercase();
        let short = match dll.rsplit_once('.') {
            Some((stem, "dll" | "ocx" | "sys")) => stem,
            _ => dll.as_str(),
        };
        // Packers leave junk in the lookup field; the loader then only needs the address table.
        let table_rva = if u64::from(lookup) >= headers_end && rva_to_off(lookup).is_some() {
            lookup
        } else {
            thunk
        };
        let Some(list) = rva_to_off(table_rva) else {
            continue;
        };
        let step = if wide { 8 } else { 4 };
        for slot in 0..MAX_IMPORTS {
            let at = list.checked_add(slot.checked_mul(step)?)?;
            let (value, by_ordinal) = if wide {
                let value = read64(at)?;
                (value, value >> 63 != 0)
            } else {
                let value = u64::from(read32(at)?);
                (value, value >> 31 != 0)
            };
            if value == 0 {
                break;
            }
            let name = if by_ordinal {
                let ordinal = (value & 0xffff) as u16;
                ordinals::lookup(&dll, ordinal)
                    .map_or_else(|| format!("ord{ordinal}"), str::to_owned)
            } else {
                let name_at = u32::try_from(value & 0x7fff_ffff).ok().and_then(rva_to_off);
                let Some(name) = name_at
                    .and_then(|off| off.checked_add(2))
                    .and_then(|off| super::c_string(bytes, off, 4096))
                else {
                    continue;
                };
                name
            };
            parts.push(format!("{short}.{}", name.to_lowercase()));
            if parts.len() >= MAX_IMPORTS {
                break;
            }
        }
    }
    if parts.is_empty() {
        return None;
    }
    pkcs7::digest("MD5", &[parts.join(",").as_bytes()])
}

fn checksum(bytes: &[u8], optional_at: usize, details: &mut FileDetails) {
    let field = optional_at.saturating_add(64);
    let Some(stored) = bytes
        .get(field..field.saturating_add(4))
        .and_then(|raw| <[u8; 4]>::try_from(raw).ok())
        .map(u32::from_le_bytes)
    else {
        return;
    };
    let mut sum = 0u64;
    let mut at = 0;
    for chunk in bytes.chunks(2) {
        if at != field && at != field + 2 {
            let word = chunk
                .iter()
                .rev()
                .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
            sum += word;
            sum = (sum & 0xffff) + (sum >> 16);
        }
        at += 2;
    }
    let computed = ((sum & 0xffff) + (sum >> 16) + bytes.len() as u64) as u32;
    if stored == 0 {
        details.fact("Build", "Checksum", "not set");
    } else if stored == computed {
        details.fact("Build", "Checksum", format!("{stored:#x} (valid)"));
    } else {
        details.fact(
            "Build",
            "Checksum",
            format!("{stored:#x} (computed {computed:#x})"),
        );
        details.warn(
            format!("The PE checksum is wrong: stored {stored:#x}, computed {computed:#x}"),
            None,
        );
    }
}

/// Bytes after the last section's raw data, minus a certificate table at the very end.
fn overlay(
    bytes: &[u8],
    sections: &[SectionRow],
    headers_end: u64,
    security: Option<(u64, u64)>,
    details: &mut FileDetails,
) {
    let end = sections
        .iter()
        .filter(|s| s.raw_size != 0)
        .map(|s| s.raw_off.saturating_add(s.raw_size))
        .max()
        .unwrap_or(headers_end)
        .max(headers_end);
    let total = bytes.len() as u64;
    let visible_end = match security {
        Some((off, size)) if off >= end && off.saturating_add(size) >= total => off,
        _ => total,
    };
    if end >= visible_end {
        return;
    }
    let Some(view) = usize::try_from(visible_end)
        .ok()
        .and_then(|stop| bytes.get(..stop))
    else {
        return;
    };
    details.overlay(view, end, 0);
}

/// Each WIN_CERTIFICATE in the table, with its digest recomputed from the file.
fn authenticode(
    bytes: &[u8],
    off: u64,
    size: u64,
    optional_at: usize,
    optional_end: usize,
    details: &mut FileDetails,
) {
    const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 2;
    let start = usize::try_from(off).ok();
    let table = start.and_then(|start| {
        let end = start.checked_add(usize::try_from(size).ok()?)?;
        bytes.get(start..end)
    });
    let (Some(table), Some(start)) = (table, start) else {
        details.warn(
            format!("The certificate table at {off:#x} runs past the end of the file"),
            None,
        );
        return;
    };
    // Hashed like signtool: everything except the checksum, this directory entry and the table.
    let checksum_at = optional_at.saturating_add(64);
    let entry_at = optional_end.saturating_add(4 * 8);
    let end = start.saturating_add(table.len());
    let parts: Option<[&[u8]; 4]> = (|| {
        Some([
            bytes.get(..checksum_at)?,
            bytes.get(checksum_at.checked_add(4)?..entry_at)?,
            bytes.get(entry_at.checked_add(8)?..start)?,
            bytes.get(end..)?,
        ])
    })();
    let mut at = 0usize;
    let mut signatures = Vec::new();
    while let Some(header) = table.get(at..at.saturating_add(8)) {
        let length = header
            .get(..4)
            .and_then(|raw| <[u8; 4]>::try_from(raw).ok())
            .map_or(0, u32::from_le_bytes) as usize;
        let kind = header
            .get(6..8)
            .and_then(|raw| <[u8; 2]>::try_from(raw).ok())
            .map_or(0, u16::from_le_bytes);
        let Some(body) = length
            .checked_sub(8)
            .and_then(|body| table.get(at + 8..(at + 8).checked_add(body)?))
        else {
            details.warn("A certificate table entry is malformed", None);
            break;
        };
        if kind == WIN_CERT_TYPE_PKCS_SIGNED_DATA {
            match pkcs7::parse(body) {
                Some(signed) => push_signed(
                    signed,
                    (start + at) as u64,
                    length as u64,
                    parts.as_ref(),
                    &mut signatures,
                ),
                None => details.warn("A certificate table entry is not readable PKCS#7", None),
            }
        } else {
            details.info(
                format!("Certificate table entry has unsupported type {kind}"),
                None,
            );
        }
        at = at.saturating_add(length).saturating_add(7) & !7;
    }
    // Parsers accept it, but it is how appended payloads hide from the signed hash's casual readers.
    if end < bytes.len() {
        details.warn("The certificate table is not at the end of the file", None);
    }
    if signatures.iter().any(|s| s.digest_matches == Some(false)) {
        details.warn(
            "The Authenticode digest does not match, so the file changed after it was signed",
            None,
        );
    }
    for signature in &signatures {
        for property in signature.certificates.iter().filter(|c| c.signer) {
            if property.self_signed {
                details.warn(
                    format!(
                        "The signing certificate is self-signed: {}",
                        property.subject
                    ),
                    None,
                );
            }
        }
    }
    details.fact(
        "Security",
        "Authenticode",
        match signatures
            .first()
            .and_then(|s| s.certificates.iter().find(|c| c.signer))
        {
            Some(cert) => format!("signed by {}", cert.subject),
            None => format!("{} in the certificate table", size_text(size)),
        },
    );
    details.signatures.extend(signatures);
}

fn push_signed(
    signed: pkcs7::Signed,
    off: u64,
    size: u64,
    parts: Option<&[&[u8]; 4]>,
    out: &mut Vec<Signature>,
) {
    let computed = signed
        .digest_algorithm
        .zip(parts)
        .and_then(|(algorithm, parts)| pkcs7::digest(algorithm, parts));
    let matches = computed
        .as_ref()
        .zip(signed.signed_digest.as_ref())
        .map(|(a, b)| a.eq_ignore_ascii_case(b));
    out.push(Signature {
        kind: "Authenticode".into(),
        off,
        size,
        digest_algorithm: signed.digest_algorithm.map(str::to_owned),
        signed_digest: signed.signed_digest,
        computed_digest: computed,
        digest_matches: matches,
        program: signed.program,
        signing_time: signed.signing_time,
        timestamp: signed.timestamp,
        timestamp_signer: signed.timestamp_signer,
        properties: Vec::new(),
        certificates: signed.certificates,
        entitlements: None,
    });
    for nested in signed.nested {
        push_signed(nested, off, size, parts, out);
    }
}
