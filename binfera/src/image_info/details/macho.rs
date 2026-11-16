//! Mach-O header, load commands, dependencies and code signature.
//! Layout reference: Apple xnu `EXTERNAL_HEADERS/mach-o/loader.h`.
use super::Ty::{Bytes, Text, U32, U64};
use super::{codesign, flags, hex, FileDetails, Spec, Tables};

const MH_MAGIC: u64 = 0xfeed_face;
const MH_MAGIC_64: u64 = 0xfeed_facf;
const VM_PROT_WRITE: u64 = 2;
const VM_PROT_EXECUTE: u64 = 4;

const LC_SEGMENT: u64 = 0x1;
const LC_SYMTAB: u64 = 0x2;
const LC_DYSYMTAB: u64 = 0xb;
const LC_LOAD_DYLIB: u64 = 0xc;
const LC_ID_DYLIB: u64 = 0xd;
const LC_LOAD_DYLINKER: u64 = 0xe;
const LC_ID_DYLINKER: u64 = 0xf;
const LC_LOAD_WEAK_DYLIB: u64 = 0x8000_0018;
const LC_SEGMENT_64: u64 = 0x19;
const LC_UUID: u64 = 0x1b;
const LC_RPATH: u64 = 0x8000_001c;
const LC_CODE_SIGNATURE: u64 = 0x1d;
const LC_SEGMENT_SPLIT_INFO: u64 = 0x1e;
const LC_REEXPORT_DYLIB: u64 = 0x8000_001f;
const LC_ENCRYPTION_INFO: u64 = 0x21;
const LC_DYLD_INFO: u64 = 0x22;
const LC_DYLD_INFO_ONLY: u64 = 0x8000_0022;
const LC_VERSION_MIN_MACOSX: u64 = 0x24;
const LC_VERSION_MIN_IPHONEOS: u64 = 0x25;
const LC_FUNCTION_STARTS: u64 = 0x26;
const LC_MAIN: u64 = 0x8000_0028;
const LC_DATA_IN_CODE: u64 = 0x29;
const LC_SOURCE_VERSION: u64 = 0x2a;
const LC_ENCRYPTION_INFO_64: u64 = 0x2c;
const LC_BUILD_VERSION: u64 = 0x32;
const LC_DYLD_EXPORTS_TRIE: u64 = 0x8000_0033;
const LC_DYLD_CHAINED_FIXUPS: u64 = 0x8000_0034;

const CMD: [Spec; 2] = [("cmd", U32), ("cmdsize", U32)];

const HEADER_FLAGS: &[(u64, &str)] = &[
    (0x1, "NOUNDEFS"),
    (0x4, "DYLDLINK"),
    (0x80, "TWOLEVEL"),
    (0x8000, "WEAK_DEFINES"),
    (0x10000, "BINDS_TO_WEAK"),
    (0x20000, "ALLOW_STACK_EXECUTION"),
    (0x200000, "PIE"),
    (0x800000, "HAS_TLV_DESCRIPTORS"),
    (0x1000000, "NO_HEAP_EXECUTION"),
    (0x2000000, "APP_EXTENSION_SAFE"),
];

fn command_name(cmd: u64) -> &'static str {
    match cmd {
        LC_SEGMENT => "LC_SEGMENT",
        LC_SYMTAB => "LC_SYMTAB",
        LC_DYSYMTAB => "LC_DYSYMTAB",
        LC_LOAD_DYLIB => "LC_LOAD_DYLIB",
        LC_ID_DYLIB => "LC_ID_DYLIB",
        LC_LOAD_DYLINKER => "LC_LOAD_DYLINKER",
        LC_ID_DYLINKER => "LC_ID_DYLINKER",
        LC_LOAD_WEAK_DYLIB => "LC_LOAD_WEAK_DYLIB",
        LC_SEGMENT_64 => "LC_SEGMENT_64",
        LC_UUID => "LC_UUID",
        LC_RPATH => "LC_RPATH",
        LC_CODE_SIGNATURE => "LC_CODE_SIGNATURE",
        LC_SEGMENT_SPLIT_INFO => "LC_SEGMENT_SPLIT_INFO",
        LC_REEXPORT_DYLIB => "LC_REEXPORT_DYLIB",
        LC_ENCRYPTION_INFO => "LC_ENCRYPTION_INFO",
        LC_DYLD_INFO => "LC_DYLD_INFO",
        LC_DYLD_INFO_ONLY => "LC_DYLD_INFO_ONLY",
        LC_VERSION_MIN_MACOSX => "LC_VERSION_MIN_MACOSX",
        LC_VERSION_MIN_IPHONEOS => "LC_VERSION_MIN_IPHONEOS",
        LC_FUNCTION_STARTS => "LC_FUNCTION_STARTS",
        LC_MAIN => "LC_MAIN",
        LC_DATA_IN_CODE => "LC_DATA_IN_CODE",
        LC_SOURCE_VERSION => "LC_SOURCE_VERSION",
        LC_ENCRYPTION_INFO_64 => "LC_ENCRYPTION_INFO_64",
        LC_BUILD_VERSION => "LC_BUILD_VERSION",
        LC_DYLD_EXPORTS_TRIE => "LC_DYLD_EXPORTS_TRIE",
        LC_DYLD_CHAINED_FIXUPS => "LC_DYLD_CHAINED_FIXUPS",
        _ => "LC_UNKNOWN",
    }
}

/// The fields following `cmd` and `cmdsize`, in the commands that matter for triage.
fn command_specs(cmd: u64) -> Vec<Spec> {
    let rest: &[Spec] = match cmd {
        LC_SEGMENT_64 => &[
            ("segname", Text(16)),
            ("vmaddr", U64),
            ("vmsize", U64),
            ("fileoff", U64),
            ("filesize", U64),
            ("maxprot", U32),
            ("initprot", U32),
            ("nsects", U32),
            ("flags", U32),
        ],
        LC_SEGMENT => &[
            ("segname", Text(16)),
            ("vmaddr", U32),
            ("vmsize", U32),
            ("fileoff", U32),
            ("filesize", U32),
            ("maxprot", U32),
            ("initprot", U32),
            ("nsects", U32),
            ("flags", U32),
        ],
        LC_SYMTAB => &[
            ("symoff", U32),
            ("nsyms", U32),
            ("stroff", U32),
            ("strsize", U32),
        ],
        LC_DYSYMTAB => &[
            ("ilocalsym", U32),
            ("nlocalsym", U32),
            ("iextdefsym", U32),
            ("nextdefsym", U32),
            ("iundefsym", U32),
            ("nundefsym", U32),
            ("tocoff", U32),
            ("ntoc", U32),
            ("modtaboff", U32),
            ("nmodtab", U32),
            ("extrefsymoff", U32),
            ("nextrefsyms", U32),
            ("indirectsymoff", U32),
            ("nindirectsyms", U32),
            ("extreloff", U32),
            ("nextrel", U32),
            ("locreloff", U32),
            ("nlocrel", U32),
        ],
        LC_DYLD_INFO | LC_DYLD_INFO_ONLY => &[
            ("rebase_off", U32),
            ("rebase_size", U32),
            ("bind_off", U32),
            ("bind_size", U32),
            ("weak_bind_off", U32),
            ("weak_bind_size", U32),
            ("lazy_bind_off", U32),
            ("lazy_bind_size", U32),
            ("export_off", U32),
            ("export_size", U32),
        ],
        LC_LOAD_DYLIB | LC_ID_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB => &[
            ("name", U32),
            ("timestamp", U32),
            ("current_version", U32),
            ("compatibility_version", U32),
        ],
        LC_LOAD_DYLINKER | LC_ID_DYLINKER | LC_RPATH => &[("path", U32)],
        LC_UUID => &[("uuid", Bytes(16))],
        LC_CODE_SIGNATURE
        | LC_SEGMENT_SPLIT_INFO
        | LC_FUNCTION_STARTS
        | LC_DATA_IN_CODE
        | LC_DYLD_EXPORTS_TRIE
        | LC_DYLD_CHAINED_FIXUPS => &[("dataoff", U32), ("datasize", U32)],
        LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => {
            &[("cryptoff", U32), ("cryptsize", U32), ("cryptid", U32)]
        }
        LC_MAIN => &[("entryoff", U64), ("stacksize", U64)],
        LC_BUILD_VERSION => &[
            ("platform", U32),
            ("minos", U32),
            ("sdk", U32),
            ("ntools", U32),
        ],
        LC_VERSION_MIN_MACOSX | LC_VERSION_MIN_IPHONEOS => &[("version", U32), ("sdk", U32)],
        LC_SOURCE_VERSION => &[("version", U64)],
        _ => &[],
    };
    let mut specs = CMD.to_vec();
    specs.extend_from_slice(rest);
    specs
}

const SECTION_32: &[Spec] = &[
    ("sectname", Text(16)),
    ("segname", Text(16)),
    ("addr", U32),
    ("size", U32),
    ("offset", U32),
    ("align", U32),
    ("reloff", U32),
    ("nreloc", U32),
    ("flags", U32),
    ("reserved1", U32),
    ("reserved2", U32),
];

const SECTION_64: &[Spec] = &[
    ("sectname", Text(16)),
    ("segname", Text(16)),
    ("addr", U64),
    ("size", U64),
    ("offset", U32),
    ("align", U32),
    ("reloff", U32),
    ("nreloc", U32),
    ("flags", U32),
    ("reserved1", U32),
    ("reserved2", U32),
    ("reserved3", U32),
];

fn cpu_name(cpu: u64) -> &'static str {
    match cpu {
        7 => "x86",
        0x0100_0007 => "x86-64",
        12 => "ARM",
        0x0100_000c => "ARM64",
        0x0200_000c => "ARM64_32",
        _ => "unknown",
    }
}

fn file_type_name(kind: u64) -> &'static str {
    match kind {
        1 => "object",
        2 => "executable",
        4 => "core",
        6 => "dylib",
        7 => "dynamic linker",
        8 => "bundle",
        10 => "debug symbols",
        11 => "kext",
        _ => "unknown",
    }
}

fn platform_name(platform: u64) -> &'static str {
    match platform {
        1 => "macOS",
        2 => "iOS",
        3 => "tvOS",
        4 => "watchOS",
        5 => "bridgeOS",
        6 => "Mac Catalyst",
        7 => "iOS simulator",
        8 => "tvOS simulator",
        9 => "watchOS simulator",
        10 => "DriverKit",
        11 => "visionOS",
        _ => "unknown",
    }
}

/// `X.Y.Z` from the packed form used by version and build commands.
fn version(value: u64) -> String {
    format!("{}.{}.{}", value >> 16, (value >> 8) & 0xff, value & 0xff)
}

fn protection(value: u64) -> String {
    format!(
        "{}{}{}",
        if value & 1 != 0 { 'r' } else { '-' },
        if value & VM_PROT_WRITE != 0 { 'w' } else { '-' },
        if value & VM_PROT_EXECUTE != 0 {
            'x'
        } else {
            '-'
        },
    )
}

struct Segment {
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    initprot: u64,
    name: String,
}

/// `whole` is the input as loaded and `slice` the selected architecture within it.
pub(in crate::image_info) fn collect(
    whole: &[u8],
    slice: &[u8],
    base: u64,
    little: bool,
) -> FileDetails {
    let mut details = FileDetails::default();
    details.hashes(whole);
    if whole.len() != slice.len() {
        details.fact(
            "Identity",
            "Universal binary",
            format!("this slice starts at file offset {base:#x}"),
        );
    }
    let mut t = Tables::new(slice, little, base);
    let magic = t.u32(0).unwrap_or(0);
    let wide = magic == MH_MAGIC_64;
    if !wide && magic != MH_MAGIC {
        return details;
    }
    let mut header_specs: Vec<Spec> = vec![
        ("magic", U32),
        ("cputype", U32),
        ("cpusubtype", U32),
        ("filetype", U32),
        ("ncmds", U32),
        ("sizeofcmds", U32),
        ("flags", U32),
    ];
    if wide {
        header_specs.push(("reserved", U32));
    }
    let Some(header) = t.add(
        if wide {
            "mach_header_64"
        } else {
            "mach_header"
        },
        0,
        &header_specs,
    ) else {
        return details;
    };
    let cpu = t.value(header, "cputype").unwrap_or(0);
    let kind = t.value(header, "filetype").unwrap_or(0);
    let header_flags = t.value(header, "flags").unwrap_or(0);
    t.note(header, "cputype", cpu_name(cpu));
    t.note(header, "filetype", file_type_name(kind));
    t.note(header, "flags", flags(header_flags, HEADER_FLAGS));
    details.fact("Identity", "Machine", cpu_name(cpu));
    details.fact("Identity", "Image type", file_type_name(kind));

    let start = if wide { 32usize } else { 28 };
    let total = t.value(header, "sizeofcmds").unwrap_or(0) as usize;
    let count = t.value(header, "ncmds").unwrap_or(0) as usize;
    let limit = start.saturating_add(total).min(slice.len());
    let mut at = start;
    let mut segments = Vec::new();
    let mut signature = None;
    let mut main_offset = None;
    let mut encrypted = false;
    let mut end = limit as u64;
    let mut read_all = true;
    for index in 0..count {
        if at.saturating_add(8) > limit {
            read_all = false;
            break;
        }
        let cmd = t.u32(at).unwrap_or(0);
        let size = t.u32(at + 4).unwrap_or(0) as usize;
        if size < 8 || at.saturating_add(size) > limit {
            read_all = false;
            break;
        }
        let specs = command_specs(cmd);
        let name = command_name(cmd);
        let Some(row) = t.add(format!("{name}[{index}]"), at, &specs) else {
            break;
        };
        t.note(row, "cmd", name);
        match cmd {
            LC_SEGMENT | LC_SEGMENT_64 => {
                let found = segment(&mut t, row, at, cmd == LC_SEGMENT_64);
                end = end.max(found.fileoff.saturating_add(found.filesize));
                if found.initprot & VM_PROT_WRITE != 0 && found.initprot & VM_PROT_EXECUTE != 0 {
                    details.warn(
                        format!("Segment {} is both writable and executable", found.name),
                        Some(found.vmaddr),
                    );
                }
                segments.push(found);
            }
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB => {
                if let Some(path) = command_string(&t, row, at, "name", size) {
                    let label = if cmd == LC_LOAD_WEAK_DYLIB {
                        "Weak dylib"
                    } else if cmd == LC_REEXPORT_DYLIB {
                        "Re-exported dylib"
                    } else {
                        "Dylib"
                    };
                    t.note(row, "name", path.clone());
                    if !path.starts_with("/usr/lib/") && !path.starts_with("/System/") {
                        details.info(
                            format!("Links a library outside system paths: {path}"),
                            None,
                        );
                    }
                    details.fact("Dependencies", label, path);
                }
            }
            LC_ID_DYLIB => {
                if let Some(path) = command_string(&t, row, at, "name", size) {
                    t.note(row, "name", path.clone());
                    details.fact("Identity", "Install name", path);
                }
            }
            LC_LOAD_DYLINKER | LC_ID_DYLINKER => {
                if let Some(path) = command_string(&t, row, at, "path", size) {
                    t.note(row, "path", path.clone());
                    details.fact("Dependencies", "Dynamic linker", path);
                }
            }
            LC_RPATH => {
                if let Some(path) = command_string(&t, row, at, "path", size) {
                    t.note(row, "path", path.clone());
                    details.fact("Dependencies", "RPATH", path);
                }
            }
            LC_UUID => {
                if let Some(raw) = slice.get(at + 8..at + 24) {
                    details.fact("Build", "UUID", uuid(raw));
                }
            }
            LC_BUILD_VERSION => {
                let platform = platform_name(t.value(row, "platform").unwrap_or(0));
                t.note(row, "platform", platform);
                details.fact("Build", "Platform", platform);
                if let Some(minos) = t.value(row, "minos") {
                    t.note(row, "minos", version(minos));
                    details.fact("Build", "Minimum OS", version(minos));
                }
                if let Some(sdk) = t.value(row, "sdk") {
                    t.note(row, "sdk", version(sdk));
                    details.fact("Build", "SDK", version(sdk));
                }
            }
            LC_VERSION_MIN_MACOSX | LC_VERSION_MIN_IPHONEOS => {
                details.fact(
                    "Build",
                    "Platform",
                    if cmd == LC_VERSION_MIN_MACOSX {
                        "macOS"
                    } else {
                        "iOS"
                    },
                );
                if let Some(minimum) = t.value(row, "version") {
                    t.note(row, "version", version(minimum));
                    details.fact("Build", "Minimum OS", version(minimum));
                }
                if let Some(sdk) = t.value(row, "sdk") {
                    t.note(row, "sdk", version(sdk));
                    details.fact("Build", "SDK", version(sdk));
                }
            }
            LC_MAIN => main_offset = t.value(row, "entryoff"),
            LC_CODE_SIGNATURE => {
                signature = t.value(row, "dataoff").zip(t.value(row, "datasize"));
            }
            LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => {
                let id = t.value(row, "cryptid").unwrap_or(0);
                t.note(
                    row,
                    "cryptid",
                    if id == 0 {
                        "not encrypted"
                    } else {
                        "encrypted"
                    },
                );
                if id != 0 {
                    encrypted = true;
                }
            }
            _ => {}
        }
        at = at.saturating_add(size);
    }
    if !read_all {
        details.warn("The load commands run past their declared size", None);
    }
    t.finish(&mut details, |off| {
        let local = off.checked_sub(base)?;
        segments
            .iter()
            .find(|s| local >= s.fileoff && local - s.fileoff < s.filesize)
            .map(|s| s.vmaddr.saturating_add(local - s.fileoff))
    });

    if let (Some(offset), Some(text)) = (main_offset, segments.iter().find(|s| s.name == "__TEXT"))
    {
        let va = text.vmaddr.saturating_add(offset);
        if !segments.iter().any(|s| {
            s.initprot & VM_PROT_EXECUTE != 0 && va >= s.vmaddr && va - s.vmaddr < s.vmsize
        }) {
            details.warn(
                "The entry point is outside every executable segment",
                Some(va),
            );
        }
    }
    details.fact(
        "Security",
        "PIE",
        if header_flags & 0x200000 != 0 {
            "yes"
        } else {
            "no"
        },
    );
    details.fact(
        "Security",
        "Encrypted",
        if encrypted { "yes" } else { "no" },
    );
    if encrypted {
        details.warn(
            "Part of the code is encrypted, so disassembly there is meaningless",
            None,
        );
    }
    if header_flags & 0x20000 != 0 {
        details.warn("The stack is allowed to be executable", None);
    }
    if segments.iter().any(|s| s.name == "__RESTRICT") {
        details.fact("Security", "__RESTRICT segment", "yes");
    }
    if let Some((off, size)) = signature {
        codesign::collect(slice, base, off, size, &mut details);
    } else {
        details.fact("Security", "Code signature", "none");
    }
    if end < slice.len() as u64 {
        details.overlay(slice, end, base);
    }
    details
}

fn segment(t: &mut Tables<'_>, row: usize, at: usize, wide: bool) -> Segment {
    let initprot = t.value(row, "initprot").unwrap_or(0);
    let maxprot = t.value(row, "maxprot").unwrap_or(0);
    t.note(row, "initprot", protection(initprot));
    t.note(row, "maxprot", protection(maxprot));
    let vmaddr = t.value(row, "vmaddr").unwrap_or(0);
    let name = t
        .list
        .get(row)
        .and_then(|s| s.fields.iter().find(|f| f.name == "segname"))
        .map(|f| f.value.trim_matches('"').to_owned())
        .unwrap_or_default();
    if let Some(found) = t.list.get_mut(row) {
        found.name = format!(
            "{} {name}",
            if wide { "LC_SEGMENT_64" } else { "LC_SEGMENT" }
        );
    }
    if vmaddr != 0 {
        t.target(row, "vmaddr", vmaddr);
    }
    let nsects = t.value(row, "nsects").unwrap_or(0) as usize;
    let header = if wide { 72 } else { 56 };
    let specs = if wide { SECTION_64 } else { SECTION_32 };
    let stride: usize = specs.iter().map(|(_, ty)| ty.size()).sum();
    for index in 0..nsects {
        let Some(section_at) = at
            .checked_add(header)
            .and_then(|base| base.checked_add(index.checked_mul(stride)?))
        else {
            break;
        };
        let Some(section) = t.add(format!("section {index} of {name}"), section_at, specs) else {
            break;
        };
        let sectname = t
            .list
            .get(section)
            .and_then(|s| s.fields.first())
            .map(|f| f.value.trim_matches('"').to_owned())
            .unwrap_or_default();
        if let Some(found) = t.list.get_mut(section) {
            found.name = format!("section {name},{sectname}");
        }
        if let Some(addr) = t.value(section, "addr").filter(|&addr| addr != 0) {
            t.target(section, "addr", addr);
        }
    }
    Segment {
        vmaddr,
        vmsize: t.value(row, "vmsize").unwrap_or(0),
        fileoff: t.value(row, "fileoff").unwrap_or(0),
        filesize: t.value(row, "filesize").unwrap_or(0),
        initprot,
        name,
    }
}

/// A path stored inside its command, at the offset held in `field`.
fn command_string(
    t: &Tables<'_>,
    row: usize,
    at: usize,
    field: &str,
    size: usize,
) -> Option<String> {
    let offset = t.value(row, field)? as usize;
    if offset >= size {
        return None;
    }
    let command = t.bytes.get(at..at.checked_add(size)?)?;
    super::c_string(command, offset, size)
}

fn uuid(raw: &[u8]) -> String {
    let text = hex(raw).to_uppercase();
    let part = |from: usize, to: usize| text.get(from..to).unwrap_or("");
    format!(
        "{}-{}-{}-{}-{}",
        part(0, 8),
        part(8, 12),
        part(12, 16),
        part(16, 20),
        part(20, 32)
    )
}
