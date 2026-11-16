//! ELF headers and hardening traits.
//! Layout reference: System V gABI. ELF has no standard signature to report.
use goblin::elf::Elf;

use super::Ty::{Bytes, U16, U32, U64, U8};
use super::{flags, hex, FileDetails, Spec, Tables};

const PT_LOAD: u64 = 1;
const PT_GNU_STACK: u64 = 0x6474_e551;
const PT_GNU_RELRO: u64 = 0x6474_e552;
const PF_X: u64 = 1;
const PF_W: u64 = 2;
const PF_R: u64 = 4;
const SHT_NOBITS: u64 = 8;
const DT_BIND_NOW: u64 = 24;
const DT_FLAGS: u64 = 30;
const DT_FLAGS_1: u64 = 0x6fff_fffb;
const NT_GNU_BUILD_ID: u32 = 3;

const fn ident() -> [Spec; 7] {
    [
        ("ei_magic", Bytes(4)),
        ("ei_class", U8),
        ("ei_data", U8),
        ("ei_version", U8),
        ("ei_osabi", U8),
        ("ei_abiversion", U8),
        ("ei_pad", Bytes(7)),
    ]
}

fn ehdr(wide: bool) -> Vec<Spec> {
    let word = if wide { U64 } else { U32 };
    let mut specs = ident().to_vec();
    specs.extend_from_slice(&[
        ("e_type", U16),
        ("e_machine", U16),
        ("e_version", U32),
        ("e_entry", word),
        ("e_phoff", word),
        ("e_shoff", word),
        ("e_flags", U32),
        ("e_ehsize", U16),
        ("e_phentsize", U16),
        ("e_phnum", U16),
        ("e_shentsize", U16),
        ("e_shnum", U16),
        ("e_shstrndx", U16),
    ]);
    specs
}

const PHDR_32: &[Spec] = &[
    ("p_type", U32),
    ("p_offset", U32),
    ("p_vaddr", U32),
    ("p_paddr", U32),
    ("p_filesz", U32),
    ("p_memsz", U32),
    ("p_flags", U32),
    ("p_align", U32),
];

const PHDR_64: &[Spec] = &[
    ("p_type", U32),
    ("p_flags", U32),
    ("p_offset", U64),
    ("p_vaddr", U64),
    ("p_paddr", U64),
    ("p_filesz", U64),
    ("p_memsz", U64),
    ("p_align", U64),
];

const SHDR_32: &[Spec] = &[
    ("sh_name", U32),
    ("sh_type", U32),
    ("sh_flags", U32),
    ("sh_addr", U32),
    ("sh_offset", U32),
    ("sh_size", U32),
    ("sh_link", U32),
    ("sh_info", U32),
    ("sh_addralign", U32),
    ("sh_entsize", U32),
];

const SHDR_64: &[Spec] = &[
    ("sh_name", U32),
    ("sh_type", U32),
    ("sh_flags", U64),
    ("sh_addr", U64),
    ("sh_offset", U64),
    ("sh_size", U64),
    ("sh_link", U32),
    ("sh_info", U32),
    ("sh_addralign", U64),
    ("sh_entsize", U64),
];

fn type_name(kind: u64) -> &'static str {
    match kind {
        1 => "relocatable",
        2 => "executable",
        3 => "shared object or PIE",
        4 => "core dump",
        _ => "unknown",
    }
}

fn machine_name(machine: u64) -> &'static str {
    match machine {
        2 => "SPARC",
        3 => "x86",
        8 => "MIPS",
        20 => "PowerPC",
        21 => "PowerPC64",
        22 => "s390",
        40 => "ARM",
        42 => "SuperH",
        43 => "SPARC V9",
        62 => "x86-64",
        183 => "AArch64",
        243 => "RISC-V",
        _ => "unknown",
    }
}

fn osabi_name(osabi: u64) -> &'static str {
    match osabi {
        0 => "System V",
        2 => "NetBSD",
        3 => "Linux",
        6 => "Solaris",
        9 => "FreeBSD",
        12 => "OpenBSD",
        _ => "unknown",
    }
}

fn segment_name(kind: u64) -> &'static str {
    match kind {
        0 => "PT_NULL",
        PT_LOAD => "PT_LOAD",
        2 => "PT_DYNAMIC",
        3 => "PT_INTERP",
        4 => "PT_NOTE",
        5 => "PT_SHLIB",
        6 => "PT_PHDR",
        7 => "PT_TLS",
        0x6474_e550 => "PT_GNU_EH_FRAME",
        PT_GNU_STACK => "PT_GNU_STACK",
        PT_GNU_RELRO => "PT_GNU_RELRO",
        0x6474_e553 => "PT_GNU_PROPERTY",
        _ => "other",
    }
}

fn section_type_name(kind: u64) -> &'static str {
    match kind {
        0 => "SHT_NULL",
        1 => "SHT_PROGBITS",
        2 => "SHT_SYMTAB",
        3 => "SHT_STRTAB",
        4 => "SHT_RELA",
        5 => "SHT_HASH",
        6 => "SHT_DYNAMIC",
        7 => "SHT_NOTE",
        SHT_NOBITS => "SHT_NOBITS",
        9 => "SHT_REL",
        11 => "SHT_DYNSYM",
        14 => "SHT_INIT_ARRAY",
        15 => "SHT_FINI_ARRAY",
        _ => "other",
    }
}

fn perms(value: u64) -> String {
    format!(
        "{}{}{}",
        if value & PF_R != 0 { 'r' } else { '-' },
        if value & PF_W != 0 { 'w' } else { '-' },
        if value & PF_X != 0 { 'x' } else { '-' },
    )
}

struct Load {
    off: u64,
    filesz: u64,
    vaddr: u64,
}

pub(in crate::image_info) fn collect(bytes: &[u8], elf: &Elf<'_>, bias: u64) -> FileDetails {
    let mut details = FileDetails::default();
    details.hashes(bytes);
    let mut t = Tables::new(bytes, elf.little_endian, 0);
    let wide = elf.is_64;
    let Some(header) = t.add(
        if wide { "Elf64_Ehdr" } else { "Elf32_Ehdr" },
        0,
        &ehdr(wide),
    ) else {
        return details;
    };
    t.note(header, "ei_magic", "\"\\x7fELF\"");
    t.note(header, "ei_class", if wide { "ELF64" } else { "ELF32" });
    t.note(
        header,
        "ei_data",
        if elf.little_endian {
            "little-endian"
        } else {
            "big-endian"
        },
    );
    let kind = t.value(header, "e_type").unwrap_or(0);
    let machine = t.value(header, "e_machine").unwrap_or(0);
    let osabi = t.value(header, "ei_osabi").unwrap_or(0);
    t.note(header, "e_type", type_name(kind));
    t.note(header, "e_machine", machine_name(machine));
    t.note(header, "ei_osabi", osabi_name(osabi));
    details.fact("Identity", "Machine", machine_name(machine));
    details.fact("Identity", "Image type", type_name(kind));
    details.fact("Identity", "OS ABI", osabi_name(osabi));
    details.fact("Identity", "Class", if wide { "ELF64" } else { "ELF32" });
    details.fact(
        "Identity",
        "Byte order",
        if elf.little_endian {
            "little-endian"
        } else {
            "big-endian"
        },
    );
    let entry = t.value(header, "e_entry").unwrap_or(0);
    if entry != 0 {
        t.target(header, "e_entry", entry.saturating_add(bias));
    }

    // Program headers.
    let ph_off = t.value(header, "e_phoff").unwrap_or(0);
    let ph_size = t.value(header, "e_phentsize").unwrap_or(0) as usize;
    let ph_count = t.value(header, "e_phnum").unwrap_or(0) as usize;
    let ph_specs = if wide { PHDR_64 } else { PHDR_32 };
    let mut loads = Vec::new();
    let mut end = t.list.first().map_or(0, |s| s.size);
    let mut exec_stack = None;
    let mut relro = false;
    let mut exec_ranges = Vec::new();
    if ph_size >= ph_specs.iter().map(|(_, ty)| ty.size()).sum() {
        for index in 0..ph_count {
            let Some(at) = usize::try_from(ph_off)
                .ok()
                .and_then(|base| base.checked_add(index.checked_mul(ph_size)?))
            else {
                break;
            };
            let Some(row) = t.add(format!("Phdr[{index}]"), at, ph_specs) else {
                break;
            };
            let p_type = t.value(row, "p_type").unwrap_or(0);
            let p_flags = t.value(row, "p_flags").unwrap_or(0);
            let off = t.value(row, "p_offset").unwrap_or(0);
            let filesz = t.value(row, "p_filesz").unwrap_or(0);
            let vaddr = t.value(row, "p_vaddr").unwrap_or(0);
            let memsz = t.value(row, "p_memsz").unwrap_or(0);
            if let Some(found) = t.list.get_mut(row) {
                found.name = format!("Phdr[{index}] {}", segment_name(p_type));
            }
            t.note(row, "p_type", segment_name(p_type));
            t.note(row, "p_flags", perms(p_flags));
            end = end.max(ph_off.saturating_add((index as u64 + 1).saturating_mul(ph_size as u64)));
            match p_type {
                PT_LOAD => {
                    t.target(row, "p_vaddr", vaddr.saturating_add(bias));
                    loads.push(Load { off, filesz, vaddr });
                    end = end.max(off.saturating_add(filesz));
                    if p_flags & PF_X != 0 {
                        exec_ranges.push((vaddr, vaddr.saturating_add(memsz)));
                        if p_flags & PF_W != 0 {
                            details.warn(
                                format!(
                                    "Segment at {:#x} is both writable and executable",
                                    vaddr.saturating_add(bias)
                                ),
                                Some(vaddr.saturating_add(bias)),
                            );
                        }
                    }
                }
                PT_GNU_STACK => exec_stack = Some(p_flags & PF_X != 0),
                PT_GNU_RELRO => relro = true,
                _ => {}
            }
        }
    }

    // Section headers usually sit past the last segment, so they are not mapped.
    let sh_off = t.value(header, "e_shoff").unwrap_or(0);
    let sh_size = t.value(header, "e_shentsize").unwrap_or(0) as usize;
    let sh_count = t.value(header, "e_shnum").unwrap_or(0) as usize;
    let sh_specs = if wide { SHDR_64 } else { SHDR_32 };
    if sh_off != 0 && sh_size >= sh_specs.iter().map(|(_, ty)| ty.size()).sum() {
        for index in 0..sh_count {
            let Some(at) = usize::try_from(sh_off)
                .ok()
                .and_then(|base| base.checked_add(index.checked_mul(sh_size)?))
            else {
                break;
            };
            let Some(row) = t.add(format!("Shdr[{index}]"), at, sh_specs) else {
                break;
            };
            let name = t
                .value(row, "sh_name")
                .and_then(|n| elf.shdr_strtab.get_at(n as usize))
                .unwrap_or("")
                .to_owned();
            if let Some(found) = t.list.get_mut(row) {
                found.name = format!("Shdr[{index}] {name}");
            }
            let sh_type = t.value(row, "sh_type").unwrap_or(0);
            t.note(row, "sh_type", section_type_name(sh_type));
            t.note(
                row,
                "sh_flags",
                flags(
                    t.value(row, "sh_flags").unwrap_or(0),
                    &[
                        (1, "WRITE"),
                        (2, "ALLOC"),
                        (4, "EXECINSTR"),
                        (0x10, "MERGE"),
                        (0x20, "STRINGS"),
                        (0x400, "TLS"),
                    ],
                ),
            );
            let addr = t.value(row, "sh_addr").unwrap_or(0);
            if addr != 0 {
                t.target(row, "sh_addr", addr.saturating_add(bias));
            }
            end = end.max(sh_off.saturating_add((index as u64 + 1).saturating_mul(sh_size as u64)));
            if sh_type != SHT_NOBITS {
                let off = t.value(row, "sh_offset").unwrap_or(0);
                let size = t.value(row, "sh_size").unwrap_or(0);
                end = end.max(off.saturating_add(size));
            }
        }
    } else if sh_off == 0 && ph_count != 0 {
        details.info("The file has no section headers", None);
    }
    t.finish(&mut details, |off| {
        loads
            .iter()
            .find(|l| off >= l.off && off - l.off < l.filesz)
            .map(|l| l.vaddr.saturating_add(off - l.off).saturating_add(bias))
    });

    if entry != 0
        && !exec_ranges.is_empty()
        && !exec_ranges
            .iter()
            .any(|&(lo, hi)| entry >= lo && entry < hi)
    {
        details.warn(
            "The entry point is outside every executable segment",
            Some(entry.saturating_add(bias)),
        );
    }
    dependency_facts(elf, &mut details);
    hardening(elf, kind, relro, exec_stack, &mut details);
    for note in elf.iter_note_headers(bytes).into_iter().flatten().flatten() {
        if note.name == "GNU" && note.n_type == NT_GNU_BUILD_ID {
            details.fact("Build", "Build ID", hex(note.desc));
        }
    }
    if !elf
        .section_headers
        .iter()
        .any(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".symtab"))
    {
        details.fact("Build", "Symbols", "stripped");
    } else {
        details.fact("Build", "Symbols", format!("{} in .symtab", elf.syms.len()));
    }
    if end < bytes.len() as u64 {
        details.overlay(bytes, end, 0);
    }
    details
}

fn dependency_facts(elf: &Elf<'_>, details: &mut FileDetails) {
    if let Some(interpreter) = elf.interpreter {
        details.fact("Dependencies", "Interpreter", interpreter);
    } else if elf.libraries.is_empty() {
        details.fact("Dependencies", "Linking", "static");
    } else {
        details.fact("Dependencies", "Interpreter", "none");
    }
    if let Some(soname) = elf.soname {
        details.fact("Identity", "SONAME", soname);
    }
    for library in &elf.libraries {
        details.fact("Dependencies", "Needed", *library);
    }
    for path in &elf.rpaths {
        details.fact("Dependencies", "RPATH", *path);
    }
    for path in &elf.runpaths {
        details.fact("Dependencies", "RUNPATH", *path);
    }
    for path in elf.rpaths.iter().chain(&elf.runpaths) {
        if path
            .split(':')
            .any(|p| p.is_empty() || p == "." || p.starts_with("/tmp") || p.starts_with("./"))
        {
            details.warn(
                format!(
                    "The library search path {path:?} includes a writable or relative directory"
                ),
                None,
            );
        }
    }
}

fn hardening(
    elf: &Elf<'_>,
    kind: u64,
    relro: bool,
    exec_stack: Option<bool>,
    details: &mut FileDetails,
) {
    let yes_no = |value: bool| if value { "yes" } else { "no" };
    details.fact("Security", "PIE", yes_no(kind == 3));
    details.fact(
        "Security",
        "NX stack",
        match exec_stack {
            Some(true) => "no",
            Some(false) => "yes",
            None => "not declared",
        },
    );
    if exec_stack == Some(true) {
        details.warn("The stack is marked executable", None);
    }
    let bind_now = elf.dynamic.as_ref().is_some_and(|dynamic| {
        dynamic.dyns.iter().any(|d| {
            d.d_tag == DT_BIND_NOW
                || (d.d_tag == DT_FLAGS && d.d_val & 8 != 0)
                || (d.d_tag == DT_FLAGS_1 && d.d_val & 1 != 0)
        })
    });
    details.fact(
        "Security",
        "RELRO",
        match (relro, bind_now) {
            (true, true) => "full",
            (true, false) => "partial",
            _ => "no",
        },
    );
    let canary = elf.dynsyms.iter().chain(elf.syms.iter()).any(|sym| {
        let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("");
        name == "__stack_chk_fail"
    });
    details.fact("Security", "Stack canary import", yes_no(canary));
}
