//! Rust names, known runtime signatures and length-delimited UTF-8 strings.
//! Ghidra 12.1.4's RustConstants and RustStringAnalyzer provide the detection and string-splitting
//! reference. Lengths below come from slice descriptors or constant call arguments, not a NUL scan.
use std::collections::{BTreeMap, BTreeSet};

use iced_x86::{InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};

use crate::demangle;
use crate::extract::image::{ImageFormat, LoadedImage};
use crate::extract::recovery::Analysis;
use binfera_ghidra::{Session, ValueType as T};

const NORETURN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../third_party/ghidra/data/RustFunctionsThatDoNotReturn"
));

/// Match qualified names too, so the legacy-only upstream list also covers v0 symbols.
pub(super) fn noreturn(raw: &str) -> bool {
    let name = runtime_name(raw);
    // These broad upstream entries can return: the backtrace trampoline is generic and the
    // cleanup hook returns the caught exception. Do not erase reachable code at those calls.
    if name.contains("__rust_end_short_backtrace")
        || name.trim_start_matches('_') == "rust_panic_cleanup"
    {
        return false;
    }
    static NAMES: std::sync::OnceLock<BTreeSet<String>> = std::sync::OnceLock::new();
    NAMES
        .get_or_init(|| {
            NORETURN
                .lines()
                .map(str::trim)
                .filter(|s| !s.is_empty() && !s.starts_with('#'))
                .filter_map(|pattern| match pattern.strip_suffix('*') {
                    Some(prefix) => demangle::rust(&format!("_{prefix}0123456789abcdefE")),
                    None => Some(pattern.to_owned()),
                })
                .collect()
        })
        .contains(name.trim_start_matches('_'))
        || matches!(
            name.as_str(),
            "std::process::exit"
                | "std::panicking::rust_panic"
                | "core::panicking::panic_nounwind"
                | "core::panicking::panic_cannot_unwind"
                | "core::panicking::panic_in_cleanup"
                | "__rust_alloc_error_handler"
        )
}

fn runtime_name(raw: &str) -> String {
    let name = demangle::rust(raw).unwrap_or_else(|| raw.to_owned());
    // Current v0 allocator shims are qualified under __rustc; older ones are C symbols.
    name.strip_prefix("__rustc::").unwrap_or(&name).to_owned()
}

/// Only scalar/pointer signatures whose machine argument layout is known. Rust names do not
/// encode a prototype, and aggregate layouts (String, Vec, fmt::Arguments) vary with rustc.
fn signature(name: &str, wide: bool) -> Option<(T, Vec<T>)> {
    let usize = if wide { T::U64 } else { T::U32 };
    Some(match name {
        "__rust_alloc" | "__rust_alloc_zeroed" => (T::Pointer, vec![usize, usize]),
        "__rust_dealloc" => (T::Void, vec![T::Pointer, usize, usize]),
        "__rust_realloc" => (T::Pointer, vec![T::Pointer, usize, usize, usize]),
        "std::process::exit" => (T::Void, vec![T::I32]),
        "std::process::abort"
        | "std::sys::unix::abort_internal"
        | "core::panicking::panic_cannot_unwind"
        | "core::panicking::panic_in_cleanup" => (T::Void, vec![]),
        "core::panicking::panic_bounds_check" => (T::Void, vec![usize, usize, T::Pointer]),
        _ => return None,
    })
}

pub(super) fn detected(analysis: &Analysis, names: &BTreeMap<u64, String>) -> bool {
    names.values().any(|s| {
        demangle::rust(s).is_some() || matches!(s.as_str(), "__rust_alloc" | "__rust_probestack")
    }) || analysis
        .image
        .sections
        .iter()
        // Read-only data can share the executable segment (KrustyLoader's static PIE), so scan
        // every section: these markers are too specific to occur in code by chance.
        .any(|s| {
            let bytes = analysis
                .image
                .bytes_at(s.address, s.file_size as usize)
                .unwrap_or_default();
            // Ghidra's RustConstants.RUST_SIGNATURES, plus Windows rustc source paths.
            [
                b"RUST_BACKTRACE".as_slice(),
                b"RUST_MIN_STACK",
                b"/rustc/",
                b"\\rustc\\",
            ]
            .iter()
            .any(|marker| bytes.windows(marker.len()).any(|w| w == *marker))
        })
}

pub(super) fn apply_function(
    native: &mut Session,
    address: u64,
    raw: &str,
    image: &LoadedImage,
) -> Result<(), binfera_ghidra::Error> {
    if !image.architecture.is_x86() {
        return Ok(());
    }
    let name = runtime_name(raw);
    let known_rust = demangle::rust(raw).is_some()
        || name.starts_with("__rust_")
        || signature(&name, image.architecture.pointer_width() == 8).is_some();
    if !known_rust {
        return Ok(());
    }
    native.set_rust_function(address)?;
    if name == "__rust_probestack" {
        native.set_call_fixup(address, "__rust_probestack")?;
    } else if name == "__rust_try" {
        native.set_call_fixup(address, "__rust_try")?;
    } else if let Some((result, parameters)) =
        signature(&name, image.architecture.pointer_width() == 8)
    {
        let model = if image.format == ImageFormat::Pe && image.architecture.pointer_width() == 8 {
            "__fastcall"
        } else {
            "__cdecl"
        };
        native.set_method_signature(address, model, "", result, &parameters, false)?;
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct StringSlice {
    pub address: u64,
    pub length: u32,
    pub descriptors: BTreeSet<u64>,
}

// Local bounds: at most 4 MiB of decoded strings and 4096 distinct addresses per image.
const MAX_STRING: usize = 4096;
const MAX_STRINGS: usize = 4096;
const MAX_BYTES: usize = 4 << 20;

fn text(image: &LoadedImage, address: u64, length: u64) -> Option<&str> {
    let size = usize::try_from(length).ok()?;
    if size == 0 || size > MAX_STRING {
        return None;
    }
    let section = image.sections.iter().find(|s| s.contains_va(address))?;
    if section.permissions.execute
        || section.permissions.write
        || address.checked_add(length)? > section.address.checked_add(section.file_size)?
    {
        return None;
    }
    let bytes = image.bytes_at(address, size)?;
    if bytes.len() != size {
        return None;
    }
    let value = std::str::from_utf8(bytes).ok()?;
    value
        .chars()
        .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        .then_some(value)
}

pub(super) fn strings(analysis: &Analysis) -> Vec<StringSlice> {
    let image = &analysis.image;
    let width = image.architecture.pointer_width();
    let mut found = BTreeMap::<u64, StringSlice>::new();
    let mut ambiguous = BTreeSet::new();
    let mut total = 0;
    let mut descriptors = 0;
    let mut inspected = 0usize;
    let mut add = |address, length, descriptor| {
        if ambiguous.contains(&address)
            || length == 0
            || length > MAX_STRING as u64
            || descriptors >= MAX_STRINGS
        {
            return;
        }
        if let Some(previous) = found.get_mut(&address) {
            if u64::from(previous.length) != length {
                ambiguous.insert(address);
                found.remove(&address);
            } else if let Some(descriptor) = descriptor {
                if previous.descriptors.insert(descriptor) {
                    descriptors += 1;
                }
            }
        } else if found.len() < MAX_STRINGS && total + length as usize <= MAX_BYTES {
            // Bound UTF-8 validation too, including rejected candidate pairs.
            if inspected + length as usize > 16 * MAX_BYTES {
                return;
            }
            inspected += length as usize;
            if text(image, address, length).is_none() {
                return;
            }
            total += length as usize;
            descriptors += usize::from(descriptor.is_some());
            found.insert(
                address,
                StringSlice {
                    address,
                    length: length as u32,
                    descriptors: descriptor.into_iter().collect(),
                },
            );
        }
    };
    let word = |bytes: &[u8]| {
        if image.architecture.little_endian() {
            bytes
                .iter()
                .enumerate()
                .fold(0u64, |n, (i, b)| n | (u64::from(*b) << (8 * i)))
        } else {
            bytes.iter().fold(0u64, |n, b| (n << 8) | u64::from(*b))
        }
    };
    for section in image.sections.iter().filter(|s| !s.permissions.execute) {
        let bytes = image
            .bytes_at(section.address, section.file_size as usize)
            .unwrap_or_default();
        let start = ((width as u64 - section.address % width as u64) % width as u64) as usize;
        for offset in (start..bytes.len().saturating_sub(2 * width - 1)).step_by(width) {
            let address = word(&bytes[offset..offset + width]);
            let length = word(&bytes[offset + width..offset + 2 * width]);
            add(address, length, Some(section.address + offset as u64));
        }
    }
    if !image.architecture.is_x86() {
        return found.into_values().collect();
    }
    // Immediate pointer/length arguments to calls, within one basic block. Track copies but
    // invalidate every written register, and clear at calls; never carry facts across branches.
    let registers: &[Register] = if width == 8 && image.format == ImageFormat::Pe {
        &[Register::RCX, Register::RDX, Register::R8, Register::R9]
    } else if width == 8 {
        &[
            Register::RDI,
            Register::RSI,
            Register::RDX,
            Register::RCX,
            Register::R8,
            Register::R9,
        ]
    } else {
        &[]
    };
    let mut info = InstructionInfoFactory::new();
    for function in analysis.functions.values() {
        for block in &function.blocks {
            let mut values = BTreeMap::new();
            for instruction in &block.insns {
                let insn = instruction.x86_instruction();
                if insn.mnemonic() == Mnemonic::Call
                    || (insn.mnemonic() == Mnemonic::Jmp
                        && instruction
                            .direct_target
                            .is_some_and(|target| analysis.functions.contains_key(&target)))
                {
                    for pair in registers.windows(2) {
                        if let (Some(&address), Some(&length)) =
                            (values.get(&pair[0]), values.get(&pair[1]))
                        {
                            add(address, length, None);
                        }
                    }
                    values.clear();
                    continue;
                }
                let value =
                    if insn.op0_kind() == OpKind::Register && insn.mnemonic() == Mnemonic::Mov {
                        match insn.op1_kind() {
                            OpKind::Immediate64 => Some(insn.immediate64()),
                            OpKind::Immediate32 => Some(u64::from(insn.immediate32())),
                            OpKind::Immediate32to64 => Some(insn.immediate32to64() as u64),
                            OpKind::Register => {
                                values.get(&insn.op1_register().full_register()).copied()
                            }
                            _ => None,
                        }
                    } else if insn.mnemonic() == Mnemonic::Lea && insn.is_ip_rel_memory_operand() {
                        Some(insn.ip_rel_memory_address())
                    } else {
                        None
                    };
                for register in info.info(insn).used_registers() {
                    if matches!(
                        register.access(),
                        OpAccess::Write
                            | OpAccess::CondWrite
                            | OpAccess::ReadWrite
                            | OpAccess::ReadCondWrite
                    ) {
                        values.remove(&register.register().full_register());
                    }
                }
                if let Some(value) = value {
                    if insn.op0_register().size() >= 4 {
                        values.insert(insn.op0_register().full_register(), value);
                    }
                }
            }
        }
    }
    // A shorter slice starting inside another one cannot safely share a global array symbol.
    // Keep exact byte lengths in the string manager; the native label layer checks overlap.
    found.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::image::{Architecture, LoadedImage, SHELLCODE_BASE};

    #[test]
    fn no_return_is_exact_and_covers_both_manglings() {
        for name in [
            "_ZN4core9panicking18panic_bounds_check17h0123456789abcdefE",
            "_RNvNtC4core9panicking18panic_bounds_check",
            "__rust_start_panic",
            "std::process::exit",
        ] {
            assert!(noreturn(name), "{name}");
        }
        for name in [
            "_ZN4core9panicking18panic_bounds_check17hmalformed",
            "mycrate::panic",
            "std::panicking::try",
            "std::sys_common::backtrace::__rust_end_short_backtrace",
            "__rust_panic_cleanup",
            "std::process::exit_hook",
        ] {
            assert!(!noreturn(name), "{name}");
        }
    }

    #[test]
    fn validates_exact_utf8_byte_lengths_and_file_backing() {
        let bytes = "firstcafé\0invalid\u{1}".as_bytes();
        let mut image = LoadedImage::from_shellcode(bytes, Architecture::X64);
        image.sections[0].permissions.execute = false;
        image.sections[0].permissions.write = false;
        let at = SHELLCODE_BASE;
        assert_eq!(text(&image, at, 5), Some("first"));
        assert_eq!(text(&image, at + 5, 5), Some("café"));
        assert_eq!(text(&image, at + 5, 4), None);
        assert_eq!(text(&image, at, bytes.len() as u64), None);
        assert_eq!(text(&image, at, u64::MAX), None);
        assert_eq!(text(&image, u64::MAX, 4), None);
        assert_eq!(text(&image, at, 0), None);
        image.sections[0].permissions.write = true;
        assert_eq!(text(&image, at, 5), None);
    }

    #[test]
    fn static_slices_are_width_aware_and_conflicts_are_omitted() -> anyhow::Result<()> {
        use crate::extract::recovery::analyze_shellcode;
        for architecture in [Architecture::X86, Architecture::X64] {
            let width = architecture.pointer_width();
            let mut bytes = vec![0u8; 128];
            let pointer = SHELLCODE_BASE + 96;
            bytes[96..107].copy_from_slice(b"firstsecond");
            for (offset, address, length) in [(0, pointer, 5u64), (2 * width, pointer + 5, 6)] {
                bytes[offset..offset + width].copy_from_slice(&address.to_le_bytes()[..width]);
                bytes[offset + width..offset + 2 * width]
                    .copy_from_slice(&length.to_le_bytes()[..width]);
            }
            let mut analysis = analyze_shellcode(&[0xc3], architecture)?;
            analysis.functions.clear();
            analysis.image = LoadedImage::from_shellcode(&bytes, architecture);
            analysis.image.sections[0].permissions.execute = false;
            analysis.image.sections[0].permissions.write = false;
            let slices = strings(&analysis);
            assert_eq!(slices.len(), 2);
            assert_eq!((slices[0].address, slices[0].length), (pointer, 5));
            assert_eq!((slices[1].address, slices[1].length), (pointer + 5, 6));
            let offset = 4 * width;
            bytes[offset..offset + width].copy_from_slice(&pointer.to_le_bytes()[..width]);
            bytes[offset + width..offset + 2 * width]
                .copy_from_slice(&11u64.to_le_bytes()[..width]);
            analysis.image = LoadedImage::from_shellcode(&bytes, architecture);
            analysis.image.sections[0].permissions.execute = false;
            analysis.image.sections[0].permissions.write = false;
            assert_eq!(
                strings(&analysis)
                    .iter()
                    .map(|s| s.address)
                    .collect::<Vec<_>>(),
                vec![pointer + 5]
            );
            assert!(!detected(&analysis, &BTreeMap::new()));
        }
        Ok(())
    }

    #[test]
    fn only_known_scalar_signatures() {
        assert!(signature("__rust_alloc", true).is_some());
        assert!(signature("core::fmt::write", true).is_none());
        assert!(signature("std::string::String::new", true).is_none());
        assert!(signature("user::__rust_alloc", true).is_none());
        assert_eq!(
            signature("__rust_realloc", false),
            Some((T::Pointer, vec![T::Pointer, T::U32, T::U32, T::U32]))
        );
    }
}

#[cfg(test)]
mod native_tests {
    use super::*;
    use crate::extract::image::{Architecture, LoadedImage};
    use binfera_ghidra::Language;

    #[test]
    fn native_slices_reject_bad_utf8_and_descriptors() -> anyhow::Result<()> {
        let mut native = Session::new(Language::X86Linux64)?;
        native.add_section(0x2000, b"firstsecond", false, true)?;
        native.add_section(0x3000, &[0xc3], false, true)?;
        native.add_section(0x4000, &[0; 16], false, true)?;
        assert!(!native.add_rust_string(0x3000, 1, 0)?);
        assert!(!native.add_rust_string(0x2000, 5, 0x4000)?);
        assert!(!native.add_rust_string(0x2000, 0, 0)?);
        assert!(!native.add_rust_string(0x2000, u32::MAX, 0)?);
        assert!(!native.add_rust_string(u64::MAX, 5, 0)?);
        assert!(native.add_rust_string(0x2000, 5, 0)?);
        assert!(native.add_rust_string(0x2005, 6, 0)?);
        Ok(())
    }

    #[test]
    fn runtime_signatures_and_noreturn_reach_native_calls() -> anyhow::Result<()> {
        for (language, architecture, format, prefix) in [
            (
                Language::X86Windows64,
                Architecture::X64,
                ImageFormat::Pe,
                vec![0xb9, 32, 0, 0, 0, 0xba, 8, 0, 0, 0],
            ),
            (
                Language::X86Linux64,
                Architecture::X64,
                ImageFormat::Elf,
                vec![0xbf, 32, 0, 0, 0, 0xbe, 8, 0, 0, 0],
            ),
            (
                Language::X86Windows32,
                Architecture::X86,
                ImageFormat::Pe,
                vec![0x6a, 8, 0x6a, 32],
            ),
            (
                Language::X86Linux32,
                Architecture::X86,
                ImageFormat::Elf,
                vec![0x6a, 8, 0x6a, 32],
            ),
        ] {
            let mut code = prefix;
            let rel = 0x80i32 - (code.len() as i32 + 5);
            code.push(0xe8);
            code.extend_from_slice(&rel.to_le_bytes());
            if architecture == Architecture::X86 {
                code.extend_from_slice(&[0x83, 0xc4, 8]);
            }
            code.extend_from_slice(&[0xb8, 42, 0, 0, 0, 0xc3]);
            code.resize(0x81, 0xc3);
            let mut image = LoadedImage::from_shellcode(&code, architecture);
            image.format = format;
            for (name, no_return) in [("__rust_alloc", false), ("std::process::exit", true)] {
                let mut native = Session::new(language)?;
                native.add_section(0x1000, &code, true, true)?;
                native.add_function(0x1000, "caller", false)?;
                native.add_function(0x1080, name, noreturn(name))?;
                apply_function(&mut native, 0x1080, name, &image)?;
                let out = native.decompile(0x1000, 5000, 1000, 10_000_000)?;
                assert!(!out.unknown_callees, "{}", out.text);
                if no_return {
                    assert!(!out.text.contains("0x2a"), "{}", out.text);
                } else {
                    assert!(out.text.contains("__rust_alloc(0x20,8)"), "{}", out.text);
                }
                native.add_section(0x2000, &[0; 16], false, false)?;
                native.add_import(0x2000, "__rust_alloc", false)?;
                apply_function(&mut native, 0x2000, "__rust_alloc", &image)?;
            }
        }
        Ok(())
    }
}
