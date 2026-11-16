//! Conservative subset of Ghidra 12.1.4's x86win, x86gcc, x86delphi and x86-64
//! pattern families. New signatures require padding, a return, or a mapping boundary.
//! These remain weak seeds: recovery visits authoritative entries and calls first.

use super::decoder::Flow;
use super::image::{Architecture, ImageFormat, LoadedImage};

pub(super) fn match_len(image: &LoadedImage, bytes: &[u8], offset: usize) -> Option<usize> {
    let rest = bytes.get(offset..)?;
    let cet = match image.architecture {
        Architecture::X86 => b"\xf3\x0f\x1e\xfb",
        Architecture::X64 => b"\xf3\x0f\x1e\xfa",
        _ => return None,
    };
    let prefix = usize::from(rest.starts_with(cet)) * 4;
    let body = rest.get(prefix..)?;
    let old: &[&[u8]] = match image.architecture {
        Architecture::X86 => &[
            b"\x8b\xff\x55\x8b\xec",
            b"\x55\x8b\xec",
            b"\x55\x89\xe5",
            b"\x56\x8b\xf1",
        ],
        Architecture::X64 => &[
            b"\x55\x48\x89\xe5",
            b"\x40\x53\x48\x83\xec",
            b"\x48\x89\x5c\x24",
        ],
        _ => &[],
    };
    if let Some(len) = longest(body, old) {
        return Some(prefix + len);
    }
    // Raw images have no unwind records or symbols. Their compiler-aligned
    // entries need not be aligned to file offset zero (a loader stub precedes them).
    if image.format == ImageFormat::Sc
        && offset >= 3
        && (bytes[..offset].ends_with(b"\x90\x90\x90")
            || bytes[..offset].ends_with(b"\xcc\xcc\xcc"))
        && !matches!(body.first(), None | Some(0x90 | 0xcc | 0x00))
        && raw_entry(image, image.image_base + offset as u64)
    {
        return Some(1);
    }
    if !boundary(&bytes[..offset]) {
        return None;
    }
    let patterns: &[&[u8]] = match image.architecture {
        Architecture::X86 if image.format == ImageFormat::Pe => &[
            b"\x53\x8b\xd8",
            b"\x53\x8b\xd9",
            b"\x53\x8b\xda",
            b"\x53\x8b\xdb",
            b"\x53\x56\x57",
            b"\x53\x55\x56",
            b"\x53\x56\x51",
            b"\x53\x56\x8b\xf2",
            b"\x53\x56\x8b\xd8",
            b"\x53\x56\x8b\xf1",
            b"\x53\x56\x8b\xda",
            b"\x53\x56\x8b\xf0",
            b"\x56\x57\x8b\xf9",
            b"\x56\x57\x8b\xf1",
            b"\x55\x57\x56\x53",
            b"\x53\x56\x84\xd2",
        ],
        Architecture::X64 => &[
            b"\x53\x48\x89\xfb",
            b"\x55\x48\x89\xfd",
            b"\x41\x57\x41\x56\x41\x55",
            b"\x41\x56\x41\x55",
            b"\x41\x55\x41\x54",
            b"\x55\x48\x8d\x2c\x24",
            b"\x55\x48\x83\xec",
            b"\xff\xf5\x48\x83\xec",
        ],
        _ => &[],
    };
    if let Some(len) = longest(body, patterns) {
        return Some(prefix + len);
    }
    let masked: &[(&[u8], &[u8])] = match image.architecture {
        Architecture::X86 => &[
            // GCC stack realignment, including MinGW.
            (
                b"\x8d\x4c\x24\x04\x83\xe4\xf0",
                b"\xff\xff\x3f\xff\xff\xff\xf0",
            ),
            (
                b"\x57\x8d\x7c\x24\x08\x83\xe4\xf0",
                b"\xff\xff\xff\x3f\xff\xff\xff\xf0",
            ),
            (
                b"\x83\xec\x00\x89\x44\x24\x00",
                b"\xff\xff\x83\xfd\xc7\x3f\x83",
            ),
        ],
        Architecture::X64 => &[
            (b"\x53\x48\x83\xec\x00", b"\xff\xff\xff\xff\x87"),
            (b"\x41\x54\x55\x48\x89\xc0", b"\xff\xff\xff\xfe\xff\xc0"),
            (
                b"\x41\x54\x55\x53\x48\x89\xc0",
                b"\xff\xff\xff\xff\xfe\xff\xc0",
            ),
        ],
        _ => &[],
    };
    if let Some(len) = masked
        .iter()
        .filter(|(pattern, mask)| {
            body.get(..pattern.len()).is_some_and(|candidate| {
                candidate
                    .iter()
                    .zip(pattern.iter())
                    .zip(mask.iter())
                    .all(|((&actual, &expected), &mask)| actual & mask == expected)
            })
        })
        .map(|(p, _)| p.len())
        .max()
    {
        return Some(prefix + len);
    }
    // The shorter Windows x64 patterns need at least three filler bytes.
    if image.architecture == Architecture::X64
        && image.format == ImageFormat::Pe
        && (bytes[..offset].ends_with(b"\x90\x90\x90")
            || bytes[..offset].ends_with(b"\xcc\xcc\xcc"))
    {
        return longest(body, &[b"\x48\x83\xec", b"\x48\x8b\xc4"]).map(|len| prefix + len);
    }
    None
}

pub(super) fn raw_entry(image: &LoadedImage, start: u64) -> bool {
    use iced_x86::Mnemonic;
    let mut address = start;
    for count in 0..64 {
        let Ok(decoded) = image.decode_at(address) else {
            return false;
        };
        let i = decoded.x86_instruction();
        if count == 0
            && !matches!(
                i.mnemonic(),
                Mnemonic::Push
                    | Mnemonic::Mov
                    | Mnemonic::Movzx
                    | Mnemonic::Movsx
                    | Mnemonic::Cmp
                    | Mnemonic::Lea
                    | Mnemonic::Sub
                    | Mnemonic::Xor
                    | Mnemonic::Test
                    | Mnemonic::Bswap
                    | Mnemonic::Ret
                    | Mnemonic::Call
                    | Mnemonic::Jmp
            )
        {
            return false;
        }
        if matches!(
            i.mnemonic(),
            Mnemonic::Int3 | Mnemonic::INVALID | Mnemonic::Add
        ) && i.op0_kind() == iced_x86::OpKind::Memory
        {
            return false;
        }
        match decoded.flow {
            Flow::Return => return true,
            Flow::UnconditionalBranch | Flow::ConditionalBranch => {
                return decoded
                    .direct_target
                    .is_some_and(|target| image.is_executable_address(target))
            }
            Flow::IndirectBranch => return count > 0,
            Flow::Terminal => return false,
            _ => address = decoded.next_address,
        }
    }
    false
}

fn longest(bytes: &[u8], patterns: &[&[u8]]) -> Option<usize> {
    patterns
        .iter()
        .filter(|pattern| bytes.starts_with(pattern))
        .map(|pattern| pattern.len())
        .max()
}

pub(super) fn boundary(before: &[u8]) -> bool {
    if before.is_empty() {
        return true;
    }
    // Complete common padding encodings from the pre-pattern files. Do not accept a
    // wildcard JMP displacement or a lone zero byte as evidence of a boundary.
    const PRE: &[&[u8]] = &[
        b"\xcc",
        b"\x90",
        b"\xc3",
        b"\x89\xf6",
        b"\x8d\x76\x00",
        b"\x8d\x74\x26\x00",
        b"\x0f\x1f\x00",
        b"\x0f\x1f\x40\x00",
        b"\x0f\x1f\x44\x00\x00",
        b"\x0f\x1f\x80\x00\x00\x00\x00",
        b"\x0f\x1f\x84\x00\x00\x00\x00\x00",
    ];
    PRE.iter().any(|p| before.ends_with(p))
        || before
            .get(before.len().saturating_sub(3)..)
            .is_some_and(|tail| {
                tail.len() == 3 && tail[0] == 0xc2 && tail[1] & 3 == 0 && tail[2] == 0
            })
}

pub(super) fn valid_code(image: &LoadedImage, start: u64, pattern_len: usize) -> bool {
    let mut address = start;
    // Check complete instructions, not just a first PUSH. A short leaf may return
    // before six instructions, but the entire signature must have decoded first.
    for _ in 0..6 {
        let Ok(insn) = image.decode_at(address) else {
            return false;
        };
        if image.va_to_file_offset(insn.next_address - 1).is_none() {
            return false;
        }
        if !matches!(insn.flow, Flow::Next | Flow::Call) {
            return insn.next_address - start >= pattern_len as u64
                && matches!(
                    insn.flow,
                    Flow::Return | Flow::UnconditionalBranch | Flow::ConditionalBranch
                );
        }
        address = insn.next_address;
    }
    address - start >= pattern_len as u64
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn image(bytes: &[u8], arch: Architecture, format: ImageFormat) -> LoadedImage {
        let mut image = LoadedImage::from_shellcode(bytes, arch);
        image.format = format;
        image
    }

    #[test]
    fn compiler_entries_require_context_and_complete_instructions() {
        for (arch, format, code) in [
            (
                Architecture::X86,
                ImageFormat::Pe,
                &b"\x53\x56\x57\x5f\x5e\x5b\xc3"[..],
            ),
            (
                Architecture::X86,
                ImageFormat::Pe,
                &b"\x53\x8b\xd8\x5b\xc3"[..],
            ),
            (
                Architecture::X86,
                ImageFormat::Elf,
                &b"\x8d\x4c\x24\x04\x83\xe4\xf0\xc3"[..],
            ),
            (
                Architecture::X64,
                ImageFormat::Elf,
                &b"\x41\x57\x41\x56\x41\x55\x41\x5d\x41\x5e\x41\x5f\xc3"[..],
            ),
            (
                Architecture::X64,
                ImageFormat::Pe,
                &b"\x55\x48\x8d\x2c\x24\x5d\xc3"[..],
            ),
        ] {
            for prefix in [
                &b"\xcc"[..],
                &b"\xc3"[..],
                &b"\x0f\x1f\x44\x00\x00"[..],
                &b""[..],
            ] {
                let bytes = [prefix, code].concat();
                let image = image(&bytes, arch, format);
                let len = match_len(&image, &bytes, prefix.len()).unwrap();
                assert!(valid_code(
                    &image,
                    image.image_base + prefix.len() as u64,
                    len
                ));
            }
            let bytes = [&b"\x01"[..], code].concat();
            assert!(match_len(&image(&bytes, arch, format), &bytes, 1).is_none());
        }
        let bytes = b"\xcc\xcc\xcc\x48\x83\xec";
        let image = image(bytes, Architecture::X64, ImageFormat::Pe);
        assert!(match_len(&image, bytes, 3).is_some());
        assert!(!valid_code(&image, image.image_base + 3, 3));
    }

    #[test]
    fn cet_keeps_the_entry_at_endbr_and_does_not_match_endbr_alone() {
        for (arch, code) in [
            (
                Architecture::X86,
                &b"\xf3\x0f\x1e\xfb\x55\x89\xe5\x5d\xc3"[..],
            ),
            (
                Architecture::X64,
                &b"\xf3\x0f\x1e\xfa\x55\x48\x89\xe5\x5d\xc3"[..],
            ),
        ] {
            let image = image(code, arch, ImageFormat::Elf);
            let len = match_len(&image, code, 0).unwrap();
            assert!(len > 4);
            assert!(valid_code(&image, image.image_base, len));
            assert!(match_len(&image, &code[..4], 0).is_none());
        }
    }
}
