//! Function discovery from stripped ELF unwind metadata and compiler entry sequences.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use binfera::extract::recovery::{analyze_with_backend, RecoveryBackend, SeedKind};

const CODE: usize = 0x200;
const FRAME: usize = 0x400;
const HEADER: usize = 0x380;
const SECTIONS: usize = 0x800;

fn u16_at(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_le_bytes());
}
fn u32_at(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn u64_at(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}

// A stripped executable with an unreferenced, frameless function at CODE+0x20.
// The exception metadata lives in a separate read-only PT_LOAD mapping.
fn elf(is64: bool, pie: bool, encoding: u8, section_headers: bool) -> (Vec<u8>, u64) {
    let mut b = vec![0; 0xa00];
    let base = if pie {
        0
    } else if is64 {
        0x400000
    } else {
        0x8048000
    };
    b[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', if is64 { 2 } else { 1 }, 1, 1]);
    u16_at(&mut b, 16, if pie { 3 } else { 2 });
    u16_at(&mut b, 18, if is64 { 62 } else { 3 });
    u32_at(&mut b, 20, 1);
    let (ehsize, phsize, shsize) = if is64 { (64, 56, 64) } else { (52, 32, 40) };
    if is64 {
        u64_at(&mut b, 24, base + CODE as u64);
        u64_at(&mut b, 32, ehsize as u64);
        u16_at(&mut b, 52, ehsize);
        u16_at(&mut b, 54, phsize);
        u16_at(&mut b, 56, 3);
        if section_headers {
            u64_at(&mut b, 40, SECTIONS as u64);
            u16_at(&mut b, 58, shsize);
            u16_at(&mut b, 60, 3);
            u16_at(&mut b, 62, 2);
        }
    } else {
        u32_at(&mut b, 24, (base + CODE as u64) as u32);
        u32_at(&mut b, 28, ehsize as u32);
        u16_at(&mut b, 40, ehsize);
        u16_at(&mut b, 42, phsize);
        u16_at(&mut b, 44, 3);
        if section_headers {
            u32_at(&mut b, 32, SECTIONS as u32);
            u16_at(&mut b, 46, shsize);
            u16_at(&mut b, 48, 3);
            u16_at(&mut b, 50, 2);
        }
    }
    for (i, (kind, offset, size, flags)) in [
        (1, 0, 0x300, 5),
        (1, 0x300, 0x700, 4),
        (0x6474e550, HEADER, 12, 4),
    ]
    .into_iter()
    .enumerate()
    {
        let p = ehsize as usize + i * phsize as usize;
        u32_at(&mut b, p, kind);
        if is64 {
            u32_at(&mut b, p + 4, flags);
            u64_at(&mut b, p + 8, offset as u64);
            u64_at(&mut b, p + 16, base + offset as u64);
            u64_at(&mut b, p + 32, size);
            u64_at(&mut b, p + 40, size);
            u64_at(&mut b, p + 48, 1);
        } else {
            u32_at(&mut b, p + 4, offset as u32);
            u32_at(&mut b, p + 8, (base + offset as u64) as u32);
            u32_at(&mut b, p + 16, size as u32);
            u32_at(&mut b, p + 20, size as u32);
            u32_at(&mut b, p + 24, flags);
            u32_at(&mut b, p + 28, 1);
        }
    }
    b[CODE..CODE + 0x100].fill(0xcc);
    b[CODE] = 0xc3;
    b[CODE + 0x20..CODE + 0x26].copy_from_slice(b"\xb8\x2a\x00\x00\x00\xc3");
    let cie = [
        0,
        0,
        0,
        0,
        1,
        b'z',
        b'R',
        0,
        1,
        if is64 { 0x78 } else { 0x7c },
        if is64 { 16 } else { 8 },
        1,
        encoding,
        0,
        0,
        0,
    ];
    u32_at(&mut b, FRAME, cie.len() as u32);
    b[FRAME + 4..FRAME + 20].copy_from_slice(&cie);
    let width = if encoding & 7 == 4 || (encoding == 0 && is64) {
        8
    } else {
        4
    };
    let fde_len = 4 + width * 2 + 4;
    u32_at(&mut b, FRAME + 20, fde_len as u32);
    u32_at(&mut b, FRAME + 24, 24);
    let target = base + CODE as u64 + 0x20;
    let initial = if encoding & 0x70 == 0x10 {
        target.wrapping_sub(base + FRAME as u64 + 28)
    } else {
        target
    };
    if width == 8 {
        u64_at(&mut b, FRAME + 28, initial);
        u64_at(&mut b, FRAME + 36, 6);
    } else {
        u32_at(&mut b, FRAME + 28, initial as u32);
        u32_at(&mut b, FRAME + 32, 6);
    }
    let frame_len = 24 + fde_len + 4;
    b[HEADER..HEADER + 4].copy_from_slice(&[1, 0x1b, 0xff, 0xff]);
    u32_at(&mut b, HEADER + 4, (FRAME - HEADER - 4) as u32);
    if section_headers {
        let sh = SECTIONS + shsize as usize;
        u32_at(&mut b, sh, 1);
        u32_at(&mut b, sh + 4, 1);
        if is64 {
            u64_at(&mut b, sh + 8, 2);
            u64_at(&mut b, sh + 16, base + FRAME as u64);
            u64_at(&mut b, sh + 24, FRAME as u64);
            u64_at(&mut b, sh + 32, frame_len as u64);
        } else {
            u32_at(&mut b, sh + 8, 2);
            u32_at(&mut b, sh + 12, (base + FRAME as u64) as u32);
            u32_at(&mut b, sh + 16, FRAME as u32);
            u32_at(&mut b, sh + 20, frame_len as u32);
        }
        let sh = sh + shsize as usize;
        u32_at(&mut b, sh, 11);
        u32_at(&mut b, sh + 4, 3);
        if is64 {
            u64_at(&mut b, sh + 24, 0x700);
            u64_at(&mut b, sh + 32, 21);
        } else {
            u32_at(&mut b, sh + 16, 0x700);
            u32_at(&mut b, sh + 20, 21);
        }
        b[0x700..0x715].copy_from_slice(b"\0.eh_frame\0.shstrtab\0");
    }
    (
        b,
        if pie {
            0x2000000 + CODE as u64 + 0x20
        } else {
            target
        },
    )
}

#[test]
fn stripped_frameless_functions_recover_with_sections_or_runtime_header() {
    for is64 in [false, true] {
        for pie in [false, true] {
            for encoding in [0, 0x1b, 0x1c] {
                for sections in [false, true] {
                    let (bytes, target) = elf(is64, pie, encoding, sections);
                    let a = analyze_with_backend(&bytes, RecoveryBackend::Native).unwrap();
                    assert!(
                        a.seeds[&target].contains(&SeedKind::EhFrame),
                        "{is64} {pie} {encoding} {sections}"
                    );
                    assert!(a.functions.contains_key(&target));
                    assert!(a.diagnostics.is_empty(), "{:?}", a.diagnostics);
                    let compat =
                        analyze_with_backend(&bytes, RecoveryBackend::VivisectCompat).unwrap();
                    assert!(!compat
                        .seeds
                        .values()
                        .any(|k| k.contains(&SeedKind::EhFrame)));
                }
            }
        }
    }
}

#[test]
fn malformed_frames_do_not_prevent_entry_recovery() {
    for (offset, value) in [(FRAME, u32::MAX), (FRAME + 24, u32::MAX), (FRAME + 20, 3)] {
        let (mut bytes, target) = elf(true, false, 0x1b, true);
        u32_at(&mut bytes, offset, value);
        let a = analyze_with_backend(&bytes, RecoveryBackend::Native).unwrap();
        assert!(a.functions.contains_key(&(target - 0x20)));
        assert!(!a
            .seeds
            .get(&target)
            .is_some_and(|k| k.contains(&SeedKind::EhFrame)));
        assert!(a
            .diagnostics
            .iter()
            .any(|d| d.message.contains(".eh_frame")));
    }
}

#[test]
fn empty_data_overflowing_and_out_of_mapping_fdes_are_rejected() {
    for (initial, len) in [
        (0x400220, 0),
        (0x400400, 6),
        (0x4002ff, 6),
        (u64::MAX - 2, 8),
    ] {
        let (mut bytes, target) = elf(true, false, 0, true);
        u64_at(&mut bytes, FRAME + 28, initial);
        u64_at(&mut bytes, FRAME + 36, len);
        let a = analyze_with_backend(&bytes, RecoveryBackend::Native).unwrap();
        assert!(!a.seeds.values().any(|k| k.contains(&SeedKind::EhFrame)));
        assert!(!a.functions.contains_key(&target));
    }
}

#[test]
fn corrupt_runtime_header_is_a_diagnostic() {
    let (mut bytes, _) = elf(true, true, 0x1b, false);
    bytes[HEADER] = 2;
    let a = analyze_with_backend(&bytes, RecoveryBackend::Native).unwrap();
    assert!(a
        .diagnostics
        .iter()
        .any(|d| d.message.contains(".eh_frame_hdr")));
}

#[test]
fn truncated_inputs_never_panic() {
    let (bytes, _) = elf(true, true, 0x1b, true);
    for len in 0..bytes.len() {
        let _ = analyze_with_backend(&bytes[..len], RecoveryBackend::Native);
    }
}

#[test]
fn cet_prologue_does_not_create_an_entry_after_endbr() {
    let (mut bytes, unwind) = elf(true, false, 0x1b, true);
    bytes[CODE + 0x40..CODE + 0x4b]
        .copy_from_slice(b"\xf3\x0f\x1e\xfa\x55\x48\x89\xe5\x90\x5d\xc3");
    let a = analyze_with_backend(&bytes, RecoveryBackend::Native).unwrap();
    let entry = unwind + 0x20;
    assert!(a.functions.contains_key(&entry));
    assert!(!a.functions.contains_key(&(entry + 4)));
}

#[test]
fn prologue_bytes_inside_an_immediate_do_not_create_a_function() {
    let (mut bytes, unwind) = elf(true, false, 0x1b, true);
    // MOVABS includes a complete-looking prologue in its immediate.
    bytes[CODE..CODE + 11].copy_from_slice(b"\x48\xb8\xcc\x55\x48\x89\xe5\x5d\xc3\x00\xc3");
    let a = analyze_with_backend(&bytes, RecoveryBackend::Native).unwrap();
    assert!(!a.functions.contains_key(&(unwind - 0x20 + 3)));
}

#[test]
fn unwind_entries_separate_fallthrough_function_scopes() {
    let (mut bytes, target) = elf(true, false, 0x1b, true);
    bytes[CODE..CODE + 0x20].fill(0x90);
    let a = analyze_with_backend(&bytes, RecoveryBackend::Native).unwrap();
    let first = &a.functions[&(target - 0x20)];
    assert!(first
        .blocks
        .iter()
        .flat_map(|b| &b.insns)
        .all(|i| i.address < target));
    assert!(a.functions.contains_key(&target));
}

#[test]
fn malformed_fde_does_not_hide_a_later_valid_record() {
    let (mut bytes, target) = elf(true, false, 0x1b, true);
    let record = bytes[FRAME + 20..FRAME + 40].to_vec();
    bytes[FRAME + 40..FRAME + 60].copy_from_slice(&record);
    u32_at(&mut bytes, FRAME + 24, 1); // Not a CIE record boundary.
    u32_at(&mut bytes, FRAME + 44, 44);
    u32_at(
        &mut bytes,
        FRAME + 48,
        (CODE as i32 + 0x20 - FRAME as i32 - 48) as u32,
    );
    u64_at(&mut bytes, SECTIONS + 64 + 32, 64);
    let a = analyze_with_backend(&bytes, RecoveryBackend::Native).unwrap();
    assert!(a.seeds[&target].contains(&SeedKind::EhFrame));
    assert!(a.functions.contains_key(&target));
    assert!(a
        .diagnostics
        .iter()
        .any(|d| d.message.contains(".eh_frame")));
}

#[test]
fn aarch64_fdes_require_aligned_file_backed_code() {
    for aligned in [false, true] {
        let (mut bytes, target) = elf(true, false, 0x1b, true);
        u16_at(&mut bytes, 18, 183);
        u32_at(&mut bytes, CODE, 0xd65f03c0); // RET
        u32_at(&mut bytes, CODE + 0x20, 0x52800540); // MOV W0, #42
        u32_at(&mut bytes, CODE + 0x24, 0xd65f03c0);
        u32_at(&mut bytes, FRAME + 32, if aligned { 8 } else { 7 });
        let a = analyze_with_backend(&bytes, RecoveryBackend::Native).unwrap();
        assert_eq!(
            a.seeds
                .get(&target)
                .is_some_and(|k| k.contains(&SeedKind::EhFrame)),
            aligned
        );
        assert_eq!(a.functions.contains_key(&target), aligned);
    }
}
