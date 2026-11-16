use binfera::extract::image::ImageError;
use binfera::image_info::inspect_shellcode;

#[test]
fn guesses_pointer_width_and_maps_file_offsets() -> Result<(), ImageError> {
    let x64 = inspect_shellcode(&[0x48, 0x89, 0xe5, 0x48, 0x31, 0xc0, 0xc3], None)?;
    assert_eq!(x64.format, "sc64");
    assert_eq!(x64.entry, Some(0));
    assert_eq!(x64.regions[0].va, 0);
    assert_eq!(x64.regions[0].size, 7);
    let x86 = inspect_shellcode(&[0x55, 0x89, 0xe5, 0x8b, 0x45, 8, 0x5d, 0xc3], None)?;
    assert_eq!(x86.format, "sc32");
    Ok(())
}

#[test]
fn exposes_ambiguity_and_allows_override() -> Result<(), ImageError> {
    let info = inspect_shellcode(&[0x31, 0xc0, 0xc3], None)?;
    assert!(info.warnings[0].contains("ambiguous"));
    let forced = inspect_shellcode(&[0x31, 0xc0, 0xc3], Some(true))?;
    assert_eq!(forced.format, "sc64");
    assert!(!forced.warnings[0].contains("guess"));
    Ok(())
}

#[test]
fn rejects_empty_uniform_text_and_invalid_input() {
    for bytes in [&[][..], &[0; 16], b"ordinary text file\n", &[0x0f, 0x0f]] {
        assert!(inspect_shellcode(bytes, None).is_err());
    }
}

#[test]
fn handles_padding_branches_prefixed_rex_and_syscalls() -> Result<(), ImageError> {
    // Prefixes before REX and RIP-relative loads are stronger evidence than instruction count.
    for bytes in [
        &[0x66, 0x48, 0x89, 0xc8, 0x48, 0x01, 0xd0, 0xc3][..],
        &[0x48, 0x8d, 0x05, 0, 0, 0, 0, 0xc3],
        &[0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05],
        &[0xeb, 2, 0xff, 0xff, 0x48, 0x89, 0xc8, 0xc3],
    ] {
        assert_eq!(inspect_shellcode(bytes, None)?.format, "sc64");
    }
    let mut padded = vec![0x90; 4096];
    padded.extend_from_slice(&[0x48, 0x89, 0xc8, 0xc3]);
    assert_eq!(inspect_shellcode(&padded, None)?.format, "sc64");
    Ok(())
}

#[test]
fn infers_os_only_from_specific_evidence() -> Result<(), ImageError> {
    let linux = inspect_shellcode(&[0x31, 0xc0, 0x40, 0xcd, 0x80], None)?;
    assert_eq!(linux.format, "sc32");
    assert_eq!(
        linux.shellcode.as_ref().and_then(|s| s.os.as_deref()),
        Some("linux")
    );
    let windows = inspect_shellcode(&[0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0, 0, 0, 0xc3], None)?;
    assert_eq!(windows.format, "sc64");
    assert_eq!(
        windows.shellcode.as_ref().and_then(|s| s.os.as_deref()),
        Some("windows")
    );
    // SYSCALL appears on more than one OS, and must not default the hint to Linux.
    let unknown = inspect_shellcode(&[0xb8, 60, 0, 0, 0, 0x0f, 0x05], None)?;
    assert!(unknown.shellcode.as_ref().is_some_and(|s| s.os.is_none()));
    Ok(())
}

#[test]
fn permits_manual_import_of_short_and_printable_code() -> Result<(), ImageError> {
    assert!(inspect_shellcode(&[0xc3], None)?
        .shellcode
        .is_some_and(|s| s.ambiguous));
    let forced = inspect_shellcode(b"PYAI", Some(false))?;
    assert_eq!(forced.format, "sc32");
    assert!(inspect_shellcode(&[], Some(false)).is_err());
    Ok(())
}

#[test]
fn shared_push_pop_and_getpc_do_not_imply_x64() -> Result<(), ImageError> {
    for bytes in [
        &[0x50, 0x58, 0xc3][..],
        &[0xe8, 0, 0, 0, 0, 0x5b, 0x31, 0xc0, 0xc3],
    ] {
        let info = inspect_shellcode(bytes, None)?;
        assert_eq!(info.format, "sc32");
        assert!(info.shellcode.is_some_and(|s| s.ambiguous));
    }
    Ok(())
}
