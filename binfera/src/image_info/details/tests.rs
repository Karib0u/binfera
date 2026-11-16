//! Parsers shared between formats, on hand-built inputs.
use super::der;
use super::*;

#[test]
fn utc_renders_known_dates() {
    assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
    assert_eq!(utc(1_600_000_000), "2020-09-13 12:26:40 UTC");
}

#[test]
fn der_reads_definite_and_indefinite_lengths() -> Result<(), &'static str> {
    let definite = [0x30, 0x03, 0x02, 0x01, 0x05];
    let item = der::element(&definite).ok_or("definite")?;
    assert_eq!(item.content, [0x02, 0x01, 0x05]);
    let indefinite = [0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00, 0xff];
    let item = der::element(&indefinite).ok_or("indefinite")?;
    assert_eq!(item.content, [0x02, 0x01, 0x05]);
    assert_eq!(item.raw.len(), 7);
    Ok(())
}

#[test]
fn der_rejects_lengths_past_the_input() {
    assert!(der::element(&[0x30, 0x05, 0x02]).is_none());
    assert!(der::element(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_none());
    assert!(der::element(&[0x30, 0x80]).is_none());
}

#[test]
fn der_bounds_nested_indefinite_lengths() {
    let hostile: Vec<u8> = [0x30u8, 0x80].repeat(10_000);
    assert!(der::element(&hostile).is_none());
}

#[test]
fn der_decodes_oids_times_and_names() -> Result<(), &'static str> {
    assert_eq!(der::oid(&[0x55, 0x04, 0x03]).as_deref(), Some("2.5.4.3"));
    assert_eq!(
        der::oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]).as_deref(),
        Some("1.2.840.113549.1.7.2")
    );
    let time = der::element(b"\x17\x0d230102030405Z").ok_or("time")?;
    assert_eq!(der::time(time).as_deref(), Some("2023-01-02 03:04:05 UTC"));
    let name = [
        0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x01, b'x',
    ];
    let name = der::element(&name).ok_or("name")?;
    assert_eq!(der::name(name).as_deref(), Some("CN=x"));
    Ok(())
}

#[test]
fn identify_recognizes_payloads_without_trusting_mz_alone() {
    assert_eq!(identify(b"PK\x03\x04rest"), Some("ZIP"));
    assert_eq!(identify(b"\x7fELF...."), Some("ELF"));
    assert_eq!(identify(b"MZ only"), None);
    let mut pe = vec![0u8; 0x48];
    pe[..2].copy_from_slice(b"MZ");
    pe[0x3c] = 0x40;
    pe[0x40..0x44].copy_from_slice(b"PE\0\0");
    assert_eq!(identify(&pe), Some("PE"));
}

#[test]
fn tables_keep_the_fields_that_fit_and_read_either_endian() -> Result<(), &'static str> {
    use Ty::{U16, U32};
    let bytes = [0x12, 0x34, 0x56, 0x78, 0x9a];
    let mut big = Tables::new(&bytes, false, 0x100);
    let row = big.add("s", 0, &[("a", U16), ("b", U32)]).ok_or("row")?;
    assert_eq!(big.value(row, "a"), Some(0x1234));
    assert_eq!(big.value(row, "b"), None); // truncated, so dropped
    let found = big.list.first().ok_or("list")?;
    assert_eq!(found.off, 0x100);
    assert_eq!(found.size, 2);
    let mut little = Tables::new(&bytes, true, 0);
    let row = little.add("s", 0, &[("a", U16)]).ok_or("row")?;
    assert_eq!(little.value(row, "a"), Some(0x3412));
    Ok(())
}

#[test]
fn overlay_is_absent_at_the_end_of_the_file() {
    let mut details = FileDetails::default();
    details.overlay(&[0u8; 8], 8, 0);
    assert!(details.overlay.is_none());
    details.overlay(&[0u8; 8], 6, 0x40);
    assert_eq!(
        details.overlay.as_ref().map(|o| (o.off, o.size)),
        Some((0x46, 2))
    );
}
