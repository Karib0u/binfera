//! Apple code signatures.
//! Layout reference: Apple xnu `osfmk/kern/cs_blobs.h`. All values are big-endian.
use super::{hex, pkcs7, FileDetails, Property, Signature};

const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade_7171;
const CSMAGIC_BLOBWRAPPER: u32 = 0xfade_0b01;
const CS_ADHOC: u32 = 0x0000_0002;
const CS_HARD: u32 = 0x0000_0100;
const CS_KILL: u32 = 0x0000_0200;
const CS_RESTRICT: u32 = 0x0000_0800;
const CS_RUNTIME: u32 = 0x0001_0000;
const CS_LINKER_SIGNED: u32 = 0x0002_0000;
const MAX_BLOBS: usize = 64;
const MAX_ENTITLEMENTS: usize = 256 * 1024;

fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    let raw = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes(raw.try_into().ok()?))
}

/// Reads the signature in `slice` at the `LC_CODE_SIGNATURE` range.
pub(super) fn collect(
    slice: &[u8],
    base: u64,
    dataoff: u64,
    datasize: u64,
    details: &mut FileDetails,
) {
    let blob = usize::try_from(dataoff).ok().and_then(|start| {
        let end = start.checked_add(usize::try_from(datasize).ok()?)?;
        slice.get(start..end)
    });
    let Some(blob) = blob else {
        details.warn("The code signature runs past the end of the file", None);
        return;
    };
    if be32(blob, 0) != Some(CSMAGIC_EMBEDDED_SIGNATURE) {
        details.warn("The code signature has an unknown format", None);
        return;
    }
    let count = be32(blob, 8).unwrap_or(0) as usize;
    let mut signature = Signature {
        kind: "Apple code signature".into(),
        off: base.saturating_add(dataoff),
        size: datasize,
        ..Signature::default()
    };
    let mut best_directory: Option<(&[u8], u8)> = None;
    for index in 0..count.min(MAX_BLOBS) {
        let at = 12 + index * 8;
        let Some(offset) = be32(blob, at + 4).map(|v| v as usize) else {
            break;
        };
        let Some(item) = blob.get(offset..) else {
            continue;
        };
        let Some(length) = be32(item, 4).map(|v| v as usize) else {
            continue;
        };
        let Some(item) = item.get(..length) else {
            continue;
        };
        match be32(item, 0) {
            Some(CSMAGIC_CODEDIRECTORY) => {
                // Alternate directories hold stronger hashes; keep the strongest.
                let hash_type = item.get(37).copied().unwrap_or(0);
                if best_directory.is_none_or(|(_, best)| hash_type > best) {
                    best_directory = Some((item, hash_type));
                }
            }
            Some(CSMAGIC_EMBEDDED_ENTITLEMENTS) => {
                let text = item.get(8..).unwrap_or_default();
                let shown = text.get(..text.len().min(MAX_ENTITLEMENTS)).unwrap_or(text);
                signature.entitlements = Some(String::from_utf8_lossy(shown).into_owned());
            }
            Some(CSMAGIC_BLOBWRAPPER) => {
                // An empty wrapper is how ad-hoc signatures leave the CMS slot.
                if let Some(signed) = item
                    .get(8..)
                    .filter(|b| !b.is_empty())
                    .and_then(pkcs7::parse)
                {
                    signature.signing_time = signed.signing_time;
                    signature.timestamp = signed.timestamp;
                    signature.timestamp_signer = signed.timestamp_signer;
                    signature.certificates = signed.certificates;
                }
            }
            _ => {}
        }
    }
    let Some((directory, _)) = best_directory else {
        details.warn("The code signature has no code directory", None);
        details.signatures.push(signature);
        return;
    };
    let cs_flags = read_directory(slice, directory, dataoff, &mut signature);
    let (status, hardened) = match cs_flags {
        Some(flags) => (signing_status(flags, &signature), flags & CS_RUNTIME != 0),
        None => ("signed".to_string(), false),
    };
    details.fact("Security", "Code signature", status);
    details.fact(
        "Security",
        "Hardened runtime",
        if hardened { "yes" } else { "no" },
    );
    if signature.digest_matches == Some(false) {
        details.warn(
            "The code signature's page hashes do not match, so the file changed after it was signed",
            None,
        );
    }
    details.signatures.push(signature);
}

fn signing_status(flags: u32, signature: &Signature) -> String {
    if flags & CS_LINKER_SIGNED != 0 {
        return "linker-signed (ad hoc)".into();
    }
    if flags & CS_ADHOC != 0 {
        return "ad hoc, no signing identity".into();
    }
    signature
        .certificates
        .iter()
        .find(|cert| cert.signer)
        .map_or_else(
            || "signed".into(),
            |cert| format!("signed by {}", cert.subject),
        )
}

fn read_directory(
    slice: &[u8],
    directory: &[u8],
    signature_off: u64,
    signature: &mut Signature,
) -> Option<u32> {
    let version = be32(directory, 8)?;
    let cs_flags = be32(directory, 12)?;
    let hash_offset = be32(directory, 16)? as usize;
    let ident_offset = be32(directory, 20)? as usize;
    let code_slots = be32(directory, 28)? as usize;
    let code_limit = be32(directory, 32)? as usize;
    let hash_size = usize::from(*directory.get(36)?);
    let hash_type = *directory.get(37)?;
    let page_shift = u32::from(*directory.get(39)?);
    let mut add = |label: &str, value: String| {
        signature.properties.push(Property {
            label: label.into(),
            value,
        });
    };
    if let Some(identifier) = super::c_string(directory, ident_offset, 512) {
        add("Identifier", identifier);
    }
    if version >= 0x20200 {
        if let Some(team) = be32(directory, 48)
            .filter(|&team| team != 0)
            .and_then(|team| super::c_string(directory, team as usize, 64))
        {
            add("Team ID", team);
        }
    }
    if cs_flags != 0 {
        add(
            "Flags",
            super::flags(
                u64::from(cs_flags),
                &[
                    (u64::from(CS_ADHOC), "adhoc"),
                    (u64::from(CS_HARD), "hard"),
                    (u64::from(CS_KILL), "kill"),
                    (u64::from(CS_RESTRICT), "restrict"),
                    (u64::from(CS_RUNTIME), "runtime"),
                    (u64::from(CS_LINKER_SIGNED), "linker-signed"),
                ],
            ),
        );
    }
    add("Directory version", format!("{version:#x}"));
    let algorithm = match hash_type {
        1 => "SHA-1",
        2 | 3 => "SHA-256",
        4 => "SHA-384",
        _ => return Some(cs_flags),
    };
    if let Some(cdhash) = pkcs7::digest(algorithm, &[directory]) {
        add("CDHash", cdhash.get(..40).unwrap_or(&cdhash).to_owned());
    }
    signature.digest_algorithm = Some(format!("{algorithm} per page"));
    signature.digest_matches = page_hashes_match(
        slice,
        directory,
        Pages {
            algorithm,
            hash_offset,
            hash_size,
            code_slots,
            code_limit,
            page_shift,
            signature_off,
        },
    );
    Some(cs_flags)
}

struct Pages {
    algorithm: &'static str,
    hash_offset: usize,
    hash_size: usize,
    code_slots: usize,
    code_limit: usize,
    page_shift: u32,
    signature_off: u64,
}

/// Compares every code page with its slot. `None` when the directory is not usable for this.
fn page_hashes_match(slice: &[u8], directory: &[u8], pages: Pages) -> Option<bool> {
    let size = 1usize
        .checked_shl(pages.page_shift)
        .filter(|_| pages.page_shift != 0)?;
    let limit = pages.code_limit;
    if limit > slice.len() || u64::try_from(limit).ok()? > pages.signature_off {
        return None;
    }
    if limit.div_ceil(size) != pages.code_slots {
        return Some(false);
    }
    for slot in 0..pages.code_slots {
        let start = slot.checked_mul(size)?;
        let end = start.checked_add(size)?.min(limit);
        let page = slice.get(start..end)?;
        let at = pages
            .hash_offset
            .checked_add(slot.checked_mul(pages.hash_size)?)?;
        let stored = directory.get(at..at.checked_add(pages.hash_size)?)?;
        let computed = pkcs7::digest(pages.algorithm, &[page])?;
        if computed.get(..pages.hash_size.checked_mul(2)?)? != hex(stored) {
            return Some(false);
        }
    }
    Some(true)
}
