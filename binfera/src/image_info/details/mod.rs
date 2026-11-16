//! Format structures and triage facts read directly from untrusted file bytes.
//!
//! Collection never fails an inspection: every read is bounded, and what cannot
//! be read becomes a note. Offsets always refer to the original input.
use serde::Serialize;

mod codesign;
mod der;
pub(super) mod elf;
pub(super) mod macho;
mod ordinals;
pub(super) mod pe;
mod pkcs7;
mod resources;
#[cfg(test)]
mod tests;

/// More header fields than any legitimate image has; the listing stays usable on hostile counts.
const MAX_FIELDS: usize = 32_768;

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileDetails {
    pub structures: Vec<Structure>,
    pub facts: Vec<Fact>,
    pub anomalies: Vec<Anomaly>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlay: Option<Overlay>,
    pub resources: Vec<Resource>,
    pub version_info: Vec<Property>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<String>,
    pub signatures: Vec<Signature>,
}

/// One on-disk header; `va` is absent when the loader does not map it.
#[derive(Debug, Serialize)]
pub struct Structure {
    pub name: String,
    pub off: u64,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub va: Option<u64>,
    pub fields: Vec<Field>,
}

#[derive(Debug, Serialize)]
pub struct Field {
    pub name: String,
    pub off: u64,
    pub size: u64,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// A virtual address the field refers to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<u64>,
    #[serde(skip)]
    raw: u64,
}

#[derive(Debug, Serialize)]
pub struct Fact {
    pub group: &'static str,
    pub label: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub va: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct Anomaly {
    /// "warn" for something suspicious, "info" for a trait or an unreadable part of the file.
    pub severity: &'static str,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub va: Option<u64>,
}

/// File bytes no header accounts for.
#[derive(Debug, Serialize)]
pub struct Overlay {
    pub off: u64,
    pub size: u64,
    pub entropy: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct Resource {
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
    pub lang: String,
    pub va: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub off: Option<u64>,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detected: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct Property {
    pub label: String,
    pub value: String,
}

/// What a signature claims and whether the file still matches it. Chains are never
/// validated, so a matching digest says the file is intact, not that it is trustworthy.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Signature {
    pub kind: String,
    pub off: u64,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub computed_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest_matches: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_signer: Option<String>,
    pub properties: Vec<Property>,
    pub certificates: Vec<Certificate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlements: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Certificate {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub sha1: String,
    pub sha256: String,
    pub signer: bool,
    pub self_signed: bool,
}

impl FileDetails {
    fn fact(&mut self, group: &'static str, label: &str, value: impl Into<String>) {
        self.facts.push(Fact {
            group,
            label: label.into(),
            value: value.into(),
            va: None,
        });
    }

    fn fact_at(&mut self, group: &'static str, label: &str, value: impl Into<String>, va: u64) {
        self.facts.push(Fact {
            group,
            label: label.into(),
            value: value.into(),
            va: Some(va),
        });
    }

    fn warn(&mut self, text: impl Into<String>, va: Option<u64>) {
        self.anomalies.push(Anomaly {
            severity: "warn",
            text: text.into(),
            va,
        });
    }

    fn info(&mut self, text: impl Into<String>, va: Option<u64>) {
        self.anomalies.push(Anomaly {
            severity: "info",
            text: text.into(),
            va,
        });
    }

    fn hashes(&mut self, bytes: &[u8]) {
        let hashes = crate::extract::sample_hashes(bytes);
        self.fact("Hashes", "MD5", hashes.md5);
        self.fact("Hashes", "SHA-1", hashes.sha1);
        self.fact("Hashes", "SHA-256", hashes.sha256);
    }

    /// Records the bytes past `end`, the last byte `bytes` accounts for.
    fn overlay(&mut self, bytes: &[u8], end: u64, base: u64) {
        let Some(data) = usize::try_from(end).ok().and_then(|end| bytes.get(end..)) else {
            return;
        };
        if data.is_empty() {
            return;
        }
        let entry = Overlay {
            off: base.saturating_add(end),
            size: data.len() as u64,
            entropy: crate::packing::entropy(data),
            kind: identify(data),
        };
        match entry.kind {
            Some(kind) if is_executable(kind) => self.warn(
                format!(
                    "{} overlay at file offset {:#x} holds an embedded {kind}",
                    size_text(entry.size),
                    entry.off
                ),
                None,
            ),
            _ => self.info(
                format!(
                    "{} of data after the last mapped byte, at file offset {:#x}",
                    size_text(entry.size),
                    entry.off
                ),
                None,
            ),
        }
        self.overlay = Some(entry);
    }
}

fn is_executable(kind: &str) -> bool {
    matches!(kind, "PE" | "ELF" | "Mach-O")
}

/// A file type from its leading bytes alone, enough to flag payloads worth a look.
fn identify(data: &[u8]) -> Option<&'static str> {
    const MAGICS: &[(&[u8], &str)] = &[
        (b"\x7fELF", "ELF"),
        (b"\xfe\xed\xfa\xce", "Mach-O"),
        (b"\xfe\xed\xfa\xcf", "Mach-O"),
        (b"\xce\xfa\xed\xfe", "Mach-O"),
        (b"\xcf\xfa\xed\xfe", "Mach-O"),
        (b"PK\x03\x04", "ZIP"),
        (b"Rar!\x1a\x07", "RAR"),
        (b"7z\xbc\xaf\x27\x1c", "7z"),
        (b"\x1f\x8b", "gzip"),
        (b"BZh", "bzip2"),
        (b"\xfd7zXZ\x00", "xz"),
        (b"MSCF", "CAB"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE document"),
        (b"%PDF-", "PDF"),
        (b"\x89PNG\r\n\x1a\n", "PNG"),
        (b"\xff\xd8\xff", "JPEG"),
        (b"GIF8", "GIF"),
        (b"<?xml", "XML"),
    ];
    if is_pe(data) {
        return Some("PE");
    }
    MAGICS
        .iter()
        .find(|(magic, _)| data.starts_with(magic))
        .map(|&(_, kind)| kind)
}

fn is_pe(data: &[u8]) -> bool {
    if !data.starts_with(b"MZ") {
        return false;
    }
    let lfanew = data
        .get(0x3c..0x40)
        .and_then(|raw| <[u8; 4]>::try_from(raw).ok())
        .map(u32::from_le_bytes);
    lfanew
        .and_then(|at| usize::try_from(at).ok())
        .and_then(|at| data.get(at..at.checked_add(4)?))
        .is_some_and(|sig| sig == b"PE\0\0")
}

fn size_text(size: u64) -> String {
    match size {
        0..=1023 => format!("{size} bytes"),
        1024..=1_048_575 => format!("{:.1} KiB", size as f64 / 1024.0),
        _ => format!("{:.1} MiB", size as f64 / 1_048_576.0),
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // infallible: writing to a String never fails.
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// A NUL-terminated string, capped so a missing terminator cannot read the whole file.
fn c_string(bytes: &[u8], at: usize, max: usize) -> Option<String> {
    let rest = bytes.get(at..)?;
    let rest = rest.get(..max.min(rest.len()))?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    Some(String::from_utf8_lossy(rest.get(..end)?).into_owned())
}

/// `seconds` since the Unix epoch as a UTC date, by Howard Hinnant's civil-from-days.
fn utc(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let secs = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

fn now() -> Option<i64> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    i64::try_from(elapsed.as_secs()).ok()
}

/// The named bits of `value`, then whatever bits have no name.
fn flags(value: u64, names: &[(u64, &str)]) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut rest = value;
    for &(bit, name) in names {
        if value & bit == bit && bit != 0 {
            out.push(name.into());
            rest &= !bit;
        }
    }
    if rest != 0 {
        out.push(format!("{rest:#x}"));
    }
    out.join(" | ")
}

#[derive(Clone, Copy)]
enum Ty {
    U8,
    U16,
    U32,
    U64,
    /// Fixed-width text such as a section name.
    Text(usize),
    Bytes(usize),
}

impl Ty {
    fn size(self) -> usize {
        match self {
            Ty::U8 => 1,
            Ty::U16 => 2,
            Ty::U32 => 4,
            Ty::U64 => 8,
            Ty::Text(n) | Ty::Bytes(n) => n,
        }
    }
}

type Spec = (&'static str, Ty);

/// Lays out on-disk structures over the bytes of one image.
struct Tables<'a> {
    bytes: &'a [u8],
    little: bool,
    /// Where `bytes` starts in the original input.
    base: u64,
    list: Vec<Structure>,
    fields: usize,
    truncated: bool,
}

impl<'a> Tables<'a> {
    fn new(bytes: &'a [u8], little: bool, base: u64) -> Self {
        Self {
            bytes,
            little,
            base,
            list: Vec::new(),
            fields: 0,
            truncated: false,
        }
    }

    fn int(&self, at: usize, size: usize) -> Option<u64> {
        let raw = self.bytes.get(at..at.checked_add(size)?)?;
        let mut value = 0u64;
        for (index, &byte) in raw.iter().enumerate() {
            let shift = if self.little { index } else { size - 1 - index };
            value |= u64::from(byte).checked_shl(u32::try_from(shift * 8).ok()?)?;
        }
        Some(value)
    }

    fn u16(&self, at: usize) -> Option<u64> {
        self.int(at, 2)
    }

    fn u32(&self, at: usize) -> Option<u64> {
        self.int(at, 4)
    }

    /// Appends the structure at `at`, keeping the fields that fit, and returns its index.
    fn add(&mut self, name: impl Into<String>, at: usize, specs: &[Spec]) -> Option<usize> {
        let mut fields = Vec::with_capacity(specs.len());
        let mut pos = at;
        for &(field, ty) in specs {
            if self.fields + fields.len() >= MAX_FIELDS {
                self.truncated = true;
                break;
            }
            let Some(parsed) = self.field(field, pos, ty) else {
                break;
            };
            fields.push(parsed);
            pos = pos.checked_add(ty.size())?;
        }
        if fields.is_empty() {
            return None;
        }
        self.fields += fields.len();
        self.list.push(Structure {
            name: name.into(),
            off: self.base.saturating_add(at as u64),
            size: (pos - at) as u64,
            va: None,
            fields,
        });
        Some(self.list.len() - 1)
    }

    fn field(&self, name: &str, at: usize, ty: Ty) -> Option<Field> {
        let size = ty.size();
        let raw = self.bytes.get(at..at.checked_add(size)?)?;
        let (value, number) = match ty {
            Ty::U8 | Ty::U16 | Ty::U32 | Ty::U64 => {
                let number = self.int(at, size)?;
                (
                    format!("{number:0width$X}h", width = size.saturating_mul(2)),
                    number,
                )
            }
            Ty::Text(_) => {
                let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
                (format!("{:?}", String::from_utf8_lossy(raw.get(..end)?)), 0)
            }
            Ty::Bytes(_) => (hex(raw), 0),
        };
        Some(Field {
            name: name.into(),
            off: self.base.saturating_add(at as u64),
            size: size as u64,
            value,
            note: None,
            target: None,
            raw: number,
        })
    }

    /// Appends a structure whose fields were decoded by the caller.
    fn add_fields(&mut self, name: &str, at: usize, fields: Vec<Field>) {
        if fields.is_empty() || self.fields + fields.len() > MAX_FIELDS {
            return;
        }
        self.fields += fields.len();
        self.list.push(Structure {
            name: name.into(),
            off: self.base.saturating_add(at as u64),
            size: fields.iter().map(|f| f.size).sum(),
            va: None,
            fields,
        });
    }

    fn value(&self, index: usize, field: &str) -> Option<u64> {
        self.list
            .get(index)?
            .fields
            .iter()
            .find(|f| f.name == field)
            .map(|f| f.raw)
    }

    fn note(&mut self, index: usize, field: &str, note: impl Into<String>) {
        if let Some(found) = self.find(index, field) {
            found.note = Some(note.into());
        }
    }

    fn target(&mut self, index: usize, field: &str, va: u64) {
        if let Some(found) = self.find(index, field) {
            found.target = Some(va);
        }
    }

    fn find(&mut self, index: usize, field: &str) -> Option<&mut Field> {
        self.list
            .get_mut(index)?
            .fields
            .iter_mut()
            .find(|f| f.name == field)
    }

    /// Settles each structure's address, then hands the list over.
    fn finish(mut self, details: &mut FileDetails, map: impl Fn(u64) -> Option<u64>) {
        for structure in &mut self.list {
            structure.va = map(structure.off);
        }
        details.structures = self.list;
        if self.truncated {
            details.info(
                format!("Only the first {MAX_FIELDS} header fields are shown"),
                None,
            );
        }
    }
}
