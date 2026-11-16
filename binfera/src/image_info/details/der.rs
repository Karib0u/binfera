//! A bounded DER reader, tolerant of the BER that signing tools emit.
//!
//! Signature blobs in malware are often damaged on purpose, so a strict parser
//! would lose the parts that are still readable. Each read returns `None` instead.

const MAX_DEPTH: usize = 32;

pub(super) const SEQUENCE: u8 = 0x30;
pub(super) const SET: u8 = 0x31;
pub(super) const OCTET_STRING: u8 = 0x04;
pub(super) const OID: u8 = 0x06;
pub(super) const INTEGER: u8 = 0x02;
pub(super) const CONTEXT_0: u8 = 0xa0;
pub(super) const CONTEXT_1: u8 = 0xa1;

#[derive(Clone, Copy)]
pub(super) struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    /// The element with its header, as hashed for a certificate thumbprint.
    pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    pub fn children(self) -> Items<'a> {
        Items { rest: self.content }
    }
}

/// The elements of a constructed value, ending at the first unreadable one.
#[derive(Clone, Copy)]
pub(super) struct Items<'a> {
    rest: &'a [u8],
}

impl<'a> Items<'a> {
    /// The next element, which must have this tag.
    pub fn expect(&mut self, tag: u8) -> Option<Tlv<'a>> {
        self.next().filter(|item| item.tag == tag)
    }

    /// Takes the next element only if it has this tag.
    pub fn optional(&mut self, tag: u8) -> Option<Tlv<'a>> {
        let (item, rest) = read(self.rest, 0)?;
        if item.tag != tag {
            return None;
        }
        self.rest = rest;
        Some(item)
    }
}

impl<'a> Iterator for Items<'a> {
    type Item = Tlv<'a>;

    fn next(&mut self) -> Option<Tlv<'a>> {
        let (item, rest) = read(self.rest, 0)?;
        self.rest = rest;
        Some(item)
    }
}

/// One element and what follows it. High-tag-number forms do not occur in these structures.
fn read(bytes: &[u8], depth: usize) -> Option<(Tlv<'_>, &[u8])> {
    if depth > MAX_DEPTH {
        return None;
    }
    let (&tag, after) = bytes.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&first, mut body) = after.split_first()?;
    let mut header = 2usize;
    if first == 0x80 {
        // Indefinite length: the content runs to the end-of-contents marker of this level.
        if tag & 0x20 == 0 {
            return None;
        }
        let mut cursor = body;
        loop {
            if cursor.starts_with(&[0, 0]) {
                let content = body.get(..body.len() - cursor.len())?;
                let total = header.checked_add(content.len())?.checked_add(2)?;
                let raw = bytes.get(..total)?;
                return Some((Tlv { tag, content, raw }, cursor.get(2..)?));
            }
            let (_, next) = read(cursor, depth + 1)?;
            cursor = next;
        }
    }
    let length = if first < 0x80 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count > 4 {
            return None;
        }
        let mut value = 0usize;
        for &byte in body.get(..count)? {
            value = value.checked_mul(256)?.checked_add(usize::from(byte))?;
        }
        body = body.get(count..)?;
        header = header.checked_add(count)?;
        value
    };
    let content = body.get(..length)?;
    let raw = bytes.get(..header.checked_add(length)?)?;
    Some((Tlv { tag, content, raw }, body.get(length..)?))
}

pub(super) fn element(bytes: &[u8]) -> Option<Tlv<'_>> {
    read(bytes, 0).map(|(item, _)| item)
}

/// Dotted form of an OBJECT IDENTIFIER's content.
pub(super) fn oid(content: &[u8]) -> Option<String> {
    let (&first, rest) = content.split_first()?;
    let mut out = format!(
        "{}.{}",
        (first / 40).min(2),
        first.saturating_sub((first / 40).min(2) * 40)
    );
    let mut value = 0u64;
    for &byte in rest {
        value = value
            .checked_mul(128)?
            .checked_add(u64::from(byte & 0x7f))?;
        if byte & 0x80 == 0 {
            out.push('.');
            out.push_str(&value.to_string());
            value = 0;
        }
    }
    Some(out)
}

/// The text of a directory or string value, whichever ASN.1 string type carries it.
pub(super) fn text(item: Tlv<'_>) -> Option<String> {
    match item.tag {
        0x0c | 0x13 | 0x14 | 0x16 | 0x1a => {
            Some(String::from_utf8_lossy(item.content).into_owned())
        }
        0x1e => Some(utf16_be(item.content)),
        _ => None,
    }
}

pub(super) fn utf16_be(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| pair.iter().fold(0u16, |acc, &b| (acc << 8) | u16::from(b)))
        .collect();
    String::from_utf16_lossy(&units)
}

/// An RDN sequence as `CN=…, O=…`, in file order.
pub(super) fn name(item: Tlv<'_>) -> Option<String> {
    let mut parts = Vec::new();
    for rdn in item.children().filter(|rdn| rdn.tag == SET) {
        for pair in rdn.children().filter(|pair| pair.tag == SEQUENCE) {
            let mut fields = pair.children();
            let Some(kind) = fields.expect(OID).and_then(|o| oid(o.content)) else {
                continue;
            };
            let Some(value) = fields.next().and_then(text) else {
                continue;
            };
            let label = match kind.as_str() {
                "2.5.4.3" => "CN",
                "2.5.4.5" => "serialNumber",
                "2.5.4.6" => "C",
                "2.5.4.7" => "L",
                "2.5.4.8" => "ST",
                "2.5.4.10" => "O",
                "2.5.4.11" => "OU",
                "1.2.840.113549.1.9.1" => "E",
                _ => continue,
            };
            parts.push(format!("{label}={value}"));
        }
    }
    Some(parts.join(", "))
}

/// A UTCTime or GeneralizedTime, shown as `YYYY-MM-DD HH:MM:SS UTC`.
pub(super) fn time(item: Tlv<'_>) -> Option<String> {
    let digits = std::str::from_utf8(item.content).ok()?;
    let (year, rest) = match item.tag {
        0x17 => {
            let short: u32 = digits.get(..2)?.parse().ok()?;
            (
                if short >= 50 {
                    1900 + short
                } else {
                    2000 + short
                },
                digits.get(2..)?,
            )
        }
        0x18 => (digits.get(..4)?.parse().ok()?, digits.get(4..)?),
        _ => return None,
    };
    let part = |at: usize| rest.get(at..at + 2)?.parse::<u32>().ok();
    Some(format!(
        "{year:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        part(0)?,
        part(2)?,
        part(4)?,
        part(6)?,
        part(8).unwrap_or(0)
    ))
}
