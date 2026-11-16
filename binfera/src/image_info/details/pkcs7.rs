//! CMS SignedData as used by Authenticode and Apple code signatures.
//! Layout references: RFC 5652, RFC 3161, and Microsoft's Authenticode PE format.
//! This reads claims only; no signature or certificate chain is verified.
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use super::der::{
    self, Items, Tlv, CONTEXT_0, CONTEXT_1, INTEGER, OCTET_STRING, OID, SEQUENCE, SET,
};
use super::{hex, Certificate};

const MAX_CERTIFICATES: usize = 64;
const MAX_NESTED: usize = 16;
const MAX_NESTING: usize = 4;

const SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
const COUNTER_SIGNATURE: &str = "1.2.840.113549.1.9.6";
const SPC_OPUS_INFO: &str = "1.3.6.1.4.1.311.2.1.12";
const SPC_NESTED_SIGNATURE: &str = "1.3.6.1.4.1.311.2.4.1";
const RFC3161_TIMESTAMP: &str = "1.3.6.1.4.1.311.3.3.1";

/// What one SignedData claims, and any signatures nested inside it.
#[derive(Default)]
pub(super) struct Signed {
    pub digest_algorithm: Option<&'static str>,
    pub signed_digest: Option<String>,
    pub program: Option<String>,
    pub signing_time: Option<String>,
    pub timestamp: Option<String>,
    pub timestamp_signer: Option<String>,
    pub certificates: Vec<Certificate>,
    pub nested: Vec<Signed>,
}

pub(super) fn parse(bytes: &[u8]) -> Option<Signed> {
    parse_nested(bytes, 0)
}

fn parse_nested(bytes: &[u8], nesting: usize) -> Option<Signed> {
    let data = signed_data(bytes)?;
    let mut fields = data.children();
    fields.expect(INTEGER)?;
    fields.expect(SET)?;
    let encapsulated = fields.expect(SEQUENCE)?;

    let mut signed = Signed::default();
    if let Some((algorithm, digest)) = indirect_data(encapsulated) {
        signed.digest_algorithm = Some(algorithm);
        signed.signed_digest = Some(digest);
    }
    let mut raw_certificates = Vec::new();
    if let Some(list) = fields.optional(CONTEXT_0) {
        raw_certificates = list.children().take(MAX_CERTIFICATES).collect();
        signed.certificates = raw_certificates
            .iter()
            .filter_map(|c| certificate(*c))
            .collect();
    }
    let _crls = fields.optional(CONTEXT_1);
    let signers = fields.expect(SET)?;
    for signer in signers.children().filter(|s| s.tag == SEQUENCE) {
        read_signer(signer, &raw_certificates, nesting, &mut signed);
    }
    Some(signed)
}

/// The SignedData sequence inside a ContentInfo.
fn signed_data(bytes: &[u8]) -> Option<Tlv<'_>> {
    let info = der::element(bytes).filter(|item| item.tag == SEQUENCE)?;
    let mut fields = info.children();
    let kind = der::oid(fields.expect(OID)?.content)?;
    if kind != SIGNED_DATA {
        return None;
    }
    fields.expect(CONTEXT_0)?.children().expect(SEQUENCE)
}

/// SpcIndirectDataContent's digest algorithm and value, when the content is one.
fn indirect_data(encapsulated: Tlv<'_>) -> Option<(&'static str, String)> {
    let mut fields = encapsulated.children();
    fields.expect(OID)?;
    let content = fields.expect(CONTEXT_0)?.children().expect(SEQUENCE)?;
    let mut parts = content.children();
    parts.expect(SEQUENCE)?;
    let mut digest_info = parts.expect(SEQUENCE)?.children();
    let algorithm = digest_name(digest_info.expect(SEQUENCE)?)?;
    let digest = digest_info.expect(OCTET_STRING)?;
    Some((algorithm, hex(digest.content)))
}

fn digest_name(identifier: Tlv<'_>) -> Option<&'static str> {
    let kind = der::oid(identifier.children().expect(OID)?.content)?;
    Some(match kind.as_str() {
        "1.2.840.113549.2.5" => "MD5",
        "1.3.14.3.2.26" => "SHA-1",
        "2.16.840.1.101.3.4.2.1" => "SHA-256",
        "2.16.840.1.101.3.4.2.2" => "SHA-384",
        "2.16.840.1.101.3.4.2.3" => "SHA-512",
        _ => return None,
    })
}

/// Hashes `parts` as one stream, for the algorithms `digest_name` knows.
pub(super) fn digest(algorithm: &str, parts: &[&[u8]]) -> Option<String> {
    fn run<D: Digest>(parts: &[&[u8]]) -> String {
        let mut hasher = D::new();
        for part in parts {
            hasher.update(part);
        }
        hex(&hasher.finalize())
    }
    Some(match algorithm {
        "MD5" => run::<Md5>(parts),
        "SHA-1" => run::<Sha1>(parts),
        "SHA-256" => run::<Sha256>(parts),
        "SHA-384" => run::<Sha384>(parts),
        "SHA-512" => run::<Sha512>(parts),
        _ => return None,
    })
}

fn certificate(item: Tlv<'_>) -> Option<Certificate> {
    let (tbs, serial) = certificate_body(item)?;
    let mut fields = tbs;
    fields.expect(SEQUENCE)?; // signature algorithm
    let issuer = der::name(fields.expect(SEQUENCE)?)?;
    let mut validity = fields.expect(SEQUENCE)?.children();
    let not_before = validity.next().and_then(der::time).unwrap_or_default();
    let not_after = validity.next().and_then(der::time).unwrap_or_default();
    let subject = der::name(fields.expect(SEQUENCE)?)?;
    Some(Certificate {
        self_signed: subject == issuer,
        subject,
        issuer,
        serial: hex(serial),
        not_before,
        not_after,
        sha1: hex(&Sha1::digest(item.raw)),
        sha256: hex(&Sha256::digest(item.raw)),
        signer: false,
    })
}

/// The TBSCertificate fields following the serial number, and the serial number.
fn certificate_body(item: Tlv<'_>) -> Option<(Items<'_>, &[u8])> {
    if item.tag != SEQUENCE {
        return None;
    }
    let mut fields = item.children().expect(SEQUENCE)?.children();
    let _version = fields.optional(CONTEXT_0);
    let serial = fields.expect(INTEGER)?;
    Some((fields, serial.content))
}

/// The certificate named by an IssuerAndSerialNumber, compared on its DER bytes.
fn signer_index(signer_id: Tlv<'_>, certificates: &[Tlv<'_>]) -> Option<usize> {
    let mut id = signer_id.children();
    let issuer = id.expect(SEQUENCE)?;
    let serial = id.expect(INTEGER)?;
    certificates.iter().position(|cert| {
        certificate_body(*cert).is_some_and(|(mut fields, number)| {
            let _algorithm = fields.next();
            number == serial.content && fields.next().is_some_and(|name| name.raw == issuer.raw)
        })
    })
}

fn read_signer(info: Tlv<'_>, certificates: &[Tlv<'_>], nesting: usize, signed: &mut Signed) {
    let mut fields = info.children();
    let _version = fields.next();
    let Some(signer_id) = fields.next() else {
        return;
    };
    if let Some(found) = signer_index(signer_id, certificates)
        .and_then(|index| certificates.get(index))
        .and_then(|raw| certificate(*raw))
        .map(|cert| cert.sha256)
    {
        for cert in signed.certificates.iter_mut().filter(|c| c.sha256 == found) {
            cert.signer = true;
        }
    }
    let _digest_algorithm = fields.next();
    if let Some(attributes) = fields.optional(CONTEXT_0) {
        for (kind, values) in attributes_of(attributes) {
            match kind.as_str() {
                SIGNING_TIME => {
                    signed.signing_time = values.clone().next().and_then(der::time);
                }
                SPC_OPUS_INFO => signed.program = values.clone().next().and_then(program_name),
                _ => {}
            }
        }
    }
    let _signature_algorithm = fields.next();
    let _signature = fields.next();
    let Some(unsigned) = fields.optional(CONTEXT_1) else {
        return;
    };
    for (kind, values) in attributes_of(unsigned) {
        match kind.as_str() {
            COUNTER_SIGNATURE => counter_signature(values, certificates, signed),
            RFC3161_TIMESTAMP => rfc3161(values, signed),
            SPC_NESTED_SIGNATURE if nesting < MAX_NESTING => {
                for value in values {
                    if signed.nested.len() >= MAX_NESTED {
                        break;
                    }
                    if let Some(inner) = parse_nested(value.raw, nesting + 1) {
                        signed.nested.push(inner);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Attribute type and value set, for each well-formed attribute.
fn attributes_of(set: Tlv<'_>) -> impl Iterator<Item = (String, Items<'_>)> {
    set.children().filter_map(|attribute| {
        let mut fields = attribute.children();
        let kind = der::oid(fields.expect(OID)?.content)?;
        Some((kind, fields.expect(SET)?.children()))
    })
}

/// SpcSpOpusInfo's programName: `[0]` of an explicit SpcString.
fn program_name(info: Tlv<'_>) -> Option<String> {
    let name = info.children().optional(CONTEXT_0)?;
    let value = name.children().next()?;
    match value.tag {
        0x80 => Some(der::utf16_be(value.content)),
        0x81 => Some(String::from_utf8_lossy(value.content).into_owned()),
        _ => None,
    }
    .filter(|text| !text.is_empty())
}

/// A legacy PKCS#9 countersignature, which is a SignerInfo using the outer certificates.
fn counter_signature(values: Items<'_>, certificates: &[Tlv<'_>], signed: &mut Signed) {
    for info in values {
        let mut fields = info.children();
        let _version = fields.next();
        let signer = fields.next();
        let _digest_algorithm = fields.next();
        let Some(attributes) = fields.optional(CONTEXT_0) else {
            continue;
        };
        for (kind, mut times) in attributes_of(attributes) {
            if kind == SIGNING_TIME {
                signed.timestamp = times.next().and_then(der::time);
            }
        }
        signed.timestamp_signer = signer
            .and_then(|id| signer_index(id, certificates))
            .and_then(|index| certificates.get(index))
            .and_then(|raw| certificate(*raw))
            .map(|cert| cert.subject);
    }
}

/// An RFC 3161 token: its own SignedData over a TSTInfo holding the time.
fn rfc3161(mut values: Items<'_>, signed: &mut Signed) {
    let Some(token) = values.next() else {
        return;
    };
    let Some(data) = signed_data(token.raw) else {
        return;
    };
    let mut fields = data.children();
    let _version = fields.next();
    let _algorithms = fields.next();
    signed.timestamp = fields.next().and_then(generalized_time);
    let certificates: Vec<_> = fields
        .optional(CONTEXT_0)
        .map(|list| list.children().take(MAX_CERTIFICATES).collect())
        .unwrap_or_default();
    let _crls = fields.optional(CONTEXT_1);
    let signer = fields
        .expect(SET)
        .and_then(|set| set.children().next())
        .and_then(|info| {
            let mut parts = info.children();
            let _version = parts.next();
            parts.next()
        });
    signed.timestamp_signer = signer
        .and_then(|id| signer_index(id, &certificates))
        .and_then(|index| certificates.get(index))
        .and_then(|raw| certificate(*raw))
        .map(|cert| cert.subject);
}

/// TSTInfo.genTime from an encapsulated content, past version, policy, imprint and serial.
fn generalized_time(encapsulated: Tlv<'_>) -> Option<String> {
    let mut fields = encapsulated.children();
    fields.expect(OID)?;
    let wrapped = fields.expect(CONTEXT_0)?.children().next()?;
    let info = der::element(wrapped.content)?;
    info.children()
        .find(|item| item.tag == 0x18)
        .and_then(der::time)
}
