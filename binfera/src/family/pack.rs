//! Reader for compact binary family/trusted-code packs (`BXFAM002`).
//!
//! Every offset, count, and family/source index is strictly bounds-checked on load so
//! damaged or untrusted `.bxfam` files return [`FamilyError::Pack`] without panicking.

use std::io::{Read, Write};

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};

use super::FamilyError;

const MAGIC: &[u8; 8] = b"BXFAM002";
const HEADER_LEN: usize = 40;
const FLAG_HAS_BANDS: u32 = 1;
const MAX_DECOMPRESSED_BYTES: usize = 512 * 1024 * 1024;
const TRUSTED_RECORD_BYTES: usize = 10;
const SHARED_RECORD_BYTES: usize = 10;
const HASH_RECORD_BYTES: usize = 15;
const BAND_RECORD_BYTES: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyMeta {
    pub name: String,
    pub sample_count: u32,
    pub unique_shapes: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedRecord {
    pub shape: u64,
    pub source_id: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedRecord {
    pub shape: u64,
    pub family_count: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashRecord {
    pub hash: u64,
    pub family_id: u16,
    pub sample_count: u16,
    pub exclusivity: u8,
    pub avg_instructions: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BandRecord {
    pub band_hash: u64,
    pub family_id: u16,
    pub sample_count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackStats {
    pub families: usize,
    pub trusted_sources: usize,
    pub trusted_shapes: usize,
    pub shared_shapes: usize,
    pub content_records: usize,
    pub shape_records: usize,
    pub band_records: usize,
}

#[derive(Debug, Clone)]
pub struct FamilyPack {
    pub(crate) families: Vec<FamilyMeta>,
    pub(crate) trusted_sources: Vec<String>,
    pub(crate) trusted_shapes: Vec<TrustedRecord>,
    pub(crate) shared_shapes: Vec<SharedRecord>,
    pub(crate) content_records: Vec<HashRecord>,
    pub(crate) shape_records: Vec<HashRecord>,
    pub(crate) band_records: Vec<BandRecord>,
}

impl FamilyPack {
    /// Constructs a pack directly from pre-sorted tables (used by tests and pack encoders).
    pub fn from_tables(
        families: Vec<FamilyMeta>,
        trusted_sources: Vec<String>,
        mut trusted_shapes: Vec<TrustedRecord>,
        mut shared_shapes: Vec<SharedRecord>,
        mut content_records: Vec<HashRecord>,
        mut shape_records: Vec<HashRecord>,
        mut band_records: Vec<BandRecord>,
    ) -> Self {
        trusted_shapes.sort_unstable_by_key(|r| r.shape);
        shared_shapes.sort_unstable_by_key(|r| r.shape);
        content_records.sort_unstable_by_key(|r| (r.hash, r.family_id));
        shape_records.sort_unstable_by_key(|r| (r.hash, r.family_id));
        band_records.sort_unstable_by_key(|r| (r.band_hash, r.family_id));
        Self {
            families,
            trusted_sources,
            trusted_shapes,
            shared_shapes,
            content_records,
            shape_records,
            band_records,
        }
    }

    pub fn stats(&self) -> PackStats {
        PackStats {
            families: self.families.len(),
            trusted_sources: self.trusted_sources.len(),
            trusted_shapes: self.trusted_shapes.len(),
            shared_shapes: self.shared_shapes.len(),
            content_records: self.content_records.len(),
            shape_records: self.shape_records.len(),
            band_records: self.band_records.len(),
        }
    }

    pub fn families(&self) -> &[FamilyMeta] {
        &self.families
    }

    pub fn trusted_source_name(&self, source_id: u16) -> Option<&str> {
        self.trusted_sources
            .get(usize::from(source_id))
            .map(String::as_str)
    }

    pub fn lookup_trusted(&self, shape: u64) -> Option<&str> {
        let idx = self
            .trusted_shapes
            .binary_search_by_key(&shape, |r| r.shape)
            .ok()?;
        let rec = self.trusted_shapes.get(idx)?;
        self.trusted_source_name(rec.source_id)
    }

    pub fn lookup_shared(&self, shape: u64) -> Option<u16> {
        let idx = self
            .shared_shapes
            .binary_search_by_key(&shape, |r| r.shape)
            .ok()?;
        self.shared_shapes.get(idx).map(|r| r.family_count)
    }

    pub fn lookup_content(&self, hash: u64) -> &[HashRecord] {
        lookup_hash_slice(&self.content_records, hash)
    }

    pub fn lookup_shape(&self, hash: u64) -> &[HashRecord] {
        lookup_hash_slice(&self.shape_records, hash)
    }

    pub fn lookup_band(&self, band_hash: u64) -> &[BandRecord] {
        let start = self
            .band_records
            .partition_point(|r| r.band_hash < band_hash);
        let mut end = start;
        while let Some(rec) = self.band_records.get(end) {
            if rec.band_hash != band_hash {
                break;
            }
            end += 1;
        }
        self.band_records.get(start..end).unwrap_or(&[])
    }

    /// Serializes this pack in the compact `BXFAM002` binary wire format.
    pub fn to_bytes(&self) -> Result<Vec<u8>, FamilyError> {
        let mut out = Vec::with_capacity(HEADER_LEN + 1024);
        let flags = if self.band_records.is_empty() {
            0_u32
        } else {
            FLAG_HAS_BANDS
        };
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&(self.families.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.trusted_sources.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.trusted_shapes.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.shared_shapes.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.content_records.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.shape_records.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.band_records.len() as u32).to_le_bytes());

        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        for fam in &self.families {
            let name_bytes = fam.name.as_bytes();
            let name_len = u16::try_from(name_bytes.len())
                .map_err(|_| FamilyError::Pack(format!("family name too long: {}", fam.name)))?;
            enc.write_all(&name_len.to_le_bytes())?;
            enc.write_all(name_bytes)?;
            enc.write_all(&fam.sample_count.to_le_bytes())?;
            enc.write_all(&fam.unique_shapes.to_le_bytes())?;
        }
        for src in &self.trusted_sources {
            let name_bytes = src.as_bytes();
            let name_len = u16::try_from(name_bytes.len())
                .map_err(|_| FamilyError::Pack(format!("trusted source too long: {src}")))?;
            enc.write_all(&name_len.to_le_bytes())?;
            enc.write_all(name_bytes)?;
        }
        for r in &self.trusted_shapes {
            enc.write_all(&r.shape.to_le_bytes())?;
            enc.write_all(&r.source_id.to_le_bytes())?;
        }
        for r in &self.shared_shapes {
            enc.write_all(&r.shape.to_le_bytes())?;
            enc.write_all(&r.family_count.to_le_bytes())?;
        }
        for r in &self.content_records {
            write_hash_record(&mut enc, *r)?;
        }
        for r in &self.shape_records {
            write_hash_record(&mut enc, *r)?;
        }
        for r in &self.band_records {
            enc.write_all(&r.band_hash.to_le_bytes())?;
            enc.write_all(&r.family_id.to_le_bytes())?;
            enc.write_all(&r.sample_count.to_le_bytes())?;
        }
        let compressed = enc.finish()?;
        out.extend_from_slice(&compressed);
        Ok(out)
    }

    /// Parses and validates a `BXFAM002` pack from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FamilyError> {
        if bytes.len() < HEADER_LEN {
            return Err(FamilyError::Pack("truncated header".into()));
        }
        if bytes.get(..8) != Some(&MAGIC[..]) {
            return Err(FamilyError::Pack("bad magic".into()));
        }
        let _flags = read_u32(bytes, 8)?;
        let family_count = read_u32(bytes, 12)? as usize;
        let trusted_source_count = read_u32(bytes, 16)? as usize;
        let trusted_count = read_u32(bytes, 20)? as usize;
        let shared_count = read_u32(bytes, 24)? as usize;
        let content_count = read_u32(bytes, 28)? as usize;
        let shape_count = read_u32(bytes, 32)? as usize;
        let band_count = read_u32(bytes, 36)? as usize;

        let mut decoder = ZlibDecoder::new(
            bytes
                .get(HEADER_LEN..)
                .ok_or_else(|| FamilyError::Pack("missing body".into()))?,
        )
        .take((MAX_DECOMPRESSED_BYTES + 1) as u64);
        let mut body = Vec::new();
        decoder.read_to_end(&mut body)?;
        if body.len() > MAX_DECOMPRESSED_BYTES {
            return Err(FamilyError::Pack(
                "decompressed pack exceeds size cap".into(),
            ));
        }

        let mut cursor = Cursor::new(&body);
        let mut families = Vec::with_capacity(family_count.min(65_536));
        for _ in 0..family_count {
            let name_len = usize::from(cursor.u16()?);
            let name_slice = cursor.take(name_len)?;
            let name = std::str::from_utf8(name_slice)
                .map_err(|_| FamilyError::Pack("non-utf8 family name".into()))?
                .to_owned();
            let sample_count = cursor.u32()?;
            let unique_shapes = cursor.u32()?;
            families.push(FamilyMeta {
                name,
                sample_count,
                unique_shapes,
            });
        }

        let mut trusted_sources = Vec::with_capacity(trusted_source_count.min(65_536));
        for _ in 0..trusted_source_count {
            let name_len = usize::from(cursor.u16()?);
            let name_slice = cursor.take(name_len)?;
            let name = std::str::from_utf8(name_slice)
                .map_err(|_| FamilyError::Pack("non-utf8 trusted source".into()))?
                .to_owned();
            trusted_sources.push(name);
        }

        let expected_tail = trusted_count
            .checked_mul(TRUSTED_RECORD_BYTES)
            .and_then(|n| n.checked_add(shared_count.checked_mul(SHARED_RECORD_BYTES)?))
            .and_then(|n| n.checked_add(content_count.checked_mul(HASH_RECORD_BYTES)?))
            .and_then(|n| n.checked_add(shape_count.checked_mul(HASH_RECORD_BYTES)?))
            .and_then(|n| n.checked_add(band_count.checked_mul(BAND_RECORD_BYTES)?))
            .ok_or_else(|| FamilyError::Pack("section size overflow".into()))?;
        if cursor.remaining() < expected_tail {
            return Err(FamilyError::Pack("truncated table section".into()));
        }

        let mut trusted_shapes = Vec::with_capacity(trusted_count);
        for _ in 0..trusted_count {
            let shape = cursor.u64()?;
            let source_id = cursor.u16()?;
            if usize::from(source_id) >= trusted_source_count {
                return Err(FamilyError::Pack("trusted source_id out of range".into()));
            }
            trusted_shapes.push(TrustedRecord { shape, source_id });
        }

        let mut shared_shapes = Vec::with_capacity(shared_count);
        for _ in 0..shared_count {
            let shape = cursor.u64()?;
            let family_count = cursor.u16()?;
            shared_shapes.push(SharedRecord {
                shape,
                family_count,
            });
        }

        let mut content_records = Vec::with_capacity(content_count);
        for _ in 0..content_count {
            content_records.push(read_hash_record(&mut cursor, family_count)?);
        }

        let mut shape_records = Vec::with_capacity(shape_count);
        for _ in 0..shape_count {
            shape_records.push(read_hash_record(&mut cursor, family_count)?);
        }

        let mut band_records = Vec::with_capacity(band_count);
        for _ in 0..band_count {
            let band_hash = cursor.u64()?;
            let family_id = cursor.u16()?;
            let sample_count = cursor.u16()?;
            if usize::from(family_id) >= family_count {
                return Err(FamilyError::Pack("band family_id out of range".into()));
            }
            band_records.push(BandRecord {
                band_hash,
                family_id,
                sample_count,
            });
        }

        Ok(Self {
            families,
            trusted_sources,
            trusted_shapes,
            shared_shapes,
            content_records,
            shape_records,
            band_records,
        })
    }
}

fn lookup_hash_slice(records: &[HashRecord], hash: u64) -> &[HashRecord] {
    let start = records.partition_point(|r| r.hash < hash);
    let mut end = start;
    while let Some(rec) = records.get(end) {
        if rec.hash != hash {
            break;
        }
        end += 1;
    }
    records.get(start..end).unwrap_or(&[])
}

fn write_hash_record(w: &mut impl Write, r: HashRecord) -> std::io::Result<()> {
    w.write_all(&r.hash.to_le_bytes())?;
    w.write_all(&r.family_id.to_le_bytes())?;
    w.write_all(&r.sample_count.to_le_bytes())?;
    w.write_all(&[r.exclusivity])?;
    w.write_all(&r.avg_instructions.to_le_bytes())?;
    Ok(())
}

fn read_hash_record(
    cursor: &mut Cursor<'_>,
    family_count: usize,
) -> Result<HashRecord, FamilyError> {
    let hash = cursor.u64()?;
    let family_id = cursor.u16()?;
    let sample_count = cursor.u16()?;
    let exclusivity = cursor.u8()?;
    let avg_instructions = cursor.u16()?;
    if usize::from(family_id) >= family_count {
        return Err(FamilyError::Pack("record family_id out of range".into()));
    }
    Ok(HashRecord {
        hash,
        family_id,
        sample_count,
        exclusivity,
        avg_instructions,
    })
}

fn read_u32(data: &[u8], at: usize) -> Result<u32, FamilyError> {
    let slice = data
        .get(at..at + 4)
        .ok_or_else(|| FamilyError::Pack("truncated header field".into()))?;
    let arr: [u8; 4] = slice
        .try_into()
        .map_err(|_| FamilyError::Pack("truncated header field".into()))?;
    Ok(u32::from_le_bytes(arr))
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], FamilyError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| FamilyError::Pack("cursor overflow".into()))?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| FamilyError::Pack("unexpected eof".into()))?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, FamilyError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, FamilyError> {
        let arr: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| FamilyError::Pack("truncated u16".into()))?;
        Ok(u16::from_le_bytes(arr))
    }

    fn u32(&mut self) -> Result<u32, FamilyError> {
        let arr: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| FamilyError::Pack("truncated u32".into()))?;
        Ok(u32::from_le_bytes(arr))
    }

    fn u64(&mut self) -> Result<u64, FamilyError> {
        let arr: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| FamilyError::Pack("truncated u64".into()))?;
        Ok(u64::from_le_bytes(arr))
    }
}
