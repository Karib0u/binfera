//! Reader for compact binary family/trusted-code packs (`BXFAM002` and `BXFAM003`).
//!
//! Every offset, count, and family/source index is strictly bounds-checked on load so
//! damaged or untrusted `.bxfam` files return [`FamilyError::Pack`] without panicking.
//!
//! # Wire format
//!
//! Both versions start with the same 40-byte little-endian header: an 8-byte magic, a `u32`
//! flags word, and seven `u32` table counts (families, trusted sources, trusted shapes, shared
//! shapes, content records, shape records, band records). `BXFAM003` appends four more `u32`
//! counts (trusted symbols, trusted strings, exclusive malware strings, reserved) so
//! [`PackHeader::read`] can describe every section without decompressing the body.
//!
//! The zlib body holds the `BXFAM002` tables in header order. A `BXFAM003` body follows them with
//! optional sections, each framed as `u32 tag | u32 byte length | payload`:
//!
//! | Tag | Section | Payload |
//! |-----|---------|---------|
//! | 1 | Trusted function symbols | `u32 count`, `u32 pool length`, UTF-8 pool, then `count` records of `u64 shape`, `u32 pool offset`, `u16 length`, `u16 source id` (`0xffff` = none) |
//! | 2 | Trusted string filter | `u8 encoding` (0 = sorted `u64`), 3 reserved bytes, `u32 count`, then `count` sorted [`origin_string_hash`](super::origin_string_hash) values |
//! | 3 | Exclusive malware strings | `u32 count`, then `count` records of `u64 hash`, `u16 sample count`, `u8 family count` (1..=3), `u8` reserved, `3 x u16 family id` (unused = `0xffff`) |
//!
//! Absent sections read as empty, and unknown tags are skipped so later minor additions remain
//! readable. A pack without any `BXFAM003` data is always written as `BXFAM002`.

use std::io::{Read, Write};

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};

use super::FamilyError;

const MAGIC_V2: &[u8; 8] = b"BXFAM002";
const MAGIC_V3: &[u8; 8] = b"BXFAM003";
const HEADER_LEN: usize = 40;
const HEADER_V3_LEN: usize = HEADER_LEN + 16;
const FLAG_HAS_BANDS: u32 = 1;
const MAX_DECOMPRESSED_BYTES: usize = 512 * 1024 * 1024;
const TRUSTED_RECORD_BYTES: usize = 10;
const SHARED_RECORD_BYTES: usize = 10;
const HASH_RECORD_BYTES: usize = 15;
const BAND_RECORD_BYTES: usize = 12;
const SYMBOL_RECORD_BYTES: usize = 16;
const MALWARE_STRING_RECORD_BYTES: usize = 18;
const TAG_TRUSTED_SYMBOLS: u32 = 1;
const TAG_TRUSTED_STRINGS: u32 = 2;
const TAG_MALWARE_STRINGS: u32 = 3;
const STRING_FILTER_SORTED_U64: u8 = 0;
const NO_ID: u16 = u16::MAX;
/// Most malware families an exclusive malware string record may name.
pub const MAX_STRING_FAMILIES: usize = 3;

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

/// Symbol name for a Trusted function, keyed by the same shape hash as [`TrustedRecord`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedSymbol {
    pub shape: u64,
    pub name: String,
    /// Index into the pack's trusted sources, when the symbol names its origin.
    pub source_id: Option<u16>,
}

/// A Trusted symbol borrowed from a loaded pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedSymbolRef<'a> {
    pub name: &'a str,
    pub source: Option<&'a str>,
}

/// A string seen only in malware, attributed to at most [`MAX_STRING_FAMILIES`] families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalwareStringRecord {
    /// [`origin_string_hash`](super::origin_string_hash) of the normalized string.
    pub hash: u64,
    pub sample_count: u16,
    family_count: u8,
    family_ids: [u16; MAX_STRING_FAMILIES],
}

impl MalwareStringRecord {
    /// Builds a record from 1 to [`MAX_STRING_FAMILIES`] family indices. Duplicate ids are merged.
    pub fn new(hash: u64, sample_count: u16, family_ids: &[u16]) -> Result<Self, FamilyError> {
        let mut ids = [NO_ID; MAX_STRING_FAMILIES];
        let mut count = 0_usize;
        for &id in family_ids {
            if id == NO_ID {
                return Err(FamilyError::Pack(
                    "reserved malware string family id".into(),
                ));
            }
            if ids.get(..count).is_some_and(|seen| seen.contains(&id)) {
                continue;
            }
            let slot = ids.get_mut(count).ok_or_else(|| {
                FamilyError::Pack(format!(
                    "malware string names more than {MAX_STRING_FAMILIES} families"
                ))
            })?;
            *slot = id;
            count += 1;
        }
        if count == 0 {
            return Err(FamilyError::Pack("malware string names no family".into()));
        }
        Ok(Self {
            hash,
            sample_count,
            family_count: count as u8,
            family_ids: ids,
        })
    }

    /// Family indices this string was observed in.
    pub fn family_ids(&self) -> &[u16] {
        self.family_ids
            .get(..usize::from(self.family_count))
            .unwrap_or(&[])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SymbolSlot {
    shape: u64,
    offset: u32,
    len: u16,
    source_id: u16,
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
    /// `BXFAM003` Trusted function symbols (0 for `BXFAM002`).
    #[serde(default)]
    pub trusted_symbols: usize,
    /// `BXFAM003` Trusted string filter entries (0 for `BXFAM002`).
    #[serde(default)]
    pub trusted_strings: usize,
    /// `BXFAM003` exclusive malware strings (0 for `BXFAM002`).
    #[serde(default)]
    pub malware_strings: usize,
}

/// Counts and LSH configuration from the fixed-size header, without decoding any tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackHeader {
    /// `2` for `BXFAM002`, `3` for `BXFAM003`.
    pub format_version: u32,
    pub lsh_enabled: bool,
    pub stats: PackStats,
}

impl PackHeader {
    /// Reads only the fixed-size header of either format version.
    pub fn read(mut reader: impl Read) -> Result<Self, FamilyError> {
        let mut bytes = [0; HEADER_V3_LEN];
        let prefix = bytes
            .get_mut(..HEADER_LEN)
            .ok_or_else(|| FamilyError::Pack("truncated header".into()))?;
        reader.read_exact(prefix)?;
        if bytes.get(..8) == Some(&MAGIC_V3[..]) {
            let extra = bytes
                .get_mut(HEADER_LEN..)
                .ok_or_else(|| FamilyError::Pack("truncated header".into()))?;
            reader.read_exact(extra)?;
        }
        Self::parse(&bytes)
    }

    /// Format name as it appears in the magic, such as `BXFAM003`.
    pub fn format_name(&self) -> String {
        format!("BXFAM{:03}", self.format_version)
    }

    fn header_len(&self) -> usize {
        if self.format_version >= 3 {
            HEADER_V3_LEN
        } else {
            HEADER_LEN
        }
    }

    fn parse(bytes: &[u8]) -> Result<Self, FamilyError> {
        if bytes.len() < HEADER_LEN {
            return Err(FamilyError::Pack("truncated header".into()));
        }
        let format_version = match bytes.get(..8) {
            Some(magic) if magic == &MAGIC_V2[..] => 2,
            Some(magic) if magic == &MAGIC_V3[..] => 3,
            _ => return Err(FamilyError::Pack("bad magic".into())),
        };
        let flags = read_u32(bytes, 8)?;
        let mut stats = PackStats {
            families: read_u32(bytes, 12)? as usize,
            trusted_sources: read_u32(bytes, 16)? as usize,
            trusted_shapes: read_u32(bytes, 20)? as usize,
            shared_shapes: read_u32(bytes, 24)? as usize,
            content_records: read_u32(bytes, 28)? as usize,
            shape_records: read_u32(bytes, 32)? as usize,
            band_records: read_u32(bytes, 36)? as usize,
            trusted_symbols: 0,
            trusted_strings: 0,
            malware_strings: 0,
        };
        if format_version == 3 {
            stats.trusted_symbols = read_u32(bytes, 40)? as usize;
            stats.trusted_strings = read_u32(bytes, 44)? as usize;
            stats.malware_strings = read_u32(bytes, 48)? as usize;
        }
        Ok(Self {
            format_version,
            lsh_enabled: flags & FLAG_HAS_BANDS != 0,
            stats,
        })
    }
}

#[derive(Debug, Clone)]
pub struct FamilyPack {
    pub(crate) format_version: u32,
    pub(crate) families: Vec<FamilyMeta>,
    pub(crate) trusted_sources: Vec<String>,
    pub(crate) trusted_shapes: Vec<TrustedRecord>,
    pub(crate) shared_shapes: Vec<SharedRecord>,
    pub(crate) content_records: Vec<HashRecord>,
    pub(crate) shape_records: Vec<HashRecord>,
    pub(crate) band_records: Vec<BandRecord>,
    symbol_pool: String,
    symbols: Vec<SymbolSlot>,
    trusted_strings: Vec<u64>,
    malware_strings: Vec<MalwareStringRecord>,
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
            format_version: 2,
            families,
            trusted_sources,
            trusted_shapes,
            shared_shapes,
            content_records,
            shape_records,
            band_records,
            symbol_pool: String::new(),
            symbols: Vec::new(),
            trusted_strings: Vec::new(),
            malware_strings: Vec::new(),
        }
    }

    /// Replaces the `BXFAM003` Trusted function symbols. Names are deduplicated into one pool;
    /// the first symbol wins when several share a shape.
    pub fn with_trusted_symbols(
        mut self,
        symbols: Vec<TrustedSymbol>,
    ) -> Result<Self, FamilyError> {
        let mut pool = String::new();
        let mut offsets: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
        let mut slots = Vec::with_capacity(symbols.len());
        for symbol in &symbols {
            let len = u16::try_from(symbol.name.len())
                .map_err(|_| FamilyError::Pack(format!("symbol too long: {}", symbol.name)))?;
            let source_id = match symbol.source_id {
                Some(id) if id == NO_ID || usize::from(id) >= self.trusted_sources.len() => {
                    return Err(FamilyError::Pack("symbol source_id out of range".into()))
                }
                Some(id) => id,
                None => NO_ID,
            };
            let offset = match offsets.get(symbol.name.as_str()) {
                Some(&offset) => offset,
                None => {
                    let offset = u32::try_from(pool.len())
                        .map_err(|_| FamilyError::Pack("symbol pool too large".into()))?;
                    pool.push_str(&symbol.name);
                    offsets.insert(&symbol.name, offset);
                    offset
                }
            };
            slots.push(SymbolSlot {
                shape: symbol.shape,
                offset,
                len,
                source_id,
            });
        }
        slots.sort_by_key(|s| s.shape);
        slots.dedup_by_key(|s| s.shape);
        self.symbol_pool = pool;
        self.symbols = slots;
        Ok(self)
    }

    /// Replaces the `BXFAM003` Trusted string filter with these
    /// [`origin_string_hash`](super::origin_string_hash) values.
    pub fn with_trusted_strings(mut self, mut hashes: Vec<u64>) -> Self {
        hashes.sort_unstable();
        hashes.dedup();
        self.trusted_strings = hashes;
        self
    }

    /// Replaces the `BXFAM003` exclusive malware string index. The first record wins for a hash.
    pub fn with_malware_strings(
        mut self,
        mut records: Vec<MalwareStringRecord>,
    ) -> Result<Self, FamilyError> {
        if records
            .iter()
            .flat_map(MalwareStringRecord::family_ids)
            .any(|&id| usize::from(id) >= self.families.len())
        {
            return Err(FamilyError::Pack(
                "malware string family_id out of range".into(),
            ));
        }
        records.sort_by_key(|r| r.hash);
        records.dedup_by_key(|r| r.hash);
        self.malware_strings = records;
        Ok(self)
    }

    /// `2` for a `BXFAM002` pack, `3` when the pack carries any `BXFAM003` section.
    pub fn format_version(&self) -> u32 {
        if self.has_v3_sections() {
            3
        } else {
            self.format_version
        }
    }

    fn has_v3_sections(&self) -> bool {
        !self.symbols.is_empty()
            || !self.trusted_strings.is_empty()
            || !self.malware_strings.is_empty()
    }

    /// True when the pack can classify strings (a Trusted string filter or malware string index).
    pub fn has_string_data(&self) -> bool {
        !self.trusted_strings.is_empty() || !self.malware_strings.is_empty()
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
            trusted_symbols: self.symbols.len(),
            trusted_strings: self.trusted_strings.len(),
            malware_strings: self.malware_strings.len(),
        }
    }

    /// Symbol name for a Trusted function shape, from the `BXFAM003` symbol section.
    pub fn lookup_trusted_symbol(&self, shape: u64) -> Option<TrustedSymbolRef<'_>> {
        let idx = self
            .symbols
            .binary_search_by_key(&shape, |s| s.shape)
            .ok()?;
        let slot = self.symbols.get(idx)?;
        let start = slot.offset as usize;
        let name = self
            .symbol_pool
            .get(start..start.checked_add(usize::from(slot.len))?)?;
        let source = if slot.source_id == NO_ID {
            None
        } else {
            self.trusted_source_name(slot.source_id)
        };
        Some(TrustedSymbolRef { name, source })
    }

    /// True when the Trusted string filter contains this
    /// [`origin_string_hash`](super::origin_string_hash).
    pub fn is_trusted_string(&self, hash: u64) -> bool {
        self.trusted_strings.binary_search(&hash).is_ok()
    }

    /// Exclusive malware string record for this [`origin_string_hash`](super::origin_string_hash).
    pub fn lookup_malware_string(&self, hash: u64) -> Option<&MalwareStringRecord> {
        let idx = self
            .malware_strings
            .binary_search_by_key(&hash, |r| r.hash)
            .ok()?;
        self.malware_strings.get(idx)
    }

    /// Family name for a family index.
    pub fn family_name(&self, family_id: u16) -> Option<&str> {
        self.families
            .get(usize::from(family_id))
            .map(|f| f.name.as_str())
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

    /// Serializes this pack: `BXFAM003` when it carries symbols or string data, else `BXFAM002`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, FamilyError> {
        let v3 = self.has_v3_sections();
        let mut out = Vec::with_capacity(HEADER_V3_LEN + 1024);
        let flags = if self.band_records.is_empty() {
            0_u32
        } else {
            FLAG_HAS_BANDS
        };
        out.extend_from_slice(if v3 { MAGIC_V3 } else { MAGIC_V2 });
        out.extend_from_slice(&flags.to_le_bytes());
        let mut counts = vec![
            self.families.len(),
            self.trusted_sources.len(),
            self.trusted_shapes.len(),
            self.shared_shapes.len(),
            self.content_records.len(),
            self.shape_records.len(),
            self.band_records.len(),
        ];
        if v3 {
            counts.extend([
                self.symbols.len(),
                self.trusted_strings.len(),
                self.malware_strings.len(),
                0,
            ]);
        }
        for count in counts {
            out.extend_from_slice(&u32_len(count)?.to_le_bytes());
        }

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
        if !self.symbols.is_empty() {
            let mut payload = Vec::with_capacity(
                8 + self.symbol_pool.len() + self.symbols.len() * SYMBOL_RECORD_BYTES,
            );
            payload.extend_from_slice(&u32_len(self.symbols.len())?.to_le_bytes());
            payload.extend_from_slice(&u32_len(self.symbol_pool.len())?.to_le_bytes());
            payload.extend_from_slice(self.symbol_pool.as_bytes());
            for s in &self.symbols {
                payload.extend_from_slice(&s.shape.to_le_bytes());
                payload.extend_from_slice(&s.offset.to_le_bytes());
                payload.extend_from_slice(&s.len.to_le_bytes());
                payload.extend_from_slice(&s.source_id.to_le_bytes());
            }
            write_section(&mut enc, TAG_TRUSTED_SYMBOLS, &payload)?;
        }
        if !self.trusted_strings.is_empty() {
            let mut payload = Vec::with_capacity(8 + self.trusted_strings.len() * 8);
            payload.extend_from_slice(&[STRING_FILTER_SORTED_U64, 0, 0, 0]);
            payload.extend_from_slice(&u32_len(self.trusted_strings.len())?.to_le_bytes());
            for hash in &self.trusted_strings {
                payload.extend_from_slice(&hash.to_le_bytes());
            }
            write_section(&mut enc, TAG_TRUSTED_STRINGS, &payload)?;
        }
        if !self.malware_strings.is_empty() {
            let mut payload =
                Vec::with_capacity(4 + self.malware_strings.len() * MALWARE_STRING_RECORD_BYTES);
            payload.extend_from_slice(&u32_len(self.malware_strings.len())?.to_le_bytes());
            for r in &self.malware_strings {
                payload.extend_from_slice(&r.hash.to_le_bytes());
                payload.extend_from_slice(&r.sample_count.to_le_bytes());
                payload.extend_from_slice(&[r.family_count, 0]);
                for id in r.family_ids {
                    payload.extend_from_slice(&id.to_le_bytes());
                }
            }
            write_section(&mut enc, TAG_MALWARE_STRINGS, &payload)?;
        }
        let compressed = enc.finish()?;
        out.extend_from_slice(&compressed);
        Ok(out)
    }

    /// Parses and validates a `BXFAM002` or `BXFAM003` pack from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FamilyError> {
        let header = PackHeader::parse(bytes)?;
        let header_len = header.header_len();
        let PackStats {
            families: family_count,
            trusted_sources: trusted_source_count,
            trusted_shapes: trusted_count,
            shared_shapes: shared_count,
            content_records: content_count,
            shape_records: shape_count,
            band_records: band_count,
            trusted_symbols: symbol_count,
            trusted_strings: trusted_string_count,
            malware_strings: malware_string_count,
        } = header.stats;

        let mut decoder = ZlibDecoder::new(
            bytes
                .get(header_len..)
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

        let mut pack = Self {
            format_version: header.format_version,
            families,
            trusted_sources,
            trusted_shapes,
            shared_shapes,
            content_records,
            shape_records,
            band_records,
            symbol_pool: String::new(),
            symbols: Vec::new(),
            trusted_strings: Vec::new(),
            malware_strings: Vec::new(),
        };
        if header.format_version >= 3 {
            pack.read_sections(&mut cursor)?;
        }
        for (name, expected, actual) in [
            ("trusted symbol", symbol_count, pack.symbols.len()),
            (
                "trusted string",
                trusted_string_count,
                pack.trusted_strings.len(),
            ),
            (
                "malware string",
                malware_string_count,
                pack.malware_strings.len(),
            ),
        ] {
            if expected != actual {
                return Err(FamilyError::Pack(format!(
                    "{name} count {actual} does not match header count {expected}"
                )));
            }
        }
        Ok(pack)
    }

    fn read_sections(&mut self, cursor: &mut Cursor<'_>) -> Result<(), FamilyError> {
        let mut seen = Vec::new();
        while cursor.remaining() > 0 {
            let tag = cursor.u32()?;
            let len = cursor.u32()? as usize;
            let payload = cursor.take(len)?;
            if seen.contains(&tag) {
                return Err(FamilyError::Pack(format!("duplicate section {tag}")));
            }
            seen.push(tag);
            let mut section = Cursor::new(payload);
            match tag {
                TAG_TRUSTED_SYMBOLS => self.read_symbols(&mut section)?,
                TAG_TRUSTED_STRINGS => self.read_trusted_strings(&mut section)?,
                TAG_MALWARE_STRINGS => self.read_malware_strings(&mut section)?,
                // Unknown optional sections are skipped for forward compatibility.
                _ => continue,
            }
            if section.remaining() != 0 {
                return Err(FamilyError::Pack(format!(
                    "trailing bytes in section {tag}"
                )));
            }
        }
        Ok(())
    }

    fn read_symbols(&mut self, section: &mut Cursor<'_>) -> Result<(), FamilyError> {
        let count = section.u32()? as usize;
        let pool_len = section.u32()? as usize;
        let pool = std::str::from_utf8(section.take(pool_len)?)
            .map_err(|_| FamilyError::Pack("non-utf8 symbol pool".into()))?;
        if count.checked_mul(SYMBOL_RECORD_BYTES) != Some(section.remaining()) {
            return Err(FamilyError::Pack("symbol section size mismatch".into()));
        }
        let mut symbols = Vec::with_capacity(count);
        for _ in 0..count {
            let slot = SymbolSlot {
                shape: section.u64()?,
                offset: section.u32()?,
                len: section.u16()?,
                source_id: section.u16()?,
            };
            let start = slot.offset as usize;
            let end = start
                .checked_add(usize::from(slot.len))
                .ok_or_else(|| FamilyError::Pack("symbol range overflow".into()))?;
            if pool.get(start..end).is_none() {
                return Err(FamilyError::Pack("symbol name out of range".into()));
            }
            if slot.source_id != NO_ID && usize::from(slot.source_id) >= self.trusted_sources.len()
            {
                return Err(FamilyError::Pack("symbol source_id out of range".into()));
            }
            symbols.push(slot);
        }
        if !symbols.is_sorted_by_key(|s| s.shape) {
            symbols.sort_by_key(|s| s.shape);
        }
        symbols.dedup_by_key(|s| s.shape);
        self.symbol_pool = pool.to_owned();
        self.symbols = symbols;
        Ok(())
    }

    fn read_trusted_strings(&mut self, section: &mut Cursor<'_>) -> Result<(), FamilyError> {
        let encoding = section.u8()?;
        if encoding != STRING_FILTER_SORTED_U64 {
            return Err(FamilyError::Pack(format!(
                "unsupported trusted string filter encoding {encoding}"
            )));
        }
        section.take(3)?;
        let count = section.u32()? as usize;
        if count.checked_mul(8) != Some(section.remaining()) {
            return Err(FamilyError::Pack(
                "trusted string section size mismatch".into(),
            ));
        }
        let mut hashes = Vec::with_capacity(count);
        for _ in 0..count {
            hashes.push(section.u64()?);
        }
        if !hashes.is_sorted() {
            hashes.sort_unstable();
        }
        hashes.dedup();
        self.trusted_strings = hashes;
        Ok(())
    }

    fn read_malware_strings(&mut self, section: &mut Cursor<'_>) -> Result<(), FamilyError> {
        let count = section.u32()? as usize;
        if count.checked_mul(MALWARE_STRING_RECORD_BYTES) != Some(section.remaining()) {
            return Err(FamilyError::Pack(
                "malware string section size mismatch".into(),
            ));
        }
        let mut records = Vec::with_capacity(count);
        for _ in 0..count {
            let hash = section.u64()?;
            let sample_count = section.u16()?;
            let family_count = usize::from(section.u8()?);
            section.u8()?;
            let mut ids = [NO_ID; MAX_STRING_FAMILIES];
            for id in &mut ids {
                *id = section.u16()?;
            }
            if !(1..=MAX_STRING_FAMILIES).contains(&family_count) {
                return Err(FamilyError::Pack(
                    "malware string family count out of range".into(),
                ));
            }
            let used = ids.get(..family_count).unwrap_or(&[]);
            if used
                .iter()
                .any(|&id| usize::from(id) >= self.families.len())
            {
                return Err(FamilyError::Pack(
                    "malware string family_id out of range".into(),
                ));
            }
            records.push(MalwareStringRecord::new(hash, sample_count, used)?);
        }
        if !records.is_sorted_by_key(|r| r.hash) {
            records.sort_by_key(|r| r.hash);
        }
        records.dedup_by_key(|r| r.hash);
        self.malware_strings = records;
        Ok(())
    }
}

fn u32_len(len: usize) -> Result<u32, FamilyError> {
    u32::try_from(len).map_err(|_| FamilyError::Pack("table too large".into()))
}

fn write_section(w: &mut impl Write, tag: u32, payload: &[u8]) -> Result<(), FamilyError> {
    w.write_all(&tag.to_le_bytes())?;
    w.write_all(&u32_len(payload.len())?.to_le_bytes())?;
    w.write_all(payload)?;
    Ok(())
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
