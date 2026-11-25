//! Layered matching over several `.bxfam` packs (for example a base pack plus an
//! organization's Trusted overlay), mixing `BXFAM002` and `BXFAM003` freely.

use super::matcher::{match_layers, LayerRef};
use super::strings::OriginString;
use super::{FamilyError, FamilyPack, MatchConfig, MatchReport, SampleSketch, TrustedSymbolRef};

/// A named pack inside a [`FamilyPackSet`].
#[derive(Debug, Clone)]
pub struct PackLayer {
    /// Display name recorded as `pack_name` on matches, usually the file name.
    pub name: String,
    pub pack: FamilyPack,
}

/// Ordered packs matched together. Layers are listed base first; later layers are overlays with
/// higher priority.
///
/// - A function shape or string Trusted by any layer is Trusted, which silences malware matches
///   from every other layer.
/// - Trusted source names and symbols come from the highest-priority layer that has one.
/// - Malware matches merge by family name, so a function is counted once per family even when
///   several layers know it; each match records the contributing layer's `pack_name`.
#[derive(Debug, Clone, Default)]
pub struct FamilyPackSet {
    layers: Vec<PackLayer>,
}

impl FamilyPackSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a pack above every pack already in the set.
    pub fn push(&mut self, name: impl Into<String>, pack: FamilyPack) {
        self.layers.push(PackLayer {
            name: name.into(),
            pack,
        });
    }

    /// Parses `(name, bytes)` pairs, base first, into a set.
    pub fn from_named_bytes<'a>(
        packs: impl IntoIterator<Item = (String, &'a [u8])>,
    ) -> Result<Self, FamilyError> {
        let mut set = Self::new();
        for (name, bytes) in packs {
            let pack = FamilyPack::from_bytes(bytes)
                .map_err(|e| FamilyError::Pack(format!("{name}: {e}")))?;
            set.push(name, pack);
        }
        Ok(set)
    }

    /// Layers in priority order, base first.
    pub fn layers(&self) -> &[PackLayer] {
        &self.layers
    }

    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }

    pub fn len(&self) -> usize {
        self.layers.len()
    }

    /// True when any layer can classify strings.
    pub fn has_string_data(&self) -> bool {
        self.layers.iter().any(|l| l.pack.has_string_data())
    }

    /// Trusted source name for a shape and the layer that supplied it, highest priority first.
    pub fn lookup_trusted(&self, shape: u64) -> Option<(&str, &str)> {
        self.layers
            .iter()
            .rev()
            .find_map(|l| l.pack.lookup_trusted(shape).map(|s| (s, l.name.as_str())))
    }

    /// Trusted symbol for a shape and the layer that supplied it, highest priority first.
    pub fn lookup_trusted_symbol(&self, shape: u64) -> Option<(TrustedSymbolRef<'_>, &str)> {
        self.layers.iter().rev().find_map(|l| {
            l.pack
                .lookup_trusted_symbol(shape)
                .map(|s| (s, l.name.as_str()))
        })
    }

    /// True when any layer's Trusted string filter contains this hash.
    pub fn is_trusted_string(&self, hash: u64) -> bool {
        self.layers.iter().any(|l| l.pack.is_trusted_string(hash))
    }

    /// Matches code only.
    pub fn match_sketch(&self, sketch: &SampleSketch, config: &MatchConfig) -> MatchReport {
        self.match_sample(sketch, None, config)
    }

    /// Matches code, then classifies `strings` (from
    /// [`extract_origin_strings`](super::extract_origin_strings)) as separate supporting evidence.
    /// The code attribution is identical with or without strings.
    pub fn match_sample(
        &self,
        sketch: &SampleSketch,
        strings: Option<&[OriginString]>,
        config: &MatchConfig,
    ) -> MatchReport {
        let layers: Vec<LayerRef<'_>> = self
            .layers
            .iter()
            .map(|l| LayerRef {
                name: Some(l.name.as_str()),
                pack: &l.pack,
            })
            .collect();
        match_layers(&layers, sketch, strings, config)
    }
}
