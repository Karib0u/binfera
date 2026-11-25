//! Code Origin reports come from the same CLI matcher as the desktop app.
use binfera::family::{
    normalize_origin_string, origin_string_hash, FamilyMatch, MatchReport, StringOriginKind,
    StringOriginReport,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::SystemTime;
use tempfile::NamedTempFile;

use crate::engine::run_cached;

#[derive(Clone, PartialEq, Eq)]
struct Pack {
    path: PathBuf,
    size: u64,
    modified: Option<SystemTime>,
}

impl Pack {
    fn at(path: PathBuf) -> std::io::Result<Self> {
        let meta = path.metadata()?;
        Ok(Self {
            path,
            size: meta.len(),
            modified: meta.modified().ok(),
        })
    }

    fn key(&self) -> String {
        // Use the OS bytes so two different non-UTF-8 paths cannot share a cache entry.
        let mut stamp = self.path.as_os_str().as_encoded_bytes().to_vec();
        stamp.extend_from_slice(format!("\0{}\0{:?}", self.size, self.modified).as_bytes());
        binfera_project::hash_bytes(&stamp)
    }

    fn validate(&self) -> Result<(), String> {
        if Self::at(self.path.clone()).is_ok_and(|current| current == *self) {
            Ok(())
        } else {
            Err("the family pack changed during matching".into())
        }
    }
}

pub(crate) struct FamilyAnalysis {
    exe: PathBuf,
    cache: PathBuf,
    version: String,
    /// Layered packs, base first. Empty when no pack is installed.
    packs: Vec<Pack>,
    jobs: HashMap<String, JoinHandle<Result<(), String>>>,
    reports: HashMap<String, Arc<CodeOrigin>>,
    failures: HashMap<String, String>,
    info: Option<Value>,
}

impl FamilyAnalysis {
    pub fn new(exe: &Path, cache: &Path, version: &str) -> Self {
        Self {
            exe: exe.to_path_buf(),
            cache: cache.to_path_buf(),
            version: version.replace(|c: char| !c.is_ascii_alphanumeric() && c != '.', "_"),
            packs: Vec::new(),
            jobs: HashMap::new(),
            reports: HashMap::new(),
            failures: HashMap::new(),
            info: None,
        }
    }

    fn refresh_pack(&mut self) {
        let current: Vec<Pack> = self
            .cache
            .parent()
            .map(|data| binfera_project::find_family_packs(data, Some(&self.exe)))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|path| path.canonicalize().ok())
            .filter_map(|path| Pack::at(path).ok())
            .collect();
        if current != self.packs {
            self.packs = current;
            self.jobs.clear();
            self.reports.clear();
            self.failures.clear();
            self.info = None;
        }
    }

    fn cache_file(&self, sha: &str, packs: &[Pack]) -> PathBuf {
        let key = match packs {
            [pack] => pack.key(),
            _ => binfera_project::hash_bytes(
                packs
                    .iter()
                    .map(Pack::key)
                    .collect::<Vec<_>>()
                    .join("\0")
                    .as_bytes(),
            ),
        };
        self.cache
            .join(format!("{sha}-{}-{key}.family.json", self.version))
    }

    /// Start background work when a binary is opened. Reopening can retry a failed match.
    pub fn start(&mut self, sha: &str, input: Arc<NamedTempFile>) {
        self.refresh_pack();
        self.failures.remove(sha);
        if self.jobs.get(sha).is_some_and(JoinHandle::is_finished) {
            self.jobs.remove(sha);
        }
        self.ensure(sha, input);
    }

    fn ensure(&mut self, sha: &str, input: Arc<NamedTempFile>) {
        if self.packs.is_empty() {
            return;
        }
        let packs = self.packs.clone();
        let target = self.cache_file(sha, &packs);
        if target.is_file() || self.jobs.contains_key(sha) || self.reports.contains_key(sha) {
            return;
        }
        let mut command = self.command();
        command.args(["family", "match", "--json"]);
        for pack in &packs {
            command.arg("--pack").arg(&pack.path);
        }
        self.jobs.insert(
            sha.into(),
            std::thread::spawn(move || {
                run_cached(command, input.path(), &target, || {
                    packs.iter().try_for_each(Pack::validate)
                })
            }),
        );
    }

    /// Reuse a report or wait for the background match. Lazily match desktop projects as needed.
    pub fn report(
        &mut self,
        sha: &str,
        input: impl FnOnce() -> Result<Arc<NamedTempFile>, String>,
    ) -> Result<Option<Arc<CodeOrigin>>, String> {
        self.refresh_pack();
        if self.packs.is_empty() {
            return Ok(None);
        }
        let file = self.cache_file(sha, &self.packs);
        if let Some(report) = self.reports.get(sha) {
            binfera_project::touch_cache_file(&file);
            return Ok(Some(Arc::clone(report)));
        }
        if let Some(error) = self.failures.get(sha) {
            return Err(error.clone());
        }
        if !file.is_file() && !self.jobs.contains_key(sha) {
            self.ensure(sha, input()?);
        }
        if let Some(job) = self.jobs.remove(sha) {
            let result = job
                .join()
                .map_err(|_| "code origin job panicked".to_string())?;
            if let Err(error) = result {
                self.failures.insert(sha.into(), error.clone());
                return Err(error);
            }
        }
        let report: MatchReport =
            serde_json::from_reader(File::open(&file).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        binfera_project::touch_cache_file(&file);
        let origin = Arc::new(CodeOrigin::new(report, self.packs.len() > 1));
        self.reports.insert(sha.into(), Arc::clone(&origin));
        Ok(Some(origin))
    }

    /// Describes the base pack at the top level, plus any overlays in priority order.
    pub fn pack_info(&mut self) -> Value {
        if let Some(info) = &self.info {
            return info.clone();
        }
        let Some((base, overlays)) = self.packs.split_first() else {
            return json!({"available": false});
        };
        let mut info = self.describe(base);
        if !overlays.is_empty() {
            info["overlays"] = json!(overlays
                .iter()
                .map(|p| self.describe(p))
                .collect::<Vec<_>>());
        }
        self.info = Some(info.clone());
        info
    }

    fn describe(&self, pack: &Pack) -> Value {
        let mut info = json!({
            "available": true,
            "name": pack.path.file_name().unwrap_or_default().to_string_lossy(),
            "path": pack.path.to_string_lossy(),
            "size": pack.size,
        });
        let output = self
            .command()
            .args(["family", "info", "--json", "--pack"])
            .arg(&pack.path)
            .output();
        match output {
            Ok(out) if out.status.success() => {
                if let Ok(Value::Object(header)) = serde_json::from_slice(&out.stdout) {
                    if let Some(object) = info.as_object_mut() {
                        object.extend(header);
                    }
                }
            }
            Ok(out) => info["error"] = json!(String::from_utf8_lossy(&out.stderr).trim()),
            Err(e) => info["error"] = json!(e.to_string()),
        }
        info
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.exe);
        command
            .env_remove("BINFERA_RULES_DIR")
            .env_remove("CAPA_RULES_DIR")
            .stdin(Stdio::null());
        command
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OriginKind {
    Malware,
    Shared,
    Unique,
    Trusted,
}

impl OriginKind {
    pub fn parse(kind: &str) -> Result<Option<Self>, String> {
        match kind {
            "all" => Ok(None),
            "malware" => Ok(Some(Self::Malware)),
            "shared" => Ok(Some(Self::Shared)),
            "unique" => Ok(Some(Self::Unique)),
            "trusted" => Ok(Some(Self::Trusted)),
            _ => Err(format!("unknown origin filter `{kind}`")),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct FunctionOrigin {
    pub kind: OriginKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_source: Option<String>,
    /// Name a `BXFAM003` pack records for this Trusted function.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_symbol: Option<String>,
    /// Pack that contributed the attribution, when several packs are layered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pack: Option<String>,
}

/// String Reuse classification of one string value.
#[derive(Serialize)]
pub(crate) struct StringOrigin {
    pub kind: StringOriginKind,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub families: Vec<String>,
}

impl StringOrigin {
    pub fn parse_filter(kind: &str) -> Result<Option<StringOriginKind>, String> {
        match kind {
            "all" => Ok(None),
            "malware" => Ok(Some(StringOriginKind::Malware)),
            "shared" => Ok(Some(StringOriginKind::Shared)),
            "unique" => Ok(Some(StringOriginKind::Unique)),
            "trusted" => Ok(Some(StringOriginKind::Trusted)),
            _ => Err(format!("unknown string origin filter `{kind}`")),
        }
    }
}

pub(crate) struct CodeOrigin {
    report: MatchReport,
    pub functions: HashMap<u64, FunctionOrigin>,
    strings: HashMap<u64, StringOrigin>,
}

impl CodeOrigin {
    /// `layered` keeps each attribution's pack name, which only matters with several packs.
    fn new(report: MatchReport, layered: bool) -> Self {
        let mut functions = HashMap::new();
        for source in &report.trusted_sources {
            let name = &source.source;
            for &address in &source.addresses {
                functions.insert(
                    address,
                    FunctionOrigin {
                        kind: OriginKind::Trusted,
                        family: None,
                        trusted_source: Some(name.clone()),
                        trusted_symbol: None,
                        pack: None,
                    },
                );
            }
        }
        for (kind, addresses) in [
            (OriginKind::Shared, &report.shared_addresses),
            (OriginKind::Unique, &report.unique_addresses),
        ] {
            for &address in addresses {
                functions.insert(
                    address,
                    FunctionOrigin {
                        kind,
                        family: None,
                        trusted_source: None,
                        trusted_symbol: None,
                        pack: None,
                    },
                );
            }
        }
        // Families are already ranked by the matcher. Keep the first attribution for each address.
        for family in &report.families {
            let name = &family.family;
            for matched in &family.functions {
                functions
                    .entry(matched.address)
                    .or_insert_with(|| FunctionOrigin {
                        kind: OriginKind::Malware,
                        family: Some(name.clone()),
                        trusted_source: None,
                        trusted_symbol: None,
                        pack: matched.pack_name.clone().filter(|_| layered),
                    });
            }
        }
        for symbol in &report.trusted_symbols {
            if let Some(origin) = functions.get_mut(&symbol.address) {
                origin.trusted_symbol = Some(symbol.trusted_symbol.clone());
                if layered {
                    origin.pack = origin.pack.take().or_else(|| symbol.pack_name.clone());
                }
            }
        }
        let strings = report
            .strings
            .iter()
            .flat_map(|s| &s.entries)
            .filter_map(|entry| {
                let hash = u64::from_str_radix(&entry.hash, 16).ok()?;
                Some((
                    hash,
                    StringOrigin {
                        kind: entry.kind,
                        families: entry.families.clone(),
                    },
                ))
            })
            .collect();
        Self {
            report,
            functions,
            strings,
        }
    }

    /// Trusted symbol for a function, used as a display name when the binary names nothing.
    pub fn trusted_symbol(&self, address: u64) -> Option<&str> {
        self.functions.get(&address)?.trusted_symbol.as_deref()
    }

    /// Classifies a string value the way the matcher did. `None` means unknown: the pack set has
    /// no string data, the value is not eligible, or the report's entry list was truncated.
    pub fn string_origin(&self, value: &str) -> Option<StringOrigin> {
        let report = self.report.strings.as_ref()?;
        let hash = origin_string_hash(&normalize_origin_string(value)?);
        if let Some(origin) = self.strings.get(&hash) {
            return Some(StringOrigin {
                kind: origin.kind,
                families: origin.families.clone(),
            });
        }
        // MCP string values are capped at 400 characters, so a long value may differ from the
        // full string the matcher hashed.
        (!report.entries_truncated && value.chars().count() < 400).then_some(StringOrigin {
            kind: StringOriginKind::Unique,
            families: Vec::new(),
        })
    }

    pub fn summary(&self) -> Value {
        let mut out = json!({
            "available": true,
            "status": "ready",
            "breakdown": self.report.breakdown,
            "top_family": self.report.families.first().map(family_summary),
            "top_trusted_source": self.report.trusted_sources.first().map(|s| &s.source),
        });
        if let Some(strings) = &self.report.strings {
            out["string_origin"] = json!({
                "breakdown": strings.breakdown,
                "string_only_hint": string_hint(strings),
            });
        }
        out
    }

    pub fn details(&self, include_functions: bool) -> Value {
        let r = &self.report;
        let mut out = json!({
            "status": "ready",
            "total_functions": r.total_functions,
            "eligible_functions": r.eligible_functions,
            "breakdown": r.breakdown,
            "function_counts": {
                "malware": r.family_matched_functions,
                "shared": r.shared_malware_functions,
                "unique": r.unique_functions,
                "trusted": r.trusted_functions,
            },
            "families": r.families.iter().take(10).map(family_summary).collect::<Vec<_>>(),
            "trusted_sources": r.trusted_sources.iter().take(10).map(|s|
                json!({"name": s.source, "matched_functions": s.functions})
            ).collect::<Vec<_>>(),
        });
        out["string_origin"] = match &r.strings {
            Some(strings) => string_origin_details(strings),
            None => json!({"available": false}),
        };
        if !r.trusted_symbols.is_empty() {
            out["trusted_symbol_count"] = json!(r.trusted_symbols.len());
        }
        if include_functions {
            let mut functions: Vec<_> = r
                .families
                .iter()
                .flat_map(|f| f.functions.iter().take(20))
                .collect();
            functions.sort_by_key(|m| (std::cmp::Reverse(m.instructions), m.address));
            functions.dedup_by_key(|m| m.address);
            out["top_malware_functions"] = json!(functions
                .iter()
                .take(20)
                .map(|m| json!({
                    "address": format!("{:#x}", m.address),
                    "instructions": m.instructions,
                    "origin": self.functions.get(&m.address),
                }))
                .collect::<Vec<_>>());
        }
        out
    }
}

/// Labeled so an agent cannot mistake it for a code verdict.
fn string_hint(strings: &StringOriginReport) -> Value {
    strings.string_only_hint.as_ref().map_or(Value::Null, |hint| {
        json!({
            "family": hint.family,
            "exclusive_strings": hint.exclusive_strings,
            "label": "string_only_hint",
            "note": "Code attribution abstained. Strings alone are a lead to verify, not a family verdict.",
        })
    })
}

fn string_origin_details(strings: &StringOriginReport) -> Value {
    let top = |kind: StringOriginKind| {
        strings
            .entries
            .iter()
            .filter(|e| e.kind == kind)
            .take(10)
            .map(|e| json!({"value": e.value.chars().take(160).collect::<String>(), "families": e.families, "encoding": e.encoding}))
            .collect::<Vec<_>>()
    };
    json!({
        "available": true,
        "note": "Supporting evidence only. String Reuse never changes the code families or confidence.",
        "total_strings": strings.total_strings,
        "breakdown": strings.breakdown,
        "string_counts": {
            "malware": strings.malware_strings,
            "shared": strings.shared_strings,
            "unique": strings.unique_strings,
            "trusted": strings.trusted_strings,
        },
        "families": strings.families.iter().take(5).map(|f| json!({
            "name": f.family,
            "exclusive_strings": f.exclusive_strings,
            "shared_strings": f.shared_strings,
            "corroborates_code": f.corroborates_code,
        })).collect::<Vec<_>>(),
        "top_malware_strings": top(StringOriginKind::Malware),
        "top_shared_strings": top(StringOriginKind::Shared),
        "string_only_hint": string_hint(strings),
    })
}

fn family_summary(family: &FamilyMatch) -> Value {
    // Same confidence levels as the Code Origin card, based on amount and quality of evidence.
    let exact = family.exact_content_hits > 0 || family.exact_shape_hits > 0;
    let confidence = match (family.exclusive_functions, family.coverage) {
        (10.., coverage) if coverage >= 0.5 => {
            if exact {
                "strong"
            } else {
                "likely"
            }
        }
        (3.., coverage) if coverage >= 0.25 && exact => "likely",
        _ => "weak",
    };
    json!({
        "name": family.family,
        "score": family.score,
        "confidence": confidence,
        "matched_functions": family.functions.len(),
        "shared_count": family.functions.iter().filter(|m| m.exclusivity > 1).count(),
        "exclusive_functions": family.exclusive_functions,
        "coverage": family.coverage,
    })
}
