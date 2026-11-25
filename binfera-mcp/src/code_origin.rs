//! Code Origin reports come from the same CLI matcher as the desktop app.
use binfera::family::{FamilyMatch, MatchReport};
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
    pack: Option<Pack>,
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
            pack: None,
            jobs: HashMap::new(),
            reports: HashMap::new(),
            failures: HashMap::new(),
            info: None,
        }
    }

    fn refresh_pack(&mut self) {
        let current = self
            .cache
            .parent()
            .and_then(|data| binfera_project::find_family_pack(data, Some(&self.exe)))
            .and_then(|path| path.canonicalize().ok())
            .and_then(|path| Pack::at(path).ok());
        if current != self.pack {
            self.pack = current;
            self.jobs.clear();
            self.reports.clear();
            self.failures.clear();
            self.info = None;
        }
    }

    fn cache_file(&self, sha: &str, pack: &Pack) -> PathBuf {
        self.cache
            .join(format!("{sha}-{}-{}.family.json", self.version, pack.key()))
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
        let Some(pack) = self.pack.clone() else {
            return;
        };
        let target = self.cache_file(sha, &pack);
        if target.is_file() || self.jobs.contains_key(sha) || self.reports.contains_key(sha) {
            return;
        }
        let mut command = self.command();
        command
            .args(["family", "match", "--json", "--pack"])
            .arg(&pack.path);
        self.jobs.insert(
            sha.into(),
            std::thread::spawn(move || {
                run_cached(command, input.path(), &target, || pack.validate())
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
        let Some(pack) = &self.pack else {
            return Ok(None);
        };
        let file = self.cache_file(sha, pack);
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
        let origin = Arc::new(CodeOrigin::new(report));
        self.reports.insert(sha.into(), Arc::clone(&origin));
        Ok(Some(origin))
    }

    pub fn pack_info(&mut self) -> Value {
        if let Some(info) = &self.info {
            return info.clone();
        }
        let Some(pack) = &self.pack else {
            return json!({"available": false});
        };
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
        self.info = Some(info.clone());
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
}

pub(crate) struct CodeOrigin {
    report: MatchReport,
    pub functions: HashMap<u64, FunctionOrigin>,
}

impl CodeOrigin {
    fn new(report: MatchReport) -> Self {
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
                    });
            }
        }
        Self { report, functions }
    }

    pub fn summary(&self) -> Value {
        json!({
            "available": true,
            "status": "ready",
            "breakdown": self.report.breakdown,
            "top_family": self.report.families.first().map(family_summary),
            "top_trusted_source": self.report.trusted_sources.first().map(|s| &s.source),
        })
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
