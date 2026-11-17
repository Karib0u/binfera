//! Analysis access for the MCP server. The server has no parser or decompiler of its own: it runs
//! the `binfera` executable as an isolated child process (so a decompiler crash cannot take the
//! server down) and keeps the results in an on-disk cache keyed by file hash and engine version.
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const JOB_TIMEOUT: Duration = Duration::from_secs(60 * 60);

#[derive(Clone, Debug)]
pub enum JobState {
    Running { since: Instant },
    Failed(String),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Job {
    Decompile,
    Capa,
}
impl Job {
    fn suffix(self) -> &'static str {
        match self {
            Job::Decompile => "decomp.jsonl",
            Job::Capa => "capa.json",
        }
    }
}

pub struct FunctionEntry {
    pub address: u64,
    pub name: String,
    pub calls: Vec<u64>,
    pub lines: usize,
    pub warnings: usize,
    /// Addresses the function reads or takes the address of (strings, tables, globals).
    pub data_refs: Vec<u64>,
    offset: u64,
    length: usize,
}

pub struct Index {
    pub functions: Vec<FunctionEntry>,
    by_address: HashMap<u64, usize>,
    /// Function entry addresses in ascending order, for finding the function an address is in.
    starts: Vec<u64>,
    pub callers: HashMap<u64, Vec<u64>>,
    /// Data address to the functions referencing it.
    pub refs_to: HashMap<u64, Vec<u64>>,
    file: PathBuf,
}

impl Index {
    /// The recovered function whose code most plausibly contains `address` (the nearest entry at
    /// or below it). Callers confirm with the function's own instruction list.
    pub fn owner(&self, address: u64) -> Option<&FunctionEntry> {
        let n = self.starts.partition_point(|s| *s <= address);
        n.checked_sub(1).and_then(|i| self.get(self.starts[i]))
    }

    pub fn get(&self, address: u64) -> Option<&FunctionEntry> {
        self.by_address.get(&address).map(|&i| &self.functions[i])
    }
    /// The full decompiler record of one function, read back from the cache file.
    pub fn record(&self, entry: &FunctionEntry) -> Result<Value, String> {
        let mut file = File::open(&self.file).map_err(|e| e.to_string())?;
        binfera_project::touch_cache_file(&self.file);
        file.seek(SeekFrom::Start(entry.offset))
            .map_err(|e| e.to_string())?;
        let mut buffer = vec![0u8; entry.length];
        file.read_exact(&mut buffer).map_err(|e| e.to_string())?;
        serde_json::from_slice(&buffer).map_err(|e| e.to_string())
    }
}

/// Where a virtual address lives in the file, from the normalised image headers.
pub struct Image {
    pub path: PathBuf,
    sections: Vec<Section>,
    pub imports: Vec<(String, String, u64)>,
    pub exports: Vec<(String, u64)>,
}
struct Section {
    va: u64,
    off: u64,
    size: u64,
    executable: bool,
}

pub struct StringEntry {
    pub address: u64,
    pub value: String,
    pub encoding: &'static str,
}

impl Image {
    fn parse(path: &str, info: &Value) -> Image {
        let sections = info["sections"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|s| Section {
                va: s["va"].as_u64().unwrap_or(0),
                off: s["off"].as_u64().unwrap_or(0),
                size: s["size"].as_u64().unwrap_or(0),
                executable: s["perms"].as_str().is_some_and(|p| p.contains('x')),
            })
            .collect();
        let imports = info["imports"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|i| {
                (
                    i["dll"].as_str().unwrap_or("").to_string(),
                    i["name"].as_str().unwrap_or("").to_string(),
                    i["va"].as_u64().unwrap_or(0),
                )
            })
            .collect();
        let exports = info["exports"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|e| {
                (
                    e["name"].as_str().unwrap_or("").to_string(),
                    e["va"].as_u64().unwrap_or(0),
                )
            })
            .collect();
        Image {
            path: PathBuf::from(path),
            sections,
            imports,
            exports,
        }
    }

    fn read(&self, va: u64, max: usize) -> Option<Vec<u8>> {
        let s = self
            .sections
            .iter()
            .find(|s| va >= s.va && va < s.va + s.size)?;
        let start = s.off + (va - s.va);
        let len = (s.size - (va - s.va)).min(max as u64) as usize;
        let mut file = File::open(&self.path).ok()?;
        file.seek(SeekFrom::Start(start)).ok()?;
        let mut buffer = vec![0u8; len];
        let n = file.read(&mut buffer).ok()?;
        buffer.truncate(n);
        Some(buffer)
    }

    /// The string at `va`, if the bytes there read as printable ASCII or UTF-16LE text.
    pub fn string_at(&self, va: u64) -> Option<StringEntry> {
        let bytes = self.read(va, 512)?;
        let ascii: Vec<u8> = bytes
            .iter()
            .copied()
            .take_while(|b| (0x20..0x7f).contains(b) || matches!(b, b'\n' | b'\r' | b'\t'))
            .collect();
        if ascii.len() >= 4 && bytes.get(ascii.len()).is_none_or(|b| *b == 0) {
            return Some(StringEntry {
                address: va,
                value: String::from_utf8_lossy(&ascii).into_owned(),
                encoding: "ascii",
            });
        }
        let wide: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|c| (0x20..0x7f).contains(c))
            .collect();
        (wide.len() >= 4).then(|| StringEntry {
            address: va,
            value: String::from_utf16_lossy(&wide),
            encoding: "utf16",
        })
    }

    /// Printable runs of at least five characters in the non-executable sections.
    pub fn scan_strings(&self, limit: usize) -> Vec<StringEntry> {
        let mut out = Vec::new();
        for s in self
            .sections
            .iter()
            .filter(|s| !s.executable && s.size > 0 && s.size <= 256 << 20)
        {
            let Some(data) = self.read(s.va, s.size as usize) else {
                continue;
            };
            let mut i = 0;
            while i < data.len() && out.len() < limit {
                let ascii_run = data[i..]
                    .iter()
                    .take_while(|b| (0x20..0x7f).contains(*b))
                    .count();
                if ascii_run >= 5 {
                    out.push(StringEntry {
                        address: s.va + i as u64,
                        value: String::from_utf8_lossy(&data[i..i + ascii_run.min(400)])
                            .into_owned(),
                        encoding: "ascii",
                    });
                    i += ascii_run + 1;
                    continue;
                }
                let wide_run = data[i..]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .take_while(|c| c[1] == 0 && (0x20..0x7f).contains(&c[0]))
                    .count();
                if wide_run >= 5 {
                    let value: String = data[i..i + wide_run.min(400) * 2]
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|c| c[0] as char)
                        .collect();
                    out.push(StringEntry {
                        address: s.va + i as u64,
                        value,
                        encoding: "utf16",
                    });
                    i += wide_run * 2 + 2;
                    continue;
                }
                i += 1;
            }
        }
        out
    }
}

pub struct Engine {
    pub exe: PathBuf,
    pub cache_dir: PathBuf,
    pub version: String,
    jobs: Arc<Mutex<HashMap<(String, Job), JobState>>>,
    indexes: HashMap<String, Arc<Index>>,
    images: HashMap<String, Arc<Image>>,
    strings: HashMap<String, Arc<Vec<StringEntry>>>,
    capability_counts: HashMap<String, Arc<HashMap<u64, usize>>>,
}

/// `FUN_00401000` out of `unsigned char * FUN_00401000(void)`.
fn function_name(text: &str) -> Option<String> {
    let line = text.lines().find(|l| l.contains('('))?;
    let head = line.split('(').next()?;
    let name = head
        .rsplit(|c: char| c.is_whitespace() || c == '*')
        .find(|t| !t.is_empty())?;
    Some(name.to_string())
}

impl Engine {
    pub fn new(exe: PathBuf, cache_dir: PathBuf, version: String) -> Engine {
        let _ = std::fs::create_dir_all(&cache_dir);
        let prune_dir = cache_dir.clone();
        std::thread::spawn(move || {
            let _ = binfera_project::prune_cache(&prune_dir, binfera_project::cache_max_bytes());
        });
        Engine {
            exe,
            cache_dir,
            version,
            jobs: Arc::default(),
            indexes: HashMap::new(),
            images: HashMap::new(),
            strings: HashMap::new(),
            capability_counts: HashMap::new(),
        }
    }

    fn cache_file(&self, sha: &str, job: Job) -> PathBuf {
        let safe: String = self
            .version
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.cache_dir
            .join(format!("{sha}-{safe}.{}", job.suffix()))
    }

    pub fn is_ready(&self, sha: &str, job: Job) -> bool {
        let file = self.cache_file(sha, job);
        if !file.is_file() {
            return false;
        }
        binfera_project::touch_cache_file(&file);
        true
    }

    /// `"ready"`, `"running"` or `"failed: ..."`; starts the job when it has not run yet.
    pub fn status(&self, sha: &str, job: Job) -> String {
        if self.is_ready(sha, job) {
            return "ready".into();
        }
        match self.jobs.lock().unwrap().get(&(sha.to_string(), job)) {
            Some(JobState::Running { since }) => {
                format!("running ({}s)", since.elapsed().as_secs())
            }
            Some(JobState::Failed(e)) => format!("failed: {e}"),
            None => "not started".into(),
        }
    }

    /// Starts `job` for the file in the background unless it is cached, running, or already failed.
    pub fn ensure(&self, sha: &str, path: &str, job: Job) {
        if self.is_ready(sha, job) {
            return;
        }
        {
            let mut jobs = self.jobs.lock().unwrap();
            if jobs.contains_key(&(sha.to_string(), job)) {
                return;
            }
            jobs.insert(
                (sha.to_string(), job),
                JobState::Running {
                    since: Instant::now(),
                },
            );
        }
        let jobs = Arc::clone(&self.jobs);
        let exe = self.exe.clone();
        let target = self.cache_file(sha, job);
        let key = (sha.to_string(), job);
        let path = path.to_string();
        std::thread::spawn(move || {
            let outcome = run_job(&exe, Path::new(&path), job, &target);
            let mut jobs = jobs.lock().unwrap();
            match outcome {
                Ok(()) => {
                    jobs.remove(&key);
                }
                Err(e) => {
                    jobs.insert(key, JobState::Failed(e));
                }
            }
        });
    }

    /// Forgets a failed job so it can be retried.
    pub fn clear_failure(&self, sha: &str, job: Job) {
        let mut jobs = self.jobs.lock().unwrap();
        if matches!(jobs.get(&(sha.to_string(), job)), Some(JobState::Failed(_))) {
            jobs.remove(&(sha.to_string(), job));
        }
    }

    pub fn index(&mut self, sha: &str) -> Result<Arc<Index>, String> {
        if let Some(index) = self.indexes.get(sha) {
            binfera_project::touch_cache_file(&self.cache_file(sha, Job::Decompile));
            return Ok(Arc::clone(index));
        }
        if !self.is_ready(sha, Job::Decompile) {
            return Err(format!(
                "decompilation is {}; retry shortly",
                self.status(sha, Job::Decompile)
            ));
        }
        let file = self.cache_file(sha, Job::Decompile);
        let index = Arc::new(build_index(&file)?);
        self.indexes.insert(sha.to_string(), Arc::clone(&index));
        Ok(index)
    }

    pub fn image(&mut self, sha: &str, path: &str) -> Result<Arc<Image>, String> {
        if let Some(image) = self.images.get(sha) {
            return Ok(Arc::clone(image));
        }
        let image = Arc::new(Image::parse(path, &self.image_info(path)?));
        self.images.insert(sha.to_string(), Arc::clone(&image));
        Ok(image)
    }

    pub fn strings(&mut self, sha: &str, path: &str) -> Result<Arc<Vec<StringEntry>>, String> {
        if let Some(strings) = self.strings.get(sha) {
            return Ok(Arc::clone(strings));
        }
        let strings = Arc::new(self.image(sha, path)?.scan_strings(200_000));
        self.strings.insert(sha.to_string(), Arc::clone(&strings));
        Ok(strings)
    }

    /// How many non-library capability rules matched at each function's address.
    pub fn capability_counts(&mut self, sha: &str) -> Arc<HashMap<u64, usize>> {
        if let Some(counts) = self.capability_counts.get(sha) {
            return Arc::clone(counts);
        }
        let mut counts: HashMap<u64, usize> = HashMap::new();
        if let Ok(capa) = self.capa(sha) {
            for rule in capa["rules"]
                .as_object()
                .into_iter()
                .flat_map(|r| r.values())
            {
                if rule["meta"]["lib"].as_bool().unwrap_or(false) {
                    continue;
                }
                let mut seen = HashSet::new();
                for m in rule["matches"].as_array().into_iter().flatten() {
                    let a = &m[0];
                    if a["type"] == "absolute" {
                        if let Some(v) = a["value"].as_u64() {
                            if seen.insert(v) {
                                *counts.entry(v).or_default() += 1;
                            }
                        }
                    }
                }
            }
            // Only cache a finished analysis; an unfinished one is retried.
            let counts = Arc::new(counts);
            self.capability_counts
                .insert(sha.to_string(), Arc::clone(&counts));
            return counts;
        }
        Arc::new(counts)
    }

    /// Functions the signature matcher identified as library code: `(address, name)`.
    pub fn library_functions(&self, sha: &str) -> Option<Vec<(u64, String)>> {
        let capa = self.capa(sha).ok()?;
        Some(
            capa["meta"]["analysis"]["library_functions"]
                .as_array()?
                .iter()
                .filter_map(|f| {
                    Some((
                        f["address"]["value"].as_u64()?,
                        f["name"].as_str()?.to_string(),
                    ))
                })
                .collect(),
        )
    }

    pub fn capa(&self, sha: &str) -> Result<Value, String> {
        let file = self.cache_file(sha, Job::Capa);
        let bytes = std::fs::read(&file)
            .map_err(|_| format!("capability analysis is {}", self.status(sha, Job::Capa)))?;
        let report = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        binfera_project::touch_cache_file(&file);
        Ok(report)
    }

    /// Normalised headers, sections, imports and exports (fast; run synchronously).
    /// Emulation runs in a fresh child with request/output files and an overall deadline.
    pub fn emulate(
        &self,
        path: &str,
        request: &Value,
        call_sites: Option<usize>,
    ) -> Result<Value, String> {
        let address = request["address"]
            .as_u64()
            .ok_or("missing emulation address")?;
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let input_path = dir.path().join("request.json");
        let output_path = dir.path().join("result.json");
        let error_path = dir.path().join("error.txt");
        serde_json::to_writer(
            File::create(&input_path).map_err(|e| e.to_string())?,
            request,
        )
        .map_err(|e| e.to_string())?;
        if std::fs::metadata(&input_path)
            .map_err(|e| e.to_string())?
            .len()
            > 8 * 1024 * 1024
        {
            return Err("emulation request exceeds 8 MiB".into());
        }
        let mut command = Command::new(&self.exe);
        command
            .env_remove("BINFERA_RULES_DIR")
            .env_remove("CAPA_RULES_DIR")
            .arg(path)
            .args(["--emulate", &format!("0x{address:x}"), "--emulate-request"])
            .stdin(File::open(&input_path).map_err(|e| e.to_string())?)
            .stdout(File::create(&output_path).map_err(|e| e.to_string())?)
            .stderr(File::create(&error_path).map_err(|e| e.to_string())?);
        if let Some(max_sites) = call_sites {
            command.args([
                "--emulate-call-sites",
                "--emulate-max-sites",
                &max_sites.to_string(),
            ]);
        }
        let mut child = command.spawn().map_err(|e| e.to_string())?;
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None)
                    if started.elapsed() < Duration::from_secs(120)
                        && std::fs::metadata(&output_path).map_or(0, |m| m.len())
                            <= 16 * 1024 * 1024 =>
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                result => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(match result {
                        Err(e) => e.to_string(),
                        _ => "emulation exceeded its process time or output limit".into(),
                    });
                }
            }
        };
        if !status.success() {
            let mut error = String::new();
            File::open(error_path)
                .map_err(|e| e.to_string())?
                .take(16384)
                .read_to_string(&mut error)
                .map_err(|e| e.to_string())?;
            return Err(format!("emulation failed: {}", error.trim()));
        }
        if std::fs::metadata(&output_path)
            .map_err(|e| e.to_string())?
            .len()
            > 16 * 1024 * 1024
        {
            return Err("emulation output exceeds 16 MiB".into());
        }
        serde_json::from_reader(File::open(output_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())
    }

    pub fn image_info(&self, path: &str) -> Result<Value, String> {
        let output = Command::new(&self.exe)
            .args(["--image-info", "--json", path])
            .env_remove("BINFERA_RULES_DIR")
            .env_remove("CAPA_RULES_DIR")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("cannot run {}: {e}", self.exe.display()))?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
        }
        serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())
    }
}

fn build_index(file: &PathBuf) -> Result<Index, String> {
    let mut reader = BufReader::new(File::open(file).map_err(|e| e.to_string())?);
    let mut functions = Vec::new();
    let mut names = HashMap::new();
    let mut offset = 0u64;
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        if line.contains("\"type\":\"start\"") {
            if let Ok(value) = serde_json::from_str::<Value>(&line) {
                if let Some(items) = value["names"].as_object() {
                    for (address, name) in items {
                        if let (Ok(address), Some(name)) = (address.parse::<u64>(), name.as_str()) {
                            names.insert(address, name.to_owned());
                        }
                    }
                }
            }
        }
        // Cheap prefilter: only function records need parsing. It must not depend on key order:
        // a writer that sorts keys puts `type` last, and a
        // starts-with check then drops every function. Escaped quotes inside strings cannot match this substring.
        if line.contains("\"type\":\"function\"") {
            if let Ok(value) = serde_json::from_str::<Value>(&line) {
                if value["type"].as_str() == Some("function") {
                    if let Some(address) = value["address"].as_u64() {
                        let text = value["text"].as_str().unwrap_or("");
                        functions.push(FunctionEntry {
                            address,
                            name: value["name"]
                                .as_str()
                                .map(str::to_owned)
                                .or_else(|| names.get(&address).cloned())
                                .or_else(|| function_name(text))
                                .unwrap_or_else(|| format!("FUN_{address:08x}")),
                            calls: value["calls"]
                                .as_array()
                                .map(|c| c.iter().filter_map(Value::as_u64).collect())
                                .unwrap_or_default(),
                            lines: text.lines().count(),
                            warnings: value["warnings"].as_array().map_or(0, Vec::len),
                            data_refs: value["data_refs"]
                                .as_array()
                                .map(|r| r.iter().filter_map(|d| d["to"].as_u64()).collect())
                                .unwrap_or_default(),
                            offset,
                            length: n,
                        });
                    }
                }
            }
        }
        offset += n as u64;
    }
    // Deferred retries replace the earlier record, including its file offset.
    let mut by_address = HashMap::new();
    let mut unique = Vec::new();
    for f in functions {
        if let Some(&index) = by_address.get(&f.address) {
            unique[index] = f;
        } else {
            by_address.insert(f.address, unique.len());
            unique.push(f);
        }
    }
    let mut callers: HashMap<u64, Vec<u64>> = HashMap::new();
    for f in &unique {
        for callee in &f.calls {
            callers.entry(*callee).or_default().push(f.address);
        }
    }
    let mut refs_to: HashMap<u64, Vec<u64>> = HashMap::new();
    for f in &unique {
        for to in &f.data_refs {
            let list = refs_to.entry(*to).or_default();
            if list.last() != Some(&f.address) {
                list.push(f.address);
            }
        }
    }
    let mut starts: Vec<u64> = unique.iter().map(|f| f.address).collect();
    starts.sort_unstable();
    Ok(Index {
        functions: unique,
        starts,
        by_address,
        callers,
        refs_to,
        file: file.clone(),
    })
}

fn run_job(exe: &Path, path: &Path, job: Job, target: &Path) -> Result<(), String> {
    let tmp = target.with_extension("tmp");
    let err_path = target.with_extension("err");
    let out = File::create(&tmp).map_err(|e| e.to_string())?;
    let err = File::create(&err_path).map_err(|e| e.to_string())?;
    let mut command = Command::new(exe);
    // `BINFERA_RULES_DIR` is clap's environment fallback for `--rules`, which conflicts with the
    // decompile and image modes, so only the capability run may see it. The server may start from
    // any directory, where `./rules` does not exist: fall back to a rules directory kept beside the
    // project database (`<data dir>/rules`).
    if job == Job::Capa {
        if std::env::var_os("BINFERA_RULES_DIR").is_none()
            && std::env::var_os("CAPA_RULES_DIR").is_none()
        {
            if let Some(rules) = target
                .parent()
                .and_then(|cache| cache.parent())
                .map(|data| data.join("rules"))
                .filter(|p| p.is_dir())
            {
                command.env("BINFERA_RULES_DIR", rules);
            }
        }
    } else {
        command
            .env_remove("BINFERA_RULES_DIR")
            .env_remove("CAPA_RULES_DIR");
    }
    match job {
        Job::Decompile => command.args(["--decompile-all", "--json"]),
        Job::Capa => command.arg("--json"),
    };
    let mut child = command
        .arg(path)
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        .spawn()
        .map_err(|e| format!("cannot run {}: {e}", exe.display()))?;
    let started = Instant::now();
    let status = loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(status) => break status,
            None if started.elapsed() > JOB_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = std::fs::remove_file(&tmp);
                return Err("timed out".into());
            }
            None => std::thread::sleep(Duration::from_millis(200)),
        }
    };
    if !status.success() {
        let message = std::fs::read_to_string(&err_path).unwrap_or_default();
        let _ = std::fs::remove_file(&tmp);
        let tail: Vec<&str> = message.lines().rev().take(3).collect();
        return Err(format!(
            "exit {}: {}",
            status.code().unwrap_or(-1),
            tail.into_iter().rev().collect::<Vec<_>>().join(" | ")
        ));
    }
    std::fs::rename(&tmp, target).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(name: &str, lines: &[&str]) -> PathBuf {
        let path = std::env::temp_dir().join(format!("binfera-mcp-{}-{name}", std::process::id()));
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        path
    }

    /// The index must not depend on where `type` sits in a record: a writer that sorts keys
    /// alphabetically puts it last.
    #[test]
    fn index_ignores_key_order() {
        let start = r#"{"type":"start","functions":[4096],"arch":"x64"}"#;
        let ordered = r#"{"type":"function","address":4096,"text":"\nvoid FUN_1000(void)\n{\n}\n","calls":[],"data_refs":[]}"#;
        let sorted = r#"{"address":4096,"calls":[],"data_refs":[],"text":"\nvoid FUN_1000(void)\n{\n}\n","type":"function"}"#;
        for (name, line) in [("ordered", ordered), ("sorted", sorted)] {
            let path = write(name, &[start, line]);
            let index = build_index(&path).unwrap();
            std::fs::remove_file(&path).ok();
            assert_eq!(index.functions.len(), 1, "{name}");
            assert_eq!(index.functions[0].address, 4096, "{name}");
        }
    }
    #[test]
    fn index_uses_inventory_names_and_last_record_offsets() {
        let start = r#"{"type":"start","functions":[4096,8192],"names":{"4096":"large.init","8192":"failed.init"}}"#;
        let pending = r#"{"type":"function","address":4096,"error":"limit","retry_pending":true,"calls":[8192]}"#;
        let failed = r#"{"type":"function","address":8192,"error":"failed"}"#;
        let retried = r#"{"type":"function","address":4096,"name":"large.init","text":"void large_init(void) {}","calls":[12288]}"#;
        let path = write("replaced", &[start, pending, failed, retried]);
        let index = build_index(&path).unwrap();
        assert_eq!(index.functions.len(), 2);
        let large = &index.functions[index.by_address[&4096]];
        assert_eq!(large.name, "large.init");
        assert_eq!(large.calls, vec![12288]);
        assert_eq!(
            index.record(large).unwrap()["text"],
            "void large_init(void) {}"
        );
        assert_eq!(
            large.offset as usize,
            start.len() + pending.len() + failed.len() + 3
        );
        assert_eq!(index.functions[index.by_address[&8192]].name, "failed.init");
        assert!(!index.callers.contains_key(&8192));
        std::fs::remove_file(path).unwrap();
    }
}
