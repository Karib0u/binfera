//! A cache of finished engine runs, so reopening a file does not analyse it again.
//!
//! The engine is deterministic: the same bytes and the same engine give the same output. A run's
//! stdout is therefore stored under the sample's SHA-256 and replayed on the next open, which turns
//! minutes of decompiling a large binary into reading a file. Only whole, successful runs of the
//! three analysis kinds are kept (image metadata, capabilities, decompile-all); single-function
//! decompiles and diffs are cheap or depend on other inputs.
//!
//! The files are the ones `binfera mcp` keeps (`<data dir>/cache/<sha>-<engine version>.<kind>`), so
//! whichever of the desktop app and an AI agent analyses a file first, the other reuses the result.
//! The engine version is the sidecar's own `--version` text, which names its rules too. Set
//! `BINFERA_NO_CACHE=1` to bypass the cache, for example while working on the engine itself.
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub struct Cache {
    /// `<data dir>/cache`, shared with `binfera mcp`.
    dir: PathBuf,
    /// The engine's version text with everything but letters, digits and dots replaced, as `binfera mcp` names its files.
    version: String,
}

/// Which stored file a run belongs to, or `None` for runs not worth keeping: the three analysis
/// passes that take a while and depend only on the sample, run with the engine's own detection.
fn kind(args: &[String]) -> Option<&'static str> {
    let has = |flag: &str| args.iter().any(|a| a == flag);
    // A forced format or OS changes the answer, and the files are shared with runs that detect.
    if [
        "--format",
        "--os",
        "--arch",
        "--guess-shellcode",
        "--decompile-function",
        "--emulate",
    ]
    .iter()
    .any(|f| has(f))
    {
        return None;
    }
    if has("--decompile-all") {
        Some("decomp.jsonl")
    } else if has("--json") && has("--rules") {
        Some("capa.json")
    } else if has("--image-info") {
        Some("image.jsonl")
    } else {
        None
    }
}

/// Whether a run is stored at all.
pub fn cacheable(args: &[String]) -> bool {
    std::env::var_os("BINFERA_NO_CACHE").is_none() && kind(args).is_some()
}

fn safe(version: &str) -> String {
    version
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// The sidecar's version text, asked once.
fn engine_version(program: &Path) -> String {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION
        .get_or_init(|| {
            let mut command = std::process::Command::new(program);
            command.arg("--version");
            #[cfg(windows)]
            std::os::windows::process::CommandExt::creation_flags(&mut command, 0x0800_0000);
            let text = command
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();
            // "binfera 1.0.0 (...)": the name is not part of the version.
            let text = text
                .strip_prefix("binfera")
                .map_or(text.as_str(), str::trim);
            safe(if text.is_empty() {
                env!("CARGO_PKG_VERSION")
            } else {
                text
            })
        })
        .clone()
}

impl Cache {
    pub fn open(program: &Path) -> Cache {
        Cache {
            dir: binfera_project::data_dir().join("cache"),
            version: engine_version(program),
        }
    }

    fn entry(&self, sha: &str, args: &[String]) -> Option<PathBuf> {
        Some(
            self.dir
                .join(format!("{sha}-{}.{}", self.version, kind(args)?)),
        )
    }

    /// The stored output, if this run was finished before.
    pub fn lookup(&self, sha: &str, args: &[String]) -> Option<File> {
        let path = self.entry(sha, args)?;
        let file = File::open(&path).ok()?;
        binfera_project::touch_cache_file(&path);
        Some(file)
    }

    /// Starts recording a run's output. It becomes visible only when [`Recording::finish`] is
    /// called, so an interrupted run never leaves a partial answer behind.
    pub fn record(&self, sha: &str, args: &[String]) -> Option<Recording> {
        let path = self.entry(sha, args)?;
        std::fs::create_dir_all(&self.dir).ok()?;
        let out = BufWriter::new(binfera_project::cache_tempfile(&path).ok()?);
        Some(Recording {
            out: Some(out),
            path,
        })
    }

    /// True when the decompilation of `sha` is stored: opening it again is immediate.
    pub fn has(&self, sha: &str) -> bool {
        self.dir
            .join(format!("{sha}-{}.decomp.jsonl", self.version))
            .is_file()
    }
}

/// Removes everything stored for `sha`, whichever engine version wrote it.
pub fn forget(sha: &str) {
    // Hashes are 64 hex digits; refuse anything that could name another file.
    if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return;
    }
    let prefix = format!("{sha}-");
    if let Ok(files) = std::fs::read_dir(binfera_project::data_dir().join("cache")) {
        for file in files.flatten() {
            if file.file_name().to_string_lossy().starts_with(&prefix) {
                let _ = std::fs::remove_file(file.path());
            }
        }
    }
}

pub struct Recording {
    out: Option<BufWriter<tempfile::NamedTempFile>>,
    path: PathBuf,
}

impl Recording {
    pub fn line(&mut self, line: &str) {
        if let Some(out) = &mut self.out {
            if writeln!(out, "{line}").is_err() {
                self.out = None;
            }
        }
    }

    /// Keeps the recording when the run completed.
    pub fn finish(self, complete: bool) {
        if !complete {
            return;
        }
        if let Some(file) = self.out.and_then(|out| out.into_inner().ok()) {
            let _ = binfera_project::publish_cache_file(file, &self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn caches_analysis_runs_only() {
        assert!(kind(&args(&["{sample}", "--image-info"])).is_some());
        assert_eq!(
            kind(&args(&["{sample}", "--decompile-all", "--jobs", "8"])),
            Some("decomp.jsonl")
        );
        assert_eq!(
            kind(&args(&["{sample}", "--json", "--rules", "{rules}"])),
            Some("capa.json")
        );
        assert!(kind(&args(&[
            "{sample}",
            "--decompile-function",
            "0x401000",
            "--json"
        ]))
        .is_none());
        assert!(kind(&args(&["fingerprint", "{sample}"])).is_none());
        assert!(kind(&args(&["diff", "a.idx", "b.idx", "--json"])).is_none());
        // A forced format is a different run from the engine's own detection.
        assert!(kind(&args(&[
            "{sample}",
            "--decompile-all",
            "--format",
            "sc32",
            "--os",
            "windows"
        ]))
        .is_none());
    }

    #[test]
    fn replays_a_finished_run_and_drops_an_unfinished_one() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            dir: dir.path().to_path_buf(),
            version: "1.0.0".into(),
        };
        let sha = "a".repeat(64);
        let run = args(&["{sample}", "--decompile-all", "--jobs", "8"]);
        assert!(cache.lookup(&sha, &run).is_none());

        let mut unfinished = cache.record(&sha, &run).unwrap();
        unfinished.line("partial");
        unfinished.finish(false);
        assert!(cache.lookup(&sha, &run).is_none());
        assert!(!cache.has(&sha));

        let mut rec = cache.record(&sha, &run).unwrap();
        rec.line("{\"type\":\"start\"}");
        rec.line("{\"type\":\"done\"}");
        rec.finish(true);
        // Another job count is the same run.
        let other_jobs = args(&["{sample}", "--decompile-all", "--jobs", "2"]);
        let path = cache.entry(&sha, &other_jobs).unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(300);
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(old)
            .unwrap();
        let lines: Vec<String> = BufReader::new(cache.lookup(&sha, &other_jobs).unwrap())
            .lines()
            .map(Result::unwrap)
            .collect();
        assert_eq!(lines, ["{\"type\":\"start\"}", "{\"type\":\"done\"}"]);
        assert!(cache.has(&sha));
        assert!(std::fs::metadata(&path).unwrap().modified().unwrap() > old);
        // The file is the one `binfera mcp` reads: `<sha>-<version>.decomp.jsonl`.
        assert!(dir
            .path()
            .join(format!("{sha}-1.0.0.decomp.jsonl"))
            .is_file());
        // A different run of the same sample is not confused with it.
        assert!(cache
            .lookup(&sha, &args(&["{sample}", "--image-info"]))
            .is_none());
    }

    #[test]
    fn concurrent_recordings_publish_whole_runs_and_cancel_independently() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            dir: dir.path().into(),
            version: "test".into(),
        };
        let sha = "a".repeat(64);
        let run = args(&["{sample}", "--decompile-all"]);
        let read = |file| std::io::read_to_string(file).unwrap();

        let mut first = cache.record(&sha, &run).unwrap();
        let mut cancelled = cache.record(&sha, &run).unwrap();
        let long_line = "x".repeat(16384);
        cancelled.line(&long_line);
        binfera_project::prune_cache(dir.path(), 0).unwrap();
        first.line("first complete run");
        first.finish(true);
        let reader = cache.lookup(&sha, &run).unwrap();
        cancelled.line("cancelled");
        drop(cancelled);
        assert_eq!(
            read(cache.lookup(&sha, &run).unwrap()),
            "first complete run\n"
        );

        let mut second = cache.record(&sha, &run).unwrap();
        second.line("second complete run");
        second.finish(true);
        assert_eq!(read(reader), "first complete run\n");
        assert_eq!(
            read(cache.lookup(&sha, &run).unwrap()),
            "first complete run\n"
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn version_text_becomes_a_file_name_part() {
        assert_eq!(
            safe("1.0.0 (capa rules v10.0.0)"),
            "1.0.0__capa_rules_v10.0.0_"
        );
    }
}
