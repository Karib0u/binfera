//! Runs the bundled native `binfera` binary for the frontend and streams its stdout back.
//!
//! One frontend "engine run" is one `binfera` process, exactly like one WebAssembly invocation in
//! the browser build, so the frontend's request shapes carry over unchanged. A run is:
//!
//! 1. `stage_sample`: the sample's bytes cross the IPC boundary once as a raw body. The desktop
//!    engine gets a private snapshot, and MCP can use the retained input.
//! 2. `run_engine`: spawns the sidecar with `{sample}` / `{rules}` placeholders in its arguments
//!    resolved, writes any small text `files` (fingerprints) into a per-run working directory,
//!    and sends each stdout line over a [`Channel`] as it is printed.
//! 3. `cancel_engine`: kills the whole process tree (`--jobs` workers are child processes).

use crate::cache::{self, Cache};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tauri::ipc::{Channel, InvokeBody, Request};
use tauri::{AppHandle, Manager, State};

/// stderr kept for the error message, as in the browser worker.
const STDERR_LINES: usize = 50;

struct Inner {
    scratch: PathBuf,
    next: AtomicU64,
    /// Staged samples: a private snapshot and its SHA-256, which names the sample in the cache.
    samples: Mutex<HashMap<u64, (Arc<tempfile::NamedTempFile>, String)>>,
    /// Process id of each live run's `binfera` process (also its process group on Unix).
    running: Mutex<HashMap<u64, u32>>,
    /// Runs the frontend cancelled, so a cancel that races ahead of the spawn still takes effect.
    cancelled: Mutex<HashSet<u64>>,
}

#[derive(Clone)]
pub struct Engine(Arc<Inner>);

impl Engine {
    pub fn new() -> Engine {
        let scratch = std::env::temp_dir().join(format!("binfera-desktop-{}", std::process::id()));
        Engine(Arc::new(Inner {
            scratch,
            next: AtomicU64::new(1),
            samples: Mutex::default(),
            running: Mutex::default(),
            cancelled: Mutex::default(),
        }))
    }

    /// Stops every run and removes the scratch directory.
    pub fn shutdown(&self) {
        let pids: Vec<u32> = self.0.running.lock().unwrap().values().copied().collect();
        for pid in pids {
            kill_tree(pid);
        }
        let _ = std::fs::remove_dir_all(&self.0.scratch);
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunRequest {
    id: u64,
    /// A handle from `stage_sample`, substituted for `{sample}` in `args`.
    sample: Option<u64>,
    /// Arguments for `binfera`; `{sample}` and `{rules}` are replaced by paths.
    args: Vec<String>,
    /// Small text files created in the run's working directory (the process runs there, so
    /// `args` can name them relative to it).
    #[serde(default)]
    files: HashMap<String, String>,
}

#[derive(Serialize)]
pub struct RunOutcome {
    /// `None` when the process was killed by a signal.
    code: Option<i32>,
    stderr: String,
    /// Lines sent over the channel. The channel's messages and this result travel separately and
    /// can arrive in either order, so the frontend counts lines to know when it has them all.
    lines: u64,
}

/// The sidecar sits beside the app executable (Tauri strips the target triple when bundling).
pub(crate) fn sidecar() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let name = if cfg!(windows) {
        "binfera.exe"
    } else {
        "binfera"
    };
    let path = exe
        .parent()
        .map(|dir| dir.join(name))
        .unwrap_or_else(|| name.into());
    if path.is_file() {
        Ok(path)
    } else {
        Err(format!(
            "the binfera engine is missing at {}: run `npm run prepare-desktop`",
            path.display()
        ))
    }
}

/// `BINFERA_RULES_DIR` (development override; `CAPA_RULES_DIR` is its old name), then the bundled resource, then the source tree.
fn rules_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let mut candidates = Vec::new();
    if let Some(dir) =
        std::env::var_os("BINFERA_RULES_DIR").or_else(|| std::env::var_os("CAPA_RULES_DIR"))
    {
        candidates.push(PathBuf::from(dir));
    }
    if let Ok(resources) = app.path().resource_dir() {
        candidates.push(resources.join("rules"));
    }
    candidates.push(Path::new(env!("CARGO_MANIFEST_DIR")).join("resources/rules"));
    candidates
        .into_iter()
        .find(|dir| dir.join("anti-analysis").is_dir())
        .ok_or_else(|| "the capa rules are missing: run `npm run prepare-desktop`".to_string())
}

#[tauri::command]
pub async fn stage_sample(state: State<'_, Engine>, request: Request<'_>) -> Result<u64, String> {
    let InvokeBody::Raw(bytes) = request.body() else {
        return Err("stage_sample expects the sample as a raw body".into());
    };
    let inner = &state.0;
    let id = inner.next.fetch_add(1, Ordering::Relaxed);
    let (sha, _) = binfera_project::retain_sample(&binfera_project::data_dir(), bytes)
        .map_err(|e| format!("could not retain the sample: {e}"))?;
    let mut sample = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
    sample.write_all(bytes).map_err(|e| e.to_string())?;
    inner
        .samples
        .lock()
        .unwrap()
        .insert(id, (Arc::new(sample), sha));
    Ok(id)
}

#[tauri::command]
pub fn release_sample(state: State<'_, Engine>, id: u64) {
    state.0.samples.lock().unwrap().remove(&id);
}

/// Flags the frontend may pass, and whether each takes a value.
const FLAGS: &[(&str, bool)] = &[
    ("--image-info", false),
    ("--guess-shellcode", false),
    ("--format", true),
    ("--os", true),
    ("--json", false),
    ("--rules", true),
    ("--decompile-all", false),
    ("--decompile-function", true),
    ("--jobs", true),
    ("--no-capabilities", false),
    ("--caps-a", true),
    ("--caps-b", true),
    // The old names, which the browser build still passes.
    ("--capa-a", true),
    ("--capa-b", true),
    ("--pair", true),
    ("--function-map", true),
    ("--pack", true),
];

fn is_hex(text: &str) -> bool {
    text.strip_prefix("0x")
        .is_some_and(|h| !h.is_empty() && h.len() <= 16 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The webview is not trusted with the command line of a process: a page that rendered hostile
/// strings from a sample must not be able to ask `binfera` for `--rules <anything>` or an
/// arbitrary path. Only the argument shapes `run.native.ts` builds are accepted: an optional
/// `fingerprint` / `diff` subcommand, known flags, `{sample}` / `{rules}` placeholders, a small
/// job count, hex addresses (or `A:B` pairs of them), and the names of the run's own `files`.
fn validate_args(args: &[String], files: &HashMap<String, String>) -> Result<(), String> {
    let bad = |arg: &str| Err(format!("argument `{arg}` is not allowed"));
    let mut rest = args;
    if let Some(first) = rest.first() {
        if first == "fingerprint" || first == "diff" {
            rest = &rest[1..];
        } else if first == "family" && rest.get(1).is_some_and(|s| s == "match") {
            rest = &rest[2..];
        }
    }
    let mut i = 0;
    while i < rest.len() {
        let arg = rest[i].as_str();
        i += 1;
        if let Some(&(_, takes_value)) = FLAGS.iter().find(|(flag, _)| *flag == arg) {
            if !takes_value {
                continue;
            }
            let Some(value) = rest.get(i) else {
                return bad(arg);
            };
            i += 1;
            let ok = match arg {
                "--rules" => value == "{rules}",
                "--pack" => value == "{family_pack}",
                "--jobs" => value.parse::<u32>().is_ok_and(|n| (1..=64).contains(&n)),
                "--decompile-function" => is_hex(value),
                "--format" => matches!(value.as_str(), "sc32" | "sc64"),
                "--os" => matches!(value.as_str(), "windows" | "linux"),
                "--pair" => value
                    .split_once(':')
                    .is_some_and(|(a, b)| is_hex(a) && is_hex(b)),
                _ => files.contains_key(value.as_str()),
            };
            if !ok {
                return bad(value);
            }
        } else if arg == "{sample}" || files.contains_key(arg) {
            continue;
        } else {
            return bad(arg);
        }
    }
    Ok(())
}

fn family_pack_path(app: &AppHandle) -> Result<PathBuf, String> {
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os("BINFERA_FAMILY_PACK") {
        candidates.push(PathBuf::from(path));
    }
    candidates.push(binfera_project::data_dir().join("family.bxfam"));
    if let Ok(resources) = app.path().resource_dir() {
        candidates.push(resources.join("family.bxfam"));
    }
    candidates.push(Path::new(env!("CARGO_MANIFEST_DIR")).join("resources/family.bxfam"));
    candidates
        .into_iter()
        .find(|p| p.is_file())
        .ok_or_else(|| "no family fingerprint pack installed".to_string())
}

#[tauri::command]
pub async fn run_engine(
    app: AppHandle,
    state: State<'_, Engine>,
    request: RunRequest,
    on_line: Channel<String>,
) -> Result<RunOutcome, String> {
    validate_args(&request.args, &request.files)?;
    let engine = state.inner().clone();
    let program = sidecar()?;
    let uses_rules = request.args.iter().any(|a| a.contains("{rules}"));
    let rules = if uses_rules {
        Some(rules_dir(&app)?)
    } else {
        None
    };
    let uses_pack = request.args.iter().any(|a| a.contains("{family_pack}"));
    let family_pack = if uses_pack {
        Some(family_pack_path(&app)?)
    } else {
        None
    };
    tauri::async_runtime::spawn_blocking(move || {
        run_blocking(&engine, program, rules, family_pack, request, on_line)
    })
    .await
    .map_err(|e| e.to_string())?
}

fn run_blocking(
    engine: &Engine,
    program: PathBuf,
    rules: Option<PathBuf>,
    family_pack: Option<PathBuf>,
    request: RunRequest,
    on_line: Channel<String>,
) -> Result<RunOutcome, String> {
    let inner = &engine.0;
    let (sample, sha) = match request.sample {
        Some(handle) => {
            let (path, sha) = inner
                .samples
                .lock()
                .unwrap()
                .get(&handle)
                .cloned()
                .ok_or("the sample was released before the run started")?;
            (Some(path), Some(sha))
        }
        None => (None, None),
    };
    // A run that was finished before is replayed instead of repeated.
    let cache = sha
        .filter(|_| sample.is_some() && cache::cacheable(&request.args))
        .map(|sha| (Cache::open(&program), sha));
    if let Some((cache, sha)) = &cache {
        if let Some(file) = cache.lookup(sha, &request.args) {
            return Ok(replay(file, request.id, inner, &on_line));
        }
    }
    let dir = inner.scratch.join(format!("run-{}", request.id));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let result = (|| {
        for (name, text) in &request.files {
            // Plain file names only: the frontend never needs a path, and this keeps it that way.
            // No leading `-`, so a file can never be read as a flag.
            let mut parts = Path::new(name).components();
            if name.starts_with('-')
                || !matches!(
                    (parts.next(), parts.next()),
                    (Some(Component::Normal(_)), None)
                )
            {
                return Err(format!("invalid file name `{name}`"));
            }
            std::fs::write(dir.join(name), text).map_err(|e| e.to_string())?;
        }
        let mut args = Vec::with_capacity(request.args.len());
        for arg in &request.args {
            let mut arg = arg.clone();
            if arg.contains("{sample}") {
                let sample = sample.as_ref().ok_or("this run needs a sample")?;
                arg = arg.replace("{sample}", &sample.path().to_string_lossy());
            }
            if let Some(rules) = &rules {
                arg = arg.replace("{rules}", &rules.to_string_lossy());
            }
            if let Some(pack) = &family_pack {
                arg = arg.replace("{family_pack}", &pack.to_string_lossy());
            }
            args.push(arg);
        }
        let mut command = Command::new(&program);
        command
            .args(&args)
            .current_dir(&dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Its own process group on Unix, so cancelling reaches the `--jobs` worker processes.
        #[cfg(unix)]
        std::os::unix::process::CommandExt::process_group(&mut command, 0);
        // No console window flashing up for each run (CREATE_NO_WINDOW).
        #[cfg(windows)]
        std::os::windows::process::CommandExt::creation_flags(&mut command, 0x0800_0000);
        let mut child = command
            .spawn()
            .map_err(|e| format!("could not start {}: {e}", program.display()))?;
        let pid = child.id();
        inner.running.lock().unwrap().insert(request.id, pid);
        if inner.cancelled.lock().unwrap().contains(&request.id) {
            kill_tree(pid);
        }

        let stderr = child.stderr.take().ok_or("no stderr")?;
        let stderr_thread = std::thread::spawn(move || {
            let mut lines = Vec::new();
            let mut reader = BufReader::new(stderr);
            let mut buf = Vec::new();
            while reader.read_until(b'\n', &mut buf).unwrap_or(0) > 0 {
                if lines.len() < STDERR_LINES {
                    lines.push(String::from_utf8_lossy(&buf).trim_end().to_string());
                }
                buf.clear();
            }
            lines
        });

        let mut recording = cache
            .as_ref()
            .and_then(|(cache, sha)| cache.record(sha, &request.args));
        let mut stdout = BufReader::with_capacity(1 << 16, child.stdout.take().ok_or("no stdout")?);
        let mut buf = Vec::new();
        let mut sent_lines = 0u64;
        while stdout
            .read_until(b'\n', &mut buf)
            .map_err(|e| e.to_string())?
            > 0
        {
            let line = String::from_utf8_lossy(&buf);
            let line = line.trim_end_matches(['\n', '\r']);
            if let Some(recording) = &mut recording {
                recording.line(line);
            }
            // The webview going away (window closed) is the end of the run, not an error.
            if on_line.send(line.to_string()).is_err() {
                recording = None;
                kill_tree(pid);
                break;
            }
            sent_lines += 1;
            buf.clear();
        }
        // Drain so the child can exit if we stopped reading early.
        let _ = std::io::copy(&mut stdout, &mut std::io::sink());
        let status = child.wait().map_err(|e| e.to_string())?;
        let stderr = stderr_thread.join().unwrap_or_default().join("\n");
        // Only a run that read to the end and exited cleanly is worth keeping.
        if let Some(recording) = recording {
            let cancelled = inner.cancelled.lock().unwrap().contains(&request.id);
            recording.finish(status.code() == Some(0) && !cancelled);
        }
        Ok(RunOutcome {
            code: status.code(),
            stderr,
            lines: sent_lines,
        })
    })();
    inner.running.lock().unwrap().remove(&request.id);
    inner.cancelled.lock().unwrap().remove(&request.id);
    let _ = std::fs::remove_dir_all(&dir);
    result
}

/// Sends a stored run's lines as if the engine had just printed them.
fn replay(file: std::fs::File, id: u64, inner: &Inner, on_line: &Channel<String>) -> RunOutcome {
    let mut reader = BufReader::with_capacity(1 << 16, file);
    let mut buf = Vec::new();
    let mut sent = 0u64;
    while reader.read_until(b'\n', &mut buf).unwrap_or(0) > 0 {
        let line = String::from_utf8_lossy(&buf);
        if on_line
            .send(line.trim_end_matches(['\n', '\r']).to_string())
            .is_err()
        {
            break;
        }
        buf.clear();
        sent += 1;
        if sent.is_multiple_of(1024) && inner.cancelled.lock().unwrap().contains(&id) {
            break;
        }
    }
    inner.cancelled.lock().unwrap().remove(&id);
    RunOutcome {
        code: Some(0),
        stderr: String::new(),
        lines: sent,
    }
}

#[tauri::command]
pub fn cancel_engine(state: State<'_, Engine>, id: u64) {
    state.0.cancelled.lock().unwrap().insert(id);
    if let Some(pid) = state.0.running.lock().unwrap().get(&id).copied() {
        kill_tree(pid);
    }
}

/// Kills a process and everything it spawned. `binfera --jobs N` runs decompile workers as child
/// processes that would otherwise outlive a killed parent.
pub(crate) fn kill_tree(pid: u32) {
    #[cfg(unix)]
    let _ = Command::new("kill")
        .args(["-KILL", "--", &format!("-{pid}")])
        .status();
    #[cfg(windows)]
    {
        let mut command = Command::new("taskkill");
        command.args(["/PID", &pid.to_string(), "/T", "/F"]);
        std::os::windows::process::CommandExt::creation_flags(&mut command, 0x0800_0000);
        let _ = command.status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }
    fn files(names: &[&str]) -> HashMap<String, String> {
        names
            .iter()
            .map(|n| (n.to_string(), String::new()))
            .collect()
    }

    #[test]
    fn accepts_what_the_frontend_builds() {
        let none = files(&[]);
        for list in [
            &["{sample}", "--image-info"][..],
            &["{sample}", "--image-info", "--guess-shellcode"],
            &[
                "{sample}",
                "--image-info",
                "--guess-shellcode",
                "--format",
                "sc32",
                "--os",
                "windows",
            ],
            &[
                "{sample}",
                "--decompile-all",
                "--jobs",
                "8",
                "--format",
                "sc64",
                "--os",
                "linux",
            ],
            &["{sample}", "--json", "--rules", "{rules}"],
            &["fingerprint", "{sample}"],
            &["{sample}", "--decompile-function", "0x401000", "--json"],
            &["{sample}", "--decompile-all", "--jobs", "8"],
            &["family", "match", "--pack", "{family_pack}", "{sample}", "--json"],
        ] {
            assert!(validate_args(&args(list), &none).is_ok(), "{list:?}");
        }
        let f = files(&["a.idx", "b.idx", "a.json", "b.json", "map.json"]);
        assert!(validate_args(
            &args(&[
                "diff", "a.idx", "b.idx", "--json", "--capa-a", "a.json", "--capa-b", "b.json"
            ]),
            &f
        )
        .is_ok());
        assert!(validate_args(
            &args(&["diff", "a.idx", "b.idx", "--no-capabilities", "--json"]),
            &f
        )
        .is_ok());
        assert!(validate_args(
            &args(&[
                "diff",
                "a.idx",
                "b.idx",
                "--pair",
                "0x10:0x20",
                "--function-map",
                "map.json",
                "--json"
            ]),
            &f
        )
        .is_ok());
    }

    #[test]
    fn refuses_everything_else() {
        let f = files(&["a.idx"]);
        for list in [
            &["{sample}", "--rules", "/etc"][..],
            &["/etc/passwd"],
            &["{sample}", "--signatures", "/tmp"],
            &["{sample}", "--jobs", "0"],
            &["{sample}", "--jobs", "9999"],
            &["{sample}", "--decompile-function", "401000"],
            &["{sample}", "--rules"],
            &["{sample}", "--format", "auto"],
            &["{sample}", "--format", "a.idx"],
            &["{sample}", "--os", "a.idx"],
            &["{sample}", "--format"],
            &["{sample}", "--os", "linux; touch /tmp/sample"],
            &["fetch-rules"],
            &["{sample}", "--pair", "0x1:zz"],
            &["diff", "other.idx"],
            &["diff", "../a.idx"],
            &["family", "match", "--pack", "/etc/passwd", "{sample}"],
        ] {
            assert!(validate_args(&args(list), &f).is_err(), "{list:?}");
        }
    }
}
