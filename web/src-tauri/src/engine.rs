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
    family_pack: Mutex<Option<PathBuf>>,
    /// Packs layered over the base pack, in order. The webview names them by index only.
    family_overlays: Mutex<Vec<PathBuf>>,
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
            family_pack: Mutex::default(),
            family_overlays: Mutex::default(),
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
                "--pack" => value == "{family_pack}" || overlay_index(value).is_some(),
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

/// The overlay a `{family_overlay:N}` placeholder names.
fn overlay_index(arg: &str) -> Option<usize> {
    let n = arg.strip_prefix("{family_overlay:")?.strip_suffix('}')?;
    if n.is_empty() || n.len() > 3 || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    n.parse().ok()
}

/// "BXFAM002" or "BXFAM003" when the file starts with a family pack magic.
fn pack_format(path: &Path) -> Option<String> {
    use std::io::Read;
    let mut magic = [0_u8; 8];
    std::fs::File::open(path)
        .ok()?
        .read_exact(&mut magic)
        .ok()?;
    matches!(&magic, b"BXFAM002" | b"BXFAM003")
        .then(|| String::from_utf8_lossy(&magic).into_owned())
}

#[derive(Serialize)]
pub struct FamilyPackStatus {
    available: bool,
    name: Option<String>,
    size: Option<u64>,
    path: Option<String>,
    format: Option<String>,
}

impl FamilyPackStatus {
    fn from_path(path: Option<&Path>) -> Self {
        let size = path
            .and_then(|p| p.metadata().ok())
            .filter(|m| m.is_file())
            .map(|m| m.len());
        Self {
            available: size.is_some(),
            name: path
                .and_then(Path::file_name)
                .map(|name| name.to_string_lossy().into_owned()),
            size,
            path: path.map(|p| p.to_string_lossy().into_owned()),
            format: path.and_then(pack_format),
        }
    }
}

fn family_pack_path(app: &AppHandle, engine: &Engine) -> Result<Option<PathBuf>, String> {
    let selected = engine.0.family_pack.lock().map_err(|e| e.to_string())?;
    let path = selected
        .as_ref()
        .filter(|p| p.is_file())
        .cloned()
        .or_else(|| binfera_project::resolve_family_pack(None))
        .or_else(|| {
            app.path()
                .resource_dir()
                .ok()
                .map(|p| p.join("family.bxfam"))
                .filter(|p| p.is_file())
        })
        .or_else(|| {
            let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("resources/family.bxfam");
            path.is_file().then_some(path)
        });
    path.map(|p| {
        p.canonicalize()
            .map_err(|e| format!("reading {}: {e}", p.display()))
    })
    .transpose()
}

#[tauri::command]
pub fn family_pack_status(
    app: AppHandle,
    state: State<'_, Engine>,
) -> Result<FamilyPackStatus, String> {
    let path = family_pack_path(&app, state.inner())?;
    Ok(FamilyPackStatus::from_path(path.as_deref()))
}

fn selected_family_pack(path: &Path) -> Result<PathBuf, String> {
    if !path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("bxfam"))
        || !path.is_file()
    {
        return Err("Select an existing .bxfam fingerprint pack.".into());
    }
    path.canonicalize()
        .map_err(|e| format!("reading {}: {e}", path.display()))
}

/// Asks for a `.bxfam` file with the native dialog; `None` when cancelled.
async fn pick_pack_file(app: &AppHandle) -> Result<Option<PathBuf>, String> {
    use tauri_plugin_dialog::DialogExt;

    let (tx, rx) = std::sync::mpsc::channel();
    app.dialog()
        .file()
        .add_filter("Binfera family pack", &["bxfam"])
        .pick_file(move |file| {
            let _ = tx.send(file);
        });
    let Some(file) = tauri::async_runtime::spawn_blocking(move || rx.recv().ok().flatten())
        .await
        .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    let path = selected_family_pack(&file.into_path().map_err(|e| e.to_string())?)?;
    if !FamilyPackStatus::from_path(Some(&path)).available {
        return Err("The selected family pack is unavailable.".into());
    }
    Ok(Some(path))
}

#[tauri::command]
pub async fn select_family_pack(
    app: AppHandle,
    state: State<'_, Engine>,
) -> Result<Option<FamilyPackStatus>, String> {
    let Some(path) = pick_pack_file(&app).await? else {
        return Ok(None);
    };
    let status = FamilyPackStatus::from_path(Some(&path));
    *state.0.family_pack.lock().map_err(|e| e.to_string())? = Some(path);
    Ok(Some(status))
}

/// Status of each overlay pack, in layer order.
#[tauri::command]
pub fn family_overlays_status(state: State<'_, Engine>) -> Result<Vec<FamilyPackStatus>, String> {
    let overlays = state.0.family_overlays.lock().map_err(|e| e.to_string())?;
    Ok(overlays
        .iter()
        .map(|p| FamilyPackStatus::from_path(Some(p)))
        .collect())
}

/// Picks a pack with the native dialog and layers it over the others.
#[tauri::command]
pub async fn add_family_overlay(
    app: AppHandle,
    state: State<'_, Engine>,
) -> Result<Option<FamilyPackStatus>, String> {
    let Some(path) = pick_pack_file(&app).await? else {
        return Ok(None);
    };
    let status = FamilyPackStatus::from_path(Some(&path));
    add_overlay(state.inner(), path)?;
    Ok(Some(status))
}

fn add_overlay(engine: &Engine, path: PathBuf) -> Result<(), String> {
    let mut overlays = engine.0.family_overlays.lock().map_err(|e| e.to_string())?;
    if overlays.len() >= MAX_FAMILY_OVERLAYS {
        return Err(format!(
            "At most {MAX_FAMILY_OVERLAYS} overlay packs can be layered."
        ));
    }
    overlays.push(path);
    Ok(())
}

#[tauri::command]
pub fn remove_family_overlay(state: State<'_, Engine>, index: usize) -> Result<(), String> {
    let mut overlays = state.0.family_overlays.lock().map_err(|e| e.to_string())?;
    if index < overlays.len() {
        overlays.remove(index);
    }
    Ok(())
}

/// Overlays a run may layer, which also bounds the `{family_overlay:N}` placeholders.
const MAX_FAMILY_OVERLAYS: usize = 16;

/// The paths of the overlays a run's placeholders name, in index order.
fn overlay_paths(engine: &Engine, args: &[String]) -> Result<Vec<PathBuf>, String> {
    let wanted = args.iter().filter_map(|a| overlay_index(a)).max();
    let Some(max) = wanted else {
        return Ok(Vec::new());
    };
    let overlays = engine.0.family_overlays.lock().map_err(|e| e.to_string())?;
    if max >= overlays.len() {
        return Err("an overlay family pack was removed before the run started".into());
    }
    overlays
        .iter()
        .map(|p| {
            p.canonicalize()
                .map_err(|e| format!("reading {}: {e}", p.display()))
        })
        .collect()
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
    let uses_pack = request.args.iter().any(|a| a == "{family_pack}");
    let family_pack = if uses_pack {
        Some(family_pack_path(&app, &engine)?.ok_or("no family fingerprint pack installed")?)
    } else {
        None
    };
    let packs = FamilyPacks {
        base: family_pack,
        overlays: overlay_paths(&engine, &request.args)?,
    };
    tauri::async_runtime::spawn_blocking(move || {
        run_blocking(&engine, program, rules, packs, request, on_line)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// The pack paths a run's `{family_pack}` and `{family_overlay:N}` placeholders become.
struct FamilyPacks {
    base: Option<PathBuf>,
    overlays: Vec<PathBuf>,
}

impl FamilyPacks {
    fn resolve(&self, arg: &str) -> Option<&Path> {
        if arg == "{family_pack}" {
            return self.base.as_deref();
        }
        self.overlays.get(overlay_index(arg)?).map(PathBuf::as_path)
    }
}

fn run_blocking(
    engine: &Engine,
    program: PathBuf,
    rules: Option<PathBuf>,
    family_packs: FamilyPacks,
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
            let arg = match family_packs.resolve(&arg) {
                Some(pack) => pack.as_os_str().to_owned(),
                None => arg.into(),
            };
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

    #[test]
    fn pack_selection_accepts_only_existing_bxfam_files() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let pack = dir.path().join("local pack.BXFAM");
        let text = dir.path().join("pack.txt");
        let folder = dir.path().join("folder.bxfam");
        std::fs::write(&pack, b"BXFAM002")?;
        std::fs::write(&text, [])?;
        std::fs::create_dir(&folder)?;
        assert_eq!(
            selected_family_pack(&pack).map_err(std::io::Error::other)?,
            pack.canonicalize()?
        );
        let status = FamilyPackStatus::from_path(Some(&pack));
        assert!(status.available);
        assert_eq!(status.name.as_deref(), Some("local pack.BXFAM"));
        assert_eq!(status.size, Some(8));
        assert!(selected_family_pack(&text).is_err());
        assert!(selected_family_pack(&folder).is_err());
        assert!(selected_family_pack(&dir.path().join("missing.bxfam")).is_err());
        assert!(!FamilyPackStatus::from_path(None).available);
        Ok(())
    }

    #[test]
    fn pack_status_reads_the_format_from_the_header() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let v2 = dir.path().join("base.bxfam");
        let v3 = dir.path().join("org.bxfam");
        let other = dir.path().join("other.bxfam");
        std::fs::write(&v2, b"BXFAM002 rest of header")?;
        std::fs::write(&v3, b"BXFAM003 rest of header")?;
        std::fs::write(&other, b"PK\x03\x04 not a pack")?;
        assert_eq!(
            FamilyPackStatus::from_path(Some(&v2)).format.as_deref(),
            Some("BXFAM002")
        );
        assert_eq!(
            FamilyPackStatus::from_path(Some(&v3)).format.as_deref(),
            Some("BXFAM003")
        );
        assert_eq!(FamilyPackStatus::from_path(Some(&other)).format, None);
        Ok(())
    }

    #[test]
    fn overlays_resolve_by_index_and_are_bounded() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let engine = Engine::new();
        let mut paths = Vec::new();
        for i in 0..MAX_FAMILY_OVERLAYS {
            let p = dir.path().join(format!("overlay-{i}.bxfam"));
            std::fs::write(&p, b"BXFAM003")?;
            add_overlay(&engine, p.clone()).map_err(std::io::Error::other)?;
            paths.push(p);
        }
        assert!(
            add_overlay(&engine, paths[0].clone()).is_err(),
            "the overlay count is capped"
        );

        let run = args(&[
            "family",
            "match",
            "--pack",
            "{family_pack}",
            "--pack",
            "{family_overlay:1}",
            "{sample}",
            "--json",
        ]);
        let resolved = overlay_paths(&engine, &run).map_err(std::io::Error::other)?;
        let packs = FamilyPacks {
            base: Some(dir.path().join("base.bxfam")),
            overlays: resolved,
        };
        assert_eq!(
            packs.resolve("{family_overlay:1}"),
            Some(paths[1].canonicalize()?.as_path())
        );
        assert_eq!(
            packs.resolve("{family_pack}"),
            Some(dir.path().join("base.bxfam").as_path())
        );
        assert_eq!(packs.resolve("{sample}"), None);

        engine.0.family_overlays.lock().unwrap().truncate(1);
        assert!(
            overlay_paths(&engine, &run).is_err(),
            "a removed overlay fails the run instead of shifting packs"
        );
        assert!(overlay_paths(&engine, &args(&["{sample}", "--image-info"]))
            .map_err(std::io::Error::other)?
            .is_empty());
        Ok(())
    }

    #[test]
    fn overlay_placeholders_parse_strictly() {
        assert_eq!(overlay_index("{family_overlay:0}"), Some(0));
        assert_eq!(overlay_index("{family_overlay:12}"), Some(12));
        for bad in [
            "{family_overlay:}",
            "{family_overlay:-1}",
            "{family_overlay:1a}",
            "{family_overlay:1234}",
            "{family_overlay:0",
            "family_overlay:0}",
            "{family_overlay: 1}",
        ] {
            assert_eq!(overlay_index(bad), None, "{bad}");
        }
    }

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
            &[
                "family",
                "match",
                "--pack",
                "{family_pack}",
                "{sample}",
                "--json",
            ],
            &[
                "family",
                "match",
                "--pack",
                "{family_pack}",
                "--pack",
                "{family_overlay:0}",
                "--pack",
                "{family_overlay:1}",
                "{sample}",
                "--json",
            ],
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
            &[
                "family",
                "match",
                "--pack",
                "{family_overlay:x}",
                "{sample}",
            ],
            &[
                "family",
                "match",
                "--pack",
                "{family_overlay:../a}",
                "{sample}",
            ],
            &["family", "match", "{family_overlay:0}", "{sample}"],
        ] {
            assert!(validate_args(&args(list), &f).is_err(), "{list:?}");
        }
    }
}
