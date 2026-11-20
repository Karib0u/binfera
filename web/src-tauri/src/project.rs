//! The persistent project database shared with `binfera mcp`.
//!
//! The same SQLite file (WAL mode) is opened by the desktop app and by the MCP server, so an AI
//! agent's renames, comments and reports appear here, and the analyst's own edits are visible to
//! the agent. The frontend polls [`project_revision`] to notice outside changes.
use binfera_project::{Annotation, ChangeInfo, Counts, Edit, EditKind, ReportInfo, Source, Store};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tauri::State;

#[derive(Default, Clone)]
pub struct Projects(
    Arc<Mutex<Option<Store>>>,
    /// Files picked in this session or resolved from a project's saved input: the only paths,
    /// besides the history's own, that `file_read` will read for the webview.
    Arc<Mutex<HashSet<PathBuf>>>,
    /// Folders the analyst opened: files inside them can be registered by `folder_open`.
    Arc<Mutex<Vec<PathBuf>>>,
);

impl Projects {
    fn with<T>(
        &self,
        f: impl FnOnce(&mut Store) -> Result<T, binfera_project::Error>,
    ) -> Result<T, String> {
        let mut guard = self
            .0
            .lock()
            .map_err(|_| "project store is poisoned".to_string())?;
        if guard.is_none() {
            let path = binfera_project::data_dir().join("projects.sqlite3");
            *guard = Some(Store::open(&path).map_err(|e| e.to_string())?);
        }
        f(guard.as_mut().expect("store opened above")).map_err(|e| e.to_string())
    }
}

#[derive(Serialize)]
pub struct Loaded {
    revision: i64,
    annotations: Vec<Annotation>,
    counts: Counts,
}

fn snapshot(store: &Store, sha: &str) -> Result<Loaded, binfera_project::Error> {
    Ok(Loaded {
        revision: store.revision(sha)?,
        annotations: store.annotations(sha, None)?,
        counts: store.counts(sha)?,
    })
}

/// Registers the project for an opened file (if new) and returns all of its annotations.
#[tauri::command]
pub fn project_load(
    state: State<'_, Projects>,
    sha256: String,
    name: String,
    size: u64,
) -> Result<Loaded, String> {
    state.with(|s| {
        s.ensure_project(&sha256, &name, size)?;
        snapshot(s, &sha256.to_ascii_lowercase())
    })
}

/// Resolve a verified project input and allow the webview to read it.
#[tauri::command]
pub fn project_path(state: State<'_, Projects>, sha256: String) -> Result<Option<String>, String> {
    let path = state.with(|s| {
        let project = s.project(&sha256.to_ascii_lowercase())?;
        Ok(
            binfera_project::project_input(&binfera_project::data_dir(), &project)
                .ok()
                .map(|p| p.to_string_lossy().into_owned()),
        )
    })?;
    if let Some(path) = &path {
        state.1.lock().unwrap().insert(PathBuf::from(path));
    }
    Ok(path)
}

#[tauri::command]
pub fn project_revision(state: State<'_, Projects>, sha256: String) -> Result<i64, String> {
    state.with(|s| s.revision(&sha256))
}

/// Analyst edits. They are human-authored, so no AI run can replace them.
#[tauri::command]
pub fn project_apply(
    state: State<'_, Projects>,
    sha256: String,
    edits: Vec<Edit>,
) -> Result<i64, String> {
    state.with(|s| {
        Ok(
            s.apply_edits(&sha256, None, "desktop", None, Source::Human, &edits)?
                .revision,
        )
    })
}

#[derive(Deserialize)]
pub struct Removal {
    kind: EditKind,
    target: String,
}

#[tauri::command]
pub fn project_remove(
    state: State<'_, Projects>,
    sha256: String,
    items: Vec<Removal>,
) -> Result<i64, String> {
    state.with(|s| {
        s.remove_annotations(
            &sha256,
            &items
                .into_iter()
                .map(|r| (r.kind, r.target))
                .collect::<Vec<_>>(),
        )
    })
}

#[tauri::command]
pub fn project_undo(
    state: State<'_, Projects>,
    sha256: String,
    run_id: String,
) -> Result<binfera_project::UndoResult, String> {
    state.with(|s| s.undo_run(&sha256, &run_id))
}

#[derive(Serialize)]
pub struct Run {
    run_id: String,
    workflow: String,
    started: i64,
    changes: i64,
}
#[derive(Serialize)]
pub struct Activity {
    revision: i64,
    runs: Vec<Run>,
    changes: Vec<ChangeInfo>,
    counts: Counts,
}

#[tauri::command]
pub fn project_activity(state: State<'_, Projects>, sha256: String) -> Result<Activity, String> {
    state.with(|s| {
        Ok(Activity {
            revision: s.revision(&sha256)?,
            runs: s
                .runs(&sha256)?
                .into_iter()
                .map(|(run_id, workflow, started, changes)| Run {
                    run_id,
                    workflow,
                    started,
                    changes,
                })
                .collect(),
            changes: s.recent_changes(&sha256, 100)?,
            counts: s.counts(&sha256)?,
        })
    })
}

#[tauri::command]
pub fn project_reports(
    state: State<'_, Projects>,
    sha256: String,
) -> Result<Vec<ReportInfo>, String> {
    state.with(|s| s.reports(&sha256))
}

#[derive(Serialize)]
pub struct ReportBody {
    json: String,
    markdown: String,
}

#[tauri::command]
pub fn project_report(
    state: State<'_, Projects>,
    sha256: String,
    version: i64,
) -> Result<ReportBody, String> {
    state.with(|s| {
        s.report(&sha256, Some(version))
            .map(|(json, markdown)| ReportBody { json, markdown })
    })
}

#[derive(Serialize)]
pub struct McpSetup {
    command: String,
    opencode: String,
    pi: String,
    vibe: String,
    database: String,
}

/// Copyable registration commands. The bundled engine is the `binfera` that serves MCP, so the
/// commands work without a separate CLI install.
#[tauri::command]
pub fn mcp_setup() -> McpSetup {
    let exe = crate::engine::sidecar()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "binfera".into());
    let quoted = if exe.contains(' ') {
        format!("\"{exe}\"")
    } else {
        exe.clone()
    };
    McpSetup {
        opencode: format!("opencode mcp add binfera --global -- {quoted} mcp"),
        pi: format!("pi mcp add binfera -- {quoted} mcp"),
        vibe: format!("vibe mcp add binfera --transport stdio --command {quoted} --arg mcp"),
        command: exe,
        database: binfera_project::data_dir()
            .join("projects.sqlite3")
            .to_string_lossy()
            .into_owned(),
    }
}

/// One line of the history: a file the analyst has opened before.
#[derive(Serialize)]
pub struct Recent {
    sha256: String,
    /// The file's name, for display.
    name: String,
    /// The original path, if known (archive members have only a filename).
    path: Option<String>,
    size: u64,
    /// Unix seconds.
    opened: i64,
    human: i64,
    ai: i64,
    reports: i64,
    /// Its analysis is stored, so opening it again is immediate.
    cached: bool,
    /// A saved input is available even if the original path is unknown or gone.
    retained: bool,
    /// The path no longer holds a file.
    missing: bool,
}

#[tauri::command]
pub fn project_recent(state: State<'_, Projects>) -> Result<Vec<Recent>, String> {
    let cache = crate::engine::sidecar()
        .ok()
        .map(|program| crate::cache::Cache::open(&program));
    state.with(|s| recent_projects(s, &binfera_project::data_dir(), cache.as_ref()))
}

fn recent_projects(
    store: &Store,
    data_dir: &Path,
    cache: Option<&crate::cache::Cache>,
) -> Result<Vec<Recent>, binfera_project::Error> {
    Ok(store
        .list_projects()?
        .into_iter()
        .map(|p| {
            let absolute = Path::new(&p.path).is_absolute();
            let name = Path::new(&p.path)
                .file_name()
                .map_or_else(|| p.path.clone(), |n| n.to_string_lossy().into_owned());
            Recent {
                cached: cache.is_some_and(|c| c.has(&p.sha256)),
                retained: binfera_project::sample_path(data_dir, &p.sha256)
                    .is_ok_and(|path| path.is_file()),
                missing: absolute && !Path::new(&p.path).is_file(),
                path: absolute.then(|| p.path.clone()),
                name,
                sha256: p.sha256,
                size: p.size,
                opened: p.opened,
                human: p.human,
                ai: p.ai,
                reports: p.reports,
            }
        })
        // Keep extracted inputs that can be reopened, even before any notes are added.
        .filter(|p| p.path.is_some() || p.retained || p.human + p.ai + p.reports > 0)
        .collect())
}

/// Removes a file from the history, with its notes, reports and stored analysis. The file itself
/// is not touched.
#[tauri::command]
pub fn project_forget(state: State<'_, Projects>, sha256: String) -> Result<(), String> {
    state.with(|s| s.forget_project(&sha256))?;
    crate::cache::forget(&sha256);
    if let Ok(path) = binfera_project::sample_path(&binfera_project::data_dir(), &sha256) {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}

#[derive(Serialize)]
pub struct Picked {
    pub path: String,
    pub name: String,
    size: u64,
    sha256: String,
}

/// Asks the analyst for a file with the system dialog and records it in the history under its
/// real path. With `expect` (a history entry's hash) the file must be that same binary, which is
/// how a moved file is found again.
#[tauri::command]
pub async fn file_pick(
    app: tauri::AppHandle,
    state: State<'_, Projects>,
    expect: Option<String>,
) -> Result<Option<Picked>, String> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = std::sync::mpsc::channel();
    app.dialog().file().pick_file(move |file| {
        let _ = tx.send(file);
    });
    let Some(file) = tauri::async_runtime::spawn_blocking(move || rx.recv().ok().flatten())
        .await
        .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    let path = file.into_path().map_err(|e| e.to_string())?;
    let picked = tauri::async_runtime::spawn_blocking({
        let state = state.inner().clone();
        move || state.register(&path)
    })
    .await
    .map_err(|e| e.to_string())??;
    if expect.is_some_and(|want| !want.eq_ignore_ascii_case(&picked.sha256)) {
        return Err("That is not the same file: its contents differ from the one analysed.".into());
    }
    Ok(Some(picked))
}

impl Projects {
    /// Remembers a folder the analyst chose, so its files may be opened.
    pub fn allow_folder(&self, root: PathBuf) {
        let mut roots = self.2.lock().unwrap();
        if !roots.contains(&root) {
            roots.push(root);
        }
    }

    /// Whether `path` (already canonical) lies inside a folder the analyst opened.
    pub fn in_folder(&self, path: &Path) -> bool {
        self.2.lock().unwrap().iter().any(|r| path.starts_with(r))
    }

    /// Records a file the analyst chose (with the dialog, or by dropping it on the window): its
    /// hash and real path go into the history, and the webview may read it from now on.
    pub fn register(&self, path: &Path) -> Result<Picked, String> {
        let path = std::fs::canonicalize(path).map_err(|e| e.to_string())?;
        if !path.is_file() {
            return Err("that is not a file".into());
        }
        let (sha256, size) = binfera_project::hash_file(&path).map_err(|e| e.to_string())?;
        let name = path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        let text = path.to_string_lossy().into_owned();
        self.with(|s| {
            s.ensure_project(&sha256, &name, size)?;
            s.set_path(&sha256, &text)
        })?;
        self.1.lock().unwrap().insert(path);
        Ok(Picked {
            path: text,
            name,
            size,
            sha256,
        })
    }
}

/// Whether the webview may read `path`: the analyst picked it, or the history knows it.
fn allowed(state: &Projects, path: &Path) -> Result<bool, String> {
    if state.1.lock().unwrap().contains(path) {
        return Ok(true);
    }
    let text = path.to_string_lossy();
    state.with(|s| Ok(s.list_projects()?.iter().any(|p| p.path == text)))
}

/// The bytes of a file the analyst picked or that the history remembers. The webview cannot name
/// any other path: it renders strings from hostile samples.
#[tauri::command]
pub async fn file_read(
    state: State<'_, Projects>,
    path: String,
) -> Result<tauri::ipc::Response, String> {
    let path = PathBuf::from(path);
    if !path.is_absolute() || !allowed(&state, &path)? {
        return Err("that file was not opened from this app".into());
    }
    let bytes = tauri::async_runtime::spawn_blocking(move || std::fs::read(&path))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("could not read the file: {e}"))?;
    Ok(tauri::ipc::Response::new(bytes))
}

/// Shows a history entry's file in the system file manager.
#[tauri::command]
pub fn file_reveal(state: State<'_, Projects>, sha256: String) -> Result<(), String> {
    let project = state.with(|s| s.project(&sha256.to_ascii_lowercase()))?;
    let original = PathBuf::from(&project.path);
    let path = if original.is_absolute() && original.is_file() {
        original
    } else {
        binfera_project::project_input(&binfera_project::data_dir(), &project)
            .map_err(|e| e.to_string())?
    };
    if !path.is_absolute() || !path.exists() {
        return Err("the file is no longer there".into());
    }
    let mut command;
    #[cfg(target_os = "macos")]
    {
        command = std::process::Command::new("open");
        command.arg("-R").arg(&path);
    }
    #[cfg(windows)]
    {
        command = std::process::Command::new("explorer");
        command.arg(format!("/select,{}", path.display()));
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        command = std::process::Command::new("xdg-open");
        command.arg(path.parent().unwrap_or(&path));
    }
    command.spawn().map(|_| ()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recent_keeps_saved_archive_members_without_notes() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("projects.sqlite3");
        let bytes = b"extracted binary";
        let (sha, saved) = binfera_project::retain_sample(dir.path(), bytes).unwrap();
        let store = Store::open(&db).unwrap();
        store
            .ensure_project(&sha, "inside.exe", bytes.len() as u64)
            .unwrap();
        store
            .ensure_project(&"a".repeat(64), "unavailable.exe", 0)
            .unwrap();
        drop(store);

        let store = Store::open(&db).unwrap();
        let recent = recent_projects(&store, dir.path(), None).unwrap();
        assert_eq!(recent.len(), 1);
        let entry = &recent[0];
        assert_eq!(entry.sha256, sha);
        assert_eq!(entry.name, "inside.exe");
        assert!(entry.path.is_none());
        assert!(entry.retained);
        assert!(!entry.missing);
        assert!(!entry.cached);
        let input =
            binfera_project::project_input(dir.path(), &store.project(&sha).unwrap()).unwrap();
        assert_eq!(input, saved);
        assert_eq!(std::fs::read(input).unwrap(), bytes);
    }

    #[test]
    fn recent_uses_saved_input_when_original_is_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("projects.sqlite3")).unwrap();
        let bytes = b"original binary";
        let original = dir.path().join("original.exe");
        std::fs::write(&original, bytes).unwrap();
        let project = store.open_project(&original).unwrap();
        let (_, saved) = binfera_project::retain_sample(dir.path(), bytes).unwrap();
        let recent = recent_projects(&store, dir.path(), None).unwrap();
        assert!(recent[0].retained);
        assert!(!recent[0].missing);
        assert_eq!(
            binfera_project::project_input(dir.path(), &project).unwrap(),
            saved
        );

        std::fs::write(&original, b"changed binary!").unwrap();
        assert_eq!(
            binfera_project::project_input(dir.path(), &project).unwrap(),
            saved
        );

        std::fs::remove_file(&original).unwrap();
        let recent = recent_projects(&store, dir.path(), None).unwrap();
        assert!(recent[0].retained);
        assert!(recent[0].missing);
        assert_eq!(
            binfera_project::project_input(dir.path(), &project).unwrap(),
            saved
        );

        std::fs::remove_file(saved).unwrap();
        let recent = recent_projects(&store, dir.path(), None).unwrap();
        assert!(!recent[0].retained);
        assert!(recent[0].missing);
        assert!(binfera_project::project_input(dir.path(), &project).is_err());
    }
}
