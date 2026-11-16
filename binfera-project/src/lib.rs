//! Persistent analysis projects: a SQLite database holding analyst and AI annotations, an
//! append-only change journal that supports undo, and saved reports.
//!
//! A project is identified by the SHA-256 of the analysed file. Desktop samples are retained
//! separately so agents can read files opened as bytes. Originals are never modified.
//! Every successful batch of edits bumps the project revision by one; writers pass
//! the revision they last read, and a stale revision is refused so that two clients cannot
//! silently overwrite one another.
#![forbid(unsafe_code)]

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

mod cache;
pub use cache::{cache_max_bytes, prune_cache, touch_cache_file};

pub const SCHEMA_VERSION: i64 = 3;
pub const MAX_NAME_LEN: usize = 128;
pub const MAX_COMMENT_LEN: usize = 2000;

#[derive(Debug)]
pub enum Error {
    Db(rusqlite::Error),
    Io(std::io::Error),
    /// The caller's revision is behind; `changed` lists the `kind:target` keys written since.
    StaleRevision {
        expected: i64,
        current: i64,
        changed: Vec<String>,
    },
    Invalid(String),
    NotFound(String),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Db(e) => write!(f, "database error: {e}"),
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::StaleRevision {
                expected,
                current,
                changed,
            } => write!(
                f,
                "stale revision: expected {expected}, project is at {current}; changed since: {}",
                changed.join(", ")
            ),
            Error::Invalid(m) | Error::NotFound(m) => f.write_str(m),
        }
    }
}
impl std::error::Error for Error {}
impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Db(e)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Who wrote an annotation. A human edit is never replaced by an AI edit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Human,
    Ai,
}
impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Source::Human => "human",
            Source::Ai => "ai",
        }
    }
    fn parse(s: &str) -> Source {
        if s == "human" {
            Source::Human
        } else {
            Source::Ai
        }
    }
}

/// How strongly the evidence supports an edit. `Certain` is backed by a string, import or
/// signature; `Guess` is a hypothesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Guess,
    Likely,
    Certain,
}
impl Confidence {
    fn as_str(self) -> &'static str {
        match self {
            Confidence::Guess => "guess",
            Confidence::Likely => "likely",
            Confidence::Certain => "certain",
        }
    }
    fn parse(s: &str) -> Confidence {
        match s {
            "certain" => Confidence::Certain,
            "likely" => Confidence::Likely,
            _ => Confidence::Guess,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EditKind {
    RenameFunction,
    /// `target` is `<function address>:<variable id>`.
    RenameVariable,
    AddComment,
    /// A marked function; the stored value is `true`, absence means unstarred.
    Star,
}
impl EditKind {
    fn as_str(self) -> &'static str {
        match self {
            EditKind::RenameFunction => "rename_function",
            EditKind::RenameVariable => "rename_variable",
            EditKind::AddComment => "add_comment",
            EditKind::Star => "star",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Edit {
    pub kind: EditKind,
    /// Function address (`0x401200`) for functions and comments; `<address>:<variable>` for variables.
    pub target: String,
    pub value: String,
    #[serde(default = "default_confidence")]
    pub confidence: Confidence,
    #[serde(default)]
    pub evidence: Vec<String>,
}
fn default_confidence() -> Confidence {
    Confidence::Likely
}

#[derive(Clone, Debug, Serialize)]
pub struct Rejected {
    pub kind: EditKind,
    pub target: String,
    pub reason: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Applied {
    pub kind: EditKind,
    pub target: String,
    /// The value actually stored, which differs from the request when a name was made unique.
    pub value: String,
    pub unchanged: bool,
}
#[derive(Debug, Serialize)]
pub struct BatchResult {
    /// The run these edits belong to: the one given, or for an AI batch sent without one, a new id,
    /// so every AI change can be undone as a unit.
    pub run_id: Option<String>,
    pub revision: i64,
    pub applied: Vec<Applied>,
    pub rejected: Vec<Rejected>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Annotation {
    pub kind: String,
    pub target: String,
    pub value: String,
    pub source: Source,
    pub confidence: Confidence,
    pub run_id: Option<String>,
    pub revision: i64,
}

#[derive(Debug, Serialize)]
pub struct UndoResult {
    pub revision: i64,
    pub reverted: usize,
    /// Edits left alone because someone changed them after the run.
    pub skipped: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReportInfo {
    pub id: i64,
    pub version: i64,
    pub title: String,
    pub created: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChangeInfo {
    pub run_id: Option<String>,
    pub kind: String,
    pub target: String,
    pub before: Option<String>,
    pub after: Option<String>,
    pub source: Source,
    pub confidence: Confidence,
    pub revision: i64,
    pub ts: i64,
    pub undone: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Counts {
    pub function_names: i64,
    pub variable_names: i64,
    pub comments: i64,
    pub human: i64,
    pub ai: i64,
}

/// SHA-256 of a file, hex encoded, streamed so large inputs are not held in memory.
pub fn hash_file(path: &Path) -> Result<(String, u64), Error> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        hasher.update(&buffer[..n]);
    }
    Ok((
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        size,
    ))
}

/// SHA-256 of bytes already in memory, hex encoded.
pub fn hash_bytes(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The retained desktop input, shared with MCP. Validate before using a hash as a filename.
pub fn sample_path(dir: &Path, sha: &str) -> Result<PathBuf, Error> {
    if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Invalid("sha256 must be 64 hex digits".into()));
    }
    Ok(dir.join("samples").join(sha.to_ascii_lowercase()))
}

/// Keep an input beyond an engine run's lifetime, publishing complete files atomically.
pub fn retain_sample(dir: &Path, bytes: &[u8]) -> Result<(String, PathBuf), Error> {
    use std::io::Write;
    let sha = hash_bytes(bytes);
    let path = sample_path(dir, &sha)?;
    if !path.is_file() {
        let parent = path.parent().expect("sample directory");
        std::fs::create_dir_all(parent)?;
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(bytes)?;
        match file.persist_noclobber(&path) {
            Ok(_) => {}
            Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.error.into()),
        }
    }
    Ok((sha, path))
}

/// Resolve a real input, never treating a display label as a relative filesystem path.
pub fn project_input(dir: &Path, project: &Project) -> Result<PathBuf, Error> {
    let original = Path::new(&project.path);
    if original.is_absolute() && original.is_file() {
        return Ok(original.to_path_buf());
    }
    let retained = sample_path(dir, &project.sha256)?;
    if retained.is_file() {
        return Ok(retained);
    }
    Err(Error::NotFound(
        "The project's input file is unavailable. Reopen the binary in the desktop app or use open_binary with its current absolute path.".into(),
    ))
}

/// The default per-user data directory, overridable with `BINFERA_DATA_DIR`.
pub fn data_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("BINFERA_DATA_DIR") {
        return PathBuf::from(dir);
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_default();
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/binfera")
    } else if cfg!(windows) {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or(home)
            .join("binfera")
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/share"))
            .join("binfera")
    }
}

/// A fresh id for an AI run whose caller did not name one.
fn new_run_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("run-{:x}", nanos & 0xffff_ffff_ffff)
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Normalises `0x401200`, `401200` or `4198912` forms to `0x401200`; `<addr>:<var>` keeps its suffix.
pub fn normalize_target(kind: EditKind, target: &str) -> Result<String, String> {
    let (address, variable) = match target.split_once(':') {
        Some((a, v)) => (a, Some(v)),
        None => (target, None),
    };
    let address = address.trim();
    let hex = address
        .strip_prefix("0x")
        .or_else(|| address.strip_prefix("0X"));
    let value = match hex {
        Some(h) => u64::from_str_radix(h, 16),
        None => u64::from_str_radix(address, 16),
    }
    .map_err(|_| format!("`{target}` is not an address"))?;
    match (kind, variable) {
        (EditKind::RenameVariable, Some(v)) if is_identifier_like(v) => {
            Ok(format!("0x{value:x}:{v}"))
        }
        (EditKind::RenameVariable, _) => Err("variable targets look like `0x401200:var_8`".into()),
        (_, None) => Ok(format!("0x{value:x}")),
        (_, Some(_)) => Err("this edit kind takes a plain address".into()),
    }
}

fn is_identifier_like(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME_LEN
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+'))
}

/// A valid C-style identifier, bounded in length.
pub fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    s.len() <= MAX_NAME_LEN
        && matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub struct Store {
    conn: Connection,
}

/// One row of the history list.
#[derive(Debug, Clone, Serialize)]
pub struct ProjectSummary {
    pub sha256: String,
    /// The file's absolute path, or just its name when the app only ever saw the bytes.
    pub path: String,
    pub size: u64,
    pub created: i64,
    pub opened: i64,
    pub revision: i64,
    pub human: i64,
    pub ai: i64,
    pub reports: i64,
}

pub struct Project {
    pub sha256: String,
    pub path: String,
    pub size: u64,
    pub revision: i64,
}

impl Store {
    /// Opens (creating and migrating) the database at `path`.
    pub fn open(path: &Path) -> Result<Store, Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Store, Error> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Store, Error> {
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        // WAL lets the desktop app read while an MCP process writes.
        let _: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=NORMAL;")?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(Error::Invalid(format!(
                "project database is schema {version}, newer than this build understands ({SCHEMA_VERSION})"
            )));
        }
        if version < 1 {
            conn.execute_batch(
                "BEGIN;
                 CREATE TABLE projects(
                   sha256 TEXT PRIMARY KEY, path TEXT NOT NULL, size INTEGER NOT NULL,
                   revision INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL, updated INTEGER NOT NULL);
                 CREATE TABLE annotations(
                   sha256 TEXT NOT NULL REFERENCES projects(sha256), kind TEXT NOT NULL, target TEXT NOT NULL,
                   value TEXT NOT NULL, source TEXT NOT NULL, confidence TEXT NOT NULL, run_id TEXT,
                   revision INTEGER NOT NULL, updated INTEGER NOT NULL,
                   PRIMARY KEY(sha256, kind, target));
                 CREATE TABLE runs(
                   sha256 TEXT NOT NULL, run_id TEXT NOT NULL, workflow TEXT NOT NULL, started INTEGER NOT NULL,
                   PRIMARY KEY(sha256, run_id));
                 CREATE TABLE changes(
                   id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT NOT NULL, run_id TEXT, kind TEXT NOT NULL,
                   target TEXT NOT NULL, before TEXT, after TEXT, source TEXT NOT NULL, confidence TEXT NOT NULL,
                   evidence TEXT NOT NULL, revision INTEGER NOT NULL, ts INTEGER NOT NULL, undone INTEGER NOT NULL DEFAULT 0);
                 CREATE INDEX changes_run ON changes(sha256, run_id);
                 CREATE INDEX changes_rev ON changes(sha256, revision);
                 CREATE TABLE reports(
                   id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT NOT NULL, version INTEGER NOT NULL,
                   title TEXT NOT NULL, json TEXT NOT NULL, markdown TEXT NOT NULL, created INTEGER NOT NULL);
                 CREATE TABLE examined(sha256 TEXT NOT NULL, address TEXT NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY(sha256,address));
                 PRAGMA user_version=1;
                 COMMIT;",
            )?;
        }
        if version < 2 {
            // `opened` is when the analyst last opened the file (`updated` only moves on edits),
            // which is what a history list sorts by.
            conn.execute_batch(
                "BEGIN;
                 ALTER TABLE projects ADD COLUMN opened INTEGER NOT NULL DEFAULT 0;
                 UPDATE projects SET opened=updated;
                 PRAGMA user_version=2;
                 COMMIT;",
            )?;
        }
        if version < 3 {
            // Kinds are stored as text, so existing tables already accept stars.
            conn.execute_batch("PRAGMA user_version=3;")?;
        }
        Ok(Store { conn })
    }

    /// Opens or reuses the project for `file`, identified by content hash.
    pub fn open_project(&self, file: &Path) -> Result<Project, Error> {
        let (sha256, size) = hash_file(file)?;
        let path = std::fs::canonicalize(file)
            .unwrap_or_else(|_| file.to_path_buf())
            .to_string_lossy()
            .into_owned();
        let t = now();
        self.conn.execute(
            "INSERT INTO projects(sha256,path,size,created,updated,opened) VALUES(?1,?2,?3,?4,?4,?4)
             ON CONFLICT(sha256) DO UPDATE SET path=excluded.path, size=excluded.size, opened=excluded.opened",
            params![sha256, path, size as i64, t],
        )?;
        self.project(&sha256)
    }

    /// Registers a project by hash with a plain filename, without a file on disk. The label may
    /// come from an untrusted webview and must never grant access to an absolute path in history.
    /// Only `open_project` and `set_path` register real paths. An existing path is kept.
    pub fn ensure_project(&self, sha256: &str, label: &str, size: u64) -> Result<Project, Error> {
        if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::Invalid("sha256 must be 64 hex digits".into()));
        }
        let mut parts = Path::new(label).components();
        if label.contains(['/', '\\', '\0'])
            || !matches!(
                (parts.next(), parts.next()),
                (Some(Component::Normal(_)), None)
            )
        {
            return Err(Error::Invalid(
                "project label must be a plain filename".into(),
            ));
        }
        let sha256 = sha256.to_ascii_lowercase();
        let t = now();
        self.conn.execute(
            "INSERT OR IGNORE INTO projects(sha256,path,size,created,updated,opened) VALUES(?1,?2,?3,?4,?4,?4)",
            params![sha256, label, size as i64, t],
        )?;
        self.touch(&sha256)?;
        self.project(&sha256)
    }

    /// Records that the project was just opened, so it moves to the top of the history.
    pub fn touch(&self, sha256: &str) -> Result<(), Error> {
        self.conn.execute(
            "UPDATE projects SET opened=?2 WHERE sha256=?1",
            params![sha256, now()],
        )?;
        Ok(())
    }

    /// Points a project at the file it was read from. A name that is not an absolute path (the
    /// desktop app registers dropped files by name) is replaced by the real path; an existing real
    /// path is replaced too, since the analyst just showed where the file is now.
    pub fn set_path(&self, sha256: &str, path: &str) -> Result<(), Error> {
        let changed = self.conn.execute(
            "UPDATE projects SET path=?2 WHERE sha256=?1",
            params![sha256, path],
        )?;
        if changed == 0 {
            return Err(Error::NotFound(format!("no project {sha256}")));
        }
        Ok(())
    }

    /// Every project, most recently opened first.
    pub fn list_projects(&self) -> Result<Vec<ProjectSummary>, Error> {
        let mut stmt = self.conn.prepare(
            "SELECT p.sha256,p.path,p.size,p.created,p.opened,p.revision,
                    (SELECT COUNT(*) FROM annotations a WHERE a.sha256=p.sha256 AND a.source='human'),
                    (SELECT COUNT(*) FROM annotations a WHERE a.sha256=p.sha256 AND a.source='ai'),
                    (SELECT COUNT(*) FROM reports r WHERE r.sha256=p.sha256)
             FROM projects p ORDER BY p.opened DESC, p.created DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ProjectSummary {
                sha256: r.get(0)?,
                path: r.get(1)?,
                size: r.get::<_, i64>(2)? as u64,
                created: r.get(3)?,
                opened: r.get(4)?,
                revision: r.get(5)?,
                human: r.get(6)?,
                ai: r.get(7)?,
                reports: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Removes a project and everything recorded for it: annotations, journal, reports. The
    /// analysed file is never touched.
    pub fn forget_project(&mut self, sha256: &str) -> Result<(), Error> {
        let tx = self.conn.transaction()?;
        for table in ["annotations", "runs", "changes", "reports", "examined"] {
            tx.execute(&format!("DELETE FROM {table} WHERE sha256=?1"), [sha256])?;
        }
        tx.execute("DELETE FROM projects WHERE sha256=?1", [sha256])?;
        tx.commit()?;
        Ok(())
    }

    pub fn project(&self, sha256: &str) -> Result<Project, Error> {
        self.conn
            .query_row(
                "SELECT path,size,revision FROM projects WHERE sha256=?1",
                [sha256],
                |r| {
                    Ok(Project {
                        sha256: sha256.to_string(),
                        path: r.get(0)?,
                        size: r.get::<_, i64>(1)? as u64,
                        revision: r.get(2)?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("no project {sha256}")))
    }

    pub fn revision(&self, sha256: &str) -> Result<i64, Error> {
        Ok(self.project(sha256)?.revision)
    }

    /// Annotations of the project, optionally of one kind.
    pub fn annotations(&self, sha256: &str, kind: Option<&str>) -> Result<Vec<Annotation>, Error> {
        let mut stmt = self.conn.prepare(
            "SELECT kind,target,value,source,confidence,run_id,revision FROM annotations
             WHERE sha256=?1 AND (?2 IS NULL OR kind=?2) ORDER BY kind,target",
        )?;
        let rows = stmt.query_map(params![sha256, kind], |r| {
            Ok(Annotation {
                kind: r.get(0)?,
                target: r.get(1)?,
                value: r.get(2)?,
                source: Source::parse(&r.get::<_, String>(3)?),
                confidence: Confidence::parse(&r.get::<_, String>(4)?),
                run_id: r.get(5)?,
                revision: r.get(6)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn counts(&self, sha256: &str) -> Result<Counts, Error> {
        let n = |sql: &str| -> Result<i64, Error> {
            Ok(self.conn.query_row(sql, [sha256], |r| r.get(0))?)
        };
        Ok(Counts {
            function_names: n(
                "SELECT COUNT(*) FROM annotations WHERE sha256=?1 AND kind='rename_function'",
            )?,
            variable_names: n(
                "SELECT COUNT(*) FROM annotations WHERE sha256=?1 AND kind='rename_variable'",
            )?,
            comments: n("SELECT COUNT(*) FROM annotations WHERE sha256=?1 AND kind='add_comment'")?,
            human: n("SELECT COUNT(*) FROM annotations WHERE sha256=?1 AND source='human'")?,
            ai: n("SELECT COUNT(*) FROM annotations WHERE sha256=?1 AND source='ai'")?,
        })
    }

    /// Applies a batch atomically. Invalid or conflicting edits are rejected individually and do not
    /// stop the rest; a stale `expected_revision` rejects the whole batch. The revision advances
    /// by one only when at least one edit changed something.
    pub fn apply_edits(
        &mut self,
        sha256: &str,
        run_id: Option<&str>,
        workflow: &str,
        expected_revision: Option<i64>,
        source: Source,
        edits: &[Edit],
    ) -> Result<BatchResult, Error> {
        // An agent that sends no run id still gets one, and learns it from the result, so the batch
        // has a run in the journal and can be undone. Analyst edits are not runs.
        let generated;
        let run_id = match (run_id, source) {
            (None, Source::Ai) => {
                generated = new_run_id();
                Some(generated.as_str())
            }
            (given, _) => given,
        };
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current: i64 = tx
            .query_row(
                "SELECT revision FROM projects WHERE sha256=?1",
                [sha256],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("no project {sha256}")))?;
        if let Some(expected) = expected_revision {
            if expected != current {
                let mut stmt = tx.prepare("SELECT DISTINCT kind||':'||target FROM changes WHERE sha256=?1 AND revision>?2")?;
                let changed = stmt
                    .query_map(params![sha256, expected], |r| r.get(0))?
                    .collect::<Result<Vec<String>, _>>()?;
                return Err(Error::StaleRevision {
                    expected,
                    current,
                    changed,
                });
            }
        }
        let next = current + 1;
        let t = now();
        if let Some(run) = run_id {
            tx.execute(
                "INSERT OR IGNORE INTO runs(sha256,run_id,workflow,started) VALUES(?1,?2,?3,?4)",
                params![sha256, run, workflow, t],
            )?;
        }
        let mut applied = Vec::new();
        let mut rejected = Vec::new();
        let mut wrote = false;
        for edit in edits {
            let reject = |reason: String| Rejected {
                kind: edit.kind,
                target: edit.target.clone(),
                reason,
            };
            let target = match normalize_target(edit.kind, &edit.target) {
                Ok(t) => t,
                Err(e) => {
                    rejected.push(reject(e));
                    continue;
                }
            };
            let mut value = edit.value.trim().to_string();
            let is_name = matches!(
                edit.kind,
                EditKind::RenameFunction | EditKind::RenameVariable
            );
            // AI names must be C identifiers. An analyst may use any short printable label.
            let name_ok = match source {
                Source::Ai => is_identifier(&value),
                Source::Human => {
                    !value.is_empty()
                        && value.len() <= MAX_NAME_LEN
                        && !value.chars().any(char::is_control)
                }
            };
            if is_name && !name_ok {
                rejected.push(reject(format!("`{value}` is not a valid name (letters, digits, underscore; max {MAX_NAME_LEN})")));
                continue;
            }
            if edit.kind == EditKind::AddComment
                && (value.is_empty() || value.len() > MAX_COMMENT_LEN)
            {
                rejected.push(reject(format!(
                    "comments must be 1..={MAX_COMMENT_LEN} bytes"
                )));
                continue;
            }
            if edit.kind == EditKind::Star && value != "true" {
                rejected.push(reject(
                    "stars must have value `true`; remove the annotation to unstar".into(),
                ));
                continue;
            }
            let kind = edit.kind.as_str();
            let existing: Option<(String, String, String)> = tx
                .query_row(
                    "SELECT value,source,confidence FROM annotations WHERE sha256=?1 AND kind=?2 AND target=?3",
                    params![sha256, kind, target],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            if let Some((_, existing_source, existing_confidence)) = &existing {
                let existing_source = Source::parse(existing_source);
                if existing_source == Source::Human && source == Source::Ai {
                    rejected.push(reject("a human-authored annotation is protected".into()));
                    continue;
                }
                if existing_source == Source::Ai
                    && source == Source::Ai
                    && edit.confidence < Confidence::parse(existing_confidence)
                {
                    rejected.push(reject(format!(
                        "existing annotation has higher confidence ({existing_confidence})"
                    )));
                    continue;
                }
            }
            if edit.kind == EditKind::RenameFunction && source == Source::Ai {
                // Names stay unique within a project: suffix rather than fail the whole edit.
                let mut candidate = value.clone();
                let mut n = 2;
                loop {
                    let taken: i64 = tx.query_row(
                        "SELECT COUNT(*) FROM annotations WHERE sha256=?1 AND kind='rename_function' AND value=?2 AND target<>?3",
                        params![sha256, candidate, target],
                        |r| r.get(0),
                    )?;
                    if taken == 0 {
                        break;
                    }
                    candidate = format!("{value}_{n}");
                    n += 1;
                }
                value = candidate;
            }
            if existing
                .as_ref()
                .is_some_and(|(v, s, _)| *v == value && Source::parse(s) == source)
            {
                applied.push(Applied {
                    kind: edit.kind,
                    target,
                    value,
                    unchanged: true,
                });
                continue;
            }
            tx.execute(
                "INSERT INTO annotations(sha256,kind,target,value,source,confidence,run_id,revision,updated)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)
                 ON CONFLICT(sha256,kind,target) DO UPDATE SET value=excluded.value, source=excluded.source,
                   confidence=excluded.confidence, run_id=excluded.run_id, revision=excluded.revision, updated=excluded.updated",
                params![sha256, kind, target, value, source.as_str(), edit.confidence.as_str(), run_id, next, t],
            )?;
            tx.execute(
                "INSERT INTO changes(sha256,run_id,kind,target,before,after,source,confidence,evidence,revision,ts)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    sha256,
                    run_id,
                    kind,
                    target,
                    existing.as_ref().map(|e| e.0.clone()),
                    value,
                    source.as_str(),
                    edit.confidence.as_str(),
                    serde_json::to_string(&edit.evidence).unwrap_or_else(|_| "[]".into()),
                    next,
                    t
                ],
            )?;
            wrote = true;
            applied.push(Applied {
                kind: edit.kind,
                target,
                value,
                unchanged: false,
            });
        }
        let revision = if wrote {
            tx.execute(
                "UPDATE projects SET revision=?2, updated=?3 WHERE sha256=?1",
                params![sha256, next, t],
            )?;
            next
        } else {
            current
        };
        tx.commit()?;
        Ok(BatchResult {
            run_id: run_id.map(str::to_owned),
            revision,
            applied,
            rejected,
        })
    }

    /// Removes annotations the analyst cleared (an empty rename in the UI), journalled like any
    /// other human change. AI-authored annotations can be removed this way too: the analyst wins.
    pub fn remove_annotations(
        &mut self,
        sha256: &str,
        items: &[(EditKind, String)],
    ) -> Result<i64, Error> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current: i64 = tx
            .query_row(
                "SELECT revision FROM projects WHERE sha256=?1",
                [sha256],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(|| Error::NotFound(format!("no project {sha256}")))?;
        let next = current + 1;
        let t = now();
        let mut removed = false;
        for (kind, target) in items {
            let target = normalize_target(*kind, target).map_err(Error::Invalid)?;
            let kind = kind.as_str();
            let before: Option<String> = tx
                .query_row(
                    "SELECT value FROM annotations WHERE sha256=?1 AND kind=?2 AND target=?3",
                    params![sha256, kind, target],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(before) = before else { continue };
            tx.execute(
                "DELETE FROM annotations WHERE sha256=?1 AND kind=?2 AND target=?3",
                params![sha256, kind, target],
            )?;
            tx.execute(
                "INSERT INTO changes(sha256,run_id,kind,target,before,after,source,confidence,evidence,revision,ts)
                 VALUES(?1,NULL,?2,?3,?4,NULL,'human','certain','[]',?5,?6)",
                params![sha256, kind, target, before, next, t],
            )?;
            removed = true;
        }
        if removed {
            tx.execute(
                "UPDATE projects SET revision=?2, updated=?3 WHERE sha256=?1",
                params![sha256, next, t],
            )?;
        }
        tx.commit()?;
        Ok(if removed { next } else { current })
    }

    /// The journal, newest first, for activity views.
    pub fn recent_changes(&self, sha256: &str, limit: usize) -> Result<Vec<ChangeInfo>, Error> {
        let mut stmt = self.conn.prepare(
            "SELECT run_id,kind,target,before,after,source,confidence,revision,ts,undone FROM changes
             WHERE sha256=?1 AND (run_id IS NULL OR run_id NOT LIKE 'undo:%') ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![sha256, limit as i64], |r| {
            Ok(ChangeInfo {
                run_id: r.get(0)?,
                kind: r.get(1)?,
                target: r.get(2)?,
                before: r.get(3)?,
                after: r.get(4)?,
                source: Source::parse(&r.get::<_, String>(5)?),
                confidence: Confidence::parse(&r.get::<_, String>(6)?),
                revision: r.get(7)?,
                ts: r.get(8)?,
                undone: r.get::<_, i64>(9)? != 0,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Reverts every change made by `run_id`, newest first. A change is left in place when the
    /// annotation has been modified since the run (by a human or another run).
    pub fn undo_run(&mut self, sha256: &str, run_id: &str) -> Result<UndoResult, Error> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current: i64 = tx.query_row(
            "SELECT revision FROM projects WHERE sha256=?1",
            [sha256],
            |r| r.get(0),
        )?;
        let next = current + 1;
        let t = now();
        let rows: Vec<(i64, String, String, Option<String>, i64)> = {
            let mut stmt = tx.prepare(
                "SELECT id,kind,target,before,revision FROM changes WHERE sha256=?1 AND run_id=?2 AND undone=0 ORDER BY id DESC",
            )?;
            let collected = stmt
                .query_map(params![sha256, run_id], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })?
                .collect::<Result<_, _>>()?;
            collected
        };
        if rows.is_empty()
            && tx.query_row(
                "SELECT COUNT(*) FROM runs WHERE sha256=?1 AND run_id=?2",
                params![sha256, run_id],
                |r| r.get::<_, i64>(0),
            )? == 0
        {
            return Err(Error::NotFound(format!("no run `{run_id}`")));
        }
        let mut reverted = 0;
        let mut skipped = Vec::new();
        for (id, kind, target, before, revision) in rows {
            let live: Option<i64> = tx
                .query_row(
                    "SELECT revision FROM annotations WHERE sha256=?1 AND kind=?2 AND target=?3 AND run_id=?4",
                    params![sha256, kind, target, run_id],
                    |r| r.get(0),
                )
                .optional()?;
            // Only the run's own latest write to a key can be undone; later writers keep theirs.
            if live != Some(revision) {
                let later: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM changes WHERE sha256=?1 AND kind=?2 AND target=?3 AND id>?4 AND undone=0",
                    params![sha256, kind, target, id],
                    |r| r.get(0),
                )?;
                if later > 0 || live.is_none() {
                    skipped.push(format!("{kind}:{target}"));
                    continue;
                }
            }
            match before {
                Some(old) => {
                    // Restore the previous value; its provenance comes from the prior journal entry.
                    let prior: Option<(String, String, Option<String>)> = tx
                        .query_row(
                            "SELECT source,confidence,run_id FROM changes WHERE sha256=?1 AND kind=?2 AND target=?3 AND id<?4 ORDER BY id DESC LIMIT 1",
                            params![sha256, kind, target, id],
                            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                        )
                        .optional()?;
                    let (s, c, r) =
                        prior.unwrap_or_else(|| ("human".into(), "certain".into(), None));
                    tx.execute(
                        "UPDATE annotations SET value=?4,source=?5,confidence=?6,run_id=?7,revision=?8,updated=?9
                         WHERE sha256=?1 AND kind=?2 AND target=?3",
                        params![sha256, kind, target, old, s, c, r, next, t],
                    )?;
                }
                None => {
                    tx.execute(
                        "DELETE FROM annotations WHERE sha256=?1 AND kind=?2 AND target=?3",
                        params![sha256, kind, target],
                    )?;
                }
            }
            tx.execute("UPDATE changes SET undone=1 WHERE id=?1", [id])?;
            tx.execute(
                "INSERT INTO changes(sha256,run_id,kind,target,before,after,source,confidence,evidence,revision,ts)
                 VALUES(?1,?2,?3,?4,NULL,NULL,'ai','certain','[\"undo\"]',?5,?6)",
                params![sha256, format!("undo:{run_id}"), kind, target, next, t],
            )?;
            // The undo marker has `undone=0` and no before value; mark it so a second undo never replays it.
            tx.execute(
                "UPDATE changes SET undone=1 WHERE id=last_insert_rowid()",
                [],
            )?;
            reverted += 1;
        }
        let revision = if reverted > 0 {
            tx.execute(
                "UPDATE projects SET revision=?2, updated=?3 WHERE sha256=?1",
                params![sha256, next, t],
            )?;
            next
        } else {
            current
        };
        tx.commit()?;
        Ok(UndoResult {
            revision,
            reverted,
            skipped,
        })
    }

    /// Records that a function's code was read, for coverage reporting.
    pub fn mark_examined(&self, sha256: &str, address: &str) -> Result<(), Error> {
        self.conn.execute(
            "INSERT OR IGNORE INTO examined(sha256,address,ts) VALUES(?1,?2,?3)",
            params![sha256, address, now()],
        )?;
        Ok(())
    }

    pub fn examined(&self, sha256: &str) -> Result<std::collections::HashSet<String>, Error> {
        let mut stmt = self
            .conn
            .prepare("SELECT address FROM examined WHERE sha256=?1")?;
        let rows = stmt.query_map([sha256], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Runs, newest first: `(run_id, workflow, started, changes)`.
    pub fn runs(&self, sha256: &str) -> Result<Vec<(String, String, i64, i64)>, Error> {
        let mut stmt = self.conn.prepare(
            "SELECT r.run_id,r.workflow,r.started,(SELECT COUNT(*) FROM changes c WHERE c.sha256=r.sha256 AND c.run_id=r.run_id AND c.undone=0)
             FROM runs r WHERE r.sha256=?1 ORDER BY r.started DESC, r.rowid DESC",
        )?;
        let rows = stmt.query_map([sha256], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Saves a report as the next version for the project. Earlier versions are kept.
    pub fn save_report(
        &mut self,
        sha256: &str,
        title: &str,
        json: &str,
        markdown: &str,
    ) -> Result<ReportInfo, Error> {
        self.project(sha256)?;
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let version: i64 = tx.query_row(
            "SELECT COALESCE(MAX(version),0)+1 FROM reports WHERE sha256=?1",
            [sha256],
            |r| r.get(0),
        )?;
        let created = now();
        tx.execute(
            "INSERT INTO reports(sha256,version,title,json,markdown,created) VALUES(?1,?2,?3,?4,?5,?6)",
            params![sha256, version, title, json, markdown, created],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(ReportInfo {
            id,
            version,
            title: title.to_string(),
            created,
        })
    }

    pub fn reports(&self, sha256: &str) -> Result<Vec<ReportInfo>, Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id,version,title,created FROM reports WHERE sha256=?1 ORDER BY version DESC",
        )?;
        let rows = stmt.query_map([sha256], |r| {
            Ok(ReportInfo {
                id: r.get(0)?,
                version: r.get(1)?,
                title: r.get(2)?,
                created: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// `(json, markdown)` of a report version, the latest when `version` is `None`.
    pub fn report(&self, sha256: &str, version: Option<i64>) -> Result<(String, String), Error> {
        self.conn
            .query_row(
                "SELECT json,markdown FROM reports WHERE sha256=?1 AND (?2 IS NULL OR version=?2) ORDER BY version DESC LIMIT 1",
                params![sha256, version],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| Error::NotFound("no such report".into()))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn retained_input_survives_restart_and_preserves_project_label() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("projects.sqlite3");
        let bytes = b"MZ retained desktop input";
        let (sha, retained) = retain_sample(dir.path(), bytes).unwrap();
        let store = Store::open(&db).unwrap();
        store
            .ensure_project(&sha, "dropped.sys", bytes.len() as u64)
            .unwrap();
        drop(store);

        let store = Store::open(&db).unwrap();
        let project = store.project(&sha).unwrap();
        assert_eq!(project.path, "dropped.sys");
        assert_eq!(project_input(dir.path(), &project).unwrap(), retained);
        assert_eq!(std::fs::read(&retained).unwrap(), bytes);
        assert_eq!(retain_sample(dir.path(), bytes).unwrap().1, retained);

        let original = dir.path().join("original.sys");
        std::fs::write(&original, bytes).unwrap();
        store.set_path(&sha, original.to_str().unwrap()).unwrap();
        assert_eq!(
            project_input(dir.path(), &store.project(&sha).unwrap()).unwrap(),
            original
        );
        std::fs::remove_file(&original).unwrap();
        assert_eq!(
            project_input(dir.path(), &store.project(&sha).unwrap()).unwrap(),
            retained
        );
        std::fs::remove_file(retained).unwrap();
        assert!(project_input(dir.path(), &project)
            .unwrap_err()
            .to_string()
            .contains("Reopen"));
    }

    #[test]
    fn retained_input_rejects_path_traversal_and_relative_labels() {
        let dir = tempfile::tempdir().unwrap();
        for sha in ["../sample", &"/".repeat(64)] {
            assert!(sample_path(dir.path(), sha).is_err());
        }
        let project = Project {
            sha256: "a".repeat(64),
            path: "Cargo.toml".into(),
            size: 0,
            revision: 0,
        };
        assert!(Path::new(&project.path).is_file());
        assert!(project_input(dir.path(), &project).is_err());
    }

    #[test]
    fn human_removal_is_journalled_and_ensure_keeps_path() {
        let (mut s, h, _d) = setup();
        let again = s.ensure_project(&h, "label-from-desktop", 3).unwrap();
        assert!(again.path.ends_with("sample.bin"));
        s.apply_edits(
            &h,
            None,
            "ui",
            None,
            Source::Human,
            &[rename("0x10", "mine", Confidence::Certain)],
        )
        .unwrap();
        let rev = s
            .remove_annotations(&h, &[(EditKind::RenameFunction, "0x10".into())])
            .unwrap();
        assert_eq!(rev, 2);
        assert!(s.annotations(&h, None).unwrap().is_empty());
        assert_eq!(s.recent_changes(&h, 10).unwrap().len(), 2);
    }

    use super::*;

    fn setup() -> (Store, String, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("sample.bin");
        std::fs::write(&file, b"MZ sample bytes").unwrap();
        let store = Store::open_in_memory().unwrap();
        let p = store.open_project(&file).unwrap();
        (store, p.sha256, dir)
    }

    #[test]
    fn untrusted_project_labels_cannot_register_file_paths() {
        let store = Store::open_in_memory().unwrap();
        let sha = "a".repeat(64);
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().join("private.txt");
        std::fs::write(&private, b"not selected for analysis").unwrap();
        for label in [
            private.to_str().unwrap(),
            "/etc/passwd",
            "C:\\Users\\analyst\\private.txt",
            "C:/Users/analyst/private.txt",
            "\\\\server\\share\\private.txt",
            "../private.txt",
            "..\\private.txt",
            "folder/sample.exe",
            "folder\\sample.exe",
            "sample.exe/",
            "sample\0.exe",
            "",
            ".",
            "..",
        ] {
            assert!(
                matches!(store.ensure_project(&sha, label, 0), Err(Error::Invalid(_))),
                "accepted path label {label:?}"
            );
            assert!(store.project(&sha).is_err());
            assert!(store.list_projects().unwrap().is_empty());
        }

        let project = store.ensure_project(&sha, "sample file.exe", 0).unwrap();
        assert_eq!(project.path, "sample file.exe");
        assert!(!Path::new(&project.path).is_absolute());
    }

    #[test]
    fn native_paths_remain_readable_after_loading_a_project_label() {
        let (store, sha, dir) = setup();
        let original = store.project(&sha).unwrap().path;
        assert!(Path::new(&original).is_absolute());
        assert_eq!(
            store.ensure_project(&sha, "sample.bin", 14).unwrap().path,
            original
        );

        let other = "b".repeat(64);
        store.ensure_project(&other, "picked.bin", 0).unwrap();
        let picked = dir.path().join("picked.bin");
        std::fs::write(&picked, b"picked bytes").unwrap();
        store.set_path(&other, picked.to_str().unwrap()).unwrap();
        assert_eq!(
            store.ensure_project(&other, "picked.bin", 12).unwrap().path,
            picked.to_str().unwrap()
        );
    }

    fn rename(target: &str, value: &str, confidence: Confidence) -> Edit {
        Edit {
            kind: EditKind::RenameFunction,
            target: target.into(),
            value: value.into(),
            confidence,
            evidence: vec![],
        }
    }

    #[test]
    fn history_lists_recent_first_and_forgets_everything() {
        let (mut s, h, _d) = setup();
        let other = "b".repeat(64);
        s.ensure_project(&other, "dropped.exe", 9).unwrap();
        s.conn
            .execute("UPDATE projects SET opened=100 WHERE sha256=?1", [&other])
            .unwrap();
        s.conn
            .execute("UPDATE projects SET opened=200 WHERE sha256=?1", [&h])
            .unwrap();
        s.apply_edits(
            &h,
            None,
            "ui",
            None,
            Source::Human,
            &[rename("0x10", "mine", Confidence::Certain)],
        )
        .unwrap();
        let list = s.list_projects().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].sha256, h);
        assert_eq!((list[0].human, list[0].ai, list[0].reports), (1, 0, 0));
        assert_eq!(list[1].path, "dropped.exe");

        s.touch(&other).unwrap();
        assert_eq!(s.list_projects().unwrap()[0].sha256, other);

        s.set_path(&other, "/tmp/dropped.exe").unwrap();
        assert_eq!(s.project(&other).unwrap().path, "/tmp/dropped.exe");
        assert!(s.set_path(&"c".repeat(64), "/x").is_err());

        s.forget_project(&h).unwrap();
        assert!(s.project(&h).is_err());
        assert!(s.annotations(&h, None).unwrap().is_empty());
        assert_eq!(s.recent_changes(&h, 10).unwrap().len(), 0);
        assert_eq!(s.list_projects().unwrap().len(), 1);
    }

    #[test]
    fn version_one_database_migrates_with_opened_set() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.sqlite3");
        {
            // A real current database, rolled back to what a version 1 build wrote.
            let s = Store::open(&path).unwrap();
            s.ensure_project(&"a".repeat(64), "f", 1).unwrap();
            s.conn
                .execute_batch(
                    "UPDATE projects SET updated=7;
                     ALTER TABLE projects DROP COLUMN opened;
                     PRAGMA user_version=1;",
                )
                .unwrap();
        }
        let s = Store::open(&path).unwrap();
        assert_eq!(s.list_projects().unwrap()[0].opened, 7);
        let v: i64 = s
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
    }

    #[test]
    fn version_two_database_preserves_annotations_and_supports_stars() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.sqlite3");
        let sha = "a".repeat(64);
        {
            let mut store = Store::open(&path).unwrap();
            store.ensure_project(&sha, "sample.bin", 1).unwrap();
            store
                .apply_edits(
                    &sha,
                    None,
                    "ui",
                    None,
                    Source::Human,
                    &[rename("0x10", "original", Confidence::Certain)],
                )
                .unwrap();
            store.conn.execute_batch("PRAGMA user_version=2;").unwrap();
        }
        let mut store = Store::open(&path).unwrap();
        let version: i64 = store
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let star = Edit {
            kind: EditKind::Star,
            target: "0X0010".into(),
            value: "true".into(),
            confidence: Confidence::Certain,
            evidence: vec![],
        };
        let result = store
            .apply_edits(
                &sha,
                None,
                "ui",
                None,
                Source::Human,
                std::slice::from_ref(&star),
            )
            .unwrap();
        assert_eq!(result.applied[0].target, "0x10");
        assert_eq!(store.annotations(&sha, None).unwrap().len(), 2);
        let repeat = store
            .apply_edits(
                &sha,
                None,
                "ui",
                None,
                Source::Human,
                std::slice::from_ref(&star),
            )
            .unwrap();
        assert_eq!(repeat.revision, result.revision);
        assert!(repeat.applied[0].unchanged);
        let rejected = store
            .apply_edits(
                &sha,
                None,
                "ai",
                None,
                Source::Ai,
                std::slice::from_ref(&star),
            )
            .unwrap();
        assert_eq!(rejected.rejected.len(), 1, "human stars are protected");
        let invalid = Edit {
            value: "false".into(),
            ..star.clone()
        };
        assert_eq!(
            store
                .apply_edits(&sha, None, "ui", None, Source::Human, &[invalid])
                .unwrap()
                .rejected
                .len(),
            1
        );
        assert!(normalize_target(EditKind::Star, "0x10:param_1").is_err());
        drop(store);
        let mut store = Store::open(&path).unwrap();
        assert_eq!(
            store.annotations(&sha, Some("star")).unwrap()[0].value,
            "true"
        );
        store
            .remove_annotations(&sha, &[(EditKind::Star, "0x10".into())])
            .unwrap();
        assert!(store.annotations(&sha, Some("star")).unwrap().is_empty());
        assert_eq!(
            store.annotations(&sha, Some("rename_function")).unwrap()[0].value,
            "original"
        );
        // Stars use the same reversible run journal as other agent edits.
        store
            .apply_edits(&sha, Some("stars"), "ai", None, Source::Ai, &[star])
            .unwrap();
        assert_eq!(store.undo_run(&sha, "stars").unwrap().reverted, 1);
        assert!(store.annotations(&sha, Some("star")).unwrap().is_empty());
    }

    #[test]
    fn ai_batch_without_a_run_id_gets_one_that_can_be_undone() {
        let (mut s, h, _d) = setup();
        let r = s
            .apply_edits(
                &h,
                None,
                "autopilot",
                None,
                Source::Ai,
                &[rename("0x10", "decode_config", Confidence::Likely)],
            )
            .unwrap();
        let run = r.run_id.expect("a run id was generated");
        assert!(run.starts_with("run-"));
        assert_eq!(s.runs(&h).unwrap().len(), 1);
        let undone = s.undo_run(&h, &run).unwrap();
        assert_eq!(undone.reverted, 1);
        assert!(s.annotations(&h, None).unwrap().is_empty());
        // The analyst's own edits are not runs.
        let human = s
            .apply_edits(
                &h,
                None,
                "ui",
                None,
                Source::Human,
                &[rename("0x20", "mine", Confidence::Certain)],
            )
            .unwrap();
        assert!(human.run_id.is_none());
        assert_eq!(s.runs(&h).unwrap().len(), 1);
    }

    #[test]
    fn apply_persists_and_bumps_revision() {
        let (mut s, h, _d) = setup();
        let r = s
            .apply_edits(
                &h,
                Some("r1"),
                "autopilot",
                Some(0),
                Source::Ai,
                &[rename("401200", "decode_config", Confidence::Likely)],
            )
            .unwrap();
        assert_eq!(r.revision, 1);
        assert_eq!(r.applied[0].target, "0x401200");
        assert_eq!(s.annotations(&h, None).unwrap()[0].value, "decode_config");
    }

    #[test]
    fn stale_revision_is_refused_with_changed_keys() {
        let (mut s, h, _d) = setup();
        s.apply_edits(
            &h,
            Some("r1"),
            "w",
            Some(0),
            Source::Ai,
            &[rename("0x10", "a", Confidence::Likely)],
        )
        .unwrap();
        let err = s
            .apply_edits(
                &h,
                Some("r2"),
                "w",
                Some(0),
                Source::Ai,
                &[rename("0x20", "b", Confidence::Likely)],
            )
            .unwrap_err();
        match err {
            Error::StaleRevision {
                current, changed, ..
            } => {
                assert_eq!(current, 1);
                assert_eq!(changed, vec!["rename_function:0x10"]);
            }
            e => panic!("{e}"),
        }
    }

    #[test]
    fn human_edits_are_protected_and_weaker_ai_does_not_replace_stronger() {
        let (mut s, h, _d) = setup();
        s.apply_edits(
            &h,
            None,
            "ui",
            None,
            Source::Human,
            &[rename("0x10", "mine", Confidence::Certain)],
        )
        .unwrap();
        let r = s
            .apply_edits(
                &h,
                Some("r"),
                "w",
                None,
                Source::Ai,
                &[rename("0x10", "theirs", Confidence::Certain)],
            )
            .unwrap();
        assert_eq!(r.rejected.len(), 1);
        s.apply_edits(
            &h,
            Some("r"),
            "w",
            None,
            Source::Ai,
            &[rename("0x20", "strong", Confidence::Certain)],
        )
        .unwrap();
        let r = s
            .apply_edits(
                &h,
                Some("r2"),
                "w",
                None,
                Source::Ai,
                &[rename("0x20", "weak", Confidence::Guess)],
            )
            .unwrap();
        assert_eq!(r.rejected.len(), 1);
    }

    #[test]
    fn invalid_names_rejected_and_duplicates_suffixed() {
        let (mut s, h, _d) = setup();
        let r = s
            .apply_edits(
                &h,
                Some("r"),
                "w",
                None,
                Source::Ai,
                &[
                    rename("0x10", "bad name!", Confidence::Likely),
                    rename("0x20", "dup", Confidence::Likely),
                    rename("0x30", "dup", Confidence::Likely),
                ],
            )
            .unwrap();
        assert_eq!(r.rejected.len(), 1);
        assert_eq!(r.applied[1].value, "dup_2");
    }

    #[test]
    fn undo_restores_previous_and_skips_later_changes() {
        let (mut s, h, _d) = setup();
        s.apply_edits(
            &h,
            None,
            "ui",
            None,
            Source::Human,
            &[rename("0x10", "mine", Confidence::Certain)],
        )
        .unwrap();
        s.apply_edits(
            &h,
            Some("r1"),
            "w",
            None,
            Source::Ai,
            &[
                rename("0x20", "x", Confidence::Likely),
                rename("0x30", "y", Confidence::Likely),
            ],
        )
        .unwrap();
        // A human edits 0x30 after the run.
        s.apply_edits(
            &h,
            None,
            "ui",
            None,
            Source::Human,
            &[rename("0x30", "human_y", Confidence::Certain)],
        )
        .unwrap();
        let u = s.undo_run(&h, "r1").unwrap();
        assert_eq!(u.reverted, 1);
        assert_eq!(u.skipped.len(), 1);
        let a = s.annotations(&h, None).unwrap();
        assert!(a.iter().any(|x| x.target == "0x30" && x.value == "human_y"));
        assert!(!a.iter().any(|x| x.target == "0x20"));
        // Undo is idempotent.
        assert_eq!(s.undo_run(&h, "r1").unwrap().reverted, 0);
    }

    #[test]
    fn reports_are_versioned() {
        let (mut s, h, _d) = setup();
        assert_eq!(s.save_report(&h, "a", "{}", "# a").unwrap().version, 1);
        assert_eq!(s.save_report(&h, "b", "{}", "# b").unwrap().version, 2);
        assert_eq!(s.report(&h, Some(1)).unwrap().1, "# a");
        assert_eq!(s.reports(&h).unwrap().len(), 2);
    }
}
