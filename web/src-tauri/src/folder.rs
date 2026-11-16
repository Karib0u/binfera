//! Opening a folder: the executables inside it, as a tree the analyst can pick from.
//!
//! The analyst chooses a folder with the system dialog. It is scanned here (never from the page),
//! and only files that look like PE, ELF, Mach-O or a zip/7z archive are listed. A file is read by the page only
//! after `folder_open` registered it, which refuses anything outside the folders that were chosen.
use crate::project::{Picked, Projects};
use serde::Serialize;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use tauri::State;

/// How deep the scan goes, how many files it looks at and how many it lists.
const MAX_DEPTH: usize = 24;
const MAX_VISITED: usize = 200_000;
const MAX_LISTED: usize = 20_000;

#[derive(Serialize, Clone)]
pub struct Entry {
    /// Path relative to the folder, `/`-separated.
    path: String,
    size: u64,
    /// `pe`, `elf`, `macho`, `zip` or `7z`.
    kind: &'static str,
}

#[derive(Serialize, Clone)]
pub struct Folder {
    root: String,
    name: String,
    files: Vec<Entry>,
    /// The scan stopped early because the folder is very large.
    truncated: bool,
}

/// The format of a file's first bytes, if it is one binfera opens. A `zip` is only a candidate:
/// docx, jar and apk files start the same way, so [`scan`] asks Magika about those.
pub fn sniff(file: &mut File, size: u64) -> Option<&'static str> {
    let mut head = [0u8; 64];
    if size < 64 || file.read_exact(&mut head).is_err() {
        return None;
    }
    match head[..4] {
        [0x7f, b'E', b'L', b'F'] => Some("elf"),
        [0xfe, 0xed, 0xfa, 0xce | 0xcf] | [0xce | 0xcf, 0xfa, 0xed, 0xfe] => Some("macho"),
        // Fat Mach-O shares its magic with Java classes; a class has a version (>= 45) there.
        [0xca, 0xfe, 0xba, 0xbe] => {
            (u32::from_be_bytes(head[4..8].try_into().ok()?) < 30).then_some("macho")
        }
        [b'P', b'K', 3, 4] => Some("zip"),
        [b'7', b'z', 0xbc, 0xaf] => (head[4..6] == [0x27, 0x1c]).then_some("7z"),
        [b'M', b'Z', ..] => {
            let at = u64::from(u32::from_le_bytes(head[0x3c..0x40].try_into().ok()?));
            let mut sig = [0u8; 4];
            (at <= size.saturating_sub(4)
                && file.seek(SeekFrom::Start(at)).is_ok()
                && file.read_exact(&mut sig).is_ok()
                && &sig == b"PE\0\0")
                .then_some("pe")
        }
        _ => None,
    }
}

/// Whether Magika, which looks at the content and not only the first bytes, says this is a plain
/// zip archive rather than an Office document, a jar, an apk or another zip-based format. Without
/// the model (it could not start) the extension decides.
fn plain_zip(session: &mut Option<Option<magika::Session>>, path: &Path) -> bool {
    let session = session.get_or_insert_with(|| magika::Session::new().ok());
    match session {
        Some(s) => s
            .identify_file_sync(path)
            .ok()
            .and_then(|t| t.content_type())
            .is_some_and(|t| matches!(t, magika::ContentType::Zip)),
        None => path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("zip")),
    }
}

pub fn scan(root: &Path) -> Folder {
    let mut magika = None;
    let mut files = Vec::new();
    let (mut visited, mut truncated) = (0usize, false);
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    'walk: while let Some((dir, depth)) = stack.pop() {
        let Ok(read) = std::fs::read_dir(&dir) else {
            continue;
        };
        for item in read.flatten() {
            // Links are skipped: they could lead out of the folder or loop.
            let Ok(kind) = item.file_type() else { continue };
            let path = item.path();
            if kind.is_dir() {
                if depth < MAX_DEPTH {
                    stack.push((path, depth + 1));
                }
            } else if kind.is_file() {
                visited += 1;
                if visited > MAX_VISITED || files.len() >= MAX_LISTED {
                    truncated = true;
                    break 'walk;
                }
                let Ok(mut file) = File::open(&path) else {
                    continue;
                };
                let Ok(size) = file.metadata().map(|m| m.len()) else {
                    continue;
                };
                if let Some(kind) = sniff(&mut file, size) {
                    drop(file);
                    if kind == "zip" && !plain_zip(&mut magika, &path) {
                        continue;
                    }
                    if let Ok(rel) = path.strip_prefix(root) {
                        let rel: Vec<_> = rel
                            .components()
                            .map(|c| c.as_os_str().to_string_lossy())
                            .collect();
                        files.push(Entry {
                            path: rel.join("/"),
                            size,
                            kind,
                        });
                    }
                }
            }
        }
    }
    files.sort_by_cached_key(|f| f.path.to_lowercase());
    Folder {
        root: root.to_string_lossy().into_owned(),
        name: root.file_name().map_or_else(
            || root.to_string_lossy().into_owned(),
            |n| n.to_string_lossy().into_owned(),
        ),
        files,
        truncated,
    }
}

impl Projects {
    /// Allows and scans a folder the analyst dropped on the window.
    pub fn open_folder(&self, dir: &Path) -> Result<Folder, String> {
        let root = std::fs::canonicalize(dir).map_err(|e| e.to_string())?;
        self.allow_folder(root.clone());
        Ok(scan(&root))
    }
}

async fn scan_blocking(state: &Projects, root: PathBuf) -> Result<Folder, String> {
    let root = tauri::async_runtime::spawn_blocking(move || std::fs::canonicalize(&root))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    if !root.is_dir() {
        return Err("that is not a folder".into());
    }
    state.allow_folder(root.clone());
    tauri::async_runtime::spawn_blocking(move || scan(&root))
        .await
        .map_err(|e| e.to_string())
}

/// Asks the analyst for a folder with the system dialog and lists the executables inside it.
#[tauri::command]
pub async fn folder_pick(
    app: tauri::AppHandle,
    state: State<'_, Projects>,
) -> Result<Option<Folder>, String> {
    use tauri_plugin_dialog::DialogExt;
    let (tx, rx) = std::sync::mpsc::channel();
    app.dialog().file().pick_folder(move |dir| {
        let _ = tx.send(dir);
    });
    let Some(dir) = tauri::async_runtime::spawn_blocking(move || rx.recv().ok().flatten())
        .await
        .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    let root = dir.into_path().map_err(|e| e.to_string())?;
    scan_blocking(&state, root).await.map(Some)
}

/// Scans a folder chosen earlier again (files come and go).
#[tauri::command]
pub async fn folder_scan(state: State<'_, Projects>, root: String) -> Result<Folder, String> {
    let root = PathBuf::from(root);
    let canonical = std::fs::canonicalize(&root).map_err(|e| e.to_string())?;
    if !state.in_folder(&canonical) {
        return Err("that folder was not opened from this app".into());
    }
    scan_blocking(&state, canonical).await
}

/// Registers one file of an opened folder (hash, history, permission to read it).
#[tauri::command]
pub async fn folder_open(
    state: State<'_, Projects>,
    root: String,
    path: String,
) -> Result<Picked, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let root = std::fs::canonicalize(root).map_err(|e| e.to_string())?;
        if !state.in_folder(&root) {
            return Err("that folder was not opened from this app".to_string());
        }
        let file = std::fs::canonicalize(root.join(&path)).map_err(|e| e.to_string())?;
        // A link planted after the scan could lead anywhere: only files really inside count.
        if !file.starts_with(&root) {
            return Err("that file is outside the opened folder".into());
        }
        state.register(&file)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, bytes: &[u8]) {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn padded(head: &[u8]) -> Vec<u8> {
        let mut v = head.to_vec();
        v.resize(128, 0);
        v
    }

    /// A valid zip holding `members` (name, content), stored without compression.
    fn zip(members: &[(&str, &[u8])]) -> Vec<u8> {
        let (mut out, mut central) = (Vec::new(), Vec::new());
        for (name, data) in members {
            let crc = {
                let mut c = !0u32;
                for b in *data {
                    c ^= u32::from(*b);
                    for _ in 0..8 {
                        c = if c & 1 == 1 {
                            (c >> 1) ^ 0xedb8_8320
                        } else {
                            c >> 1
                        };
                    }
                }
                !c
            };
            let offset = out.len() as u32;
            let mut common = Vec::new();
            common.extend([20, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // version, flags, method, time, date
            common.extend(crc.to_le_bytes());
            common.extend((data.len() as u32).to_le_bytes());
            common.extend((data.len() as u32).to_le_bytes());
            common.extend((name.len() as u16).to_le_bytes());
            common.extend([0, 0]);
            out.extend(b"PK\x03\x04");
            out.extend(&common);
            out.extend(name.as_bytes());
            out.extend(*data);
            central.extend(b"PK\x01\x02\x14\x00");
            central.extend(&common);
            central.extend([0; 8]); // comment, disk, internal attrs
            central.extend([0; 4]); // external attrs
            central.extend(offset.to_le_bytes());
            central.extend(name.as_bytes());
        }
        let start = out.len() as u32;
        out.extend(&central);
        out.extend(b"PK\x05\x06\0\0\0\0");
        out.extend((members.len() as u16).to_le_bytes());
        out.extend((members.len() as u16).to_le_bytes());
        out.extend((central.len() as u32).to_le_bytes());
        out.extend(start.to_le_bytes());
        out.extend([0, 0]);
        out
    }

    #[test]
    fn lists_plain_zips_but_not_documents() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "loot.dat",
            &zip(&[
                ("a.txt", &b"hello world, this is a sample ".repeat(20)),
                ("b.bin", &[7u8; 300]),
            ]),
        );
        write(
            root,
            "report.zip",
            &zip(&[
                ("[Content_Types].xml", br#"<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#),
                ("word/document.xml", b"<w:document/>"),
            ]),
        );
        let got: Vec<_> = scan(root).files.iter().map(|f| f.path.clone()).collect();
        assert_eq!(got, ["loot.dat"]);
    }

    #[test]
    fn lists_only_executables_in_a_tree() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "a/b/tool.elf", &padded(b"\x7fELF"));
        write(root, "mac", &padded(&[0xcf, 0xfa, 0xed, 0xfe]));
        let mut pe = padded(b"MZ");
        pe[0x3c] = 0x40;
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        write(root, "win/x.dll", &pe);
        write(root, "dos.exe", &padded(b"MZ"));
        write(
            root,
            "sevenz.bin",
            &padded(&[b'7', b'z', 0xbc, 0xaf, 0x27, 0x1c]),
        );
        write(root, "readme.txt", &padded(b"hello"));
        write(
            root,
            "Foo.class",
            &padded(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0x34]),
        );
        let found = scan(root);
        let got: Vec<_> = found
            .files
            .iter()
            .map(|f| (f.path.as_str(), f.kind))
            .collect();
        assert_eq!(
            got,
            [
                ("a/b/tool.elf", "elf"),
                ("mac", "macho"),
                ("sevenz.bin", "7z"),
                ("win/x.dll", "pe")
            ]
        );
        assert!(!found.truncated);
    }
}
