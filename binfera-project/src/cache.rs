//! Shared eviction policy for desktop and MCP engine results.
use std::fs::{self, File};
use std::path::Path;
use std::time::{Duration, SystemTime};

fn cache_directory(target: &Path) -> &Path {
    target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Each writer owns a same-directory file that can be published atomically on success.
pub fn cache_tempfile(target: &Path) -> std::io::Result<tempfile::NamedTempFile> {
    let name = target.file_name().unwrap_or_default();
    let directory = cache_directory(target);
    // tempfile publishes with Win32 APIs that need a verbatim prefix for long paths.
    #[cfg(windows)]
    let directory = directory.canonicalize()?;
    tempfile::Builder::new()
        .prefix(name)
        .suffix(".part")
        .tempfile_in(directory)
}

/// Publish the first completed result for this key and keep it available to readers.
pub fn publish_cache_file(file: tempfile::NamedTempFile, target: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    let absolute = cache_directory(target)
        .canonicalize()?
        .join(target.file_name().ok_or(std::io::ErrorKind::InvalidInput)?);
    #[cfg(windows)]
    let target = absolute.as_path();
    match file.persist_noclobber(target) {
        Ok(_) => Ok(()),
        Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists && target.is_file() => Ok(()),
        Err(e) => Err(e.error),
    }
}

/// Default 2 GiB, overridable in MiB with `BINFERA_CACHE_MAX_MB` (zero removes completed results at startup).
pub fn cache_max_bytes() -> u64 {
    std::env::var("BINFERA_CACHE_MAX_MB")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .and_then(|mb| mb.checked_mul(1024 * 1024))
        .unwrap_or(2 * 1024 * 1024 * 1024)
}

/// Best effort: a read-only cache remains usable even when its timestamp cannot be updated.
pub fn touch_cache_file(path: &Path) {
    if let Ok(file) = File::options().write(true).open(path) {
        let _ = file.set_modified(SystemTime::now());
    }
}

/// Removes stale partial writes, then evicts the least recently used files until under the cap.
/// Versions share the budget. Recent partial writes belong to running jobs and are left alone.
pub fn prune_cache(dir: &Path, max_bytes: u64) -> std::io::Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let mut files = Vec::new();
    let mut total = 0u64;
    for entry in entries.flatten() {
        // Do not follow symlinks or recurse into directories.
        if !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "part") {
            if modified
                .elapsed()
                .is_ok_and(|age| age > Duration::from_secs(86400))
            {
                let _ = fs::remove_file(path);
            }
            continue;
        }
        total = total.saturating_add(meta.len());
        files.push((modified, path, meta.len()));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    for (_, path, size) in files {
        if total <= max_bytes {
            break;
        }
        if fs::remove_file(path).is_ok() {
            total = total.saturating_sub(size);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn publishes_cache_files_in_long_paths_without_clobbering() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let directory = dir
            .path()
            .join("nested".repeat(24))
            .join("cache".repeat(12));
        fs::create_dir_all(&directory)?;
        let target = directory.join(format!("{}.family.json", "a".repeat(196)));
        assert!(target.as_os_str().len() > 260);

        for bytes in [b"first", b"other"] {
            let mut file = cache_tempfile(&target)?;
            file.write_all(bytes)?;
            publish_cache_file(file, &target)?;
        }
        assert_eq!(fs::read(target)?, b"first");
        Ok(())
    }

    fn entry(dir: &Path, name: &str, age: u64) -> std::path::PathBuf {
        let path = dir.join(name);
        fs::write(&path, [0; 10]).unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(age))
            .unwrap();
        path
    }

    #[test]
    fn evicts_oldest_across_versions_and_keeps_touched_results() {
        let dir = tempfile::tempdir().unwrap();
        let touched = entry(dir.path(), "sample-v1.decomp.jsonl", 300);
        let oldest = entry(dir.path(), "sample-v2.capa.json", 200);
        let newer = entry(dir.path(), "sample-v3.image.jsonl", 100);
        touch_cache_file(&touched);
        prune_cache(dir.path(), 20).unwrap();
        assert!(!oldest.exists());
        assert!(newer.exists());
        assert!(touched.exists());
        prune_cache(dir.path(), 0).unwrap();
        assert!(!touched.exists());
        assert!(!newer.exists());
    }

    #[test]
    fn removes_stale_parts_but_preserves_active_writes_and_directories() {
        let dir = tempfile::tempdir().unwrap();
        let stale = entry(dir.path(), "stale.part", 86401);
        let active = entry(dir.path(), "active.part", 60);
        fs::create_dir(dir.path().join("nested")).unwrap();
        prune_cache(dir.path(), 0).unwrap();
        assert!(!stale.exists());
        assert!(active.exists());
        assert!(dir.path().join("nested").is_dir());
        prune_cache(&dir.path().join("missing"), 0).unwrap();
    }
}
