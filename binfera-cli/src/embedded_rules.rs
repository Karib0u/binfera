//! The capability rules built into the binary (see `build.rs`), unpacked on first use.
//!
//! The rule loader reads a directory, so the pack is written once to
//! `<data dir>/embedded-rules/<id>`, where the id is a hash of the pack: a new binary with new rules
//! unpacks to a new folder, and the same binary reuses what it already wrote. A folder is trusted
//! only once its `.complete` marker exists, so an interrupted unpack is redone.
use std::path::PathBuf;

static PACK: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rules.pack"));

/// The folder holding the embedded rules, or `None` when the binary has none or they cannot be written.
pub fn unpack() -> Option<PathBuf> {
    if PACK.is_empty() {
        return None;
    }
    let id = &binfera_project::hash_bytes(PACK)[..16];
    let dir = binfera_project::data_dir().join("embedded-rules").join(id);
    if dir.join(".complete").is_file() {
        return Some(dir);
    }
    // Written beside the target and renamed into place, so two processes unpacking at once are safe.
    let staging = dir.with_extension(format!("tmp{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&staging);
    let written = write_all(&staging).is_some();
    if written && std::fs::rename(&staging, &dir).is_ok() {
        return Some(dir);
    }
    let _ = std::fs::remove_dir_all(&staging);
    // Another process may have finished first.
    dir.join(".complete").is_file().then_some(dir)
}

fn write_all(root: &std::path::Path) -> Option<()> {
    // `[u32 length][bytes]` at `at`, advancing past it.
    fn chunk(at: &mut usize) -> Option<&'static [u8]> {
        let len = u32::from_le_bytes(PACK.get(*at..*at + 4)?.try_into().ok()?) as usize;
        let data = PACK.get(*at + 4..*at + 4 + len)?;
        *at += 4 + len;
        Some(data)
    }
    let mut at = 0;
    while at < PACK.len() {
        let name = std::str::from_utf8(chunk(&mut at)?).ok()?;
        let data = chunk(&mut at)?;
        // The pack is our own build output, but never write outside the folder.
        if name.split('/').any(|part| part.is_empty() || part == "..") {
            return None;
        }
        let path = root.join(name);
        std::fs::create_dir_all(path.parent()?).ok()?;
        std::fs::write(path, data).ok()?;
    }
    std::fs::write(root.join(".complete"), b"").ok()
}
