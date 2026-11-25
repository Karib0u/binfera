use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Resolve an explicit path or look for a pack in the standard per-user locations.
pub fn resolve_family_pack(explicit: Option<&Path>) -> Option<PathBuf> {
    match explicit {
        Some(path) => Some(path.to_path_buf()),
        None => resolve_family_packs(&[]).into_iter().next(),
    }
}

/// Resolve the packs to layer, base first.
///
/// Explicit paths win. Otherwise the existing files listed in `BINFERA_FAMILY_PACKS`, or else in
/// `BINFERA_FAMILY_PACK`, are used; both accept one path or a platform path list (`:` on Unix,
/// `;` on Windows). Without any, the first of `family.bxfam` in the data directory and
/// `family.bxfam` beside the executable is used.
pub fn resolve_family_packs(explicit: &[PathBuf]) -> Vec<PathBuf> {
    if !explicit.is_empty() {
        return explicit.to_vec();
    }
    let executable = std::env::current_exe().ok();
    resolve(&crate::data_dir(), executable.as_deref(), &env_packs())
}

/// Find a pack for an engine using a caller-supplied data directory and executable.
pub fn find_family_pack(data_dir: &Path, executable: Option<&Path>) -> Option<PathBuf> {
    find_family_packs(data_dir, executable).into_iter().next()
}

/// Find layered packs, base first, for an engine using a caller-supplied data directory and
/// executable. See [`resolve_family_packs`].
pub fn find_family_packs(data_dir: &Path, executable: Option<&Path>) -> Vec<PathBuf> {
    resolve(data_dir, executable, &env_packs())
}

fn env_packs() -> Vec<PathBuf> {
    ["BINFERA_FAMILY_PACKS", "BINFERA_FAMILY_PACK"]
        .into_iter()
        .filter_map(std::env::var_os)
        .map(|value| split_pack_list(&value))
        .find(|packs| packs.iter().any(|p| p.is_file()))
        .unwrap_or_default()
}

/// One existing path stays whole even if it contains the separator; otherwise split the list.
fn split_pack_list(value: &OsString) -> Vec<PathBuf> {
    let whole = PathBuf::from(value);
    if whole.is_file() {
        return vec![whole];
    }
    std::env::split_paths(value)
        .filter(|p| !p.as_os_str().is_empty())
        .collect()
}

fn resolve(data_dir: &Path, executable: Option<&Path>, env_packs: &[PathBuf]) -> Vec<PathBuf> {
    let listed: Vec<PathBuf> = env_packs.iter().filter(|p| p.is_file()).cloned().collect();
    if !listed.is_empty() {
        return listed;
    }
    std::iter::once(data_dir.join("family.bxfam"))
        .chain(
            executable
                .and_then(Path::parent)
                .map(|dir| dir.join("family.bxfam")),
        )
        .find(|path| path.is_file())
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolution_precedence() -> std::io::Result<()> {
        let tmp = tempfile::tempdir()?;
        let data = tmp.path().join("data");
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&data)?;
        std::fs::create_dir_all(&bin)?;
        let executable = bin.join("binfera");
        let beside_exe = bin.join("family.bxfam");
        let installed = data.join("family.bxfam");
        let env_pack = tmp.path().join("env.bxfam");
        let explicit = tmp.path().join("explicit.bxfam");
        let find = |explicit: Option<&PathBuf>| match explicit {
            Some(path) => Some(path.clone()),
            None => resolve(&data, Some(&executable), std::slice::from_ref(&env_pack))
                .into_iter()
                .next(),
        };

        assert_eq!(find(None), None);
        std::fs::write(&beside_exe, [])?;
        assert_eq!(find(None), Some(beside_exe));
        std::fs::create_dir(&env_pack)?;
        std::fs::write(&installed, [])?;
        assert_eq!(find(None), Some(installed));
        std::fs::remove_dir(&env_pack)?;
        std::fs::write(&env_pack, [])?;
        assert_eq!(find(None), Some(env_pack.clone()));
        assert_eq!(find(Some(&explicit)), Some(explicit));
        Ok(())
    }

    #[test]
    fn pack_lists_keep_order_and_skip_missing_entries() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = tempfile::tempdir()?;
        let base = tmp.path().join("base.bxfam");
        let overlay = tmp.path().join("org.bxfam");
        let missing = tmp.path().join("missing.bxfam");
        std::fs::write(&base, [])?;
        std::fs::write(&overlay, [])?;
        let list = std::env::join_paths([&base, &missing, &overlay])?;
        let packs = split_pack_list(&list);
        assert_eq!(packs, [base.clone(), missing, overlay.clone()]);
        assert_eq!(resolve(tmp.path(), None, &packs), [base.clone(), overlay]);
        // A single existing path is never split.
        assert_eq!(split_pack_list(&base.clone().into_os_string()), [base]);
        Ok(())
    }
}
