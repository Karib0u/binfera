use std::path::{Path, PathBuf};

/// Resolve an explicit path or look for a pack in the standard per-user locations.
pub fn resolve_family_pack(explicit: Option<&Path>) -> Option<PathBuf> {
    let executable = std::env::current_exe().ok();
    resolve(
        explicit,
        &crate::data_dir(),
        executable.as_deref(),
        env_pack().as_deref(),
    )
}

/// Find a pack for an engine using a caller-supplied data directory and executable.
pub fn find_family_pack(data_dir: &Path, executable: Option<&Path>) -> Option<PathBuf> {
    resolve(None, data_dir, executable, env_pack().as_deref())
}

fn env_pack() -> Option<PathBuf> {
    std::env::var_os("BINFERA_FAMILY_PACK").map(PathBuf::from)
}

fn resolve(
    explicit: Option<&Path>,
    data_dir: &Path,
    executable: Option<&Path>,
    env_pack: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return Some(path.to_path_buf());
    }
    env_pack
        .map(Path::to_path_buf)
        .into_iter()
        .chain(std::iter::once(data_dir.join("family.bxfam")))
        .chain(
            executable
                .and_then(Path::parent)
                .map(|dir| dir.join("family.bxfam")),
        )
        .find(|path| path.is_file())
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
        let find = |explicit| resolve(explicit, &data, Some(&executable), Some(&env_pack));

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
}
