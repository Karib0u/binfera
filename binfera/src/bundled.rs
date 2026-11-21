//! Large bundled data files (FLIRT signature databases, Function ID packs).
//!
//! Native builds embed them with `include_bytes!`, exactly as before. The Emscripten (browser)
//! build leaves them out of the module so the ~50 MB of data downloads separately, is cached
//! by the browser, and can be limited to what a sample needs (one Function ID pack, not
//! both). The page mounts them under [`DIR`] in the module's in-memory file system before
//! running; a missing file is a contextual error, never a silent skip.

/// Where the host page mounts the data files on the Emscripten target.
#[cfg(target_os = "emscripten")]
pub const DIR: &str = "/sigs";

/// Yields `Result<Cow<'static, [u8]>, String>` for the file `sigs/$name`.
#[cfg(not(target_os = "emscripten"))]
macro_rules! bundled {
    ($name:literal) => {
        Ok::<std::borrow::Cow<'static, [u8]>, String>(std::borrow::Cow::Borrowed(include_bytes!(
            concat!(env!("CARGO_MANIFEST_DIR"), "/sigs/", $name)
        )))
    };
}

#[cfg(target_os = "emscripten")]
macro_rules! bundled {
    ($name:literal) => {
        $crate::bundled::read($name)
    };
}

pub(crate) use bundled;

#[cfg(target_os = "emscripten")]
pub fn read(name: &str) -> Result<std::borrow::Cow<'static, [u8]>, String> {
    let path = std::path::Path::new(DIR).join(name);
    std::fs::read(&path)
        .map(std::borrow::Cow::Owned)
        .map_err(|e| format!("bundled data file {} is not mounted: {e}", path.display()))
}

/// Hands the Windows API prototype archive for `wide` (64-bit) or 32-bit images to the native
/// bridge. Native builds embed both archives and this does nothing; the Emscripten build reads
/// the page-mounted `/sigs/winapi{64,32}.pack` once per process and architecture. A pack that is
/// not mounted is reported on stderr once and registered as empty: Windows imports then stay
/// untyped instead of failing the decompilation.
#[cfg(all(feature = "decompiler", target_os = "emscripten"))]
pub(crate) fn register_windows_pack(wide: bool) {
    use std::sync::OnceLock;
    static LOADED: [OnceLock<()>; 2] = [OnceLock::new(), OnceLock::new()];
    LOADED[usize::from(wide)].get_or_init(|| {
        let bytes = if wide {
            bundled!("winapi64.pack")
        } else {
            bundled!("winapi32.pack")
        };
        match bytes {
            Ok(bytes) => binfera_ghidra::set_windows_pack(wide, &bytes),
            Err(error) => {
                eprintln!("binfera: no Windows prototypes, imports stay untyped: {error}");
                binfera_ghidra::set_windows_pack(wide, &[]);
            }
        }
    });
}

#[cfg(all(feature = "decompiler", not(target_os = "emscripten")))]
pub(crate) fn register_windows_pack(_wide: bool) {}
