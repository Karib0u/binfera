//! Ephemeral recovery handoff between the CLI parent and its persistent workers.
//! The private file belongs to one invocation of the same executable.
use super::*;
use sha2::{Digest, Sha256};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

const MAGIC: &[u8; 8] = b"BNVR0001";
fn config() -> impl bincode::config::Config {
    bincode::config::standard().with_limit::<1_073_741_824>()
}
fn error(error: impl std::fmt::Display) -> DecompileError {
    DecompileError::Input(format!("worker recovery snapshot: {error}"))
}
fn options_key(options: &BatchOptions) -> String {
    format!("{:?}", (options.format, &options.arch, &options.os))
}

/// Prepare native and optional compatibility recovery once, before starting workers.
/// Returns false for inputs handled by the serial managed/data-only paths.
#[doc(hidden)]
pub fn prepare(bytes: &[u8], options: &BatchOptions, path: &Path) -> Result<bool, DecompileError> {
    options.validate()?;
    if crate::extract::dotnet::looks_like_dotnet_pe(bytes) || unsupported_elf_cpu(bytes).is_some() {
        return Ok(false);
    }
    let repaired = crate::extract::elf::without_corrupt_section_headers(bytes);
    let bytes = repaired.as_deref().unwrap_or(bytes);
    let (mut session, native) = options.open(bytes)?;
    let mut output = BufWriter::new(std::fs::File::create(path).map_err(error)?);
    output.write_all(MAGIC).map_err(error)?;
    output.write_all(&Sha256::digest(bytes)).map_err(error)?;
    bincode::serde::encode_into_std_write(options_key(options), &mut output, config())
        .map_err(error)?;
    bincode::serde::encode_into_std_write(&native, &mut output, config()).map_err(error)?;
    let compatible = selection::needs_compatibility(&native);
    bincode::serde::encode_into_std_write(compatible, &mut output, config()).map_err(error)?;
    if compatible {
        let (listed, rejected) = selection::select_analysis(bytes, native, &mut session)?;
        bincode::serde::encode_into_std_write((&listed, &rejected), &mut output, config())
            .map_err(error)?;
    }
    bincode::serde::encode_into_std_write(&session.warnings, &mut output, config())
        .map_err(error)?;
    output.flush().map_err(error)?;
    Ok(true)
}

pub(super) fn open(
    bytes: &[u8],
    options: &BatchOptions,
    path: &Path,
) -> Result<(DecompilerSession, Analysis, BTreeSet<u64>), DecompileError> {
    let started = std::time::Instant::now();
    let mut input = BufReader::new(std::fs::File::open(path).map_err(error)?);
    let mut header = [0u8; 40];
    input.read_exact(&mut header).map_err(error)?;
    if &header[..8] != MAGIC || header[8..] != Sha256::digest(bytes)[..] {
        return Err(error("version or input hash mismatch"));
    }
    let saved_options: String =
        bincode::serde::decode_from_std_read(&mut input, config()).map_err(error)?;
    if saved_options != options_key(options) {
        return Err(error("input options mismatch"));
    }
    let native: Analysis =
        bincode::serde::decode_from_std_read(&mut input, config()).map_err(error)?;
    let (mut session, native) = options.open_recovered(bytes, Some(native))?;
    let compatible: bool =
        bincode::serde::decode_from_std_read(&mut input, config()).map_err(error)?;
    let (analysis, rejected) = if compatible {
        let (listed, rejected) =
            bincode::serde::decode_from_std_read(&mut input, config()).map_err(error)?;
        (listed, rejected)
    } else {
        (native, BTreeSet::new())
    };
    session.warnings = bincode::serde::decode_from_std_read(&mut input, config()).map_err(error)?;
    session.initialization_ms = started.elapsed().as_secs_f64() * 1000.0;
    Ok((session, analysis, rejected))
}
