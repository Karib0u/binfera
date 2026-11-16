//! `inspect()`: normalized image headers, mappings, imports and exports, without recovering or
//! decompiling any code. The same document `binfera --image-info -j` prints.

use binfera::api::Format;
use binfera::image_info;
use pyo3::prelude::*;

use crate::analyze::{json_to_py, parse_format, read_input};
use crate::error::{CorruptFileError, UnsupportedFormatError};

/// Reads the headers of a PE, ELF or Mach-O image, or of raw shellcode with `format="sc32"` or
/// `"sc64"`, and returns them as a `dict`: sections, regions, imports, exports, file details and
/// warnings. With `guess_shellcode`, an input that has no executable header is tried as x86/x64
/// raw code.
#[pyfunction]
#[pyo3(signature = (data_or_path, *, format=None, arch=None, guess_shellcode=false))]
pub fn inspect(
    py: Python<'_>,
    data_or_path: &Bound<'_, PyAny>,
    format: Option<String>,
    arch: Option<String>,
    guess_shellcode: bool,
) -> PyResult<Py<PyAny>> {
    let (bytes, _) = read_input(data_or_path)?;
    let format = parse_format(format.as_deref())?;
    if matches!(format, Format::Freeze | Format::Dotnet) {
        return Err(UnsupportedFormatError::new_err(
            "inspect reads PE, ELF and Mach-O headers or raw shellcode (format sc32/sc64)",
        ));
    }
    let json = py.detach(move || -> PyResult<String> {
        let bytes = binfera::extract::elf::without_corrupt_section_headers(&bytes).unwrap_or(bytes);
        let arch = arch.as_deref().unwrap_or("auto");
        let info = match format {
            Format::Sc32 => image_info::inspect_shellcode(&bytes, Some(false)),
            Format::Sc64 => image_info::inspect_shellcode(&bytes, Some(true)),
            _ if guess_shellcode
                && !binfera::extract::looks_like_pe(&bytes)
                && !binfera::extract::looks_like_elf(&bytes)
                && !binfera::extract::looks_like_macho(&bytes) =>
            {
                image_info::inspect_shellcode(&bytes, None)
            }
            _ => image_info::inspect(&bytes, Some(arch)),
        }
        .map_err(|e| CorruptFileError::new_err(e.to_string()))?;
        serde_json::to_string(&info)
            .map_err(|e| CorruptFileError::new_err(format!("serializing image info: {e}")))
    })?;
    json_to_py(py, json)
}
