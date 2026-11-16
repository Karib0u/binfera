//! Go binaries: the toolchain version and the function table every Go executable carries.
//!
//! The Go linker writes its own symbol table, `pclntab`, into every binary, stripped or not:
//! each function's entry, extent and full name (`os.(*File).Write`). The toolchain version is in
//! the build information block (`\xff Go buildinf:`), and failing that the table's own layout gives
//! a lower bound. A port of the reading half of Ghidra 12.1.4's Go support
//! (`GoBuildInfo`, `GoPcHeader`, `GoFuncData`, `GoModuledata`), for x86 and x86-64 images.
use crate::extract::image::{Architecture, LoadedImage};

pub mod pclntab;

pub use pclntab::{FunctionTable, GoFunction};

/// A Go toolchain release, `go1.21.3` read as 1.21.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct GoVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl GoVersion {
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// `go1.21.3`, `go1.22rc1` or `go1.20 X:boringcrypto`. Development builds (`devel ...`) and
    /// anything else carry no usable version.
    pub fn parse(text: &str) -> Option<Self> {
        let rest = text.strip_prefix("go")?;
        let mut numbers = rest
            .split(|c: char| !c.is_ascii_digit())
            .take_while(|part| !part.is_empty());
        let major = numbers.next()?.parse().ok()?;
        let minor = numbers.next()?.parse().ok()?;
        // `go1.21rc2` has no patch; the separator after the minor version must be a dot for a
        // third number to count.
        let after_minor = rest
            .trim_start_matches(|c: char| c.is_ascii_digit())
            .strip_prefix('.')?
            .trim_start_matches(|c: char| c.is_ascii_digit());
        let patch = if after_minor.starts_with('.') {
            numbers.next().and_then(|n| n.parse().ok()).unwrap_or(0)
        } else {
            0
        };
        Some(Self::new(major, minor, patch))
    }

    /// Go 1.17 introduced the register ABI (`ABIInternal`) on amd64.
    pub fn has_register_abi(self) -> bool {
        self >= Self::new(1, 17, 0)
    }
}

impl std::fmt::Display for GoVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "go{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// What a Go binary says about itself.
#[derive(Clone, Debug)]
pub struct GoBinary {
    /// From the build information; `None` for a development toolchain or when the block is
    /// missing or damaged.
    pub build_version: Option<GoVersion>,
    /// Without build information (a memory dump, say): the release named by a `go1.N.M` string in
    /// the data (`runtime.buildVersion`), when one fits the table layout.
    pub version_string: Option<GoVersion>,
    pub functions: FunctionTable,
    /// Register stack checks disambiguate garbled Go 1.17 from the shared 1.16 layout.
    pub register_abi_evidence: bool,
}

impl GoBinary {
    /// The toolchain version: the build information's, else a release string in the data, else the
    /// oldest release that writes this table layout. Each must fit the layout.
    pub fn version(&self) -> GoVersion {
        let layout = self.functions.layout;
        self.build_version
            .filter(|version| layout.written_by(*version))
            .or(self.version_string)
            .unwrap_or_else(|| {
                if layout == pclntab::Layout::Go116 && self.register_abi_evidence {
                    GoVersion::new(1, 17, 0)
                } else {
                    layout.first_version()
                }
            })
    }
}

/// Reads the Go metadata of an x86, x86-64 or AArch64 image. `None` when the image is not Go, or its
/// function table cannot be found or read.
pub fn parse(image: &LoadedImage) -> Option<GoBinary> {
    if !matches!(
        image.architecture,
        Architecture::X86 | Architecture::X64 | Architecture::AArch64
    ) {
        return None;
    }
    let functions = pclntab::find(image)?;
    let build_version = build_version(image);
    let version_string = if build_version.is_none() {
        version_string(image, functions.layout)
    } else {
        None
    };
    let register_abi_evidence = image.architecture == Architecture::X64
        && functions.layout == pclntab::Layout::Go116
        && functions
            .functions
            .iter()
            .filter(|function| {
                // Go amd64 stackguard0 comparison, at an instruction boundary near entry.
                let mut address = function.entry;
                for _ in 0..12 {
                    let Ok(insn) = image.decode_at(address) else {
                        break;
                    };
                    if insn.bytes == [0x49, 0x3b, 0x66, 0x10] {
                        return true;
                    }
                    if insn.flow != crate::extract::decoder::Flow::Next {
                        break;
                    }
                    address += insn.bytes.len() as u64;
                    if address >= function.end {
                        break;
                    }
                }
                false
            })
            .take(2)
            .count()
            >= 2;
    Some(GoBinary {
        register_abi_evidence,
        build_version,
        version_string,
        functions,
    })
}

/// The first `go1.N` or `go1.N.M` string in non-executable data whose release writes `layout`.
/// The runtime keeps its own version there (`runtime.buildVersion`); requiring the layout to
/// match keeps most unrelated strings (a module's minimum release, say) from being taken for it,
/// but this is a heuristic, used only when the build information is missing.
fn version_string(image: &LoadedImage, layout: pclntab::Layout) -> Option<GoVersion> {
    const PREFIX: &[u8] = b"go1.";
    let sections = image
        .sections
        .iter()
        .filter(|s| !s.permissions.execute)
        .chain(image.sections.iter().filter(|s| s.permissions.execute));
    for section in sections {
        let Some(bytes) = image.bytes_at(section.address, usize::MAX) else {
            continue;
        };
        let mut at = 0;
        while let Some(found) = bytes.get(at..).and_then(|rest| find(rest, PREFIX)) {
            let start = at + found;
            at = start + 1;
            // Go packs its string constants without separators, so the string may run into
            // others on both sides; only the digits and dots belong to it. A source file named for
            // a release (`bits_go1.13.go`) ends that run with a dot and is not a version.
            let run: Vec<u8> = bytes
                .get(start..)
                .unwrap_or_default()
                .iter()
                .take(16)
                .enumerate()
                .take_while(|(i, b)| *i < PREFIX.len() || b.is_ascii_digit() || **b == b'.')
                .map(|(_, b)| *b)
                .collect();
            if run.ends_with(b".") {
                continue;
            }
            let Ok(text) = std::str::from_utf8(&run) else {
                continue;
            };
            if let Some(version) = GoVersion::parse(text).filter(|v| layout.written_by(*v)) {
                // Old Go PE files can keep read-only strings in executable
                // .text. Require a counted-string header before believing one.
                let address = section.address + start as u64;
                if !section.permissions.execute || counted_version(image, address, run.len()) {
                    return Some(version);
                }
            }
        }
    }
    None
}

fn counted_version(image: &LoadedImage, address: u64, length: usize) -> bool {
    let pointer = image.architecture.pointer_width();
    image.sections.iter().any(|section| {
        image
            .bytes_at(section.address, usize::MAX)
            .is_some_and(|bytes| {
                bytes.windows(2 * pointer).step_by(pointer).any(|header| {
                    read_uint(&header[..pointer]) == Some(address)
                        && read_uint(&header[pointer..]) == Some(length as u64)
                })
            })
    })
}

/// `src/debug/buildinfo/buildinfo.go`: the magic, then the pointer size and flags.
const BUILDINFO_MAGIC: &[u8] = b"\xff Go buildinf:";
const BUILDINFO_HEADER: usize = 32;
/// Flag bit 1: the version and module strings follow the header inline (Go 1.18+); otherwise
/// the header holds pointers to two Go strings.
const BUILDINFO_INLINE: u8 = 2;
const BUILDINFO_BIG_ENDIAN: u8 = 1;
/// Longest version string accepted (`go1.22.0 X:boringcrypto,...` is far shorter).
const MAX_VERSION_LEN: usize = 256;

/// The toolchain version from the build information block. The block is 16-byte aligned in a
/// data section (`.go.buildinfo` in ELF, the start of `.data` in PE); Ghidra looks in those two
/// places, this searches every non-executable section for the aligned magic.
pub fn build_version(image: &LoadedImage) -> Option<GoVersion> {
    let pointer = image.architecture.pointer_width();
    for section in &image.sections {
        if section.permissions.execute {
            continue;
        }
        let Some(bytes) = image.bytes_at(section.address, usize::MAX) else {
            continue;
        };
        let mut at = 0usize;
        while let Some(found) = find(bytes.get(at..)?, BUILDINFO_MAGIC) {
            let start = at + found;
            at = start + 1;
            if !(section.address + start as u64).is_multiple_of(16) {
                continue;
            }
            let Some(header) = bytes.get(start..start + BUILDINFO_HEADER) else {
                break;
            };
            let (size, flags) = (header[14] as usize, header[15]);
            if flags & BUILDINFO_BIG_ENDIAN != 0 {
                return None;
            }
            let text = if flags & BUILDINFO_INLINE != 0 {
                inline_string(bytes.get(start + BUILDINFO_HEADER..)?)
            } else {
                if size != pointer {
                    return None;
                }
                let string = read_uint(header.get(16..16 + size)?)?;
                go_string(image, string, pointer)
            };
            return text.as_deref().and_then(GoVersion::parse);
        }
    }
    None
}

/// A uvarint length, then that many bytes.
fn inline_string(bytes: &[u8]) -> Option<String> {
    let (length, used) = uvarint(bytes)?;
    let length = usize::try_from(length).ok()?;
    if length > MAX_VERSION_LEN {
        return None;
    }
    let text = bytes.get(used..used.checked_add(length)?)?;
    String::from_utf8(text.to_vec()).ok()
}

/// A Go string header `{data *byte, len int}` at `address`.
fn go_string(image: &LoadedImage, address: u64, pointer: usize) -> Option<String> {
    let header = image.bytes_at(address, 2 * pointer)?;
    let data = read_uint(header.get(..pointer)?)?;
    let length = usize::try_from(read_uint(header.get(pointer..2 * pointer)?)?).ok()?;
    if length > MAX_VERSION_LEN {
        return None;
    }
    let text = image.bytes_at(data, length)?;
    if text.len() != length {
        return None;
    }
    String::from_utf8(text.to_vec()).ok()
}

fn uvarint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (index, byte) in bytes.iter().take(10).enumerate() {
        value |= u64::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    None
}

/// A little-endian unsigned integer of 4 or 8 bytes.
pub(crate) fn read_uint(bytes: &[u8]) -> Option<u64> {
    match bytes.len() {
        4 => Some(u64::from(u32::from_le_bytes(bytes.try_into().ok()?))),
        8 => Some(u64::from_le_bytes(bytes.try_into().ok()?)),
        _ => None,
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_release_versions() {
        assert_eq!(GoVersion::parse("go1.21.3"), Some(GoVersion::new(1, 21, 3)));
        assert_eq!(GoVersion::parse("go1.22"), Some(GoVersion::new(1, 22, 0)));
        assert_eq!(
            GoVersion::parse("go1.22rc1"),
            Some(GoVersion::new(1, 22, 0))
        );
        assert_eq!(
            GoVersion::parse("go1.20.5 X:boringcrypto"),
            Some(GoVersion::new(1, 20, 5))
        );
        assert_eq!(GoVersion::parse("devel go1.23-abc"), None);
        assert_eq!(GoVersion::parse("go"), None);
        assert!(GoVersion::new(1, 17, 0).has_register_abi());
        assert!(!GoVersion::new(1, 16, 15).has_register_abi());
    }

    #[test]
    fn reads_inline_strings() {
        let mut bytes = vec![8];
        bytes.extend_from_slice(b"go1.22.4");
        assert_eq!(inline_string(&bytes).as_deref(), Some("go1.22.4"));
        assert_eq!(inline_string(&[9, b'g']), None);
        assert_eq!(inline_string(&[0xff; 12]), None);
    }

    #[test]
    fn executable_version_requires_a_matching_counted_string_header() {
        let mut bytes = vec![0; 128];
        bytes[16..24].copy_from_slice(b"go1.12.3");
        bytes[64..71].copy_from_slice(b"go1.9.2");
        bytes[96..104].copy_from_slice(&0x1040u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&7u64.to_le_bytes());
        let image = LoadedImage::from_shellcode_at(&bytes, Architecture::X64, 0x1000);
        assert_eq!(
            version_string(&image, pclntab::Layout::Go12),
            Some(GoVersion::new(1, 9, 2))
        );
        bytes[104..112].copy_from_slice(&6u64.to_le_bytes());
        let image = LoadedImage::from_shellcode_at(&bytes, Architecture::X64, 0x1000);
        assert_eq!(version_string(&image, pclntab::Layout::Go12), None);
    }
}
