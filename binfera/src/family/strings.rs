//! Deterministic string normalization and hashing shared by `BXFAM003` packs and the matcher.
//!
//! String Reuse is supporting evidence only. It never changes code attribution: see
//! [`StringOriginReport`](super::StringOriginReport).

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::extract::features::strings::{extract_ascii_strings, extract_unicode_strings};

/// Shortest normalized string (in characters) that takes part in String Reuse.
pub const MIN_ORIGIN_STRING_CHARS: usize = 8;
/// Most distinct strings taken from one sample, which bounds matching time and memory.
pub const MAX_SAMPLE_STRINGS: usize = 200_000;

/// How a string was stored in the binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringEncoding {
    Ascii,
    Utf16le,
}

/// A normalized, hashed string extracted from a sample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OriginString {
    /// Output of [`normalize_origin_string`].
    pub value: String,
    /// [`origin_string_hash`] of `value`.
    pub hash: u64,
    pub encoding: StringEncoding,
    /// File offset of the first occurrence.
    pub offset: u64,
}

/// Normalizes an extracted string for String Reuse, or returns `None` when it carries no
/// attribution value.
///
/// The rules are part of the `BXFAM003` contract, so pack builders and the matcher must agree:
///
/// 1. Runs of Unicode whitespace collapse to one ASCII space, and the ends are trimmed.
///    Case is preserved.
/// 2. Strings containing other control characters are rejected.
/// 3. At least [`MIN_ORIGIN_STRING_CHARS`] characters and 4 distinct characters remain.
/// 4. At least one letter is present (rejects numbers, dates, and punctuation runs).
/// 5. Pure hexadecimal (optionally `0x`-prefixed), UUIDs, GUIDs, MAC addresses, and other
///    hex-and-separator runs that contain a digit are rejected.
/// 6. Generic boilerplate is rejected: DOS stubs, compiler/runtime messages, manifests, system
///    DLL names, mangled symbols, compiler-reserved `_identifiers`, and common Win32 API names.
pub fn normalize_origin_string(raw: &str) -> Option<String> {
    if raw.chars().any(|c| c.is_control() && !c.is_whitespace()) {
        return None;
    }
    let mut value = String::with_capacity(raw.len());
    for word in raw.split_whitespace() {
        if !value.is_empty() {
            value.push(' ');
        }
        value.push_str(word);
    }
    if value.chars().count() < MIN_ORIGIN_STRING_CHARS {
        return None;
    }
    if !value.chars().any(char::is_alphabetic) {
        return None;
    }
    let distinct: HashSet<char> = value.chars().take(64).collect();
    if distinct.len() < 4 {
        return None;
    }
    if is_hex_like(&value) || is_boilerplate(&value) {
        return None;
    }
    Some(value)
}

/// 64-bit hash of a normalized string: FNV-1a over a domain tag and the UTF-8 bytes, finished
/// with the SplitMix64 mixer. Part of the `BXFAM003` contract.
pub fn origin_string_hash(normalized: &str) -> u64 {
    let mut h = super::fnv1a_step(super::FNV_OFFSET, b"bxfam-str\0");
    h = super::fnv1a_step(h, normalized.as_bytes());
    h = (h ^ (h >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    h = (h ^ (h >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    h ^ (h >> 31)
}

/// Extracts ASCII and UTF-16LE strings from raw file bytes, normalizes them with
/// [`normalize_origin_string`], and deduplicates by hash, keeping the first occurrence.
pub fn extract_origin_strings(bytes: &[u8]) -> Vec<OriginString> {
    let mut raw: Vec<(usize, String, StringEncoding)> =
        extract_ascii_strings(bytes, MIN_ORIGIN_STRING_CHARS)
            .into_iter()
            .map(|s| (s.offset, s.s, StringEncoding::Ascii))
            .chain(
                extract_unicode_strings(bytes, MIN_ORIGIN_STRING_CHARS)
                    .into_iter()
                    .map(|s| (s.offset, s.s, StringEncoding::Utf16le)),
            )
            .collect();
    raw.sort_by_key(|(offset, _, _)| *offset);
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (offset, s, encoding) in raw {
        if out.len() >= MAX_SAMPLE_STRINGS {
            break;
        }
        let Some(value) = normalize_origin_string(&s) else {
            continue;
        };
        let hash = origin_string_hash(&value);
        if seen.insert(hash) {
            out.push(OriginString {
                value,
                hash,
                encoding,
                offset: offset as u64,
            });
        }
    }
    out
}

fn is_hex_like(value: &str) -> bool {
    let body = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if !body.is_empty() && body.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    value.chars().any(|c| c.is_ascii_digit())
        && value
            .chars()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, '-' | ':' | '{' | '}' | ' ' | ','))
}

/// Lowercase exact strings that appear in many unrelated binaries.
const BOILERPLATE: &[&str] = &[
    "microsoft visual c++ runtime library",
    "<program name unknown>",
    "runtime error!",
    "bad allocation",
    "bad array new length",
    "unknown exception",
    "string too long",
    "invalid string position",
    "vector too long",
    "map/set too long",
    "deque<t> too long",
    "list<t> too long",
    "invalid argument",
    "generic error",
    "iostream stream error",
    "bad exception",
    "bad function call",
    "bad cast",
    "permission denied",
    "no such file or directory",
    "resource temporarily unavailable",
    "operation not permitted",
    "not enough space",
    "result too large",
    "illegal byte sequence",
    "unknown pseudo relocation protocol version %d.",
    "unknown pseudo relocation bit size %d.",
    "argument domain error (domain)",
    "argument singularity (sign)",
    "overflow range error (overflow)",
    "the result is too small to be represented (underflow)",
    "total loss of significance (tloss)",
    "partial loss of significance (ploss)",
    "_matherr(): %s in %s(%g, %g) (retval=%g)",
    "mingw-w64 runtime failure:",
    "address %p has no image-section",
    "virtualquery failed for %d bytes at address %p",
    "virtualprotect failed with code 0x%x",
    "microsoft.windows.common-controls",
    "urn:schemas-microsoft-com:asm.v1",
    "urn:schemas-microsoft-com:asm.v3",
    "requestedexecutionlevel",
    "requestedprivileges",
    "6595b64144ccf1df",
    "stringfileinfo",
    "varfileinfo",
    "translation",
    "companyname",
    "filedescription",
    "fileversion",
    "internalname",
    "legalcopyright",
    "originalfilename",
    "productname",
    "productversion",
    "vs_version_info",
    "january",
    "february",
    "september",
    "november",
    "december",
    "wednesday",
    "thursday",
    "saturday",
];

/// Lowercase prefixes of boilerplate lines.
const BOILERPLATE_PREFIXES: &[&str] = &[
    "!this program cannot be run in dos mode",
    "this program cannot be run in dos mode",
    "this program must be run under win32",
    "index out of bounds: the len is",
    "called `option::unwrap()` on a `none` value",
    "called `result::unwrap()` on an `err` value",
    "attempt to add with overflow",
    "attempt to subtract with overflow",
    "attempt to multiply with overflow",
    "attempt to divide by zero",
    "<assembly xmlns",
    "<?xml version=",
    "<trustinfo xmlns",
    "<requestedexecutionlevel",
    "<security>",
    "<application xmlns",
    "<supportedos id=",
    "<compatibility xmlns",
    "<dependentassembly>",
    "<assemblyidentity ",
    "</assembly>",
    "</trustinfo>",
    "gcc: (gnu)",
    "gcc: (",
    "api-ms-win-",
    "ext-ms-win-",
    "go build id",
    "go.buildid",
    "rust_panic",
    "rustc version",
];

/// Lowercase system DLL names.
const SYSTEM_DLLS: &[&str] = &[
    "advapi32",
    "bcrypt",
    "comctl32",
    "comdlg32",
    "crypt32",
    "dbghelp",
    "gdi32",
    "gdiplus",
    "imm32",
    "iphlpapi",
    "kernel32",
    "kernelbase",
    "msvcp140",
    "msvcrt",
    "mscoree",
    "mswsock",
    "netapi32",
    "ntdll",
    "ole32",
    "oleaut32",
    "psapi",
    "rpcrt4",
    "secur32",
    "setupapi",
    "shell32",
    "shlwapi",
    "ucrtbase",
    "urlmon",
    "user32",
    "userenv",
    "uxtheme",
    "vcruntime140",
    "version",
    "winhttp",
    "wininet",
    "winmm",
    "winspool",
    "ws2_32",
    "wsock32",
    "wtsapi32",
];

/// Leading verbs of common Win32/NT API names, matched only on a whole CamelCase identifier
/// whose next character is uppercase (`GetProcAddress`, `RegOpenKeyExW`, `NtQueryInformation`).
const API_PREFIXES: &[&str] = &[
    "Add",
    "Adjust",
    "Alloc",
    "Attach",
    "Begin",
    "Bit",
    "Call",
    "Change",
    "Char",
    "Check",
    "Close",
    "Co",
    "Compare",
    "Connect",
    "Control",
    "Convert",
    "Copy",
    "Create",
    "Crypt",
    "Def",
    "Delete",
    "Destroy",
    "Device",
    "Disable",
    "Disconnect",
    "Dispatch",
    "Draw",
    "Duplicate",
    "Enable",
    "End",
    "Enter",
    "Enum",
    "Exit",
    "Expand",
    "File",
    "Find",
    "Flush",
    "Format",
    "Free",
    "Get",
    "Global",
    "Heap",
    "Http",
    "Init",
    "Initialize",
    "Interlocked",
    "Internet",
    "Is",
    "Leave",
    "Load",
    "Local",
    "Lock",
    "Lookup",
    "Map",
    "Message",
    "Module",
    "Move",
    "Multi",
    "Net",
    "Nt",
    "Ole",
    "Open",
    "Output",
    "Path",
    "Peek",
    "Post",
    "Process",
    "Query",
    "Raise",
    "Read",
    "Reg",
    "Register",
    "Release",
    "Remove",
    "Reset",
    "Resume",
    "Rtl",
    "Send",
    "Set",
    "Shell",
    "Show",
    "Sleep",
    "Start",
    "Str",
    "Suspend",
    "System",
    "Terminate",
    "Tls",
    "Translate",
    "Unhandled",
    "Unlock",
    "Unmap",
    "Unregister",
    "Update",
    "Virtual",
    "Wait",
    "Wide",
    "Win",
    "Write",
    "WSA",
    "Zw",
];

/// Code bytes that happen to be printable, such as the x86-64 register pushes and pops
/// `AWAVAUATVWSH` and `A_A^A]A\_^[]`: every byte in `0x40..=0x5f` with an opcode-run signature.
fn is_opcode_run(value: &str) -> bool {
    const SIGNATURES: &[&str] = &[
        "AWAV", "AVAU", "AUAT", "ATAU", "AVAW", "VWSH", "WVSH", "SVWH", "A^A_", "A_A^", "A]A\\",
        "A\\A]",
    ];
    value.bytes().all(|b| (0x40..=0x5f).contains(&b))
        && (value.bytes().any(|b| b"[\\]^".contains(&b))
            || SIGNATURES.iter().any(|sig| value.contains(sig)))
}

fn is_identifier(value: &str) -> bool {
    value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn is_api_name(value: &str) -> bool {
    if !is_identifier(value) || value.len() > 64 {
        return false;
    }
    API_PREFIXES.iter().any(|prefix| {
        value
            .strip_prefix(prefix)
            .and_then(|rest| rest.chars().next())
            .is_some_and(|c| c.is_ascii_uppercase())
    })
}

fn is_boilerplate(value: &str) -> bool {
    if is_opcode_run(value) {
        return true;
    }
    let lower = value.to_ascii_lowercase();
    if BOILERPLATE.contains(&lower.as_str())
        || BOILERPLATE_PREFIXES.iter().any(|p| lower.starts_with(p))
    {
        return true;
    }
    for ext in [".dll", ".drv", ".sys", ".ocx"] {
        if let Some(stem) = lower.strip_suffix(ext) {
            if SYSTEM_DLLS.contains(&stem) {
                return true;
            }
        }
    }
    if SYSTEM_DLLS.contains(&lower.as_str()) {
        return true;
    }
    // Compiler-reserved names (`_initterm`, `__getmainargs`) and mangled C++/Rust symbols.
    if value.starts_with('_') && is_identifier(value) {
        return true;
    }
    if (value.starts_with('?') && value.contains("@@"))
        || ((value.starts_with("_ZN") || value.starts_with("_R")) && !value.contains(' '))
    {
        return true;
    }
    is_api_name(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_whitespace_and_keeps_case() {
        assert_eq!(
            normalize_origin_string("  Global\\\\Mutex\t  QbotLoader \r\n").as_deref(),
            Some("Global\\\\Mutex QbotLoader")
        );
        assert_eq!(
            normalize_origin_string("hxxp://evil.example/gate.php").as_deref(),
            Some("hxxp://evil.example/gate.php")
        );
    }

    #[test]
    fn rejects_noise() {
        for raw in [
            "short",
            "12345678901",
            "0xDEADBEEFCAFE",
            "deadbeefcafebabe",
            "{3F2504E0-4F89-11D3-9A0C-0305E82C3301}",
            "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
            "00:1A:2B:3C:4D:5E",
            "AAAAAAAAAAAAAAAA",
            "abababababab",
            "==========",
            "2024-01-01 12:00:00",
            "!This program cannot be run in DOS mode.$",
            "UAWAVAUATVWSH",
            "X[_^A\\A]A^A_]H",
            "AWAVATVWSH",
            "index out of bounds: the len is 3",
            "KERNEL32.dll",
            "api-ms-win-crt-runtime-l1-1-0.dll",
            "GetProcAddress",
            "RegOpenKeyExW",
            "NtQueryInformationProcess",
            "VirtualAlloc",
            "__getmainargs",
            "?what@exception@std@@UEBAPEBDXZ",
            "Microsoft Visual C++ Runtime Library",
            "bad\u{0001}string here",
        ] {
            assert_eq!(normalize_origin_string(raw), None, "{raw}");
        }
    }

    #[test]
    fn keeps_distinctive_strings() {
        for raw in [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Bot/1.3",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "svchostt.exe",
            "Getaway driver",
            "cmd.exe /c del %s",
            "QBOT_MUTEX_NAME",
        ] {
            assert!(normalize_origin_string(raw).is_some(), "{raw}");
        }
    }

    #[test]
    fn hash_is_stable() {
        assert_eq!(
            origin_string_hash("hxxp://evil.example/gate.php"),
            origin_string_hash("hxxp://evil.example/gate.php")
        );
        assert_ne!(
            origin_string_hash("hxxp://evil.example/gate.php"),
            origin_string_hash("hxxp://evil.example/gate.PHP")
        );
        // Pinned value: the hash is part of the BXFAM003 contract.
        assert_eq!(origin_string_hash("BXFAM003 test"), PINNED_HASH);
    }

    const PINNED_HASH: u64 = 0x80a2_2cbb_0945_74e4;

    #[test]
    fn extracts_ascii_and_utf16_once() {
        let mut bytes = b"\0\0hxxp://evil.example/gate.php\0\0".to_vec();
        for c in "Global\\EvilMutex42".encode_utf16() {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        bytes.extend_from_slice(b"\0\0hxxp://evil.example/gate.php\0GetProcAddress\0");
        let strings = extract_origin_strings(&bytes);
        let values: Vec<_> = strings
            .iter()
            .map(|s| (s.value.as_str(), s.encoding))
            .collect();
        assert_eq!(
            values,
            [
                ("hxxp://evil.example/gate.php", StringEncoding::Ascii),
                ("Global\\EvilMutex42", StringEncoding::Utf16le),
            ]
        );
        assert_eq!(strings[0].offset, 2);
    }
}
