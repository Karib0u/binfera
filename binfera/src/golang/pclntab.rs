//! The Go function table (`pclntab`): every function's entry, extent, name and flags.
//!
//! Four layouts exist, told apart by the header's magic (Go's `runtime/symtab.go`,
//! Ghidra's `GoPcHeader` and `GoFuncData`):
//!
//! | Magic | Go | Function table | Name offsets from |
//! |---|---|---|---|
//! | `0xfffffffb` | 1.2 - 1.15 | `(entry uintptr, funcoff uintptr)` after the header | the table |
//! | `0xfffffffa` | 1.16 - 1.17 | the same, at `pclnOffset` | `funcnameOffset` |
//! | `0xfffffff0` | 1.18 - 1.19 | `(entryoff u32, funcoff u32)` from `textStart` | `funcnameOffset` |
//! | `0xfffffff1` | 1.20+ | as 1.18; `_func` gains `startLine` | `funcnameOffset` |
//!
//! The table sits in a read-only data section (`.gopclntab` in ELF, inside `.rdata` in PE); the
//! loader maps ELF segments rather than sections, so it is found by its header everywhere.
use super::{read_uint, GoVersion};
use crate::extract::image::{Architecture, LoadedImage};

/// A function as the Go linker recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoFunction {
    pub entry: u64,
    /// The next function's entry, or the table's end address for the last one.
    pub end: u64,
    /// The full Go name, `os.(*File).Write`, `main.main.func1`, `type:.eq.main.T`.
    pub name: String,
    /// Written in assembly (`funcFlag_ASM`, Go 1.18+): no Go signature applies.
    pub assembly: bool,
    /// Total incoming argument and result bytes (`_func.args`), None for unknown (-1).
    pub args_size: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    Go12,
    Go116,
    Go118,
    Go120,
}

impl Layout {
    fn from_magic(magic: u32) -> Option<Self> {
        match magic {
            0xffff_fffb => Some(Self::Go12),
            0xffff_fffa => Some(Self::Go116),
            0xffff_fff0 => Some(Self::Go118),
            0xffff_fff1 => Some(Self::Go120),
            _ => None,
        }
    }

    /// Whether a toolchain of this release writes this layout.
    pub fn written_by(self, version: GoVersion) -> bool {
        let next = match self {
            Self::Go12 => Some(GoVersion::new(1, 16, 0)),
            Self::Go116 => Some(GoVersion::new(1, 18, 0)),
            Self::Go118 => Some(GoVersion::new(1, 20, 0)),
            Self::Go120 => None,
        };
        version >= self.first_version() && next.is_none_or(|next| version < next)
    }

    /// The oldest toolchain that writes this layout.
    pub fn first_version(self) -> GoVersion {
        match self {
            Self::Go12 => GoVersion::new(1, 2, 0),
            Self::Go116 => GoVersion::new(1, 16, 0),
            Self::Go118 => GoVersion::new(1, 18, 0),
            Self::Go120 => GoVersion::new(1, 20, 0),
        }
    }
}

#[derive(Clone, Debug)]
pub struct FunctionTable {
    /// Where the header starts.
    pub address: u64,
    pub layout: Layout,
    pub pointer_size: usize,
    /// In entry order.
    pub functions: Vec<GoFunction>,
}

impl FunctionTable {
    /// `address` lies inside a function the table lists, past its entry: a branch target, a
    /// switch arm or a block after a call that does not return, never a function of its own.
    pub fn inside(&self, address: u64) -> bool {
        let index = self.functions.partition_point(|f| f.entry <= address);
        index
            .checked_sub(1)
            .and_then(|index| self.functions.get(index))
            .is_some_and(|f| f.entry < address && address < f.end)
    }
}

/// `funcFlag_ASM` in `_func.flag` (Go 1.18+).
const FLAG_ASM: u8 = 4;
/// A sanity bound on the number of functions; real binaries have tens of thousands.
const MAX_FUNCTIONS: u64 = 2_000_000;
const MAX_NAME: usize = 4096;
/// How many entries are checked before a candidate header is believed.
const VALIDATE: usize = 16;

/// The function table of `image`: the first header, in section order, whose first entries name
/// executable code with readable names.
pub fn find(image: &LoadedImage) -> Option<FunctionTable> {
    if !matches!(
        image.architecture,
        Architecture::X86 | Architecture::X64 | Architecture::AArch64
    ) {
        return None;
    }
    let pointer = image.architecture.pointer_width();
    for section in &image.sections {
        let Some(bytes) = image.bytes_at(section.address, usize::MAX) else {
            continue;
        };
        let mut offset = 0usize;
        while offset + 8 <= bytes.len() {
            // The header is pointer-aligned; check the magic's last byte before decoding.
            let candidate = bytes.get(offset..offset + 8)?;
            if candidate[0] & 0xf0 == 0xf0
                && candidate[1..4] == [0xff; 3]
                && candidate[4..6] == [0, 0]
                && candidate[7] as usize == pointer
            {
                let address = section.address + offset as u64;
                if let Some(table) = read(image, address, pointer) {
                    return Some(table);
                }
            }
            offset += pointer;
        }
    }
    find_without_magic(image, pointer)
}

/// Obfuscators overwrite the header's magic (MacSync's reads `0x7534109d`) and leave the rest of
/// the table intact, since the runtime itself only reads the fields after it. Headers of the
/// right shape outside code are tried with each layout, newest first; [`read`]'s validation of
/// the first entries decides.
fn find_without_magic(image: &LoadedImage, pointer: usize) -> Option<FunctionTable> {
    // Only Go images pay for the scan.
    let go_section = image.sections.iter().any(|s| s.name.ends_with("gopclntab"));
    if !go_section && build_id_function(image).is_none() && !has_build_info(image) {
        return None;
    }
    let quantum = quantum(image);
    for section in image.sections.iter().filter(|s| !s.permissions.execute) {
        let Some(bytes) = image.bytes_at(section.address, usize::MAX) else {
            continue;
        };
        let mut offset = 0usize;
        while offset + 8 <= bytes.len() {
            if bytes[offset + 4..offset + 8] == [0, 0, quantum, pointer as u8] {
                let address = section.address + offset as u64;
                for layout in [Layout::Go120, Layout::Go118, Layout::Go116, Layout::Go12] {
                    if let Some(table) = read_layout(image, address, pointer, layout) {
                        return Some(table);
                    }
                }
            }
            offset += pointer;
        }
    }
    None
}

/// `minLC`, the instruction size quantum for this architecture.
fn quantum(image: &LoadedImage) -> u8 {
    if image.architecture == crate::extract::image::Architecture::AArch64 {
        4
    } else {
        1
    }
}

/// Reads the table whose header is at `address`. `None` unless the header is well formed and its
/// first entries are plausible.
pub fn read(image: &LoadedImage, address: u64, pointer: usize) -> Option<FunctionTable> {
    let bytes = image.bytes_at(address, usize::MAX)?;
    let magic = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
    read_layout(image, address, pointer, Layout::from_magic(magic)?)
}

fn read_layout(
    image: &LoadedImage,
    address: u64,
    pointer: usize,
    layout: Layout,
) -> Option<FunctionTable> {
    let bytes = image.bytes_at(address, usize::MAX)?;
    if bytes.get(4..8)? != [0, 0, quantum(image), pointer as u8] {
        return None;
    }
    let word = |index: usize| -> Option<u64> {
        let at = 8 + index * pointer;
        read_uint(bytes.get(at..at + pointer)?)
    };
    let at = |offset: u64| usize::try_from(offset).ok();
    let count = word(0)?;
    if count == 0 || count > MAX_FUNCTIONS {
        return None;
    }
    let count = usize::try_from(count).ok()?;
    // (where the function table starts, where name offsets count from, the entry base)
    let (table, names, text) = match layout {
        Layout::Go12 => (8 + pointer, 0, 0),
        Layout::Go116 => (at(word(6)?)?, at(word(2)?)?, 0),
        Layout::Go118 | Layout::Go120 => (at(word(7)?)?, at(word(3)?)?, word(2)?),
    };
    let text = if text == 0 && matches!(layout, Layout::Go118 | Layout::Go120) {
        moduledata_text(image, address, pointer)?
    } else {
        text
    };
    // Entries are (entry, funcoff) words before 1.18 and u32 pairs after; one more entry (the end
    // address) follows the last function.
    let field = match layout {
        Layout::Go12 | Layout::Go116 => pointer,
        Layout::Go118 | Layout::Go120 => 4,
    };
    let entry_at = |index: usize| -> Option<(u64, usize)> {
        let at = table.checked_add(index.checked_mul(2 * field)?)?;
        let entry = read_uint(bytes.get(at..at + field)?)?;
        let entry = if field == 4 && text != 0 {
            text.checked_add(entry)?
        } else {
            entry
        };
        let funcoff = match bytes.get(at + field..at + 2 * field) {
            Some(raw) => usize::try_from(read_uint(raw)?).ok()?,
            None => 0,
        };
        Some((entry, funcoff))
    };
    // `_func`'s offsets are relative to the table for 1.2, and to the function table after.
    let func_base = match layout {
        Layout::Go12 => 0,
        _ => table,
    };
    let name_at = |funcoff: usize| -> Option<(String, bool)> {
        let func = func_base.checked_add(funcoff)?;
        // `_func` starts with the entry (a word, or a u32 from 1.18), then `nameoff int32`.
        let name_field = func + field;
        let nameoff = i32::from_le_bytes(bytes.get(name_field..name_field + 4)?.try_into().ok()?);
        let start = names.checked_add(usize::try_from(nameoff).ok()?)?;
        let raw = bytes.get(start..)?;
        let end = raw.iter().take(MAX_NAME).position(|b| *b == 0)?;
        let name = String::from_utf8_lossy(raw.get(..end)?).into_owned();
        // `_func.flag`: after entryoff, nameoff, args, deferreturn, pcsp, pcfile, pcln,
        // npcdata, cuOffset (nine u32), then startLine from 1.20, then funcID.
        let flag_at = match layout {
            Layout::Go118 => Some(func + 9 * 4 + 1),
            Layout::Go120 => Some(func + 10 * 4 + 1),
            _ => None,
        };
        let assembly = flag_at
            .and_then(|at| bytes.get(at))
            .is_some_and(|flag| flag & FLAG_ASM != 0);
        Some((name, assembly))
    };

    // A memory dump of a relocated image (a DLL loaded at another base) keeps the link-time
    // addresses. The `go:buildid` function's body is the build ID string; where that string
    // really is gives the displacement. It is the first function unless C code was linked in
    // ahead of the Go code (`-buildmode=c-shared`).
    let (first, _) = entry_at(0)?;
    let displacement = if image.is_executable_address(first) {
        0
    } else {
        let build_id = (0..count).find_map(|index| {
            let (entry, funcoff) = entry_at(index)?;
            let (name, _) = name_at(funcoff)?;
            (name == "go:buildid" || name == "go.buildid").then_some(entry)
        })?;
        build_id_function(image)?.wrapping_sub(build_id)
    };
    let entry_at = |index: usize| -> Option<(u64, usize)> {
        entry_at(index).map(|(entry, funcoff)| (entry.wrapping_add(displacement), funcoff))
    };
    let executable = |entry: u64| image.is_executable_address(entry);
    // Validate before reading everything: a stray magic in data is common enough.
    // Obfuscators blank some names (MacSync), so a minority of empty ones is accepted.
    let mut previous = 0;
    let mut blank = 0;
    for index in 0..count.min(VALIDATE) {
        let (entry, funcoff) = entry_at(index)?;
        if entry < previous || !executable(entry) {
            return None;
        }
        let (name, _) = name_at(funcoff)?;
        if name.is_empty() {
            blank += 1;
        } else if !name.bytes().all(|b| b.is_ascii_graphic() || b >= 0x80) {
            return None;
        }
        previous = entry;
    }
    if blank * 4 > count.min(VALIDATE) {
        return None;
    }
    let (end, _) = entry_at(count)?;
    let mut functions = Vec::with_capacity(count);
    for index in 0..count {
        let Some((entry, funcoff)) = entry_at(index) else {
            break;
        };
        let next = entry_at(index + 1).map_or(end, |(next, _)| next);
        let Some((mut name, assembly)) = name_at(funcoff) else {
            continue;
        };
        if name.is_empty() {
            name = format!("FUN_{entry:08x}");
        }
        if !executable(entry) {
            continue;
        }
        functions.push(GoFunction {
            entry,
            end: next.max(entry),
            name,
            assembly,
            args_size: func_base
                .checked_add(funcoff)
                .and_then(|at| at.checked_add(field)?.checked_add(4))
                .and_then(|at| bytes.get(at..at.checked_add(4)?))
                .and_then(|raw| <[u8; 4]>::try_from(raw).ok())
                .map(i32::from_le_bytes)
                .and_then(|size| u32::try_from(size).ok()),
        });
    }
    functions.sort_by_key(|function| function.entry);
    functions.dedup_by_key(|function| function.entry);
    Some(FunctionTable {
        address,
        layout,
        pointer_size: pointer,
        functions,
    })
}

/// Whether the `runtime/debug` build information marker is present.
fn has_build_info(image: &LoadedImage) -> bool {
    const MARKER: &[u8] = b"\xff Go buildinf:";
    image.sections.iter().any(|section| {
        image
            .bytes_at(section.address, usize::MAX)
            .is_some_and(|bytes| bytes.windows(MARKER.len()).any(|w| w == MARKER))
    })
}

/// The address of the `go:buildid` function: the first `\xff Go build ID: ` in executable memory.
fn build_id_function(image: &LoadedImage) -> Option<u64> {
    const MARKER: &[u8] = b"\xff Go build ID: ";
    image
        .sections
        .iter()
        .filter(|section| section.permissions.execute)
        .find_map(|section| {
            let bytes = image.bytes_at(section.address, usize::MAX)?;
            let at = bytes.windows(MARKER.len()).position(|w| w == MARKER)?;
            Some(section.address + at as u64)
        })
}

/// Go 1.18+ `runtime.moduledata`, whose first word points at the table header: its `text`
/// field, for a header whose own `textStart` is zero. Fields, in words: `pcHeader`, then six
/// slices (`funcnametab`, `cutab`, `filetab`, `pctab`, `pclntable`, `ftab`) of three words,
/// `findfunctab`, `minpc`, `maxpc`, `text`.
fn moduledata_text(image: &LoadedImage, header: u64, pointer: usize) -> Option<u64> {
    const TEXT_WORD: usize = 1 + 6 * 3 + 3;
    let needle = header.to_le_bytes();
    let needle = needle.get(..pointer)?;
    for section in &image.sections {
        if section.permissions.execute {
            continue;
        }
        let Some(bytes) = image.bytes_at(section.address, usize::MAX) else {
            continue;
        };
        let mut offset = 0;
        while offset + (TEXT_WORD + 1) * pointer <= bytes.len() {
            if bytes.get(offset..offset + pointer)? == needle {
                let at = offset + TEXT_WORD * pointer;
                let text = read_uint(bytes.get(at..at + pointer)?)?;
                if image.is_executable_address(text) {
                    return Some(text);
                }
            }
            offset += pointer;
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::extract::image::{Architecture, ImageFormat, MappedSection, Permissions};

    const TEXT: u64 = 0x401000;
    const DATA: u64 = 0x500000;

    fn image(architecture: Architecture, data: Vec<u8>) -> LoadedImage {
        image_with_text(architecture, vec![0xc3; 0x1000], data)
    }

    fn image_with_text(
        architecture: Architecture,
        mut bytes: Vec<u8>,
        data: Vec<u8>,
    ) -> LoadedImage {
        bytes.resize(0x1000, 0xc3);
        let size = data.len() as u64;
        bytes.extend(data);
        LoadedImage::for_test(
            ImageFormat::Pe,
            architecture,
            0x400000,
            vec![
                MappedSection {
                    name: ".text".into(),
                    address: TEXT,
                    virtual_size: 0x1000,
                    file_offset: 0,
                    file_size: 0x1000,
                    permissions: Permissions {
                        read: true,
                        write: false,
                        execute: true,
                    },
                },
                MappedSection {
                    name: ".rdata".into(),
                    address: DATA,
                    virtual_size: size,
                    file_offset: 0x1000,
                    file_size: size,
                    permissions: Permissions {
                        read: true,
                        write: false,
                        execute: false,
                    },
                },
            ],
            BTreeMap::new(),
            bytes,
        )
    }

    /// A Go 1.20 table: header, names, then the function table and two `_func` records.
    fn go120(pointer: usize, functions: &[(u32, &str, u8)]) -> Vec<u8> {
        let word = |value: u64| value.to_le_bytes()[..pointer].to_vec();
        let header_len = 8 + 8 * pointer;
        let mut names = Vec::new();
        let mut name_offsets = Vec::new();
        for (_, name, _) in functions {
            name_offsets.push(names.len() as i32);
            names.extend_from_slice(name.as_bytes());
            names.push(0);
        }
        let names_at = header_len;
        let table_at = names_at + names.len();
        let mut table = Vec::new();
        let table_len = (functions.len() * 2 + 1) * 4;
        let func_len = 10 * 4 + 4;
        for (index, (entry, _, _)) in functions.iter().enumerate() {
            table.extend_from_slice(&entry.to_le_bytes());
            table.extend_from_slice(&((table_len + index * func_len) as u32).to_le_bytes());
        }
        table.extend_from_slice(&0x100u32.to_le_bytes());
        for (index, (entry, _, flag)) in functions.iter().enumerate() {
            let mut func = vec![0u8; func_len];
            func[..4].copy_from_slice(&entry.to_le_bytes());
            func[4..8].copy_from_slice(&name_offsets[index].to_le_bytes());
            func[41] = *flag;
            table.extend(func);
        }
        let mut bytes = vec![0xf1, 0xff, 0xff, 0xff, 0, 0, 1, pointer as u8];
        bytes.extend(word(functions.len() as u64));
        bytes.extend(word(0)); // nfiles
        bytes.extend(word(TEXT)); // textStart
        bytes.extend(word(names_at as u64)); // funcnameOffset
        bytes.extend(word(0)); // cuOffset
        bytes.extend(word(0)); // filetabOffset
        bytes.extend(word(0)); // pctabOffset
        bytes.extend(word(table_at as u64)); // pclnOffset
        bytes.extend(names);
        bytes.extend(table);
        bytes
    }

    #[test]
    fn arm64_uses_four_byte_instruction_quantum() {
        let mut data = go120(
            8,
            &[(0x10, "main.main", 0), (0x40, "runtime.memmove", FLAG_ASM)],
        );
        assert!(find(&image(Architecture::AArch64, data.clone())).is_none());
        data[6] = 4;
        let binary = crate::golang::parse(&image(Architecture::AArch64, data.clone()))
            .expect("arm64 Go metadata");
        assert_eq!(binary.functions.functions.len(), 2);
        assert_eq!(binary.functions.functions[0].name, "main.main");
        assert!(find(&image(Architecture::X64, data)).is_none());
    }

    #[test]
    fn reads_a_go120_table() {
        for (architecture, pointer) in [(Architecture::X64, 8), (Architecture::X86, 4)] {
            let mut data = vec![0u8; 16];
            data.extend(go120(
                pointer,
                &[
                    (0x10, "main.main", 0),
                    (0x40, "os.(*File).Write", 0),
                    (0x80, "runtime.memmove", FLAG_ASM),
                ],
            ));
            let image = image(architecture, data);
            let table = find(&image).expect("table");
            assert_eq!(table.address, DATA + 16);
            assert_eq!(table.layout, Layout::Go120);
            let summary: Vec<_> = table
                .functions
                .iter()
                .map(|f| (f.entry, f.end, f.name.as_str(), f.assembly))
                .collect();
            assert_eq!(
                summary,
                [
                    (TEXT + 0x10, TEXT + 0x40, "main.main", false),
                    (TEXT + 0x40, TEXT + 0x80, "os.(*File).Write", false),
                    (TEXT + 0x80, TEXT + 0x100, "runtime.memmove", true),
                ]
            );
        }
    }

    #[test]
    fn rebases_a_relocated_dump_by_the_build_id() {
        // The table names a text start 0x10000 below where the code really is.
        let mut data = go120(8, &[(0x10, "go:buildid", 0), (0x40, "main.main", 0)]);
        data[8 + 2 * 8..8 + 3 * 8].copy_from_slice(&(TEXT - 0x10000).to_le_bytes());
        let mut text = vec![0xc3; 0x10];
        text.extend_from_slice(b"\xff Go build ID: \"x\"");
        let image = image_with_text(Architecture::X64, text, data);
        let table = find(&image).expect("table");
        assert_eq!(table.functions[0].entry, TEXT + 0x10);
        assert_eq!(table.functions[1].entry, TEXT + 0x40);
    }

    #[test]
    fn rejects_a_stray_magic() {
        // The header is well formed, but the entry lies outside executable memory.
        let mut data = go120(8, &[(0x10, "main.main", 0)]);
        data[8 + 2 * 8..8 + 3 * 8].copy_from_slice(&DATA.to_le_bytes());
        assert!(find(&image(Architecture::X64, data)).is_none());
        // A truncated header.
        assert!(find(&image(
            Architecture::X64,
            vec![0xf1, 0xff, 0xff, 0xff, 0, 0, 1, 8]
        ))
        .is_none());
    }

    #[test]
    fn reads_a_table_whose_magic_was_overwritten() {
        let mut data = go120(8, &[(0x10, "main.main", 0), (0x20, "main.f", 0)]);
        data[..4].copy_from_slice(&0x7534_109d_u32.to_le_bytes());
        // Without evidence of Go, a header of this shape is not looked for.
        assert!(find(&image(Architecture::X64, data.clone())).is_none());
        data.extend_from_slice(b"\xff Go buildinf:");
        let table = find(&image(Architecture::X64, data)).expect("table");
        assert_eq!(table.layout, Layout::Go120);
        let names: Vec<_> = table.functions.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["main.main", "main.f"]);
    }
}

#[cfg(test)]
mod argument_area_tests {
    use super::*;
    use crate::extract::image::{Architecture, LoadedImage};

    #[test]
    fn argument_area_is_signed_and_follows_the_layout_entry_width() {
        for (magic, pointer) in [
            (0xffff_fffbu32, 4usize),
            (0xffff_fffb, 8),
            (0xffff_fffa, 4),
            (0xffff_fffa, 8),
            (0xffff_fff0, 4),
            (0xffff_fff0, 8),
            (0xffff_fff1, 4),
            (0xffff_fff1, 8),
        ] {
            for args in [12i32, -1] {
                let mut bytes = vec![0; 0x1100];
                bytes[..4].copy_from_slice(&magic.to_le_bytes());
                bytes[6] = 1;
                bytes[7] = pointer as u8;
                let put = |bytes: &mut [u8], at: usize, width: usize, value: u64| {
                    bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
                };
                put(&mut bytes, 8, pointer, 1);
                let old = magic == 0xffff_fffb;
                let relative = matches!(magic, 0xffff_fff0 | 0xffff_fff1);
                let field = if relative { 4 } else { pointer };
                let table = if old { 8 + pointer } else { 0x80 };
                let record = if old { 0x100 } else { table + 0x40 };
                if !old {
                    put(
                        &mut bytes,
                        8 + if relative { 7 } else { 6 } * pointer,
                        pointer,
                        table as u64,
                    );
                    put(
                        &mut bytes,
                        8 + if relative { 3 } else { 2 } * pointer,
                        pointer,
                        0x200,
                    );
                }
                if relative {
                    put(&mut bytes, 8 + 2 * pointer, pointer, 0x1000);
                }
                put(&mut bytes, table, field, if relative { 0 } else { 0x1000 });
                put(
                    &mut bytes,
                    table + field,
                    field,
                    if old { 0x100 } else { 0x40 },
                );
                put(
                    &mut bytes,
                    table + field * 2,
                    field,
                    if relative { 1 } else { 0x1001 },
                );
                put(&mut bytes, record + field, 4, if old { 0x200 } else { 0 });
                bytes[record + field + 4..record + field + 8].copy_from_slice(&args.to_le_bytes());
                bytes[0x200..0x207].copy_from_slice(b"main.f\0");
                bytes[0x1000] = 0xc3;
                let image = LoadedImage::from_shellcode_at(
                    &bytes,
                    if pointer == 4 {
                        Architecture::X86
                    } else {
                        Architecture::X64
                    },
                    0,
                );
                let table = read(&image, 0, pointer);
                assert!(table.is_some(), "{magic:x} {pointer}");
                assert_eq!(
                    table.and_then(|t| t.functions.first().and_then(|f| f.args_size)),
                    u32::try_from(args).ok()
                );
            }
        }
    }
}
