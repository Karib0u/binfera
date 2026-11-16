//! Render counted Go strings without NUL scans or global address-only typing.
use super::stack_strings::literal;
use crate::extract::image::{ImageFormat, LoadedImage};
use std::collections::BTreeMap;

/// A byte range of the text.
type Span = (usize, usize);

pub(super) struct Strings {
    word: u32,
    regions: Vec<(u64, Vec<u8>)>,
}
impl Strings {
    pub(super) fn new(image: &LoadedImage, code_end: Option<u64>) -> Self {
        Self {
            word: image.architecture.pointer_width() as u32,
            // Mach-O maps whole segments, and Go keeps its string data in `__TEXT,__rodata`.
            regions: image
                .sections
                .iter()
                .filter(|s| {
                    s.permissions.read
                        && !s.permissions.write
                        && (!s.permissions.execute
                            || image.format == ImageFormat::Macho
                            || (image.format == ImageFormat::Pe && code_end.is_some()))
                })
                .filter_map(|s| {
                    // Old Go PE files place rodata after their function table's
                    // code extent, inside executable .text. Keep code excluded.
                    let start = if s.permissions.execute && image.format == ImageFormat::Pe {
                        s.address.max(code_end?)
                    } else {
                        s.address
                    };
                    let size = s.file_size.checked_sub(start.checked_sub(s.address)?)?;
                    image
                        .bytes_at(start, usize::try_from(size).ok()?)
                        .map(|bytes| (start, bytes.to_vec()))
                })
                .collect(),
        }
    }
    fn read(&self, address: u64, length: u64) -> Option<String> {
        if length > 4096 {
            return None;
        }
        if length == 0 {
            return Some("\"\"".into());
        }
        self.regions.iter().find_map(|(base, data)| {
            let start = usize::try_from(address.checked_sub(*base)?).ok()?;
            let end = start.checked_add(usize::try_from(length).ok()?)?;
            Some(literal(data.get(start..end)?))
        })
    }
    /// Bytes at `address` that read as text of exactly `length` bytes: UTF-8 without control
    /// characters other than tab and line breaks. Untyped pairs are only believed then.
    fn read_text(&self, address: u64, length: u64) -> Option<String> {
        if length == 0 || length > 4096 {
            return None;
        }
        self.regions.iter().find_map(|(base, data)| {
            let start = usize::try_from(address.checked_sub(*base)?).ok()?;
            let bytes = data.get(start..start.checked_add(usize::try_from(length).ok()?)?)?;
            let text = std::str::from_utf8(bytes).ok()?;
            text.chars()
                .all(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
                .then(|| literal(bytes))
        })
    }

    /// `(pointer, length)` pairs the decompiler did not type as Go strings: in a garbled build,
    /// before the register ABI or on arm64, a string is passed as two adjacent arguments, or
    /// stored as two consecutive words (`*p = &DAT_…; p[1] = 3;`). The pointer is replaced by
    /// the literal when the bytes read as text of exactly that length.
    pub(super) fn render_untyped(&self, text: &str) -> String {
        let text = self.render_arguments(text);
        self.render_stores(&text)
    }

    fn render_arguments(&self, text: &str) -> String {
        let masked = super::unit::mask_literals(text);
        let bytes = masked.as_bytes();
        // Open parentheses: whether a call opens it, where its current argument starts, and the
        // byte spans of its arguments so far.
        let mut frames: Vec<(bool, usize, Vec<Span>)> = Vec::new();
        let mut replacements = Vec::new();
        for (at, &byte) in bytes.iter().enumerate() {
            match byte {
                b'(' => {
                    // Long qualified names wrap before their argument list.
                    let prefix = masked[..at].trim_end();
                    let word = prefix
                        .rsplit(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                        .next()
                        .unwrap_or("");
                    let call = !word.is_empty()
                        && !matches!(word, "if" | "while" | "for" | "switch" | "sizeof");
                    frames.push((call, at + 1, Vec::new()));
                }
                b',' => {
                    if let Some((_, start, args)) = frames.last_mut() {
                        args.push((*start, at));
                        *start = at + 1;
                    }
                }
                b')' => {
                    let Some((call, start, mut args)) = frames.pop() else {
                        continue;
                    };
                    if !call {
                        continue;
                    }
                    args.push((start, at));
                    for pair in args.windows(2) {
                        let (pointer_at, length_at) = (pair[0], pair[1]);
                        let argument = text[pointer_at.0..pointer_at.1].trim();
                        let Some(address) = untyped_pointer(argument) else {
                            continue;
                        };
                        let Some(value) = number(text[length_at.0..length_at.1].trim())
                            .and_then(|length| self.read_text(address, length))
                        else {
                            continue;
                        };
                        let lead = text[pointer_at.0..pointer_at.1].len()
                            - text[pointer_at.0..pointer_at.1].trim_start().len();
                        let start = pointer_at.0 + lead;
                        replacements.push((start, start + argument.len(), value));
                    }
                }
                _ => {}
            }
        }
        apply(text, replacements)
    }

    fn render_stores(&self, text: &str) -> String {
        let masked = super::unit::mask_literals(text);
        let lines: Vec<&str> = text.lines().collect();
        let masked: Vec<&str> = masked.lines().collect();
        let stores: Vec<Option<(Slot, &str)>> = lines
            .iter()
            .zip(&masked)
            .map(|(line, masked)| {
                // A plain store: no literal, comment or call on the line.
                if masked.trim() != line.trim() {
                    return None;
                }
                let (lhs, rhs) = line.trim().strip_suffix(';')?.split_once(" = ")?;
                Some((slot(lhs, self.word)?, rhs))
            })
            .collect();
        let mut out: Vec<String> = lines.iter().map(|l| (*l).to_owned()).collect();
        for (index, store) in stores.iter().enumerate() {
            let Some((pointer_slot, rhs)) = store else {
                continue;
            };
            let Some(address) = untyped_pointer(rhs) else {
                continue;
            };
            // The length is stored within a few lines on either side, in the same run of stores.
            let near = |step: isize| {
                (1..=4)
                    .map(move |distance| index as isize + step * distance)
                    .take_while(|at| {
                        *at >= 0 && stores.get(*at as usize).is_some_and(Option::is_some)
                    })
                    .filter_map(|at| stores[at as usize].as_ref())
            };
            let length = near(1).chain(near(-1)).find_map(|(slot, value)| {
                (slot.base == pointer_slot.base
                    && slot.offset == pointer_slot.offset + i64::from(self.word))
                .then(|| number(value))
                .flatten()
            });
            if let Some(value) = length.and_then(|length| self.read_text(address, length)) {
                if let Some((lhs, _)) = out[index].split_once(" = ") {
                    out[index] = format!("{lhs} = {value};");
                }
            }
        }
        let mut result = out.join("\n");
        if text.ends_with('\n') {
            result.push('\n');
        }
        result
    }

    pub(super) fn render(&self, text: &str) -> String {
        let trailing_newline = text.ends_with('\n');
        let masked = super::unit::mask_literals(text);
        let mask_lines: Vec<_> = masked.lines().collect();
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        let mut index = 0;
        while index < lines.len() {
            let start = index;
            let mut pointers = BTreeMap::new();
            let mut lengths = BTreeMap::new();
            while let Some(line) = lines.get(index) {
                if mask_lines
                    .get(index)
                    .is_none_or(|line| line.trim().is_empty())
                {
                    break;
                }
                let Some((lhs, rhs)) = line
                    .trim()
                    .strip_suffix(';')
                    .and_then(|l| l.split_once(" = "))
                else {
                    break;
                };
                if let Some(name) = lhs.strip_suffix(".str") {
                    if pointers.contains_key(name) {
                        break;
                    }
                    let Some(address) = pointer(rhs) else { break };
                    pointers.insert(name.to_string(), (index, address));
                } else if let Some(name) = lhs.strip_suffix(".len") {
                    if lengths.contains_key(name) {
                        break;
                    }
                    let Some(length) = number(rhs) else { break };
                    lengths.insert(name.to_string(), length);
                } else {
                    break;
                }
                index += 1;
            }
            for (name, (at, address)) in pointers {
                if let Some(value) = lengths
                    .get(&name)
                    .and_then(|&length| self.read(address, length))
                {
                    if let Some((lhs, _)) = lines[at].split_once(" = ") {
                        lines[at] = format!("{lhs} = (uint8 *){value};");
                    }
                }
            }
            if index == start {
                index += 1;
            }
        }
        let text = lines.join("\n");
        // On 386 the entire descriptor fits in one integer; on amd64 it can
        // be printed as a 128-bit constant. The low word is the pointer.
        let mut result = String::new();
        let masked = super::unit::mask_literals(&text);
        let mut consumed = 0;
        let mut rest = text.as_str();
        let marker = "(string)0x";
        while let Some(at) = masked[consumed..].find(marker) {
            result.push_str(&rest[..at]);
            rest = &rest[at..];
            let count = rest[marker.len()..]
                .bytes()
                .take_while(u8::is_ascii_hexdigit)
                .count();
            let end = marker.len() + count;
            let value = u128::from_str_radix(&rest[marker.len()..end], 16).ok();
            let bits = self.word * 8;
            let rendered = value.and_then(|value| {
                let address = (value & ((1u128 << bits) - 1)) as u64;
                let length = u64::try_from(value >> bits).ok()?;
                self.read(address, length)
                    .map(|s| format!("(string){{(uint8 *){s},{length}}}"))
            });
            result.push_str(rendered.as_deref().unwrap_or(&rest[..end]));
            rest = &rest[end..];
            consumed = text.len() - rest.len();
        }
        result.push_str(rest);
        if trailing_newline {
            result.push('\n');
        }
        result
    }
}
/// A store target as a base and a byte offset: `*p` and `p[k]` (words), `*(T *)(p + 0x10)`, and
/// stack slots `local_14`, `uStack_10` (below the frame) or `in_stack_00000008` (above it).
#[derive(PartialEq, Eq)]
struct Slot {
    base: String,
    offset: i64,
}

fn slot(lhs: &str, word: u32) -> Option<Slot> {
    let word = i64::from(word);
    let identifier = |s: &str| {
        !s.is_empty()
            && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && !s.as_bytes()[0].is_ascii_digit()
    };
    let make = |base: &str, offset: i64| {
        identifier(base).then(|| Slot {
            base: base.to_owned(),
            offset,
        })
    };
    if let Some(rest) = lhs.strip_prefix('*') {
        // `*(T *)(p + 0x10)`, `*(T *)p` or `*p`.
        let rest = match rest.strip_prefix('(') {
            Some(cast) => cast.split_once(')')?.1,
            None => rest,
        };
        if let Some(inner) = rest.strip_prefix('(').and_then(|r| r.strip_suffix(')')) {
            let (base, offset) = inner.split_once(" + ")?;
            return make(base, i64::try_from(number(offset)?).ok()?);
        }
        return make(rest, 0);
    }
    if let Some((base, index)) = lhs.strip_suffix(']').and_then(|l| l.split_once('[')) {
        return make(base, i64::try_from(number(index)?).ok()?.checked_mul(word)?);
    }
    let hex = |s: &str| i64::from_str_radix(s, 16).ok();
    if let Some(offset) = lhs.strip_prefix("in_stack_") {
        return Some(Slot {
            base: "in_stack".into(),
            offset: hex(offset)?,
        });
    }
    let (prefix, offset) = lhs.rsplit_once('_')?;
    (prefix == "local" || prefix.ends_with("Stack")).then_some(Slot {
        base: "stack".into(),
        offset: -hex(offset)?,
    })
}

/// A pointer argument or value: `&DAT_004845b8`, `&s_…_004845b8`, `(char *)0x4845b8`,
/// `(uint8 *)(s_… + 0x5)` or a bare hexadecimal address.
fn untyped_pointer(s: &str) -> Option<u64> {
    let mut s = s.trim();
    // Drop leading casts such as `(char *)` or `(undefined *)`.
    while let Some(rest) = s.strip_prefix('(') {
        let (cast, after) = rest.split_once(')')?;
        if !cast.ends_with('*') {
            break;
        }
        s = after.trim_start();
    }
    if !(s.starts_with('&') || s.starts_with("0x") || s.starts_with('(') || s.starts_with("s_")) {
        return None;
    }
    pointer(s)
}

fn apply(text: &str, mut replacements: Vec<(usize, usize, String)>) -> String {
    replacements.sort_by_key(|(start, _, _)| std::cmp::Reverse(*start));
    let mut text = text.to_owned();
    let mut limit = usize::MAX;
    for (start, end, value) in replacements {
        if end <= limit {
            text.replace_range(start..end, &value);
            limit = start;
        }
    }
    text
}

fn number(s: &str) -> Option<u64> {
    s.strip_prefix("0x")
        .map_or_else(|| s.parse().ok(), |s| u64::from_str_radix(s, 16).ok())
}
fn pointer(s: &str) -> Option<u64> {
    let s = s.strip_prefix("(uint8 *)").unwrap_or(s).trim();
    let s = s
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(s);
    let (base, offset) = s
        .split_once(" + ")
        .map_or(Some((s, 0)), |(base, offset)| Some((base, number(offset)?)))?;
    let base = base.trim_start_matches('&');
    let address = number(base).or_else(|| {
        if !base.starts_with("s_") && !base.starts_with("DAT_") {
            return None;
        }
        u64::from_str_radix(base.rsplit_once('_')?.1, 16).ok()
    })?;
    address.checked_add(offset)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pe_rodata_after_go_code_is_read_without_including_instructions() {
        use crate::extract::image::Architecture;
        let mut image = LoadedImage::from_shellcode(b"CODEhello", Architecture::X64);
        image.format = ImageFormat::Pe;
        image.sections[0].permissions.write = false;
        let base = image.sections[0].address;
        let strings = Strings::new(&image, Some(base + 4));
        assert_eq!(strings.read(base, 4), None);
        assert_eq!(strings.read_text(base + 4, 5).as_deref(), Some("\"hello\""));
        assert!(Strings::new(&image, None).regions.is_empty());
    }

    #[test]
    fn exact_lengths_overlapping_literals_and_embedded_nuls() {
        let strings = Strings {
            word: 4,
            regions: vec![(0x1000, b"helloworld\0!".to_vec())],
        };
        let text = "  a[0].str = (uint8 *)0x1000;\n  a[1].str = (uint8 *)(s_hello_00001000 + 0x5);\n  a[0].len = 5;\n  a[1].len = 7;\n  f((string)0x500001000);\n";
        let result = strings.render(text);
        assert!(result.contains("(uint8 *)\"hello\";"));
        assert!(result.contains("(uint8 *)\"world\\0!\";"));
        assert!(result.contains("(string){(uint8 *)\"hello\",5}"));
        assert_eq!(strings.read(0x1000, 13), None);
    }
    #[test]
    fn calls_and_reassignments_break_pairing() {
        let strings = Strings {
            word: 8,
            regions: vec![(0x1000, b"hello".to_vec())],
        };
        for text in [
            "  a.str = (uint8 *)0x1000;\n  f();\n  a.len = 5;\n",
            "  a.str = (uint8 *)0x1000;\n  a.str = (uint8 *)0x2000;\n  a.len = 5;\n",
        ] {
            assert_eq!(strings.render(text), text);
        }
        assert!(strings
            .render("f((string)0x50000000000001000);\n")
            .contains("\"hello\""));
    }
    #[test]
    fn untyped_pairs_in_arguments_and_consecutive_stores() {
        let strings = Strings {
            word: 4,
            regions: vec![(0x4845b8, b"adxaesavx\x01\x02".to_vec())],
        };
        let text = "  f(&DAT_004845b8,3);\n  *puVar4 = &DAT_004845bb;\n  puVar4[1] = 3;\n  \
                    *(undefined4 *)(iVar1 + 8) = (char *)0x4845be;\n  \
                    *(undefined4 *)(iVar1 + 0xc) = 3;\n  local_14 = &DAT_004845b8;\n  \
                    local_10 = 6;\n";
        let result = strings.render_untyped(text);
        assert!(result.contains("f(\"adx\",3);"), "{result}");
        assert_eq!(
            strings.render_untyped("long.qualified.call\n    (&DAT_004845b8,3);"),
            "long.qualified.call\n    (\"adx\",3);"
        );
        assert!(result.contains("*puVar4 = \"aes\";"), "{result}");
        assert!(
            result.contains("*(undefined4 *)(iVar1 + 8) = \"avx\";"),
            "{result}"
        );
        assert!(result.contains("local_14 = \"adxaes\";"), "{result}");
        // The wrong word, a non-text byte, or a length that runs past the data: unchanged.
        for text in [
            "  *p = &DAT_004845b8;\n  p[2] = 3;\n",
            "  f(&DAT_004845b8,10);\n",
            "  f(&DAT_004845b8,64);\n",
            "  f(g,&DAT_004845b8);\n",
        ] {
            assert_eq!(strings.render_untyped(text), text);
        }
    }

    #[test]
    fn string_markers_in_literals_and_comments_are_unchanged() {
        let strings = Strings {
            word: 4,
            regions: vec![(0x1000, b"hello".to_vec())],
        };
        let text = "puts(\"(string)0x500001000\");\n/* (string)0x500001000 */\n/*\na.str = (uint8 *)0x1000;\na.len = 5;\n*/\n";
        assert_eq!(strings.render(text), text);
    }
}
