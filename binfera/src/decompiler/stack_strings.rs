//! Coalesce adjacent constant writes within one declared byte array. Never join
//! separate locals, cross control flow, or change the number of bytes written.
use std::collections::BTreeMap;

pub(super) fn literal(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    for (index, &byte) in bytes.iter().enumerate() {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            // `\0` would absorb a following octal digit; spell it out then.
            0 if !matches!(bytes.get(index + 1), Some(b'0'..=b'7')) => out.push_str("\\0"),
            32..=126 => out.push(char::from(byte)),
            _ => out.push_str(&format!("\\{byte:03o}")),
        }
    }
    out.push('"');
    out
}

fn number(text: &str) -> Option<usize> {
    match text.strip_prefix("0x") {
        Some(hex) => usize::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

fn byte(text: &str) -> Option<u8> {
    if let Some(s) = text.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        return match s.as_bytes() {
            [b] => Some(*b),
            b"\\0" => Some(0),
            b"\\n" => Some(b'\n'),
            b"\\r" => Some(b'\r'),
            b"\\t" => Some(b'\t'),
            b"\\\\" => Some(b'\\'),
            b"\\'" => Some(b'\''),
            [b'\\', b'x', ..] => u8::from_str_radix(&s[2..], 16).ok(),
            _ => None,
        };
    }
    if let Some(negative) = text.strip_prefix('-') {
        let magnitude = number(negative)?;
        return (magnitude <= 128).then_some((0u8).wrapping_sub(magnitude as u8));
    }
    u8::try_from(number(text)?).ok()
}

fn store<'a>(
    line: &'a str,
    arrays: &BTreeMap<&str, usize>,
) -> Option<(&'a str, &'a str, usize, u8)> {
    let trimmed = line.trim_start();
    let indent = line.get(..line.len() - trimmed.len())?;
    let (lhs, rhs) = trimmed.strip_suffix(';')?.split_once(" = ")?;
    let (name, offset) = lhs.strip_suffix(']')?.split_once('[')?;
    let offset = number(offset)?;
    (offset < *arrays.get(name)?).then_some((indent, name, offset, byte(rhs)?))
}

pub(super) fn render(text: &str, addresses: &mut Vec<Vec<u64>>) -> String {
    let lines: Vec<_> = text.split('\n').collect();
    let arrays: BTreeMap<_, _> = lines
        .iter()
        .filter_map(|line| {
            let decl = line.trim().strip_suffix(';')?;
            let (ty, rest) = decl.split_once(' ')?;
            if !matches!(
                ty,
                "uint1"
                    | "int1"
                    | "xunknown1"
                    | "undefined1"
                    | "char"
                    | "CHAR"
                    | "BYTE"
                    | "uint8"
                    | "int8"
            ) {
                return None;
            }
            // int8/uint8 are eight-byte native types, but one-byte Go types. Do not
            // guess which spelling a session uses.
            if matches!(ty, "uint8" | "int8") {
                return None;
            }
            let (name, count) = rest.strip_suffix(']')?.split_once(" [")?;
            if !name.contains("Stack_") {
                return None;
            }
            Some((name, number(count)?))
        })
        .collect();
    let mapped = addresses.len() == lines.len();
    let mut output = Vec::new();
    let mut mappings = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        let start = index;
        let mut replacement = None;
        if let Some((indent, name, first, value)) = store(lines[index], &arrays) {
            let mut bytes = vec![value];
            while let Some((next_indent, next_name, offset, value)) = lines
                .get(start + bytes.len())
                .and_then(|line| store(line, &arrays))
            {
                if next_indent != indent
                    || next_name != name
                    || offset != first + bytes.len()
                    || bytes.len() >= 4096
                {
                    break;
                }
                bytes.push(value);
            }
            if bytes.len() >= 4 {
                let destination = if first == 0 {
                    name.to_string()
                } else {
                    format!("{name} + {first:#x}")
                };
                // The explicit size excludes the literal's synthetic terminator.
                replacement = Some(format!(
                    "{indent}builtin_memcpy({destination},{},{});",
                    literal(&bytes),
                    bytes.len()
                ));
                index += bytes.len();
            }
        }
        if let Some(line) = replacement {
            output.push(line);
        } else {
            output.push(lines[index].to_string());
            index += 1;
        }
        if mapped {
            let mut merged: Vec<_> = addresses[start..index].iter().flatten().copied().collect();
            merged.sort_unstable();
            merged.dedup();
            mappings.push(merged);
        }
    }
    if mapped {
        *addresses = mappings;
    }
    output.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn copy_preserves_bytes_and_source_mapping() {
        let text = "  uint1 auStack_10 [8];\n  auStack_10[1] = 0;\n  auStack_10[2] = 0x41;\n  auStack_10[3] = 0x22;\n  auStack_10[4] = 0xff;\n";
        let mut lines = vec![vec![], vec![1], vec![2], vec![3], vec![4], vec![]];
        assert_eq!(
            render(text, &mut lines),
            "  uint1 auStack_10 [8];\n  builtin_memcpy(auStack_10 + 0x1,\"\\0A\\\"\\377\",4);\n"
        );
        assert_eq!(lines, vec![vec![], vec![1, 2, 3, 4], vec![]]);
    }
    #[test]
    fn c_escapes_keep_every_byte_unambiguous() {
        assert_eq!(literal(b"a\r\n\tb"), "\"a\\r\\n\\tb\"");
        // A NUL before an octal digit keeps all three digits, otherwise `\01` would be one byte.
        assert_eq!(literal(b"\x001\x00x\x00"), "\"\\0001\\0x\\0\"");
    }
    #[test]
    fn never_crosses_calls_gaps_array_bounds_or_wide_elements() {
        for text in [
            "  uint1 auStack_10 [3];\n  auStack_10[0] = 1;\n  auStack_10[1] = 2;\n  auStack_10[2] = 3;\n  auStack_10[3] = 4;\n",
            "  uint4 auStack_10 [4];\n  auStack_10[0] = 1;\n  auStack_10[1] = 2;\n  auStack_10[2] = 3;\n  auStack_10[3] = 4;\n",
            "  uint1 auStack_10 [8];\n  auStack_10[0] = 1;\n  call();\n  auStack_10[1] = 2;\n  auStack_10[2] = 3;\n  auStack_10[4] = 4;\n",
        ] { assert_eq!(render(text, &mut vec![]), text); }
    }
}
