//! Nim's C-backend module initializers. The spelling follows compiler/mangleutils.nim
//! and compiler/cgen.nim in Nim 1.6 and 2.2. No ABI or parameter types are encoded.

pub(super) fn demangle(raw: &str) -> Option<String> {
    let raw = raw.strip_prefix('@').unwrap_or(raw);
    let raw = match raw.rsplit_once('@') {
        Some((name, bytes)) if !bytes.is_empty() && bytes.bytes().all(|b| b.is_ascii_digit()) => {
            name
        }
        _ => raw,
    };
    let raw = raw.trim_start_matches('_');
    let (module, kind) = raw
        .strip_suffix("DatInit000")
        .map(|m| (m, "datinit"))
        .or_else(|| raw.strip_suffix("Init000").map(|m| (m, "init")))?;
    if module.is_empty()
        || !module
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return None;
    }
    let module = module.strip_suffix('_').unwrap_or(module);
    let name =
        if module.starts_with("atm") || module.starts_with("atp") || module.starts_with("atn") {
            let path = decode(module)?;
            let path = path.get(2..)?; // @m, @p and @n identify the source-path root.
            path.replace("@s", "/")
        } else {
            // Older releases name modules directly (stdlib_osInit000).
            module.strip_prefix("stdlib_").unwrap_or(module).to_owned()
        };
    if name.is_empty() {
        return None;
    }
    Some(format!("{name}::{kind}"))
}

fn decode(mut input: &str) -> Option<String> {
    const ESCAPES: &[(&str, char)] = &[
        ("backslash", '\\'),
        ("percent", '%'),
        ("dollar", '$'),
        ("colon", ':'),
        ("slash", '/'),
        ("minus", '-'),
        ("tilde", '~'),
        ("emark", '!'),
        ("qmark", '?'),
        ("star", '*'),
        ("plus", '+'),
        ("roof", '^'),
        ("amp", '&'),
        ("dot", '.'),
        ("bar", '|'),
        ("eq", '='),
        ("lt", '<'),
        ("gt", '>'),
        ("at", '@'),
    ];
    let mut out = Vec::with_capacity(input.len());
    while !input.is_empty() {
        if let Some((escape, value)) = ESCAPES.iter().find(|(s, _)| input.starts_with(s)) {
            out.push(*value as u8);
            input = &input[escape.len()..];
        } else if input.starts_with('X')
            && input.len() >= 3
            && input.as_bytes()[1..3].iter().all(u8::is_ascii_hexdigit)
        {
            let byte = u8::from_str_radix(&input[1..3], 16).ok()?;
            if byte.is_ascii_control() {
                return None;
            }
            out.push(byte);
            input = &input[3..];
        } else {
            out.push(input.as_bytes()[0]);
            input = &input[1..];
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_paths_and_old_fastcall_names() {
        assert_eq!(
            demangle("atmdotdotatsdotdotatslibatssystemdotnim_Init000").as_deref(),
            Some("../../lib/system.nim::init")
        );
        assert_eq!(
            demangle("atpstdatsexitprocsdotnim_DatInit000").as_deref(),
            Some("std/exitprocs.nim::datinit")
        );
        assert_eq!(
            demangle("@stdlib_httpclientInit000@0").as_deref(),
            Some("httpclient::init")
        );
        assert_eq!(
            demangle("_systemDatInit000@0").as_deref(),
            Some("system::datinit")
        );
        assert_eq!(demangle("atexit"), None);
        assert_eq!(demangle("Init000"), None);
        assert_eq!(demangle("atmX00_Init000"), None);
    }
}
