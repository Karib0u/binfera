//! Collapse the `repne scasb` scan that measures a C string into `strlen`.
//! The counter, cursor and loaded byte must have no other use, and the length
//! must be read in a form that only a length can take (`~count - 1`, or a test
//! of the count against its value for an empty string).
use regex::Regex;
use std::sync::LazyLock;

static START: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^( +)([A-Za-z_]\w*) = (-1|0xffffffff);$").ok());

fn uses(text: &str, name: &str) -> usize {
    text.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|token| *token == name)
        .count()
}

fn declared(lines: &[String], name: &str) -> Option<usize> {
    lines.iter().position(|l| {
        l.starts_with("  ")
            && !l.starts_with("   ")
            && !l.contains('=')
            && l.strip_suffix(&format!("{name};"))
                .is_some_and(|rest| rest.ends_with([' ', '*']))
    })
}

pub(super) fn render(text: &str, addresses: &mut Vec<Vec<u64>>) -> (String, usize) {
    if !text.contains("do {") {
        return (text.to_owned(), 0);
    }
    let Some(start) = START.as_ref() else {
        return (text.to_owned(), 0);
    };
    let mut lines: Vec<String> = text.split('\n').map(str::to_owned).collect();
    for at in 0..lines.len().saturating_sub(8) {
        let Some(c) = start.captures(&lines[at]) else {
            continue;
        };
        let (indent, count, initial) = (c[1].to_owned(), c[2].to_owned(), c[3].to_owned());
        let Some(p) = Regex::new(&format!(r"^{indent}(\w+) = (.+);$"))
            .ok()
            .and_then(|re| {
                re.captures(&lines[at + 1])
                    .map(|p| (p[1].to_owned(), p[2].to_owned()))
            })
        else {
            continue;
        };
        let (cursor, expression) = p;
        let body = &lines[at + 2..at + 8];
        let step = [
            format!("{indent}  {count} = {count} + -1;"),
            format!("{indent}  {count} = {count} - 1;"),
        ];
        let loaded = body[3]
            .trim()
            .strip_suffix(&format!(" = *{cursor};"))
            .map(str::to_owned);
        let Some(byte) = loaded else { continue };
        let shape = body[0] == format!("{indent}do {{")
            && body[1] == format!("{indent}  if ({count} == 0) break;")
            && step.contains(&body[2])
            && body[4] == format!("{indent}  {cursor} = {cursor} + 1;")
            && body[5] == format!("{indent}}} while ({byte} != '\\0');");
        if !shape || [&count, &cursor, &byte].iter().any(|n| n.is_empty()) {
            continue;
        }
        // A scan variable is reused for the next scan, so a whole-function count
        // would refuse nearly every loop. Instead follow each variable forward
        // from the loop to its next top-level assignment: the loop is dead
        // there, and until then nothing may read it.
        if indent.len() != 2 || text.contains("goto ") {
            continue;
        }
        let user = (at + 8..lines.len()).find(|&n| uses(&lines[n], &count) > 0);
        let Some(user) = user else { continue };
        let dead_but_for = |name: &str, allowed: Option<usize>| -> bool {
            let mut in_scan = false;
            for (n, line) in lines.iter().enumerate().skip(at + 8) {
                // The next scan writes its variables in the body of a top-level
                // `do` loop, which runs at least once.
                if line == "  do {" {
                    in_scan = true;
                } else if line.starts_with("  }") {
                    in_scan = false;
                }
                if uses(line, name) == 0 {
                    continue;
                }
                let trimmed = line.trim_start();
                let rest = trimmed
                    .strip_prefix(&format!("{name} = "))
                    .or_else(|| trimmed.strip_prefix(&format!("for ({name} = ")));
                let top_level = line.len() - trimmed.len() == 2 || in_scan;
                if top_level
                    && rest.is_some_and(|r| uses(r.split(';').next().unwrap_or(r), name) == 0)
                {
                    return true;
                }
                if Some(n) != allowed || uses(line, name) != 1 {
                    return false;
                }
            }
            true
        };
        if !dead_but_for(&count, Some(user))
            || !dead_but_for(&cursor, None)
            || !dead_but_for(&byte, None)
        {
            continue;
        }
        let (Some(count_decl), Some(cursor_decl), Some(byte_decl)) = (
            declared(&lines, &count),
            declared(&lines, &cursor),
            declared(&lines, &byte),
        ) else {
            continue;
        };
        let signed = initial == "-1";
        let empty = if signed { "-2" } else { "0xfffffffe" };
        let length = format!("strlen({expression})");
        let line = &lines[user];
        let rewritten = if line.contains(&format!("~{count} - 1")) {
            line.replacen(&format!("~{count} - 1"), &length, 1)
        } else if line.contains(&format!("({count} == {empty})")) {
            line.replacen(&format!("{count} == {empty}"), &format!("{length} == 0"), 1)
        } else {
            continue;
        };
        lines[user] = rewritten;
        let mut removed: Vec<usize> = (at..at + 8).collect();
        for (name, decl) in [
            (&count, count_decl),
            (&cursor, cursor_decl),
            (&byte, byte_decl),
        ] {
            let remaining: usize = lines
                .iter()
                .enumerate()
                .filter(|(n, _)| !removed.contains(n))
                .map(|(_, l)| uses(l, name))
                .sum();
            if remaining == 1 {
                removed.push(decl);
            }
        }
        removed.sort_unstable();
        removed.dedup();
        for index in removed.into_iter().rev() {
            lines.remove(index);
            if index < addresses.len() {
                addresses.remove(index);
            }
        }
        let joined = lines.join("\n");
        let (rest, more) = render(&joined, addresses);
        return (rest, 1 + more);
    }
    (text.to_owned(), 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(start: &str, test: &str) -> String {
        format!("int f(char *s)\n{{\n  char c;\n  int n;\n  char *p;\n  \n  n = {start};\n  p = s;\n  do {{\n    if (n == 0) break;\n    n = n + -1;\n    c = *p;\n    p = p + 1;\n  }} while (c != '\\0');\n  {test}\n}}\n")
    }

    #[test]
    fn length_forms_become_strlen() {
        let text = sample("0xffffffff", "return ~n - 1;");
        let mut addresses: Vec<_> = (0..text.split('\n').count())
            .map(|n| vec![n as u64])
            .collect();
        let (out, n) = render(&text, &mut addresses);
        assert_eq!(n, 1);
        assert_eq!(out, "int f(char *s)\n{\n  \n  return strlen(s);\n}\n");
        assert_eq!(addresses.len(), out.split('\n').count());
        let (out, _) = render(&sample("-1", "if (n == -2) {"), &mut Vec::new());
        assert!(out.contains("if (strlen(s) == 0) {"), "{out}");
    }

    #[test]
    fn other_uses_keep_the_loop() {
        let (_, n) = render(&sample("-1", "return n;"), &mut Vec::new());
        assert_eq!(n, 0);
        let (_, n) = render(&sample("-1", "return ~n - 1 + *p;"), &mut Vec::new());
        assert_eq!(n, 0);
    }
}
