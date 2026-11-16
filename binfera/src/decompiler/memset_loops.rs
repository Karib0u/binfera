//! Collapse the counted zeroing loop that `rep stos` becomes into `memset`.
//! Only a loop whose counter and cursor are used nowhere else is rewritten,
//! so no later read of either variable can change meaning.
use regex::Regex;
use std::sync::LazyLock;

static INIT: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^( +)([A-Za-z_]\w*) = (?:\([^()]*\))?(.+);$").ok());
static HEAD: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"^ +for \(([A-Za-z_]\w*) = (0x[0-9a-f]+|\d+); ([A-Za-z_]\w*) != 0; ([A-Za-z_]\w*) = ([A-Za-z_]\w*) \+ -1\) \{$").ok()
});

fn element_size(declared: &str) -> Option<usize> {
    Some(match declared {
        "char" | "unsigned char" | "signed char" => 1,
        "short" | "unsigned short" => 2,
        "int" | "unsigned int" => 4,
        "long long" | "unsigned long long" => 8,
        _ => return None,
    })
}

fn uses(text: &str, name: &str) -> usize {
    text.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|token| *token == name)
        .count()
}

pub(super) fn render(text: &str, addresses: &mut Vec<Vec<u64>>) -> (String, usize) {
    if !text.contains("for (") {
        return (text.to_owned(), 0);
    }
    let (Some(init), Some(head)) = (INIT.as_ref(), HEAD.as_ref()) else {
        return (text.to_owned(), 0);
    };
    let mut lines: Vec<String> = text.split('\n').map(str::to_owned).collect();
    let mut rewritten = 0;
    let mut at = 0;
    while at + 5 <= lines.len() {
        let Some(h) = head.captures(&lines[at]) else {
            at += 1;
            continue;
        };
        let (counter, count) = (h[1].to_owned(), &h[2]);
        let same = h[3] == counter && h[4] == counter && h[5] == counter;
        let Some(count) = number(count).filter(|n| *n > 0) else {
            at += 1;
            continue;
        };
        let Some(i) = at.checked_sub(1).and_then(|p| init.captures(&lines[p])) else {
            at += 1;
            continue;
        };
        let cursor = i[2].to_owned();
        let start = i[3].to_owned();
        let indent = &i[1];
        let store_ok = [
            format!("{indent}  *{cursor} = 0;"),
            format!("{indent}  *{cursor} = 0x0;"),
        ]
        .contains(&lines[at + 1]);
        let step_ok = lines[at + 2] == format!("{indent}  {cursor} = {cursor} + 1;");
        let close_ok = lines[at + 3] == format!("{indent}}}");
        if !(same && store_ok && step_ok && close_ok) || counter == cursor {
            at += 1;
            continue;
        }
        // Declaration, initialiser, store and step for the cursor; declaration,
        // initialiser, test and step for the counter.
        // `rep stosd; stosw; stosb` leaves up to three more zero stores through
        // the advanced cursor. They belong to the same memset.
        let short = format!("{indent}*(unsigned short *){cursor} = 0;");
        let after_short = format!("{indent}*(unsigned char *)((int){cursor} + 2) = 0;");
        let plain_byte = format!("{indent}*(unsigned char *){cursor} = 0;");
        let tail_lines: Vec<&String> = (0..2).map_while(|n| lines.get(at + 4 + n)).collect();
        // Offsets are relative to the advanced cursor, so only a dword loop fits.
        let (tail, tail_bytes) = match (tail_lines.first(), tail_lines.get(1)) {
            _ if element_size_of(&lines, &cursor) != Some(4) => (0, 0),
            (Some(a), Some(b)) if **a == short && **b == after_short => (2, 3),
            (Some(a), _) if **a == short => (1, 2),
            (Some(a), _) if **a == plain_byte => (1, 1),
            _ => (0, 0),
        };
        if uses(text, &cursor) != 5 + tail || uses(text, &counter) != 5 {
            at += 1;
            continue;
        }
        let find_decl = |name: &str| {
            lines.iter().position(|l| {
                l.starts_with("  ")
                    && !l.starts_with("   ")
                    && !l.contains('=')
                    && l.strip_suffix(&format!("{name};"))
                        .is_some_and(|rest| rest.ends_with([' ', '*']))
            })
        };
        let (Some(cursor_decl), Some(counter_decl)) = (find_decl(&cursor), find_decl(&counter))
        else {
            at += 1;
            continue;
        };
        let cursor_type = lines[cursor_decl]
            .trim()
            .strip_suffix(&format!(" *{cursor};"))
            .and_then(element_size);
        let Some(size) = cursor_type else {
            at += 1;
            continue;
        };
        lines[at - 1] = format!(
            "{indent}memset({start}, 0, 0x{:x});",
            count * size + tail_bytes
        );
        let mut removed = vec![at, at + 1, at + 2, at + 3, cursor_decl, counter_decl];
        removed.extend((0..tail).map(|n| at + 4 + n));
        removed.sort_unstable();
        removed.dedup();
        for index in removed.into_iter().rev() {
            lines.remove(index);
            if index < addresses.len() {
                addresses.remove(index);
            }
        }
        rewritten += 1;
        // Token counts were taken on the old text; stop after one rewrite per
        // pass and recount by recursing on the new text.
        let joined = lines.join("\n");
        let (rest, more) = render(&joined, addresses);
        return (rest, rewritten + more);
    }
    (text.to_owned(), 0)
}

fn number(text: &str) -> Option<usize> {
    match text.strip_prefix("0x") {
        Some(hex) => usize::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOOP: &str = "void f()\n{\n  int iVar1;\n  unsigned int *pxVar2;\n  \n  pxVar2 = &buffer;\n  for (iVar1 = 0x10; iVar1 != 0; iVar1 = iVar1 + -1) {\n    *pxVar2 = 0;\n    pxVar2 = pxVar2 + 1;\n  }\n  work();\n}\n";

    #[test]
    fn unused_cursor_and_counter_become_memset() {
        let mut addresses: Vec<_> = (0..LOOP.split('\n').count())
            .map(|n| vec![n as u64])
            .collect();
        let (out, n) = render(LOOP, &mut addresses);
        assert_eq!(n, 1);
        assert_eq!(
            out,
            "void f()\n{\n  \n  memset(&buffer, 0, 0x40);\n  work();\n}\n"
        );
        assert_eq!(addresses.len(), out.split('\n').count());
        assert_eq!(addresses[3], vec![5]);
    }

    #[test]
    fn a_cursor_read_afterwards_keeps_the_loop() {
        let text = LOOP.replace("work();", "work(pxVar2);");
        assert_eq!(render(&text, &mut Vec::new()).1, 0);
        let nonzero = LOOP.replace("= 0;", "= 7;");
        assert_eq!(render(&nonzero, &mut Vec::new()).1, 0);
        let pointers = LOOP.replace("unsigned int *pxVar2", "void **pxVar2");
        assert_eq!(render(&pointers, &mut Vec::new()).1, 0);
    }

    #[test]
    fn stosw_and_stosb_tail_joins_the_memset() {
        let tail = LOOP.replace(
            "  work();",
            "  *(unsigned short *)pxVar2 = 0;\n  *(unsigned char *)((int)pxVar2 + 2) = 0;\n  work();",
        );
        let (out, n) = render(&tail, &mut Vec::new());
        assert_eq!(n, 1);
        assert!(out.contains("memset(&buffer, 0, 0x43);"), "{out}");
        assert!(!out.contains("pxVar2"), "{out}");
        // A byte store at the cursor after a word store would overlap it.
        let overlap = LOOP.replace(
            "  work();",
            "  *(unsigned short *)pxVar2 = 0;\n  *(unsigned char *)pxVar2 = 0;\n  work();",
        );
        let (out, _) = render(&overlap, &mut Vec::new());
        assert!(out.contains("*(unsigned char *)pxVar2 = 0;"), "{out}");
    }
}

fn element_size_of(lines: &[String], cursor: &str) -> Option<usize> {
    lines.iter().find_map(|l| {
        l.trim()
            .strip_suffix(&format!(" *{cursor};"))
            .and_then(element_size)
    })
}
