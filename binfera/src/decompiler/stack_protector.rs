//! Hide a saved canary only when its sole use is a canonical failure check.
//! Assembly and noncanonical checks remain available to the caller.
use regex::Regex;
use std::sync::LazyLock;

static SAVE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
    r"^  ([A-Za-z_]\w*) = (\*\([A-Za-z_][A-Za-z_0-9 ]*\*\)(?:_+stack_chk_guard|\(in_(?:FS|GS)_OFFSET \+ 0x(?:28|14)\)));$"
).ok()
});

pub(super) fn render(text: &str, addresses: &mut Vec<Vec<u64>>) -> (String, bool) {
    if !text.contains("stack_chk_fail") {
        return (text.to_owned(), false);
    }
    let Some(save) = SAVE.as_ref() else {
        return (text.to_owned(), false);
    };
    let mut lines: Vec<String> = text.split('\n').map(str::to_owned).collect();
    for index in 0..lines.len() {
        let Some(capture) = save.captures(&lines[index]) else {
            continue;
        };
        let local = capture[1].to_owned();
        let guard = capture[2].to_owned();
        // Declaration, save and comparison only. Never remove a value used by
        // application code, an exposed canary, or another integrity check.
        let uses = text
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .filter(|token| *token == local)
            .count();
        if uses != 3 {
            continue;
        }
        let Some(declaration) = lines.iter().position(|line| {
            line.starts_with("  ") && line.ends_with(&format!(" {local};")) && !line.contains('=')
        }) else {
            continue;
        };
        let mut removed = vec![declaration, index];
        let mut changed = false;
        for check in index + 1..lines.len() {
            let equal = lines[check] == format!("  if ({guard} == {local}) {{")
                || lines[check] == format!("  if ({local} == {guard}) {{");
            let unequal = lines[check] == format!("  if ({guard} != {local}) {{")
                || lines[check] == format!("  if ({local} != {guard}) {{");
            if !equal && !unequal {
                continue;
            }
            if equal
                && lines
                    .get(check + 1)
                    .is_some_and(|l| l.starts_with("    return "))
                && lines.get(check + 2).is_some_and(|l| l == "  }")
            {
                let mut fail = check + 3;
                while lines
                    .get(fail)
                    .is_some_and(|l| l.trim() == "/* WARNING: Subroutine does not return */")
                {
                    fail += 1;
                }
                if lines
                    .get(fail)
                    .is_some_and(|l| l.trim().trim_start_matches('_') == "stack_chk_fail();")
                    && lines.get(fail + 1).is_some_and(|l| l == "}")
                {
                    lines[check + 1] = lines[check + 1].replacen("    ", "  ", 1);
                    removed.push(check);
                    removed.extend(check + 2..=fail);
                    changed = true;
                }
            } else if unequal {
                let mut fail = check + 1;
                while lines
                    .get(fail)
                    .is_some_and(|l| l.trim() == "/* WARNING: Subroutine does not return */")
                {
                    fail += 1;
                }
                if lines
                    .get(fail)
                    .is_some_and(|l| l.trim().trim_start_matches('_') == "stack_chk_fail();")
                    && lines.get(fail + 1).is_some_and(|l| l == "  }")
                {
                    removed.extend(check..=fail + 1);
                    changed = true;
                }
            }
            break;
        }
        if changed {
            removed.sort_unstable();
            removed.dedup();
            for index in removed.into_iter().rev() {
                lines.remove(index);
                if !addresses.is_empty() && index < addresses.len() {
                    addresses.remove(index);
                }
            }
            return (lines.join("\n"), true);
        }
    }
    (text.to_owned(), false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hides_only_an_unexposed_canary_and_keeps_line_mapping() {
        let text = "int f()\n{\n  long long local_8;\n  local_8 = *(long long *)__stack_chk_guard;\n  work();\n  if (*(long long *)__stack_chk_guard == local_8) {\n    return 7;\n  }\n                    /* WARNING: Subroutine does not return */\n  __stack_chk_fail();\n}\n";
        let mut addresses: Vec<_> = (0..text.split('\n').count())
            .map(|n| vec![n as u64])
            .collect();
        let (rendered, hidden) = render(text, &mut addresses);
        assert!(hidden);
        assert_eq!(rendered, "int f()\n{\n  work();\n  return 7;\n}\n");
        assert_eq!(
            addresses,
            vec![vec![0], vec![1], vec![4], vec![6], vec![10], vec![11]]
        );
        let exposed = text.replace("work();", "work(local_8);");
        assert!(!render(&exposed, &mut Vec::new()).1);
        let different_guard = text.replacen("== local_8", "== other", 1);
        assert!(!render(&different_guard, &mut Vec::new()).1);
    }

    #[test]
    fn tls_guard_with_a_failure_branch() {
        let text = "void f()\n{\n  long local_8;\n  local_8 = *(long *)(in_FS_OFFSET + 0x28);\n  work();\n  if (local_8 != *(long *)(in_FS_OFFSET + 0x28)) {\n    __stack_chk_fail();\n  }\n  return;\n}\n";
        let (rendered, hidden) = render(text, &mut Vec::new());
        assert!(hidden);
        assert!(!rendered.contains("local_8"));
        assert!(!rendered.contains("stack_chk"));
        assert!(rendered.contains("work();\n  return;"));
    }
}
