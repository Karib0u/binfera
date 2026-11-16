//! Known effect models for runtime helpers that ordinary calling-convention
//! rules misdescribe.
//!
//! Ghidra replaces calls to these helpers with the p-code snippets declared as
//! `<callfixup>` entries in the compiler specification. The table maps a
//! recognized function name to the fixup it uses. The names are the `<target>`
//! entries of `x86-64-win.cspec` and `x86win.cspec`, compared without leading
//! underscores because FLIRT and Function ID spell the same helper with different
//! prefixes. A test checks both tables against the vendored specifications.

/// Ordered by fixup. Keep in step with the vendored `x86-64-win.cspec`.
const FIXUPS_X64: &[(&str, &str)] = &[
    ("security_check_cookie", "security_check_cookie"),
    ("alloca_probe", "alloca_probe"),
    ("alloca_probe2", "alloca_probe"),
    ("chkstk", "alloca_probe"),
    ("chkstk2", "alloca_probe"),
    ("chkstk_ms", "alloca_probe"),
    ("guard_dispatch_icall", "guard_dispatch_icall"),
];

/// Keep in step with the vendored `x86win.cspec`. Its `*_align` fixups are commented out there,
/// so the engine does not know them and they are not listed.
const FIXUPS_X86: &[(&str, &str)] = &[
    ("EH_prolog", "EH_prolog"),
    ("EH_prolog3", "EH_prolog3"),
    ("EH_prolog3_GS", "EH_prolog3"),
    ("EH_prolog3_catch", "EH_prolog3"),
    ("EH_prolog3_catch_GS", "EH_prolog3"),
    ("EH_epilog3", "EH_epilog3"),
    ("EH_epilog3_GS", "EH_epilog3"),
    ("EH_epilog3_catch", "EH_epilog3"),
    ("EH_epilog3_catch_GS", "EH_epilog3"),
    ("SEH_epilog", "EH_epilog3"),
    ("SEH_epilog4", "EH_epilog3"),
    ("SEH_epilog4_GS", "EH_epilog3"),
    ("alloca_probe", "alloca_probe"),
    ("alloca_probe_8", "alloca_probe"),
    ("alloca_probe_16", "alloca_probe"),
    ("chkstk", "alloca_probe"),
    ("SEH_prolog", "SEH_prolog"),
    ("SEH_prolog4", "SEH_prolog4"),
    ("SEH_prolog4_GS", "SEH_prolog4"),
    ("RTC_CheckEsp", "__RTC_CheckEsp"),
    ("security_check_cookie", "security_check_cookie"),
];

/// Keep in step with the vendored `x86gcc.cspec` (System V i386): the position-independent code
/// thunks that load the return address into a register, and the kernel's tracing and
/// retpoline helpers.
const FIXUPS_X86_GCC: &[(&str, &str)] = &[
    ("i686.get_pc_thunk.ax", "get_pc_thunk_ax"),
    ("x86.get_pc_thunk.ax", "get_pc_thunk_ax"),
    ("i686.get_pc_thunk.bp", "get_pc_thunk.bp"),
    ("x86.get_pc_thunk.bp", "get_pc_thunk.bp"),
    ("i686.get_pc_thunk.bx", "get_pc_thunk_bx"),
    ("x86.get_pc_thunk.bx", "get_pc_thunk_bx"),
    ("i686.get_pc_thunk.cx", "get_pc_thunk_cx"),
    ("x86.get_pc_thunk.cx", "get_pc_thunk_cx"),
    ("i686.get_pc_thunk.dx", "get_pc_thunk_dx"),
    ("x86.get_pc_thunk.dx", "get_pc_thunk_dx"),
    ("i686.get_pc_thunk.di", "get_pc_thunk_di"),
    ("x86.get_pc_thunk.di", "get_pc_thunk_di"),
    ("i686.get_pc_thunk.si", "get_pc_thunk_si"),
    ("x86.get_pc_thunk.si", "get_pc_thunk_si"),
    ("x86_return_thunk", "x86_return_thunk"),
    ("fentry__", "fentry"),
    ("mcount", "mcount"),
    ("x86_indirect_thunk_ebp", "x86_indirect_thunk_ebp"),
    ("x86_indirect_thunk_eax", "x86_indirect_thunk_eax"),
    ("x86_indirect_thunk_ebx", "x86_indirect_thunk_ebx"),
    ("x86_indirect_thunk_ecx", "x86_indirect_thunk_ecx"),
    ("x86_indirect_thunk_edx", "x86_indirect_thunk_edx"),
];

/// The `x86gcc.cspec` call fixup for a System V i386 helper named by the image's symbols.
pub fn gcc_x86_call_fixup(name: &str) -> Option<&'static str> {
    let name = name.trim_start_matches('_');
    FIXUPS_X86_GCC
        .iter()
        .find(|(helper, _)| *helper == name)
        .map(|(_, fixup)| *fixup)
}

/// The `__x86.get_pc_thunk.<reg>` a function's body is, `mov <reg>, [esp]; ret`, as gcc emits
/// it. A stripped image keeps the body but loses the name, so this identifies it by its bytes.
pub fn gcc_x86_pc_thunk(code: &[u8]) -> Option<&'static str> {
    let [0x8b, modrm, 0x24, 0xc3, ..] = code else {
        return None;
    };
    Some(match modrm {
        0x04 => "__x86.get_pc_thunk.ax",
        0x0c => "__x86.get_pc_thunk.cx",
        0x14 => "__x86.get_pc_thunk.dx",
        0x1c => "__x86.get_pc_thunk.bx",
        0x2c => "__x86.get_pc_thunk.bp",
        0x34 => "__x86.get_pc_thunk.si",
        0x3c => "__x86.get_pc_thunk.di",
        _ => return None,
    })
}

/// The compiler-spec call fixup for a recognized helper, if there is one.
/// `wide` selects the x86-64 table, otherwise the x86-32 one.
pub fn call_fixup(name: &str, wide: bool) -> Option<&'static str> {
    let name = name.trim_start_matches('_');
    (if wide { FIXUPS_X64 } else { FIXUPS_X86 })
        .iter()
        .find(|(helper, _)| *helper == name)
        .map(|(_, fixup)| *fixup)
}

#[cfg(test)]
mod tests {
    use super::{
        call_fixup, gcc_x86_call_fixup, gcc_x86_pc_thunk, FIXUPS_X64, FIXUPS_X86, FIXUPS_X86_GCC,
    };
    use std::collections::BTreeSet;

    #[test]
    fn prefixes_do_not_matter() {
        assert_eq!(
            call_fixup("__security_check_cookie", true),
            Some("security_check_cookie")
        );
        assert_eq!(
            call_fixup("security_check_cookie", true),
            Some("security_check_cookie")
        );
        assert_eq!(call_fixup("___chkstk_ms", true), Some("alloca_probe"));
        assert_eq!(call_fixup("_alloca_probe_16", true), None);
        assert_eq!(call_fixup("_alloca_probe_16", false), Some("alloca_probe"));
        assert_eq!(
            call_fixup("__EH_prolog3_catch_GS", false),
            Some("EH_prolog3")
        );
        assert_eq!(call_fixup("memcpy", true), None);
        assert_eq!(call_fixup("memcpy", false), None);
    }

    /// The (target, fixup) pairs of a compiler spec, leading underscores removed.
    fn spec_pairs(path: &str) -> BTreeSet<(String, String)> {
        let text = std::fs::read_to_string(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../third_party/ghidra/specs/").to_owned() + path,
        )
        .expect("vendored compiler spec");
        // Commented-out fixups are not part of the specification the engine loads.
        let mut text = text;
        while let Some(start) = text.find("<!--") {
            let end = text[start..]
                .find("-->")
                .map_or(text.len(), |at| start + at + 3);
            text.replace_range(start..end, "");
        }
        let mut pairs = BTreeSet::new();
        for block in text.split("<callfixup name=\"").skip(1) {
            let (fixup, rest) = block.split_once('"').expect("fixup name");
            let body = rest.split("</callfixup>").next().expect("fixup body");
            for target in body.split("<target name=\"").skip(1) {
                let name = target
                    .split('"')
                    .next()
                    .expect("target name")
                    .trim_start_matches('_');
                if !name.starts_with("thunk_") && !name.starts_with("FID_conflict") {
                    pairs.insert((name.to_owned(), fixup.to_owned()));
                }
            }
        }
        pairs
    }

    fn table(entries: &[(&str, &str)]) -> BTreeSet<(String, String)> {
        entries
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    #[test]
    fn tables_match_the_vendored_compiler_specs() {
        assert_eq!(table(FIXUPS_X64), spec_pairs("x86-64-win.cspec"));
        assert_eq!(table(FIXUPS_X86), spec_pairs("x86win.cspec"));
        assert_eq!(table(FIXUPS_X86_GCC), spec_pairs("x86gcc.cspec"));
    }

    #[test]
    fn pc_thunks_are_found_by_name_and_by_body() {
        assert_eq!(
            gcc_x86_call_fixup("__x86.get_pc_thunk.bx"),
            Some("get_pc_thunk_bx")
        );
        assert_eq!(
            gcc_x86_call_fixup("__i686.get_pc_thunk.bp"),
            Some("get_pc_thunk.bp")
        );
        assert_eq!(gcc_x86_call_fixup("memcpy"), None);
        assert_eq!(
            gcc_x86_pc_thunk(&[0x8b, 0x1c, 0x24, 0xc3]),
            Some("__x86.get_pc_thunk.bx")
        );
        assert_eq!(gcc_x86_pc_thunk(&[0x8b, 0x24, 0x24, 0xc3]), None);
        assert_eq!(gcc_x86_pc_thunk(&[0x8b, 0x1c, 0x24, 0x90]), None);
        // Every thunk the body identifies has a fixup.
        for modrm in [0x04, 0x0c, 0x14, 0x1c, 0x2c, 0x34, 0x3c] {
            let name = gcc_x86_pc_thunk(&[0x8b, modrm, 0x24, 0xc3]);
            assert!(name.and_then(gcc_x86_call_fixup).is_some(), "{name:?}");
        }
    }
}
