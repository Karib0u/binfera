//! Go programs: names, signatures and conventions from the binary's own metadata.
//!
//! A port of what Ghidra 12.1.4's `GolangSymbolAnalyzer` gives the decompiler: every function is
//! named from the function table; a standard library function takes its signature from Ghidra's Go
//! API snapshots (packed by `scripts/decompiler_types/pack_go_snapshots.py`), with the storage the
//! Go ABI assigns; `.abi0` functions use the stack ABI; the runtime's `duffzero`, `duffcopy` and
//! write-barrier helpers get the conventions `x86-64-golang.cspec` defines for them; and the names in
//! `GolangFunctionsThatDoNotReturn` do not return.
use std::collections::BTreeSet;

use crate::golang::GoVersion;

/// Ghidra 12.1.4 `Features/Base/data/GolangFunctionsThatDoNotReturn`, vendored unchanged.
const NORETURN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../third_party/ghidra/data/GolangFunctionsThatDoNotReturn"
));

/// The function names that never return.
pub(super) fn noreturn_names() -> BTreeSet<&'static str> {
    NORETURN
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

/// Function-table entries Ghidra does not make functions of (`FUNCNAMES_TO_IGNORE`).
pub(super) fn ignored(name: &str) -> bool {
    name == "go:buildid" || name == "go.buildid"
}

/// The runtime helper conventions of `GolangSymbolAnalyzer.fixDuffFunctions` and
/// `fixGcWriteBarrierFunctions` (amd64 only: the x86-32 specification gives these models no
/// registers), as `set_go_special` names them, plus a locked empty prototype for the stack-growth
/// helpers, which Ghidra leaves inferred.
pub(super) fn special(name: &str, version: GoVersion, wide: bool) -> Option<String> {
    // The stack-growth helpers every prologue calls are `$0-0` in each release and on both widths.
    if matches!(
        name.strip_suffix(".abi0").unwrap_or(name),
        "runtime.morestack" | "runtime.morestack_noctxt"
    ) {
        return Some("void".into());
    }
    // runtime/asm_{amd64,386}.s, Go 1.13 through 1.25: these assembly
    // stubs use register pairs even when ordinary Go functions use the stack ABI.
    if version.major == 1 && (13..=25).contains(&version.minor) {
        let base = name.strip_suffix('U').unwrap_or(name);
        let registers = match base {
            "runtime.panicIndex" | "runtime.panicSliceB" | "runtime.panicSlice3C" => Some("ax_cx"),
            "runtime.panicSliceAlen" | "runtime.panicSliceAcap" | "runtime.panicSlice3B" => {
                Some("cx_dx")
            }
            "runtime.panicSlice3Alen" | "runtime.panicSlice3Acap" => Some("dx_bx"),
            "runtime.panicSliceConvert" if base == name => Some("dx_bx"),
            _ => None,
        };
        if let Some(registers) = registers {
            let unsigned = if base == name { "" } else { "_u" };
            return Some(format!("panic_{registers}{unsigned}"));
        }
    }
    match name {
        "runtime.duffzero" => return Some("duffzero".into()),
        "runtime.duffcopy" => return Some("duffcopy".into()),
        _ => {}
    }
    if !wide {
        return None;
    }
    // GoConstants.GCWRITE_BATCH_VERS ("1.21-") and GCWRITE_BUFFERED_VERS ("-1.20").
    if version >= GoVersion::new(1, 21, 0) {
        if name == "gcWriteBarrier" {
            return Some("gcwrite_batch_numbytes".into());
        }
        let count = name.strip_prefix("runtime.gcWriteBarrier")?;
        return matches!(count, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8")
            .then(|| "gcwrite_batch".into());
    }
    let register = name.strip_prefix("runtime.gcWriteBarrier")?;
    if register.is_empty() {
        return Some("gcwrite_buffered".into());
    }
    // GoConstants.GCWRITE_BUFFERED_x86_64_Regs, Go's register names.
    const REGISTERS: &[&str] = &["CX", "DX", "BX", "BP", "SI", "R8", "R9"];
    REGISTERS.contains(&register).then(|| {
        let register = if register.starts_with('R') {
            register.to_string()
        } else {
            format!("R{register}")
        };
        format!("gcwrite_buffered:{register}")
    })
}

/// The key the API snapshot files a function under (`GoSymbolName.getStrippedSymbolString`): the
/// package path, then a pointer receiver qualified by it (`os.(*File).Write` is
/// `os.(*os.File).Write`), then the name. Value-receiver methods (`net/netip.Addr.String`) are filed
/// as named. `None` for what the snapshot never has: compiler-generated names (`go:`, `type:`),
/// closures, method values, and anything with type arguments.
pub(super) fn snapshot_key(name: &str) -> Option<String> {
    if name.starts_with("go:")
        || name.starts_with("go.")
        || name.starts_with("type:")
        || name.starts_with("type.")
        || name.contains('[')
    {
        return None;
    }
    // Before Go 1.18 names may use a middle dot and a division slash.
    let name = name.replace('\u{b7}', ".").replace('\u{2215}', "/");
    let limit = name.find('(').unwrap_or(name.len());
    let package_start = name.get(..limit)?.rfind('/').map_or(0, |at| at + 1);
    let package_end = package_start + name.get(package_start..)?.find('.')?;
    let package = name.get(..package_end)?;
    let rest = name.get(package_end + 1..)?;
    let parts = split_top_level(rest);
    let last = parts.last()?;
    let generated = last.ends_with("-fm")
        || last.chars().all(|c| c.is_ascii_digit())
        || ["func", "gowrap", "deferwrap"].iter().any(|prefix| {
            last.strip_prefix(prefix)
                .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
        })
        || last.contains("-range");
    if generated || parts.len() > 2 {
        return None;
    }
    match parts.as_slice() {
        [receiver, method] if receiver.starts_with('(') => {
            let receiver = receiver.strip_prefix('(')?.strip_suffix(')')?;
            let qualified = match receiver.strip_prefix('*') {
                Some(base) => format!("*{package}.{base}"),
                None => format!("{package}.{receiver}"),
            };
            Some(format!("{package}.({qualified}).{method}"))
        }
        _ => Some(format!("{package}.{rest}")),
    }
}

/// `rest` split on dots outside parentheses.
fn split_top_level(rest: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut depth, mut start) = (0usize, 0usize);
    for (at, ch) in rest.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            '.' if depth == 0 => {
                parts.push(&rest[start..at]);
                start = at + 1;
            }
            _ => {}
        }
    }
    parts.push(&rest[start..]);
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_helpers_are_versioned_and_do_not_type_abi0_wrappers() {
        for wide in [false, true] {
            for minor in [13, 16, 17, 25] {
                let version = GoVersion::new(1, minor, 0);
                assert_eq!(
                    special("runtime.panicIndex", version, wide).as_deref(),
                    Some("panic_ax_cx")
                );
                assert_eq!(
                    special("runtime.panicSliceAcapU", version, wide).as_deref(),
                    Some("panic_cx_dx_u")
                );
                assert_eq!(
                    special("runtime.panicSlice3Alen", version, wide).as_deref(),
                    Some("panic_dx_bx")
                );
                assert_eq!(special("runtime.panicIndex.abi0", version, wide), None);
                assert_eq!(special("example.panicIndex", version, wide), None);
                assert_eq!(special("runtime.panicSliceConvertU", version, wide), None);
            }
            for minor in [12, 26] {
                assert_eq!(
                    special("runtime.panicIndex", GoVersion::new(1, minor, 0), wide),
                    None
                );
            }
        }
    }

    #[test]
    fn files_names_as_the_snapshot_does() {
        let key = |name: &str| snapshot_key(name);
        assert_eq!(key("fmt.Fprintf").as_deref(), Some("fmt.Fprintf"));
        assert_eq!(
            key("os.(*File).Write").as_deref(),
            Some("os.(*os.File).Write")
        );
        assert_eq!(
            key("crypto/ecdh.(*nistCurve).GenerateKey").as_deref(),
            Some("crypto/ecdh.(*crypto/ecdh.nistCurve).GenerateKey")
        );
        assert_eq!(
            key("net/netip.Addr.string6").as_deref(),
            Some("net/netip.Addr.string6")
        );
        assert_eq!(
            key("golang.org/x/net/http2.(*Framer).WriteData").as_deref(),
            Some("golang.org/x/net/http2.(*golang.org/x/net/http2.Framer).WriteData")
        );
        assert_eq!(
            key("runtime\u{b7}mallocgc").as_deref(),
            Some("runtime.mallocgc")
        );
        for generated in [
            "main.main.func1",
            "main.main.func1.2",
            "os.(*File).Write.func1",
            "net/http.(*Server).Serve-fm",
            "main.main.gowrap1",
            "slices.Sort[go.shape.int]",
            "type:.eq.main.T",
            "go:buildid",
        ] {
            assert_eq!(key(generated), None, "{generated}");
        }
    }

    #[test]
    fn runtime_helpers_by_release() {
        let old = GoVersion::new(1, 20, 0);
        let new = GoVersion::new(1, 21, 0);
        assert_eq!(
            special("runtime.duffzero", new, true).as_deref(),
            Some("duffzero")
        );
        assert_eq!(
            special("runtime.duffzero", new, false).as_deref(),
            Some("duffzero")
        );
        for wide in [false, true] {
            assert_eq!(
                special("runtime.morestack_noctxt", old, wide).as_deref(),
                Some("void")
            );
            assert_eq!(
                special("runtime.morestack.abi0", new, wide).as_deref(),
                Some("void")
            );
        }
        assert_eq!(
            special("runtime.gcWriteBarrier3", new, true).as_deref(),
            Some("gcwrite_batch")
        );
        assert_eq!(
            special("gcWriteBarrier", new, true).as_deref(),
            Some("gcwrite_batch_numbytes")
        );
        assert_eq!(special("runtime.gcWriteBarrier3", old, true), None);
        assert_eq!(
            special("runtime.gcWriteBarrier", old, true).as_deref(),
            Some("gcwrite_buffered")
        );
        assert_eq!(
            special("runtime.gcWriteBarrierCX", old, true).as_deref(),
            Some("gcwrite_buffered:RCX")
        );
        assert_eq!(
            special("runtime.gcWriteBarrierR8", old, true).as_deref(),
            Some("gcwrite_buffered:R8")
        );
        assert!(noreturn_names().contains("runtime.throw"));
        assert!(!noreturn_names().iter().any(|name| name.starts_with('#')));
    }
}
