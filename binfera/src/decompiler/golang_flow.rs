//! Recognize runtime scaffolding from decoded code and the Go function table.
use crate::{
    extract::{
        decoder::Flow,
        image::{Architecture, LoadedImage},
    },
    golang::GoBinary,
};
use iced_x86::{Mnemonic, OpKind, Register};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn stack_checks(image: &LoadedImage, go: &GoBinary) -> Vec<(u64, u64, u32)> {
    let named = |names: &[&str]| -> BTreeSet<u64> {
        go.functions
            .functions
            .iter()
            .filter(|f| names.contains(&f.name.strip_suffix(".abi0").unwrap_or(&f.name)))
            .map(|f| f.entry)
            .collect()
    };
    let morestack = named(&["runtime.morestack", "runtime.morestack_noctxt"]);
    if image.architecture == Architecture::AArch64 {
        let helpers = named(&[
            "runtime.morestack",
            "runtime.morestack_noctxt",
            "runtime.morestackc",
        ]);
        let checks: Vec<_> = go
            .functions
            .functions
            .iter()
            .filter_map(|f| aarch64_stack_check(image, f.entry, f.end))
            .collect();
        // As on x86, a renamed helper is known by the slow paths that call it.
        let mut uses = BTreeMap::<u64, usize>::new();
        for (_, helper) in &checks {
            *uses.entry(*helper).or_default() += 1;
        }
        return checks
            .into_iter()
            .filter(|(_, helper)| helpers.contains(helper) || uses[helper] >= 3)
            .map(|(branch, _)| branch)
            .collect();
    }
    if !matches!(image.architecture, Architecture::X86 | Architecture::X64) {
        return Vec::new();
    }
    // `morestackc` aborts: functions that must run on the system stack check stackguard1 and
    // call it without branching back.
    let aborting = named(&["runtime.morestackc"]);
    let guarded: Vec<_> = go
        .functions
        .functions
        .iter()
        .filter_map(|function| guarded_branch(image, function.entry, function.end))
        .collect();
    // Garbled builds rename the runtime, so a helper is also known by its use: one that many
    // guarded slow paths call and branch back to their entry from.
    let mut uses = BTreeMap::<u64, usize>::new();
    for check in &guarded {
        for slow in [check.taken, check.fallthrough] {
            if let Some(SlowPath::Retries(helper)) = slow_path(image, slow, check.entry, check.end)
            {
                *uses.entry(helper).or_default() += 1;
            }
        }
    }
    let helpers: BTreeSet<u64> = uses
        .into_iter()
        .filter(|(helper, count)| morestack.contains(helper) || *count >= 3)
        .map(|(helper, _)| helper)
        .collect();
    let known = |slow: Option<SlowPath>| match slow {
        Some(SlowPath::Retries(helper)) => helpers.contains(&helper),
        Some(SlowPath::Aborts(helper)) => aborting.contains(&helper),
        None => false,
    };
    let mut branches = Vec::new();
    for check in guarded {
        let at = (check.address, check.length);
        if known(slow_path(image, check.taken, check.entry, check.end)) {
            branches.push((at.0, check.fallthrough, at.1));
        } else if known(slow_path(image, check.fallthrough, check.entry, check.end)) {
            branches.push((at.0, check.taken, at.1));
        }
    }
    branches
}

/// `ldr x16,[x28,#16]` (the goroutine's stackguard0), a compare, then `b.ls` to a slow path
/// that saves the link register, spills or reloads through SP, calls `morestack` once and
/// branches back to the entry. Returns the `b.ls` and its fall-through, as on x86.
fn aarch64_stack_check(
    image: &LoadedImage,
    entry: u64,
    end: u64,
) -> Option<((u64, u64, u32), u64)> {
    // `ldr x16,[x28,#16]`, or `#24` (stackguard1) for functions run on the system stack.
    const LDR_STACKGUARD: u32 = 0xf940_0b90;
    const LDR_STACKGUARD1: u32 = 0xf940_0f90;
    let word = |at: u64| {
        image
            .bytes_at(at, 4)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(u32::from_le_bytes)
    };
    // Sign-extended word offset of a branch immediate of `bits` bits at bit `shift`.
    let offset = |insn: u32, shift: u32, bits: u32| {
        let field = (insn >> shift) & ((1 << bits) - 1);
        (i64::from(field) << (64 - bits) >> (64 - bits)) * 4
    };
    let mut guard = false;
    let mut at = entry;
    for _ in 0..8 {
        let insn = word(at)?;
        if insn == LDR_STACKGUARD || insn == LDR_STACKGUARD1 {
            guard = true;
        } else if insn & 0xff00_001f == 0x5400_0009 {
            // b.ls: the slow path when SP is at or below the guard.
            if !guard {
                return None;
            }
            let slow = at.checked_add_signed(offset(insn, 5, 19))?;
            return aarch64_slow_path(image, slow, entry, end)
                .map(|helper| ((at, at + 4, 4), helper));
        } else if insn & 0xff00_0010 == 0x5400_0000 || insn & 0x7c00_0000 == 0x1400_0000 {
            return None;
        }
        at += 4;
    }
    None
}

/// The helper a slow path calls once before branching back to the entry.
fn aarch64_slow_path(image: &LoadedImage, mut at: u64, entry: u64, end: u64) -> Option<u64> {
    let mut called = None;
    for _ in 0..32 {
        if at < entry || at >= end {
            return None;
        }
        let insn = image
            .bytes_at(at, 4)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(u32::from_le_bytes)?;
        let target = |shift: u32, bits: u32| {
            let field = (insn >> shift) & ((1 << bits) - 1);
            at.checked_add_signed((i64::from(field) << (64 - bits) >> (64 - bits)) * 4)
        };
        if insn & 0xfc00_0000 == 0x9400_0000 {
            // bl
            if called.is_some() {
                return None;
            }
            called = Some(target(0, 26)?);
        } else if insn & 0xfc00_0000 == 0x1400_0000 {
            // b: back to the entry, after the call.
            return called.filter(|_| target(0, 26) == Some(entry));
        } else if insn == 0xaa1e_03e3 {
            // mov x3, x30: morestack's caller link register.
        } else if insn & 0x0a00_0000 == 0x0800_0000 && (insn >> 5) & 0x1f == 31 {
            // A load or store addressed through SP: argument spill or reload.
        } else {
            return None;
        }
        at += 4;
    }
    None
}

/// The conditional branch after a stack-guard comparison near a function's entry.
struct Guarded {
    entry: u64,
    end: u64,
    address: u64,
    length: u32,
    taken: u64,
    fallthrough: u64,
}

fn guarded_branch(image: &LoadedImage, entry: u64, end: u64) -> Option<Guarded> {
    let mut address = entry;
    let mut guard = false;
    for _ in 0..16 {
        let insn = image.decode_at(address).ok()?;
        let op = insn.x86_instruction();
        if insn.flow == Flow::ConditionalBranch {
            return guard.then_some(Guarded {
                entry,
                end,
                address,
                length: insn.bytes.len() as u32,
                taken: insn.direct_target?,
                fallthrough: insn.next_address,
            });
        }
        // stackguard0, or stackguard1 one word later for functions run on the system stack.
        guard = op.mnemonic() == Mnemonic::Cmp
            && op.op1_kind() == OpKind::Memory
            && op.memory_index() == Register::None
            && if image.architecture == Architecture::X64 {
                // R14 holds the goroutine from Go 1.17; before, RCX is loaded from TLS.
                matches!(op.memory_base(), Register::R14 | Register::RCX)
                    && matches!(op.memory_displacement64(), 16 | 24)
            } else {
                op.memory_base() == Register::ECX && matches!(op.memory_displacement64(), 8 | 12)
            };
        if insn.flow != Flow::Next {
            return None;
        }
        address = insn.next_address;
        if address >= end {
            return None;
        }
    }
    None
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SlowPath {
    /// Spills, a call, reloads and a branch back to the entry: `morestack`.
    Retries(u64),
    /// A call that does not come back: `morestackc`.
    Aborts(u64),
}

fn slow_path(image: &LoadedImage, mut address: u64, entry: u64, end: u64) -> Option<SlowPath> {
    let mut called = None;
    for _ in 0..32 {
        if address < entry || address >= end {
            return called.map(SlowPath::Aborts);
        }
        let insn = image.decode_at(address).ok()?;
        match insn.flow {
            Flow::Call if called.is_none() => called = Some(insn.direct_target?),
            Flow::UnconditionalBranch => {
                return (insn.direct_target == Some(entry)).then_some(SlowPath::Retries(called?));
            }
            Flow::Next => {
                let op = insn.x86_instruction();
                // Padding after the call, of any encoding (`nop dword ptr [rax+rax]`).
                if op.mnemonic() == Mnemonic::Nop || op.mnemonic() == Mnemonic::Int3 {
                    if op.mnemonic() == Mnemonic::Int3 {
                        return called.map(SlowPath::Aborts);
                    }
                } else {
                    // Argument spills and reloads through the stack pointer, in any width.
                    let moves = matches!(
                        op.mnemonic(),
                        Mnemonic::Mov
                            | Mnemonic::Movzx
                            | Mnemonic::Movsx
                            | Mnemonic::Movsxd
                            | Mnemonic::Movss
                            | Mnemonic::Movsd
                            | Mnemonic::Movups
                            | Mnemonic::Movaps
                            | Mnemonic::Movq
                    );
                    let memory = op.op0_kind() == OpKind::Memory || op.op1_kind() == OpKind::Memory;
                    if !moves
                        || op.memory_index() != Register::None
                        || (memory && !matches!(op.memory_base(), Register::ESP | Register::RSP))
                        || (op.op0_kind() == OpKind::Register
                            && matches!(op.op0_register(), Register::ESP | Register::RSP))
                    {
                        return None;
                    }
                }
            }
            _ => return None,
        }
        address = insn.next_address;
    }
    None
}

/// The runtime's `duffzero` or `duffcopy` by name, or, in a garbled build that renames the runtime,
/// by its body: one long Duff suffix from the entry to a `ret`.
pub(super) fn duff_helper<'a>(
    image: &LoadedImage,
    go: &'a GoBinary,
    name: &str,
) -> Option<&'a crate::golang::GoFunction> {
    let functions = &go.functions.functions;
    functions.iter().find(|f| f.name == name).or_else(|| {
        let copy = name == "runtime.duffcopy";
        if image.architecture == Architecture::AArch64 {
            // runtime/duff_arm64.s: `stp xzr,xzr,[x20],#16` 63 times before a last plain `stp`, or
            // `ldp x26,x27,[x20],#16; stp x26,x27,[x21],#16` 64 times, then `ret`.
            let body: &[u32] = if copy {
                &[0xa8c1_6e9a, 0xa881_6eba]
            } else {
                &[0xa881_7e9f]
            };
            return functions.iter().find(|f| {
                image
                    .bytes_at(f.entry, 63 * 4 * body.len())
                    .is_some_and(|bytes| {
                        bytes.len() == 63 * 4 * body.len()
                            && bytes.chunks_exact(4).enumerate().all(|(i, word)| {
                                u32::from_le_bytes([word[0], word[1], word[2], word[3]])
                                    == body[i % body.len()]
                            })
                    })
            });
        }
        functions.iter().find(|f| {
            // 386 `duffzero` is 128 one-byte `stosd`: 129 bytes of code clearing 512.
            f.end - f.entry >= 64
                && duff(image, f.entry, f.end, copy).is_some_and(|helper| helper.size >= 256)
        })
    })
}

/// Go 1.21+ arm64 write barriers whose names are gone, by shape: `gcWriteBarrier1` to `8` are
/// each `mov x25,#8n; b gcWriteBarrier`. At least four such stubs branching to one target name
/// it, with the conventions `special` gives the named helpers.
pub(super) fn arm64_write_barriers(image: &LoadedImage, go: &GoBinary) -> BTreeMap<u64, String> {
    let mut stubs = BTreeMap::<u64, Vec<u64>>::new();
    if image.architecture != Architecture::AArch64 {
        return BTreeMap::new();
    }
    for function in &go.functions.functions {
        if function.end - function.entry > 16 {
            continue;
        }
        let Some(bytes) = image.bytes_at(function.entry, 8).filter(|b| b.len() == 8) else {
            continue;
        };
        let first = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let second = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        // `orr x25,xzr,#imm` or `movz x25,#imm`, then `b`.
        let sets_x25 = first & 0x1f == 25
            && (first & 0xff80_03e0 == 0xb200_03e0 || first & 0xff80_0000 == 0xd280_0000);
        if !sets_x25 || second & 0xfc00_0000 != 0x1400_0000 {
            continue;
        }
        let offset = (i64::from(second & 0x03ff_ffff) << 38 >> 38) * 4;
        if let Some(target) = (function.entry + 4).checked_add_signed(offset) {
            stubs.entry(target).or_default().push(function.entry);
        }
    }
    let mut kinds = BTreeMap::new();
    for (target, entries) in stubs
        .into_iter()
        .filter(|(_, e)| (4..=8).contains(&e.len()))
    {
        kinds.insert(target, "gcwrite_batch_numbytes".to_owned());
        for entry in entries {
            kinds.insert(entry, "gcwrite_batch".to_owned());
        }
    }
    kinds
}

#[derive(Clone, Debug)]
pub(super) struct Duff {
    pub copy: bool,
    pub wide: bool,
    pub offset: u64,
    pub size: u64,
}

/// Validate complete suffixes, rather than assuming an offset/size formula for every Go version.
pub(super) fn duff(image: &LoadedImage, mut address: u64, end: u64, copy: bool) -> Option<Duff> {
    let wide = image.architecture == Architecture::X64;
    let mut size = 0;
    let mut dest = 0;
    let mut first = None;
    for _ in 0..1024 {
        if address >= end {
            return None;
        }
        let insn = image.decode_at(address).ok()?;
        let bytes = image.bytes_at(address, 16)?;
        if bytes.first() == Some(&0xc3) {
            return (size > 0).then_some(Duff {
                copy,
                wide,
                offset: first.unwrap_or(0),
                size,
            });
        }
        if copy {
            let pattern: &[u8] = if wide {
                &[
                    0x0f, 0x10, 0x06, 0x48, 0x83, 0xc6, 0x10, 0x0f, 0x11, 0x07, 0x48, 0x83, 0xc7,
                    0x10,
                ]
            } else {
                &[0x8b, 0x0e, 0x83, 0xc6, 4, 0x89, 0x0f, 0x83, 0xc7, 4]
            };
            if !bytes.starts_with(pattern) {
                return None;
            }
            size += if wide { 16 } else { 4 };
            address += pattern.len() as u64;
            continue;
        }
        if !wide {
            if bytes.first() != Some(&0xab) {
                return None;
            }
            size += 4;
        } else {
            let op = insn.x86_instruction();
            if op.mnemonic() == Mnemonic::Movups
                && op.op0_kind() == OpKind::Memory
                && op.memory_base() == Register::RDI
                && op.memory_index() == Register::None
                && matches!(op.op1_register(), Register::XMM0 | Register::XMM15)
            {
                let offset = dest + op.memory_displacement64();
                let start = *first.get_or_insert(offset);
                if offset != start + size {
                    return None;
                }
                size += 16;
            } else if op.mnemonic() == Mnemonic::Lea
                && op.op0_register() == Register::RDI
                && op.memory_base() == Register::RDI
                && op.memory_index() == Register::None
                && op.memory_displacement64() == 64
            {
                dest += 64;
            } else {
                return None;
            }
        }
        address = insn.next_address;
    }
    None
}

/// Replace only known helper call tokens, retaining newlines for the instruction mapping.
pub(super) fn render_duff(text: &str, helpers: &BTreeMap<String, Duff>) -> String {
    let mut text = text.to_owned();
    for (name, helper) in helpers {
        let mut from = text.find('{').unwrap_or(text.len());
        while let Some(start) = find_call(&text, from, name) {
            let open = start + name.len();
            let mut depth = 0i32;
            let mut commas = Vec::new();
            let mut close = None;
            for (i, byte) in text.bytes().enumerate().skip(open) {
                match byte {
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            close = Some(i);
                            break;
                        }
                    }
                    b',' if depth == 1 => commas.push(i),
                    _ => {}
                }
            }
            let Some(close) = close else {
                break;
            };
            let args = &text[open + 1..close];
            let valid = if helper.copy {
                commas.len() == 1
            } else if helper.wide {
                commas.is_empty()
            } else {
                commas.len() == 1 && text[commas[0] + 1..close].trim() == "0"
            };
            if !valid || args.contains(['"', '\'']) {
                from = close + 1;
                continue;
            }
            let mut args = args.to_owned();
            if helper.offset != 0 {
                let split = commas.first().map_or(args.len(), |i| i - open - 1);
                args.insert_str(split, &format!(")) + {}", helper.offset));
                args.insert_str(0, "((char *)(");
            }
            if !helper.copy && helper.wide {
                args.push_str(",0");
            }
            let replacement = format!(
                "{}({args},{})",
                if helper.copy { "memmove" } else { "memset" },
                helper.size
            );
            text.replace_range(start..=close, &replacement);
            from = start + replacement.len();
        }
    }
    text
}

fn find_call(text: &str, mut at: usize, name: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    while at < bytes.len() {
        if matches!(bytes[at], b'"' | b'\'') {
            let quote = bytes[at];
            at += 1;
            while at < bytes.len() {
                if bytes[at] == b'\\' {
                    at = (at + 2).min(bytes.len());
                } else if bytes[at] == quote {
                    at += 1;
                    break;
                } else {
                    at += 1;
                }
            }
        } else if bytes.get(at..at + 2) == Some(b"/*") {
            at += 2;
            while at < bytes.len() && bytes.get(at..at + 2) != Some(b"*/") {
                at += 1;
            }
            at = (at + 2).min(bytes.len());
        } else if bytes.get(at..at + 2) == Some(b"//") {
            while at < bytes.len() && bytes[at] != b'\n' {
                at += 1;
            }
        } else {
            let boundary = at == 0
                || !(bytes[at - 1].is_ascii_alphanumeric() || matches!(bytes[at - 1], b'_' | b'.'));
            if boundary
                && bytes.get(at..at + name.len()) == Some(name.as_bytes())
                && bytes.get(at + name.len()) == Some(&b'(')
            {
                return Some(at);
            }
            at += 1;
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::extract::image::SHELLCODE_BASE;

    #[test]
    fn aarch64_stack_growth_requires_the_guard_and_a_clean_retry() {
        use crate::golang::pclntab::{FunctionTable, GoFunction, Layout};
        let base = SHELLCODE_BASE;
        // ldr x16,[x28,#16]; cmp sp,x16; b.ls slow; ret;
        // slow: mov x3,x30; bl morestack; b entry; nop; morestack: ret.
        let program = [
            0xf940_0b90u32,
            0xeb30_63ff,
            0x5400_0049,
            0xd65f_03c0,
            0xaa1e_03e3,
            0x9400_0003,
            0x17ff_fffa,
            0xd503_201f,
            0xd65f_03c0,
        ];
        let function = |entry, end, name: &str| GoFunction {
            entry,
            end,
            name: name.into(),
            assembly: false,
            args_size: None,
        };
        let go = GoBinary {
            build_version: None,
            version_string: None,
            register_abi_evidence: false,
            functions: FunctionTable {
                address: 0,
                layout: Layout::Go120,
                pointer_size: 8,
                functions: vec![
                    function(base, base + 32, "main.main"),
                    function(base + 32, base + 36, "runtime.morestack_noctxt"),
                ],
            },
        };
        let checks = |words: &[u32]| {
            let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
            stack_checks(
                &LoadedImage::from_shellcode(&bytes, Architecture::AArch64),
                &go,
            )
        };
        assert_eq!(checks(&program), vec![(base + 8, base + 12, 4)]);
        // No stackguard load, other work on the slow path, or another callee: keep the branch.
        for (index, word) in [(0, 0xd503_201f), (4, 0x9100_0400), (5, 0x9400_0002)] {
            let mut words = program;
            words[index] = word;
            assert!(checks(&words).is_empty(), "word {index} = {word:#x}");
        }
    }

    #[test]
    fn stack_growth_requires_a_guard_helper_and_retry_without_other_side_effects() {
        use crate::golang::pclntab::{FunctionTable, GoFunction, Layout};
        let base = SHELLCODE_BASE;
        // cmp rsp,[r14+16]; jbe slow; ret; slow: call morestack; jmp entry.
        let mut bytes = vec![
            0x49, 0x3b, 0x66, 0x10, 0x76, 1, 0xc3, 0xe8, 4, 0, 0, 0, 0xeb, 0xf2, 0x90, 0x90, 0xc3,
        ];
        let go = GoBinary {
            build_version: None,
            version_string: None,
            register_abi_evidence: true,
            functions: FunctionTable {
                address: 0,
                layout: Layout::Go116,
                pointer_size: 8,
                functions: vec![
                    GoFunction {
                        entry: base,
                        end: base + 16,
                        name: "main.main".into(),
                        assembly: false,
                        args_size: None,
                    },
                    GoFunction {
                        entry: base + 16,
                        end: base + 17,
                        name: "runtime.morestack".into(),
                        assembly: true,
                        args_size: None,
                    },
                ],
            },
        };
        let image = LoadedImage::from_shellcode(&bytes, Architecture::X64);
        assert_eq!(stack_checks(&image, &go), vec![(base + 4, base + 6, 2)]);
        bytes[8] = 5; // An unrelated call cannot be discarded.
        let image = LoadedImage::from_shellcode(&bytes, Architecture::X64);
        assert!(stack_checks(&image, &go).is_empty());
        let image = LoadedImage::from_shellcode(
            &[0x48, 0x89, 0x07, 0xe8, 8, 0, 0, 0, 0xeb, 0xf6],
            Architecture::X64,
        );
        // A store through RDI is not an argument spill.
        assert!(slow_path(&image, base, base, base + 10).is_none());
    }

    #[test]
    fn garbled_stack_growth_helper_is_known_by_its_callers() {
        use crate::golang::pclntab::{FunctionTable, GoFunction, Layout};
        let base = SHELLCODE_BASE;
        // Three functions of 20 bytes, then the helper (`ret`) at 60:
        // cmp rsp,[r14+16]; jbe slow; ret; slow: call helper; nop dword [rax+rax]; jmp entry.
        let mut bytes = Vec::new();
        let mut functions = Vec::new();
        for index in 0..3u64 {
            let at = 20 * index;
            let call = (60 - (at + 12)) as u8;
            let back = (0u8).wrapping_sub(19);
            bytes.extend([0x49, 0x3b, 0x66, 0x10, 0x76, 1, 0xc3, 0xe8, call, 0, 0, 0]);
            bytes.extend([0x0f, 0x1f, 0x44, 0, 0, 0xeb, back, 0xcc]);
            functions.push(GoFunction {
                entry: base + at,
                end: base + at + 20,
                name: format!("aBcD{index}"),
                assembly: false,
                args_size: None,
            });
        }
        bytes.push(0xc3);
        functions.push(GoFunction {
            entry: base + 60,
            end: base + 61,
            name: "xYz".into(),
            assembly: true,
            args_size: None,
        });
        let mut go = GoBinary {
            build_version: None,
            version_string: None,
            register_abi_evidence: true,
            functions: FunctionTable {
                address: 0,
                layout: Layout::Go120,
                pointer_size: 8,
                functions,
            },
        };
        let image = LoadedImage::from_shellcode(&bytes, Architecture::X64);
        let expected: Vec<_> = (0..3)
            .map(|i| (base + 20 * i + 4, base + 20 * i + 6, 2))
            .collect();
        assert_eq!(stack_checks(&image, &go), expected);
        // Two callers are not enough evidence for an unnamed helper.
        go.functions.functions.remove(0);
        assert!(stack_checks(&image, &go).is_empty());
    }

    #[test]
    fn garbled_duff_helper_is_found_by_its_body() {
        use crate::golang::pclntab::{FunctionTable, GoFunction, Layout};
        // 386 `duffzero`: 128 `stosd` and a `ret`, under an obfuscated name.
        let mut bytes = vec![0xc3; 16];
        bytes.extend(vec![0xab; 128]);
        bytes.push(0xc3);
        let base = SHELLCODE_BASE;
        let function = |entry: u64, end: u64, name: &str| GoFunction {
            entry,
            end,
            name: name.into(),
            assembly: true,
            args_size: None,
        };
        let go = GoBinary {
            build_version: None,
            version_string: None,
            register_abi_evidence: false,
            functions: FunctionTable {
                address: 0,
                layout: Layout::Go120,
                pointer_size: 4,
                functions: vec![
                    function(base, base + 16, "aBc"),
                    function(base + 16, base + 145, "PrLzWq"),
                ],
            },
        };
        let image = LoadedImage::from_shellcode(&bytes, Architecture::X86);
        let helper = duff_helper(&image, &go, "runtime.duffzero").unwrap();
        assert_eq!(helper.entry, base + 16);
        assert!(duff_helper(&image, &go, "runtime.duffcopy").is_none());
    }

    #[test]
    fn renamed_arm64_write_barriers_and_duffzero_are_found_by_shape() {
        use crate::golang::pclntab::{FunctionTable, GoFunction, Layout};
        let base = SHELLCODE_BASE;
        // gcWriteBarrier at 0, then four stubs `mov x25,#8n; b gcWriteBarrier` of 16 bytes, then
        // `duffzero`: 63 `stp xzr,xzr,[x20],#16`, one `stp xzr,xzr,[x20]`, `ret`.
        let mut words = vec![0xd65f_03c0u32, 0, 0, 0];
        for n in 1..=4u32 {
            let at = words.len() as u32;
            words.push(0xd280_0019 | (8 * n) << 5);
            words.push(0x1400_0000 | (0u32.wrapping_sub(at + 1) & 0x03ff_ffff));
            words.extend([0, 0]);
        }
        let duffzero = words.len() as u64 * 4;
        words.extend(std::iter::repeat_n(0xa881_7e9f, 63));
        words.extend([0xa900_7e9f, 0xd65f_03c0]);
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let function = |entry: u64, end: u64| GoFunction {
            entry: base + entry,
            end: base + end,
            name: format!("FUN_{entry:x}"),
            assembly: true,
            args_size: None,
        };
        let mut functions = vec![function(0, 16)];
        functions.extend((1..=4).map(|n| function(16 * n, 16 * n + 16)));
        functions.push(function(duffzero, duffzero + 65 * 4));
        let go = GoBinary {
            build_version: None,
            version_string: None,
            register_abi_evidence: true,
            functions: FunctionTable {
                address: 0,
                layout: Layout::Go120,
                pointer_size: 8,
                functions,
            },
        };
        let image = LoadedImage::from_shellcode(&bytes, Architecture::AArch64);
        let barriers = arm64_write_barriers(&image, &go);
        assert_eq!(
            barriers.get(&base).map(String::as_str),
            Some("gcwrite_batch_numbytes")
        );
        assert!((1..=4)
            .all(|n| barriers.get(&(base + 16 * n)).map(String::as_str) == Some("gcwrite_batch")));
        let helper = duff_helper(&image, &go, "runtime.duffzero").unwrap();
        assert_eq!(helper.entry, base + duffzero);
        assert!(duff_helper(&image, &go, "runtime.duffcopy").is_none());
    }

    #[test]
    fn duff_suffix_size_is_decoded_and_not_guessed_from_offset() {
        let image = LoadedImage::from_shellcode(&[0xab, 0xab, 0xab, 0xc3], Architecture::X86);
        let helper = duff(&image, SHELLCODE_BASE + 1, SHELLCODE_BASE + 4, false).unwrap();
        assert_eq!(helper.size, 8);
        let helpers = BTreeMap::from([("go_duffzero_1001".to_owned(), helper)]);
        let text = "void f() {\n  go_duffzero_1001((void *)(p + 1),0);\n}";
        let rendered = render_duff(text, &helpers);
        assert!(rendered.contains("memset((void *)(p + 1),0,8)"));
        assert_eq!(text.lines().count(), rendered.lines().count());
        assert_eq!(
            render_duff("void f() { go_duffzero_1001(p,0x1234); }", &helpers),
            "void f() { go_duffzero_1001(p,0x1234); }"
        );
        let quoted = "void f() { puts(\"go_duffzero_1001(p,0)\"); /* go_duffzero_1001(p,0); */ }";
        assert_eq!(render_duff(quoted, &helpers), quoted);
        let image = LoadedImage::from_shellcode(&[0xab, 0x90, 0xc3], Architecture::X86);
        assert!(duff(&image, SHELLCODE_BASE, SHELLCODE_BASE + 3, false).is_none());
    }
}
