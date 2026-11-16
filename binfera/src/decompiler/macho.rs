//! Objective-C metadata supplies method types and selector-bearing thunk names.
use super::{Analysis, Architecture, DecompileError, DecompilerSession, ValueType};
use crate::extract::loader::macho_metadata::Metadata;
use std::collections::BTreeMap;

/// Only scalar and pointer encodings have unambiguous storage here. Aggregate,
/// vector, bit-field and unknown encodings stay inferred.
fn signature(encoding: &str) -> Option<(ValueType, Vec<ValueType>)> {
    let mut chars = encoding.chars().peekable();
    let mut types = Vec::new();
    while let Some(ch) = chars.next() {
        if ch.is_ascii_digit() || matches!(ch, '+' | '-' | 'r' | 'n' | 'N' | 'o' | 'O' | 'R' | 'V')
        {
            continue;
        }
        let value = match ch {
            'v' => ValueType::Void,
            'c' => ValueType::I8,
            'C' => ValueType::U8,
            's' => ValueType::I16,
            'S' => ValueType::U16,
            'i' | 'l' => ValueType::I32,
            'I' | 'L' => ValueType::U32,
            'q' => ValueType::I64,
            'Q' => ValueType::U64,
            'f' => ValueType::F32,
            'd' => ValueType::F64,
            'B' => ValueType::Bool,
            '*' | ':' => ValueType::CharPointer,
            '@' | '#' => {
                if chars.peek() == Some(&'?') {
                    chars.next();
                }
                if chars.peek() == Some(&'"') {
                    chars.next();
                    loop {
                        if chars.next()? == '"' {
                            break;
                        }
                    }
                }
                ValueType::Pointer
            }
            _ => return None,
        };
        types.push(value);
        if types.len() > 33 {
            return None;
        }
    }
    let result = *types.first()?;
    let parameters = types.get(1..)?.to_vec();
    (!parameters.contains(&ValueType::Void)).then_some((result, parameters))
}

pub(super) fn selector_stubs(
    analysis: &Analysis,
    metadata: &Metadata,
) -> BTreeMap<u64, (String, u64, u64)> {
    let mut stubs = BTreeMap::new();
    if analysis.image.architecture != Architecture::AArch64 {
        return stubs;
    }
    let image = &analysis.image;
    for &address in analysis.functions.keys() {
        let Some(second) = address.checked_add(4) else {
            continue;
        };
        let (Ok(first), Ok(second)) = (image.decode_at(address), image.decode_at(second)) else {
            continue;
        };
        // Apple's objc_msgSend$selector stubs load the selector into x1 and
        // then use the normal x16 import thunk. Verify both halves.
        let Some(word) = second
            .bytes
            .get(..4)
            .and_then(|v| <[u8; 4]>::try_from(v).ok())
            .map(u32::from_le_bytes)
        else {
            continue;
        };
        if word & 31 != 1 {
            continue;
        }
        let Some(selector) = crate::extract::decoder::aarch64_plt_got_target(&first, &second)
            .and_then(|slot| metadata.selectors.get(&slot))
        else {
            continue;
        };
        let Some((branch, slot)) = address
            .checked_add(8)
            .and_then(|at| super::aarch64_import_thunk(analysis, at))
        else {
            continue;
        };
        if !image
            .import_locations
            .get(&slot)
            .is_some_and(|name| name.ends_with(".objc_msgSend"))
        {
            continue;
        }
        stubs.insert(
            address,
            (
                format!("objc_msgSend${}", selector.replace(':', "_")),
                branch,
                slot,
            ),
        );
    }
    stubs
}

pub(super) fn apply(
    session: &mut DecompilerSession,
    analysis: &Analysis,
    metadata: &Metadata,
) -> Result<(), DecompileError> {
    let init = |e: binfera_ghidra::Error| DecompileError::Initialization(e.to_string());
    for (address, encoding) in &metadata.signatures {
        if session.in_code(*address) {
            if let Some((result, parameters)) = signature(encoding) {
                session
                    .native
                    .set_signature(*address, result, &parameters)
                    .map_err(init)?;
            }
        }
    }
    if analysis.image.architecture == Architecture::X64 {
        let swift_metadata = metadata
            .labels
            .values()
            .any(|name| name.ends_with("::type_descriptor"));
        let mut self_functions = std::collections::BTreeSet::new();
        if swift_metadata {
            // A direct Swift call also consumes the preserved self register.
            // Propagate that evidence through short wrapper chains.
            for _ in 0..4 {
                let previous = self_functions.len();
                for address in analysis.functions.keys() {
                    let function = &analysis.functions[address];
                    let forwards_self =
                        function.blocks.iter().flat_map(|b| &b.insns).any(|i| {
                            i.direct_target
                                .is_some_and(|target| self_functions.contains(&target))
                        }) && function.blocks.iter().flat_map(|b| &b.insns).all(|i| {
                            !super::InstructionInfoFactory::new()
                                .info(i.x86_instruction())
                                .used_registers()
                                .iter()
                                .any(|r| {
                                    r.register().full_register() == super::Register::R13
                                        && matches!(
                                            r.access(),
                                            super::OpAccess::Write
                                                | super::OpAccess::CondWrite
                                                | super::OpAccess::ReadWrite
                                                | super::OpAccess::ReadCondWrite
                                        )
                                })
                        });
                    if super::conventions::inputs_with_callees(
                        analysis,
                        *address,
                        &[super::Register::R13],
                        &self_functions,
                    )
                    .contains(&super::Register::R13)
                        || forwards_self
                    {
                        self_functions.insert(*address);
                    }
                }
                if previous == self_functions.len() {
                    break;
                }
            }
        }
        for address in analysis.functions.keys() {
            let name = session.names.get(address).map(String::as_str).unwrap_or("");
            let raw = name.trim_start_matches('_');
            let named = raw.starts_with("$s")
                || raw.starts_with("$S")
                || raw.starts_with("T0")
                || name.ends_with("::metadata_accessor");
            let self_input = self_functions.contains(address)
                || (named
                    && super::conventions::inputs(analysis, *address, &[super::Register::R13])
                        .contains(&super::Register::R13));
            if named || self_input {
                session
                    .native
                    .set_function_model(
                        *address,
                        if self_input {
                            "__swiftself"
                        } else {
                            "__swiftcall"
                        },
                    )
                    .map_err(init)?;
            }
        }
    }
    let thunks = super::import_thunks(analysis);
    for (address, import) in analysis.image.import_locations.iter().chain(thunks.iter()) {
        let Some((library, name)) = import.rsplit_once('.') else {
            continue;
        };
        if !matches!(library, "libobjc.A" | "libobjc") {
            continue;
        }
        if name == "objc_msgSend" || name == "objc_msgSendSuper2" {
            session
                .native
                .set_method_signature(
                    *address,
                    "__cdecl",
                    "",
                    ValueType::Pointer,
                    &[ValueType::Pointer, ValueType::CharPointer],
                    true,
                )
                .map_err(init)?;
            continue;
        }
        let (result, parameters): (_, &[ValueType]) = match name {
            "class_createInstance" => (ValueType::Pointer, &[ValueType::Pointer, ValueType::U64]),
            "objc_opt_new"
            | "objc_alloc"
            | "objc_alloc_init"
            | "objc_retain"
            | "objc_autorelease"
            | "objc_retainAutoreleasedReturnValue"
            | "objc_autoreleaseReturnValue" => (ValueType::Pointer, &[ValueType::Pointer]),
            "objc_release" => (ValueType::Void, &[ValueType::Pointer]),
            "objc_storeStrong" => (
                ValueType::Void,
                &[ValueType::PointerPointer, ValueType::Pointer],
            ),
            _ => continue,
        };
        session
            .native
            .set_signature(*address, result, parameters)
            .map_err(init)?;
    }
    for (address, (_, branch, slot)) in selector_stubs(analysis, metadata) {
        session
            .native
            .add_tail_call(address, branch, slot)
            .map_err(init)?;
    }
    let senders: std::collections::BTreeSet<u64> = analysis
        .image
        .import_locations
        .iter()
        .chain(thunks.iter())
        .filter(|(_, import)| {
            import.rsplit_once('.').is_some_and(|(library, name)| {
                matches!(library, "libobjc.A" | "libobjc")
                    && matches!(name, "objc_msgSend" | "objc_msgSendSuper2")
            })
        })
        .map(|(address, _)| *address)
        .collect();
    for (caller, site, count) in message_sends(analysis, metadata, &senders) {
        session
            .native
            .set_message_send(caller, site, count)
            .map_err(init)?;
    }
    Ok(())
}

/// Calls to `objc_msgSend` whose selector the caller loads from `__objc_selrefs` just before, as
/// (caller, call site, argument count): self, the selector, then one per colon.
fn message_sends(
    analysis: &Analysis,
    metadata: &Metadata,
    senders: &std::collections::BTreeSet<u64>,
) -> Vec<(u64, u64, u32)> {
    let mut sends = Vec::new();
    for (caller, function) in &analysis.functions {
        for block in &function.blocks {
            for (index, insn) in block.insns.iter().enumerate() {
                let target = insn.direct_target.or_else(|| {
                    // `call qword ptr [rip+slot]` through the import slot itself.
                    (analysis.image.architecture == Architecture::X64
                        && insn.flow == crate::extract::decoder::Flow::IndirectCall)
                        .then(|| insn.x86_instruction())
                        .filter(|op| op.is_ip_rel_memory_operand())
                        .map(|op| op.ip_rel_memory_address())
                });
                if !matches!(
                    insn.flow,
                    crate::extract::decoder::Flow::Call
                        | crate::extract::decoder::Flow::IndirectCall
                ) || !target.is_some_and(|t| senders.contains(&t))
                {
                    continue;
                }
                let selector = match analysis.image.architecture {
                    Architecture::X64 => x64_selector(&block.insns[..index]),
                    Architecture::AArch64 => aarch64_selector(&block.insns[..index]),
                    _ => None,
                };
                let Some(selector) = selector.and_then(|slot| metadata.selectors.get(&slot)) else {
                    continue;
                };
                let colons = selector.bytes().filter(|b| *b == b':').count() as u32;
                sends.push((*caller, insn.address, 2 + colons));
            }
        }
    }
    sends
}

/// The selector slot of the last write to RSI before a call: `mov rsi,[rip+selref]`.
fn x64_selector(before: &[crate::extract::decoder::DecodedInstruction]) -> Option<u64> {
    use super::{InstructionInfoFactory, OpAccess, Register};
    let mut info = InstructionInfoFactory::new();
    for insn in before.iter().rev().take(16) {
        let op = insn.x86_instruction();
        let writes = info.info(op).used_registers().iter().any(|r| {
            r.register().full_register() == Register::RSI
                && !matches!(r.access(), OpAccess::Read | OpAccess::CondRead)
        });
        if writes {
            return (op.mnemonic() == iced_x86::Mnemonic::Mov
                && op.op0_register() == Register::RSI
                && op.is_ip_rel_memory_operand())
            .then(|| op.ip_rel_memory_address());
        }
    }
    None
}

/// The selector slot loaded into x1 before a call: `adrp xN, page; ldr x1, [xN, #offset]`, with
/// no other instruction naming x1 as its destination in between.
fn aarch64_selector(before: &[crate::extract::decoder::DecodedInstruction]) -> Option<u64> {
    let word = |insn: &crate::extract::decoder::DecodedInstruction| {
        insn.bytes
            .get(..4)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(u32::from_le_bytes)
    };
    let mut iter = before.iter().enumerate().rev().take(16);
    let (index, ldr) = iter.find(|(_, insn)| word(insn).is_some_and(|w| w & 31 == 1))?;
    let ldr_word = word(ldr)?;
    if ldr_word & 0xffc0_001f != 0xf940_0001 {
        return None;
    }
    let base = (ldr_word >> 5) & 31;
    let (adrp_insn, adrp) = before[..index]
        .iter()
        .rev()
        .take(8)
        .find_map(|insn| word(insn).filter(|w| w & 31 == base).map(|w| (insn, w)))?;
    if adrp & 0x9f00_0000 != 0x9000_0000 {
        return None;
    }
    let immediate = (((adrp >> 5) & 0x7ffff) << 2) | ((adrp >> 29) & 3);
    let offset = ((immediate as i64) << 43) >> 31;
    let page = (adrp_insn.address & !0xfff).wrapping_add_signed(offset);
    Some(page.wrapping_add(u64::from((ldr_word >> 10) & 0xfff) * 8))
}

/// References to constant `CFString` objects (`cfstr_…`, or `&cfstr_…`), outside literals and
/// comments, as `CFSTR("…")`.
pub(super) fn render_cfstrings(text: &str, cfstrings: &BTreeMap<String, String>) -> String {
    let masked = super::unit::mask_literals(text);
    let bytes = masked.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    let mut from = 0;
    while let Some(found) = masked[from..].find("cfstr_") {
        let name_start = from + found;
        let end = name_start
            + masked[name_start..]
                .bytes()
                .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
                .count();
        from = end;
        if name_start > 0
            && (bytes[name_start - 1].is_ascii_alphanumeric() || bytes[name_start - 1] == b'_')
        {
            continue;
        }
        let start = if name_start > 0 && bytes[name_start - 1] == b'&' {
            name_start - 1
        } else {
            name_start
        };
        if let Some(value) = cfstrings.get(&text[name_start..end]) {
            out.push_str(&text[last..start]);
            out.push_str(&format!(
                "CFSTR({})",
                super::stack_strings::literal(value.as_bytes())
            ));
            last = end;
        }
    }
    out.push_str(&text[last..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_cfstrings_print_their_text() {
        let strings = BTreeMap::from([("cfstr_1000".to_owned(), "/bin/bash".to_owned())]);
        assert_eq!(
            render_cfstrings(
                "f(&cfstr_1000,cfstr_1000,xcfstr_1000,&cfstr_2000); /* cfstr_1000 */ g(\"cfstr_1000\");",
                &strings
            ),
            "f(CFSTR(\"/bin/bash\"),CFSTR(\"/bin/bash\"),xcfstr_1000,&cfstr_2000); /* cfstr_1000 */ g(\"cfstr_1000\");"
        );
    }
    #[test]
    fn encodings_preserve_self_selector_and_scalar_storage() {
        assert_eq!(
            signature("q24@0:8q16"),
            Some((
                ValueType::I64,
                vec![ValueType::Pointer, ValueType::CharPointer, ValueType::I64]
            ))
        );
        assert_eq!(signature("{Pair=ii}16@0:8"), None);
        assert_eq!(
            signature("v24@0:8@\"NSObject\"16"),
            Some((
                ValueType::Void,
                vec![
                    ValueType::Pointer,
                    ValueType::CharPointer,
                    ValueType::Pointer
                ]
            ))
        );
    }
}
