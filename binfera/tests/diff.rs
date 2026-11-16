//! Comparing binaries: what must count as a change, and what must not.
use binfera::diff::{
    compare, diff_functions, fingerprint, is_fingerprint, ChangeReason, DiffDocument, Fingerprint,
    FingerprintOptions, Verdict,
};

const ELF: &[u8] = include_bytes!("fixtures/elf64_sysv/dynamic.elf");
const DLL32: &[u8] = include_bytes!("fixtures/cpp/rtti32.dll");
const DLL64: &[u8] = include_bytes!("fixtures/cpp/rtti64.dll");
const ARM64: &[u8] = include_bytes!("fixtures/macho/thin-arm64-exe");
const X64: &[u8] = include_bytes!("fixtures/macho/thin-x86_64-exe");

type Outcome = Result<(), Box<dyn std::error::Error>>;

fn print(bytes: &[u8]) -> Result<Fingerprint, binfera::diff::DiffError> {
    fingerprint(
        bytes,
        &FingerprintOptions {
            detail: true,
            name: "sample".to_string(),
            ..FingerprintOptions::default()
        },
    )
}

fn diff(a: &[u8], b: &[u8]) -> Result<DiffDocument, binfera::diff::DiffError> {
    Ok(compare(&print(a)?, &print(b)?, None))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Every string a function references, with the function's address.
fn string_user(print: &Fingerprint) -> Option<(u64, String)> {
    print.functions.iter().find_map(|function| {
        function.refs.iter().find_map(|reference| match reference {
            binfera::diff::Ref::Str(text) => Some((function.address, text.clone())),
            _ => None,
        })
    })
}

#[test]
fn a_file_is_identical_to_itself() -> Outcome {
    let document = diff(ELF, ELF)?;
    assert_eq!(document.verdict, Verdict::Identical);
    assert!(!document.matches.is_empty());
    assert!(document
        .matches
        .iter()
        .all(|m| !m.changed && m.a_addr == m.b_addr));
    assert!(document.unmatched_a.is_empty() && document.unmatched_b.is_empty());
    assert_eq!(document.similarity.overall, 1.0);
    Ok(())
}

/// The failure a masked function hash cannot see: same instructions, a different string.
#[test]
fn a_changed_string_marks_the_function_changed() -> Outcome {
    let original = print(ELF)?;
    let (address, text) = string_user(&original).ok_or("no function references a string")?;
    let mut patched = ELF.to_vec();
    let at = find(&patched, text.as_bytes()).ok_or("string not in the file")?;
    patched[at] ^= 0x01;
    let document = compare(&original, &print(&patched)?, None);
    assert_eq!(document.verdict, Verdict::Changed);
    let found = document
        .matches
        .iter()
        .find(|m| m.a_addr == address)
        .ok_or("function not matched")?;
    assert!(found.changed, "{found:?}");
    assert_eq!(found.reasons, [ChangeReason::String]);
    assert_eq!(found.b_addr, address);
    let others = document.matches.iter().filter(|m| m.changed).count();
    assert!(others <= 2, "a string change touched {others} functions");
    Ok(())
}

/// The other one: same bytes around the call, a different callee.
#[test]
fn a_redirected_call_marks_the_function_changed() -> Outcome {
    let original = print(ELF)?;
    let caller = original
        .functions
        .iter()
        .find(|f| {
            f.refs
                .iter()
                .any(|r| matches!(r, binfera::diff::Ref::Call(_)))
        })
        .ok_or("no function calls another")?;
    let detail = original.details.get(&caller.address).ok_or("no listing")?;
    let call = detail
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .find(|insn| insn.bytes.starts_with("e8"))
        .ok_or("no direct call")?;
    let image = binfera::extract::image::LoadedImage::parse(ELF)?;
    let offset = image.va_to_file_offset(call.address).ok_or("unmapped")? as usize;
    let mut patched = ELF.to_vec();
    // Back to the function's own start: the encoding stays a direct call.
    let relative = (caller.address as i64 - (call.address as i64 + 5)) as i32;
    patched[offset + 1..offset + 5].copy_from_slice(&relative.to_le_bytes());

    let document = compare(&original, &print(&patched)?, None);
    let found = document
        .matches
        .iter()
        .find(|m| m.a_addr == caller.address)
        .ok_or("caller not matched")?;
    assert!(found.changed, "{found:?}");
    assert!(found.reasons.contains(&ChangeReason::Callee), "{found:?}");
    assert!(
        !found.evidence.callees_only_a.is_empty() || !found.evidence.callees_only_b.is_empty(),
        "{:?}",
        found.evidence
    );

    // The instruction reads the same once masked, so only the function match can show it.
    let patched = print(&patched)?;
    let forward = binfera::diff::function_map(&original, &patched);
    let (Some(old), Some(new)) = (
        original.details.get(&caller.address),
        patched.details.get(&caller.address),
    ) else {
        return Err("no listing".into());
    };
    let rows = diff_functions(old, new, Some(&forward));
    let moved = rows.blocks.iter().flat_map(|block| &block.rows).any(|row| {
        row.status != binfera::diff::pair::Status::Same
            && row
                .a
                .as_ref()
                .is_some_and(|insn| insn.address == call.address)
    });
    assert!(moved, "the redirected call should be a changed row");
    Ok(())
}

/// The score can be checked against what it was made from.
#[test]
fn a_changed_function_says_what_changed() -> Outcome {
    let original = print(ELF)?;
    let (address, text) = string_user(&original).ok_or("no function references a string")?;
    let mut patched = ELF.to_vec();
    let at = find(&patched, text.as_bytes()).ok_or("string not in the file")?;
    patched[at] ^= 0x01;
    let document = compare(&original, &print(&patched)?, None);
    let found = document
        .matches
        .iter()
        .find(|m| m.a_addr == address)
        .ok_or("function not matched")?;
    let evidence = &found.evidence;
    assert!(evidence.same_instructions);
    assert_eq!(evidence.strings_only_a, std::slice::from_ref(&text));
    assert_eq!(evidence.strings_only_b.len(), 1);
    assert_ne!(evidence.strings_only_b, std::slice::from_ref(&text));
    assert!(!evidence.signals.is_empty());
    assert!(evidence
        .signals
        .iter()
        .all(|s| (0.0..=1.0).contains(&s.value)));
    Ok(())
}

/// A changed string has to reach the listing too, or the row would read as unchanged.
#[test]
fn a_changed_string_is_a_changed_row() -> Outcome {
    let original = print(ELF)?;
    let (address, text) = string_user(&original).ok_or("no function references a string")?;
    let mut patched = ELF.to_vec();
    let at = find(&patched, text.as_bytes()).ok_or("string not in the file")?;
    patched[at] ^= 0x01;
    let patched = print(&patched)?;
    let (Some(old), Some(new)) = (
        original.details.get(&address),
        patched.details.get(&address),
    ) else {
        return Err("no listing".into());
    };
    let rows = diff_functions(old, new, None);
    let changed: Vec<_> = rows
        .blocks
        .iter()
        .flat_map(|block| &block.rows)
        .filter(|row| row.status != binfera::diff::pair::Status::Same)
        .collect();
    assert_eq!(changed.len(), 1, "{changed:?}");
    assert!(changed[0]
        .a
        .as_ref()
        .and_then(|i| i.note.as_ref())
        .is_some());
    Ok(())
}

/// Applies a PE's base relocations for a new image base.
fn rebase(pe: &[u8], delta: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let image = binfera::extract::image::LoadedImage::parse(pe)?;
    let le32 = |at: usize| -> Result<u32, Box<dyn std::error::Error>> {
        Ok(u32::from_le_bytes(pe[at..at + 4].try_into()?))
    };
    let optional = le32(0x3c)? as usize + 24;
    let wide = pe[optional..optional + 2] == [0x0b, 0x02];
    let mut out = pe.to_vec();
    let base = if wide {
        let base = u64::from_le_bytes(pe[optional + 24..optional + 32].try_into()?);
        out[optional + 24..optional + 32].copy_from_slice(&(base + delta).to_le_bytes());
        base
    } else {
        let base = u64::from(le32(optional + 28)?);
        out[optional + 28..optional + 32].copy_from_slice(&((base + delta) as u32).to_le_bytes());
        base
    };
    let directory = optional + if wide { 112 } else { 96 } + 5 * 8;
    let (rva, size) = (le32(directory)?, le32(directory + 4)?);
    assert!(size > 0, "the fixture must have base relocations");
    let mut at = image
        .va_to_file_offset(base + u64::from(rva))
        .ok_or("relocations unmapped")? as usize;
    let end = at + size as usize;
    while at + 8 <= end {
        let (page, length) = (le32(at)?, le32(at + 4)? as usize);
        if length < 8 {
            break;
        }
        for entry in pe[at + 8..at + length].as_chunks::<2>().0 {
            let word = u16::from_le_bytes(*entry);
            let va = base + u64::from(page) + u64::from(word & 0xfff);
            match word >> 12 {
                10 => {
                    let slot = image.va_to_file_offset(va).ok_or("slot unmapped")? as usize;
                    let value = u64::from_le_bytes(out[slot..slot + 8].try_into()?);
                    out[slot..slot + 8].copy_from_slice(&(value + delta).to_le_bytes());
                }
                3 => {
                    let slot = image.va_to_file_offset(va).ok_or("slot unmapped")? as usize;
                    let value = u32::from_le_bytes(out[slot..slot + 4].try_into()?);
                    out[slot..slot + 4].copy_from_slice(&(value + delta as u32).to_le_bytes());
                }
                _ => {}
            }
        }
        at += length;
    }
    Ok(out)
}

#[test]
fn a_rebased_copy_is_equivalent() -> Outcome {
    for dll in [DLL32, DLL64] {
        let rebased = rebase(dll, 0x1000_0000)?;
        assert_ne!(rebased, dll);
        let document = diff(dll, &rebased)?;
        assert!(document.file_delta.is_empty(), "{:?}", document.file_delta);
        assert!(document.unmatched_a.is_empty() && document.unmatched_b.is_empty());
        let changed: Vec<_> = document.matches.iter().filter(|m| m.changed).collect();
        assert!(changed.is_empty(), "{changed:?}");
        assert_eq!(document.verdict, Verdict::Equivalent);
    }
    Ok(())
}

#[test]
fn matching_does_not_depend_on_which_run_produced_it() -> Outcome {
    let first = diff(DLL64, ELF)?;
    let second = diff(DLL64, ELF)?;
    assert_eq!(
        serde_json::to_string(&first)?,
        serde_json::to_string(&second)?
    );
    Ok(())
}

#[test]
fn fingerprints_round_trip_and_compare_the_same() -> Outcome {
    let original = print(ELF)?;
    let mut written = Vec::new();
    original.write_ndjson(&mut written)?;
    assert!(is_fingerprint(&written));
    assert!(!is_fingerprint(ELF));
    let read = Fingerprint::read_ndjson(written.as_slice())?;
    assert!(read == original, "the file read back differs");
    assert_eq!(
        compare(&read, &read, None),
        compare(&original, &original, None)
    );
    Ok(())
}

#[test]
fn different_architectures_compare_files_but_not_functions() -> Outcome {
    let document = diff(X64, ARM64)?;
    assert!(!document.functions_compared);
    assert!(document.matches.is_empty());
    assert_eq!(document.verdict, Verdict::Changed);
    assert!(document
        .warnings
        .iter()
        .any(|w| w.contains("architectures")));
    Ok(())
}

#[test]
fn aarch64_addresses_are_masked_and_strings_resolved() -> Outcome {
    let original = print(ARM64)?;
    assert!(original
        .details
        .values()
        .flat_map(|function| &function.blocks)
        .flat_map(|block| &block.instructions)
        .filter(|insn| insn.text.starts_with("adrp"))
        .all(|insn| insn.norm.contains('@')),);
    assert!(
        string_user(&original).is_some(),
        "adrp+add should resolve a string"
    );
    Ok(())
}

#[test]
fn a_pair_diff_finds_the_changed_instruction() -> Outcome {
    let original = print(ELF)?;
    let function = original
        .details
        .values()
        .max_by_key(|f| f.blocks.iter().map(|b| b.instructions.len()).sum::<usize>())
        .ok_or("no functions")?;
    let same = diff_functions(function, function, None);
    assert_eq!(same.similarity, 1.0);

    let mut edited = function.clone();
    let insn = edited
        .blocks
        .iter_mut()
        .flat_map(|block| &mut block.instructions)
        .nth(1)
        .ok_or("too small")?;
    insn.norm = format!("{} ; patched", insn.norm);
    let changed = diff_functions(function, &edited, None);
    assert!(changed.similarity < 1.0);
    let rows: Vec<_> = changed
        .blocks
        .iter()
        .flat_map(|block| &block.rows)
        .filter(|row| row.status != binfera::diff::pair::Status::Same)
        .collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].status, binfera::diff::pair::Status::Changed);
    Ok(())
}

#[test]
fn a_rule_gained_and_lost_is_reported_with_guards() -> Outcome {
    let bytes = include_str!("fixtures/resultdoc/pma01-02-exe.json");
    let left: binfera::rd::ResultDocument = serde_json::from_str(bytes)?;
    let mut right = left.clone();
    let (name, _) = right
        .rules
        .iter()
        .find(|(_, rule)| !rule.meta.lib && !rule.meta.is_subscope_rule)
        .ok_or("no reported rule")?;
    let name = name.clone();
    let rule = right.rules.remove(&name).ok_or("gone")?;
    let mut renamed = rule.clone();
    renamed.meta.name = "gained rule".to_string();
    right.rules.insert("gained rule".to_string(), renamed);
    let print = print(ELF)?;
    let document = compare(&print, &print, Some((&left, &right)));
    let delta = document.capability_delta.ok_or("no delta")?;
    assert_eq!(
        delta.removed.first().map(|r| r.name.as_str()),
        Some(name.as_str())
    );
    assert_eq!(
        delta.added.first().map(|r| r.name.as_str()),
        Some("gained rule")
    );
    Ok(())
}
