#![cfg(feature = "decompiler")]
use binfera_ghidra::{Language, Session, ValueType};

fn session() -> anyhow::Result<Session> {
    session_with(&[0x8d, 0x41, 0x01, 0xc3])
}

fn session_with(helper: &[u8]) -> anyhow::Result<Session> {
    let mut session = Session::new(Language::X86Windows64)?;
    let mut code = vec![0xcc; 96];
    code[..helper.len()].copy_from_slice(helper);
    code[32..46].copy_from_slice(&[
        0x48, 0x83, 0xec, 0x28, 0xe8, 0xd7, 0xff, 0xff, 0xff, 0x48, 0x83, 0xc4, 0x28, 0xc3,
    ]); // caller: call helper
    code[64..70].copy_from_slice(&[0xb9, 0, 0, 0, 0, 0xc3]); // unrelated void function
    session.add_section(0x1000, &code, true, true)?;
    for (address, name) in [
        (0x1000, "helper"),
        (0x1020, "caller"),
        (0x1040, "unrelated"),
    ] {
        session.add_function(address, name, false)?;
    }
    Ok(session)
}

#[test]
fn undeclared_register_inputs_do_not_cross_temporary_hints() -> anyhow::Result<()> {
    // EDI is not a Windows x64 argument register.
    let mut session = session_with(&[0x89, 0xf8, 0xc3])?;
    let first = session.decompile(0x1020, 10_000, 10_000, 20_000_000)?;
    let hint = session.decompile_with_hints(0x1040, 10_000, 10_000, 20_000_000, 4, false)?;
    assert!(hint.inference_cache_evictions > 0);
    let again = session.decompile(0x1020, 10_000, 10_000, 20_000_000)?;
    assert!(again.inference_cache_misses > 0);
    assert_eq!(first.text, again.text);
    Ok(())
}

#[test]
fn counted_string_abis_keep_the_conservative_reset() -> anyhow::Result<()> {
    let mut session = session()?;
    session.set_counted_strings(true)?;
    session.decompile(0x1020, 10_000, 10_000, 20_000_000)?;
    let hint = session.decompile_with_hints(0x1040, 10_000, 10_000, 20_000_000, 4, false)?;
    assert!(hint.inference_cache_evictions > 0);
    assert!(
        session
            .decompile(0x1020, 10_000, 10_000, 20_000_000)?
            .inference_cache_misses
            > 0
    );
    Ok(())
}

#[test]
fn unrelated_return_hints_preserve_cached_callee_analysis() -> anyhow::Result<()> {
    let mut session = session()?;
    let first = session.decompile(0x1020, 10_000, 10_000, 20_000_000)?;
    assert!(first.inference_cache_misses > 0);
    let hinted = session.decompile_with_hints(0x1040, 10_000, 10_000, 20_000_000, 4, false)?;
    assert!(hinted
        .inference_invalidation_reasons
        .iter()
        .any(|reason| reason.starts_with("temporary return hint:")));
    assert_eq!(hinted.inference_cache_evictions, 0);
    let again = session.decompile(0x1020, 10_000, 10_000, 20_000_000)?;
    assert_eq!(first.text, again.text);
    assert!(again.inference_cache_hits > 0);
    assert_eq!(again.inference_cache_misses, 0);
    Ok(())
}

#[test]
fn explicit_signatures_and_instruction_limits_still_invalidate_cached_facts() -> anyhow::Result<()>
{
    let mut session = session()?;
    session.decompile(0x1020, 10_000, 10_000, 20_000_000)?;
    let changed_limit = session.decompile(0x1020, 10_000, 9_000, 20_000_000)?;
    assert!(changed_limit.inference_cache_evictions > 0);
    assert!(changed_limit.inference_cache_misses > 0);
    session.set_signature(0x1000, ValueType::U64, &[ValueType::U64])?;
    let explicit = session.decompile(0x1020, 10_000, 9_000, 20_000_000)?;
    assert_eq!(explicit.inference_cache_hits, 0);
    assert!(explicit.text.contains("helper("));
    Ok(())
}

#[test]
fn temporary_return_hints_invalidate_transitive_dependents() -> anyhow::Result<()> {
    let mut session = Session::new(Language::X86Windows64)?;
    let mut code = vec![0xcc; 128];
    code[..6].copy_from_slice(&[0xb9, 0, 0, 0, 0, 0xc3]);
    code[32..46].copy_from_slice(&[
        0x48, 0x83, 0xec, 0x28, 0xe8, 0xd7, 0xff, 0xff, 0xff, 0x48, 0x83, 0xc4, 0x28, 0xc3,
    ]);
    code[96..112].copy_from_slice(&[
        0x48, 0x83, 0xec, 0x28, 0xe8, 0xb7, 0xff, 0xff, 0xff, 0x48, 0x83, 0xc4, 0x28, 0x31, 0xc0,
        0xc3,
    ]);
    session.add_section(0x1000, &code, true, true)?;
    for (address, name) in [(0x1000, "leaf"), (0x1020, "middle"), (0x1060, "outer")] {
        session.add_function(address, name, false)?;
    }
    let first = session.decompile(0x1060, 10_000, 10_000, 20_000_000)?;
    assert!(first.inference_cache_misses >= 2);
    let hinted = session.decompile_with_hints(0x1000, 10_000, 10_000, 20_000_000, 4, false)?;
    assert!(hinted.inference_cache_evictions >= 2);
    let again = session.decompile(0x1060, 10_000, 10_000, 20_000_000)?;
    assert!(again.inference_cache_misses >= 2);
    assert_eq!(first.text, again.text);
    Ok(())
}

#[test]
fn memory_dependent_inferences_are_recomputed_per_request() -> anyhow::Result<()> {
    // mov eax,[rip+0xffa]; ret. Even a leaf can observe request-local data symbols.
    let mut session = session_with(&[0x8b, 0x05, 0xfa, 0x0f, 0, 0, 0xc3])?;
    session.add_section(0x2000, &[42, 0, 0, 0], false, false)?;
    let first = session.decompile(0x1020, 10_000, 10_000, 20_000_000)?;
    assert!(first.inference_cache_misses > 0);
    let again = session.decompile(0x1020, 10_000, 10_000, 20_000_000)?;
    assert!(again.inference_cache_misses > 0);
    assert!(again.inference_cache_evictions > 0);
    assert!(again
        .inference_invalidation_reasons
        .iter()
        .any(|reason| reason.starts_with("request context:")));
    assert_eq!(first.text, again.text);
    Ok(())
}

#[test]
fn sibling_requests_do_not_share_context_dependent_callee_results() -> anyhow::Result<()> {
    use binfera::decompiler::{DecompilerSession, ResourceLimits};
    let sample = include_bytes!("../../tests/testfiles/fb690a23b66d4f90dac83f1b4d6dec0074aff68d6ef62c2613120bd4d17cfbdd.exe_");
    let mut session = DecompilerSession::from_pe(sample)?;
    session.set_limits(ResourceLimits {
        timeout_ms: 60_000,
        ..Default::default()
    })?;
    let target = 0x14009a994;
    let sibling = 0x14009a858;
    let first = session.decompile_function(target)?;
    let prior = session.decompile_function(sibling)?;
    let again = session.decompile_function(target)?;
    assert_eq!(first.text, again.text);
    assert_eq!(first.warnings, again.warnings);
    assert_eq!(prior.text, session.decompile_function(sibling)?.text);

    let mut fresh = DecompilerSession::from_pe(sample)?;
    fresh.set_limits(ResourceLimits {
        timeout_ms: 60_000,
        ..Default::default()
    })?;
    fresh.decompile_function(sibling)?;
    assert_eq!(first.text, fresh.decompile_function(target)?.text);
    Ok(())
}
