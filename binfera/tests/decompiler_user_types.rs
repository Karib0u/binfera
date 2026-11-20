//! Proof of concept for analyst-editable types (docs/roadmap.md, "Analyst-editable semantics",
//! step 1). A stripped function reads a record through an untyped pointer; the analyst supplies
//! the record's layout and the function's prototype. Only today's mechanisms are used: the
//! debug-type loader, locked debug signatures, the project store and the inference cache.
//!
//! An analyst's overlay reaches `DecompilerSession` today only by posing as embedded DWARF
//! (`Analysis::dwarf`, applied once when the session is built). A live session can only be
//! edited through the raw bridge (`binfera_ghidra::Session`), which `DecompilerSession` hides.
//! Each ignored test states what is missing and which roadmap step supplies it; each is written
//! to pass, unchanged, once that step exists.
#![cfg(feature = "decompiler")]
use std::collections::BTreeMap;
use std::sync::Arc;

use binfera::decompiler::{CallingConvention, DecompilerSession};
use binfera::dwarf::DebugInfo;
use binfera::extract::recovery::Analysis;
use binfera_ghidra::{DebugField, DebugParameter, DebugType, Language, Session};
use binfera_project::{Edit, EditKind, Source, Store};

/// `fixtures/user_types/packet.c`, built by `build.sh`: no symbol table and no debug sections.
const PACKET: &[u8] = include_bytes!("fixtures/user_types/packet.elf");
/// `int packet_score(void *)`: reads three fields of `struct packet`.
const SCORE: u64 = 0x2012a0;
/// `int packet_reset(void *, unsigned)`: writes three fields, then passes the pointer on.
const RESET: u64 = 0x2012b0;
/// `int packet_total(void *)`: passes each node on and follows `next`.
const TOTAL: u64 = 0x2012d0;
const FUNCTIONS: [u64; 3] = [SCORE, RESET, TOTAL];

const FIELDS: [&str; 4] = ["kind", "length", "checksum", "next"];
const RENAMED: [&str; 4] = ["kind", "payload_size", "checksum", "next"];

const STRUCT_ID: u64 = 4;
const POINTER_ID: u64 = 5;
const INT_ID: u64 = 3;

/// The analyst's `struct packet`, as the debug-type records the bridge loads.
fn types(fields: [&str; 4]) -> Vec<DebugType> {
    let plain = |id, kind: &str, name: &str, size, target| DebugType {
        id,
        kind: kind.into(),
        name: name.into(),
        size,
        target,
        count: 0,
        fields: Vec::new(),
    };
    let field = |name: &str, offset, type_id| DebugField {
        name: name.into(),
        offset,
        type_id,
    };
    vec![
        plain(1, "uint", "uint32_t", 4, 0),
        plain(2, "uint", "uint64_t", 8, 0),
        plain(INT_ID, "int", "int", 4, 0),
        DebugType {
            id: STRUCT_ID,
            kind: "struct".into(),
            name: "packet".into(),
            size: 24,
            target: 0,
            count: 0,
            fields: vec![
                field(fields[0], 0, 1),
                field(fields[1], 4, 1),
                field(fields[2], 8, 2),
                field(fields[3], 16, POINTER_ID),
            ],
        },
        plain(POINTER_ID, "pointer", "", 8, STRUCT_ID),
    ]
}

/// The overlay: `struct packet` and `int packet_score(struct packet *packet)`. `DebugInfo` keeps
/// its fields crate-private, so a caller outside the crate can only build one through serde.
fn overlay_json(fields: [&str; 4]) -> serde_json::Value {
    serde_json::json!({
        "functions": {
            SCORE.to_string(): {
                "name": "packet_score",
                "result": INT_ID,
                "parameters": [["packet", POINTER_ID]],
                "locals": [],
                "frame": null,
                "signature": true,
                "model": "",
                "varargs": false,
                "go": false,
                "multi": false,
                "noreturn": false,
            }
        },
        "types": types(fields),
        "diagnostics": [],
    })
}

fn overlay(fields: [&str; 4]) -> anyhow::Result<DebugInfo> {
    Ok(serde_json::from_value(overlay_json(fields))?)
}

fn analysis() -> anyhow::Result<Analysis> {
    Ok(DecompilerSession::from_bytes_with_analysis(PACKET)?.1)
}

/// A native session built from the recovered analysis, with the overlay posing as DWARF.
fn session(analysis: &Analysis, overlay: Option<DebugInfo>) -> anyhow::Result<DecompilerSession> {
    let mut analysis = analysis.clone();
    analysis.dwarf = overlay.map(Arc::new);
    let session = DecompilerSession::from_analysis(
        &analysis,
        &BTreeMap::new(),
        CallingConvention::SystemVX64,
    )?;
    assert!(session.warnings().is_empty(), "{:?}", session.warnings());
    Ok(session)
}

fn texts(session: &mut DecompilerSession, order: &[u64]) -> anyhow::Result<BTreeMap<u64, String>> {
    order
        .iter()
        .map(|&address| Ok((address, session.decompile_function(address)?.text)))
        .collect()
}

fn base_texts(analysis: &Analysis) -> anyhow::Result<BTreeMap<u64, String>> {
    texts(&mut session(analysis, None)?, &FUNCTIONS)
}

fn typed_texts(analysis: &Analysis, fields: [&str; 4]) -> anyhow::Result<BTreeMap<u64, String>> {
    texts(&mut session(analysis, Some(overlay(fields)?))?, &FUNCTIONS)
}

/// The bridge alone, the only layer that accepts types after a session is built.
fn raw_session() -> anyhow::Result<Session> {
    use object::{Object, ObjectSection};
    let file = object::File::parse(PACKET)?;
    let text = file
        .section_by_name(".text")
        .ok_or_else(|| anyhow::anyhow!("no .text"))?;
    let mut session = Session::new(Language::X86Linux64)?;
    session.add_section(text.address(), text.data()?, true, true)?;
    for address in FUNCTIONS {
        session.add_function(address, &format!("FUN_{address:x}"), false)?;
    }
    Ok(session)
}

fn raw_apply(session: &mut Session, fields: [&str; 4]) -> anyhow::Result<()> {
    session.add_debug_types(&types(fields))?;
    let parameter = DebugParameter {
        name: "packet".into(),
        type_id: POINTER_ID,
    };
    anyhow::ensure!(
        session.set_debug_signature(SCORE, INT_ID, "", &[parameter], false, false, false, false)?,
        "signature rejected"
    );
    Ok(())
}

fn raw_texts(session: &mut Session, order: &[u64]) -> anyhow::Result<BTreeMap<u64, String>> {
    order
        .iter()
        .map(|&address| {
            let output = session.decompile(address, 10_000, 10_000, 20_000_000)?;
            Ok((address, output.text))
        })
        .collect()
}

fn fresh_raw_texts(fields: Option<[&str; 4]>) -> anyhow::Result<BTreeMap<u64, String>> {
    let mut session = raw_session()?;
    if let Some(fields) = fields {
        raw_apply(&mut session, fields)?;
    }
    raw_texts(&mut session, &FUNCTIONS)
}

// 1. A user struct is injected without DWARF.
#[test]
fn p1_user_struct_is_injected_without_dwarf() -> anyhow::Result<()> {
    use object::{Object, ObjectSection};
    let file = object::File::parse(PACKET)?;
    assert!(file.symbols().next().is_none());
    assert!(!file
        .sections()
        .any(|s| s.name().is_ok_and(|n| n.contains("debug"))));
    let analysis = analysis()?;
    // A stripped ELF still gets an (empty) debug record from recovery.
    assert!(analysis
        .dwarf
        .as_ref()
        .is_none_or(|debug| debug.functions.is_empty()));

    let base = base_texts(&analysis)?;
    assert!(base[&SCORE].contains("(int *param_1)"), "{}", base[&SCORE]);
    let typed = typed_texts(&analysis, FIELDS)?;
    assert!(
        typed[&SCORE].contains("packet *packet"),
        "{}",
        typed[&SCORE]
    );
    Ok(())
}

// 2. A signature refers to it.
#[test]
fn p2_signature_refers_to_the_struct() -> anyhow::Result<()> {
    let typed = typed_texts(&analysis()?, FIELDS)?;
    assert!(
        typed[&SCORE].contains("int packet_score(packet *packet)"),
        "{}",
        typed[&SCORE]
    );
    Ok(())
}

// 3. Field accesses appear in the output.
#[test]
fn p3_field_accesses_replace_pointer_arithmetic() -> anyhow::Result<()> {
    let analysis = analysis()?;
    let base = base_texts(&analysis)?;
    assert!(
        base[&SCORE].contains("param_1[1] * 3 + *param_1 ^ param_1[2]"),
        "{}",
        base[&SCORE]
    );
    let typed = typed_texts(&analysis, FIELDS)?;
    assert!(
        typed[&SCORE]
            .contains("packet->length * 3 + packet->kind ^ (unsigned int)packet->checksum"),
        "{}",
        typed[&SCORE]
    );
    assert!(!typed[&SCORE].contains("param_1"), "{}", typed[&SCORE]);
    Ok(())
}

// 4. Callers benefit where data flow allows. Neither caller is typed by the analyst: the locked
// parameter type flows back into each caller's own unlocked parameter, through a direct copy
// (packet_reset) and through a loop phi fed by `next` (packet_total).
#[test]
fn p4_callers_inherit_the_type_through_data_flow() -> anyhow::Result<()> {
    let analysis = analysis()?;
    let base = base_texts(&analysis)?;
    assert!(base[&RESET].contains("param_1[3] = 0;"), "{}", base[&RESET]);
    assert!(
        base[&TOTAL].contains("param_1 = *(int **)(param_1 + 4);"),
        "{}",
        base[&TOTAL]
    );
    let typed = typed_texts(&analysis, FIELDS)?;
    let reset = &typed[&RESET];
    for line in [
        "FUN_2012b0(packet *packet,",
        "packet->kind = param_2;",
        "packet->length = 0;",
        "packet->checksum = 0;",
        "packet_score(packet);",
    ] {
        assert!(reset.contains(line), "{line}\n{reset}");
    }
    let total = &typed[&TOTAL];
    for line in [
        "FUN_2012d0(packet *packet)",
        "packet_score(packet);",
        "packet = packet->next;",
    ] {
        assert!(total.contains(line), "{line}\n{total}");
    }
    Ok(())
}

// 5. Renaming a field changes the output. Passes only by building a new native session.
#[test]
fn p5_renaming_a_field_changes_the_output_after_a_session_rebuild() -> anyhow::Result<()> {
    let analysis = analysis()?;
    let before = typed_texts(&analysis, FIELDS)?;
    let after = typed_texts(&analysis, RENAMED)?;
    for address in FUNCTIONS {
        assert_eq!(
            after[&address],
            before[&address].replace("->length", "->payload_size")
        );
    }
    assert!(after[&SCORE].contains("packet->payload_size * 3"));
    assert!(after[&RESET].contains("packet->payload_size = 0;"));
    Ok(())
}

// 5, live: the same rename applied to a session that already holds the first layout.
#[test]
#[ignore = "a completed structure is not redefined in a live session: add_debug_types returns \
            the pointer memoized for a type id by the previous call \
            (binfera-ghidra/native/bridge.cc:2965-2966), so the re-locked signature still points \
            at the old layout and the output is unchanged; with fresh ids the renamed layout is \
            printed as `packet_dwarf_00000068` instead (bridge.cc:2953). DecompilerSession \
            exposes no edit after construction (binfera/src/decompiler.rs:404). Roadmap step 5 \
            (a changed layout gets a new version under a fresh internal name and its bindings are \
            repointed, without that name reaching the output), on step 3's single loader"]
fn p5_renaming_a_field_in_a_live_session_matches_a_fresh_session() -> anyhow::Result<()> {
    let mut live = raw_session()?;
    raw_apply(&mut live, FIELDS)?;
    let before = raw_texts(&mut live, &FUNCTIONS)?;
    assert!(
        before[&SCORE].contains("packet->length"),
        "{}",
        before[&SCORE]
    );
    raw_apply(&mut live, RENAMED)?;
    assert_eq!(
        raw_texts(&mut live, &FUNCTIONS)?,
        fresh_raw_texts(Some(RENAMED))?
    );
    Ok(())
}

// 6. The edit survives reopening the project. Today only the replay half holds: a new session
// built from a fresh recovery and the same overlay prints the same text.
#[test]
fn p6_replaying_the_overlay_after_reopening_reproduces_the_output() -> anyhow::Result<()> {
    let first = typed_texts(&analysis()?, FIELDS)?;
    let reopened = typed_texts(&analysis()?, FIELDS)?;
    assert_eq!(first, reopened);
    Ok(())
}

/// A type edit as an agent or the UI would send it. The value is this test's own encoding of
/// the overlay; step 2 replaces it with the semantic model's.
fn signature_edit(fields: [&str; 4]) -> anyhow::Result<Edit> {
    Ok(serde_json::from_value(serde_json::json!({
        "kind": "set_function_signature",
        "target": format!("{SCORE:#x}"),
        "value": overlay_json(fields).to_string(),
        "confidence": "certain",
    }))?)
}

fn store_with_edit(path: &std::path::Path, sha: &str) -> anyhow::Result<()> {
    let mut store = Store::open(path)?;
    store.ensure_project(sha, "packet.elf", PACKET.len() as u64)?;
    let result = store.apply_edits(
        sha,
        None,
        "define-struct",
        None,
        Source::Human,
        &[signature_edit(FIELDS)?],
    )?;
    assert!(result.rejected.is_empty(), "{:?}", result.rejected);
    Ok(())
}

/// What a reopened project replays into a new session.
fn stored_overlay(path: &std::path::Path, sha: &str) -> anyhow::Result<Option<DebugInfo>> {
    let store = Store::open(path)?;
    let stored = store.annotations(sha, Some("set_function_signature"))?;
    anyhow::ensure!(stored.len() <= 1, "{stored:?}");
    stored
        .first()
        .map(|annotation| Ok(serde_json::from_str(&annotation.value)?))
        .transpose()
}

#[test]
#[ignore = "the project store holds only string renames, comments and stars: binfera-project \
            EditKind (binfera-project/src/lib.rs:121) has no type or signature edit, so the edit \
            fails to deserialize (unknown variant `set_function_signature`), and schema 3 \
            (binfera-project/src/lib.rs:23) has no table for types; roadmap step 2 (SQLite \
            schema 4 with types, bindings and signatures under the revision and change journal)"]
fn p6_type_edits_persist_in_the_project_store() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("projects.db");
    let sha = binfera_project::hash_bytes(PACKET);
    store_with_edit(&path, &sha)?;
    let replayed = stored_overlay(&path, &sha)?.ok_or_else(|| anyhow::anyhow!("edit lost"))?;
    let analysis = analysis()?;
    assert_eq!(
        texts(&mut session(&analysis, Some(replayed))?, &FUNCTIONS)?,
        typed_texts(&analysis, FIELDS)?
    );
    Ok(())
}

// 7. Removing the edit restores the original output. Passes only by building a new native
// session from the same recovery, which step 5 keeps as the design for deletions. A live
// session has no call that unlocks a debug signature (set_debug_signature locks the prototype
// for good, binfera-ghidra/native/bridge.cc:3077) or drops a type, so no live variant exists.
#[test]
fn p7_dropping_the_overlay_restores_the_original_after_a_session_rebuild() -> anyhow::Result<()> {
    let analysis = analysis()?;
    let original = base_texts(&analysis)?;
    let typed = typed_texts(&analysis, FIELDS)?;
    for address in FUNCTIONS {
        assert_ne!(original[&address], typed[&address]);
    }
    assert_eq!(base_texts(&analysis)?, original);
    Ok(())
}

#[test]
#[ignore = "removal goes through the project store, which cannot hold the edit: binfera-project \
            EditKind (binfera-project/src/lib.rs:121) has no type or signature edit, so it fails \
            to deserialize (unknown variant `set_function_signature`); roadmap step 2 (schema 4 \
            under the change journal), then step 5 rebuilds the native session"]
fn p7_removing_the_stored_edit_restores_the_original() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("projects.db");
    let sha = binfera_project::hash_bytes(PACKET);
    store_with_edit(&path, &sha)?;
    let kind: EditKind = serde_json::from_str("\"set_function_signature\"")?;
    Store::open(&path)?.remove_annotations(&sha, &[(kind, format!("{SCORE:#x}"))])?;
    let replayed = stored_overlay(&path, &sha)?;
    assert!(replayed.is_none());
    let analysis = analysis()?;
    assert_eq!(
        texts(&mut session(&analysis, replayed)?, &FUNCTIONS)?,
        base_texts(&analysis)?
    );
    Ok(())
}

// 8. The output does not depend on which functions were decompiled first.
#[test]
fn p8_output_does_not_depend_on_request_order() -> anyhow::Result<()> {
    let analysis = analysis()?;
    let callee_first = typed_texts(&analysis, FIELDS)?;
    let mut reversed = FUNCTIONS;
    reversed.reverse();
    let callers_first = texts(&mut session(&analysis, Some(overlay(FIELDS)?))?, &reversed)?;
    assert_eq!(callee_first, callers_first);
    // Requests repeated in one session reuse cached callee facts without changing the text.
    let mut session = session(&analysis, Some(overlay(FIELDS)?))?;
    let once = texts(&mut session, &FUNCTIONS)?;
    assert_eq!(texts(&mut session, &reversed)?, once);
    assert_eq!(once, callee_first);
    Ok(())
}

// 8, live: an edit made after callers were decompiled (and the callee's inferred prototype
// cached) prints what a session that had the edit from the start prints.
#[test]
fn p8_edits_after_earlier_requests_match_a_fresh_session() -> anyhow::Result<()> {
    let mut live = raw_session()?;
    let mut reversed = FUNCTIONS;
    reversed.reverse();
    let untyped = raw_texts(&mut live, &reversed)?;
    assert_eq!(untyped, fresh_raw_texts(None)?);
    raw_apply(&mut live, FIELDS)?;
    let typed = raw_texts(&mut live, &reversed)?;
    assert_eq!(typed, fresh_raw_texts(Some(FIELDS))?);
    assert!(typed[&TOTAL].contains("packet->next"), "{}", typed[&TOTAL]);
    Ok(())
}
