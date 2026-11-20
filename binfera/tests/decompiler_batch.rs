#![cfg(feature = "decompiler")]
use binfera::decompiler::{decompile_all, BatchEvent, BatchOptions, DecompileError};
use std::collections::BTreeSet;

const FIXTURE: &[u8] = include_bytes!("../../tests/decompiler/fixtures.dll");
const ARM64_PE: &[u8] = include_bytes!("fixtures/aarch64_decompiler/windows.exe");

#[test]
fn batch_keeps_the_exported_arm64_import_wrapper() -> anyhow::Result<()> {
    let address = 0x140001058;
    let mut found = false;
    decompile_all(ARM64_PE, &BatchOptions::default(), |event| {
        match event {
            BatchEvent::Start {
                functions, names, ..
            } => {
                assert!(functions.contains(&address));
                assert_eq!(names.get(&address).map(String::as_str), Some("imported"));
            }
            BatchEvent::Function(function) if function.address == address => {
                assert_eq!(function.extra, Some(false));
                assert!(function
                    .text
                    .as_deref()
                    .is_some_and(|text| text.contains("GetTickCount()")));
                found = true;
            }
            _ => {}
        }
        Ok(())
    })?;
    assert!(found);
    Ok(())
}

#[test]
fn batch_skips_pe_forwarders_data_exports_and_unexported_stubs() -> anyhow::Result<()> {
    let mut bytes = ARM64_PE.to_vec();
    // Point the imported and ninth exports at a forwarder and a data value in .rdata.
    let forwarder = b"KERNEL32.GetTickCount\0";
    bytes[0x714..0x714 + forwarder.len()].copy_from_slice(forwarder);
    bytes[0x730..0x734].copy_from_slice(&42u32.to_le_bytes());
    bytes[0x104..0x108].copy_from_slice(&0x12au32.to_le_bytes()); // export directory size
    bytes[0x1b0..0x1b4].copy_from_slice(&0x134u32.to_le_bytes()); // .rdata virtual size
    bytes[0x640..0x644].copy_from_slice(&0x2114u32.to_le_bytes());
    bytes[0x644..0x648].copy_from_slice(&0x2130u32.to_le_bytes());

    let pe = goblin::pe::PE::parse(&bytes)?;
    assert!(pe
        .exports
        .iter()
        .any(|export| export.name == Some("imported")
            && export.rva == 0x2114
            && export.reexport.is_some()));
    assert!(pe.exports.iter().any(|export| export.name == Some("ninth")
        && export.rva == 0x2130
        && export.reexport.is_none()));

    // The entry point still calls the original stub even after removing its export.
    let stub = 0x140001058;
    let options = BatchOptions::default();
    let (session, native) = options.open(&bytes)?;
    assert!(native.functions.contains_key(&stub));
    assert!(session.is_import_thunk(stub));
    let excluded = [stub, 0x140002114, 0x140002130];
    decompile_all(&bytes, &options, |event| {
        match event {
            BatchEvent::Start { functions, .. } => {
                assert!(excluded.iter().all(|address| !functions.contains(address)));
            }
            BatchEvent::Function(function) => assert!(!excluded.contains(&function.address)),
            _ => {}
        }
        Ok(())
    })?;
    Ok(())
}

#[test]
fn batch_keeps_an_x64_import_wrapper_with_a_direct_call_or_unwind_entry() -> anyhow::Result<()> {
    let stub = 0x1dca81120;
    let options = BatchOptions::default();
    for (called, with_unwind, compatible) in [
        (false, false, true),
        (true, false, true),
        (false, true, true),
        (false, true, false),
    ] {
        let mut bytes = FIXTURE.to_vec();
        if called {
            // Call the GetTickCount stub at RVA 0x1120 instead of calling through the IAT.
            bytes[0x4eb..0x4f1].copy_from_slice(&[0xe8, 0x30, 0, 0, 0, 0x90]);
        }
        if with_unwind {
            // Append a RUNTIME_FUNCTION with the same empty unwind info as branches.
            for (offset, value) in [(0x854, 0x1120u32), (0x858, 0x1126), (0x85c, 0x4004)] {
                bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            }
            bytes[0x124..0x128].copy_from_slice(&0x60u32.to_le_bytes()); // exception directory size
            bytes[0x1e0..0x1e4].copy_from_slice(&0x60u32.to_le_bytes()); // .pdata virtual size
        }
        if !compatible {
            bytes[0xa00] = 2; // version of an earlier record that compatibility recovery stops at
        }
        let expected = called || with_unwind;
        if expected {
            let (session, native) = options.open(&bytes)?;
            assert!(native.functions.contains_key(&stub));
            assert!(session.is_import_thunk(stub));
        }
        let mut found = false;
        decompile_all(&bytes, &options, |event| {
            match event {
                BatchEvent::Start { functions, .. } => {
                    assert_eq!(functions.contains(&stub), expected);
                }
                BatchEvent::Function(function) if function.address == stub => {
                    assert_eq!(function.extra, Some(false));
                    assert!(function
                        .text
                        .as_deref()
                        .is_some_and(|text| text.contains("GetTickCount()")));
                    found = true;
                }
                _ => {}
            }
            Ok(())
        })?;
        assert_eq!(found, expected);
    }
    Ok(())
}

fn stable_events(events: &[BatchEvent]) -> Result<Vec<serde_json::Value>, serde_json::Error> {
    events
        .iter()
        .map(|event| {
            let mut value = serde_json::to_value(event)?;
            if let Some(object) = value.as_object_mut() {
                object.remove("ms");
                object.remove("timings");
            }
            Ok(value)
        })
        .collect()
}

#[test]
fn recovery_snapshot_preserves_native_outputs_and_diagnostics() -> anyhow::Result<()> {
    use binfera::decompiler::{decompile_all_cached, prepare_decompile_all};
    let directory = tempfile::tempdir()?;
    for bytes in [
        FIXTURE,
        ARM64_PE,
        include_bytes!("fixtures/aarch64_decompiler/pie.elf").as_slice(),
        include_bytes!("fixtures/risc/thumb.elf").as_slice(),
        include_bytes!("fixtures/risc/mips.elf").as_slice(),
        include_bytes!("fixtures/rust/strings-v0.elf").as_slice(),
        include_bytes!("fixtures/dwarf/dwarf5.elf").as_slice(),
    ] {
        let cache = directory.path().join("recovery.bin");
        let options = BatchOptions::default();
        assert!(prepare_decompile_all(bytes, &options, &cache)?);
        let mut serial = Vec::new();
        decompile_all(bytes, &options, |event| {
            serial.push(event);
            Ok(())
        })?;
        let mut cached = Vec::new();
        decompile_all_cached(bytes, &options, &cache, |event| {
            cached.push(event);
            Ok(())
        })?;
        assert_eq!(stable_events(&serial)?, stable_events(&cached)?);
        let mut changed = bytes.to_vec();
        changed[0] ^= 1;
        let error = decompile_all_cached(&changed, &options, &cache, |_| {
            panic!("mismatched input emitted output")
        })
        .err()
        .ok_or_else(|| anyhow::anyhow!("accepted mismatched snapshot"))?;
        assert!(error.to_string().contains("hash mismatch"));
    }
    Ok(())
}

#[test]
fn recovery_snapshot_binds_the_selected_macho_slice() -> anyhow::Result<()> {
    use binfera::decompiler::{decompile_all_cached, prepare_decompile_all};
    let bytes = include_bytes!("fixtures/macho/fat-x86_64-arm64-exe");
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("recovery.bin");
    for arch in ["arm64", "x86_64"] {
        let options = BatchOptions {
            arch: Some(arch.into()),
            ..Default::default()
        };
        assert!(prepare_decompile_all(bytes, &options, &path)?);
        let mut serial = Vec::new();
        decompile_all(bytes, &options, |event| {
            serial.push(event);
            Ok(())
        })?;
        let mut cached = Vec::new();
        decompile_all_cached(bytes, &options, &path, |event| {
            cached.push(event);
            Ok(())
        })?;
        assert_eq!(stable_events(&serial)?, stable_events(&cached)?);
        let wrong = BatchOptions {
            arch: Some("auto".into()),
            ..Default::default()
        };
        let result = decompile_all_cached(bytes, &wrong, &path, |_| {
            panic!("wrong slice emitted an event")
        });
        assert!(result
            .err()
            .is_some_and(|e| e.to_string().contains("options mismatch")));
    }
    Ok(())
}

fn collect(options: BatchOptions) -> Result<Vec<BatchEvent>, DecompileError> {
    let mut events = Vec::new();
    decompile_all(FIXTURE, &options, |event| {
        events.push(event);
        Ok(())
    })?;
    Ok(events)
}

#[test]
fn malformed_optional_delay_imports_keep_the_native_batch() -> anyhow::Result<()> {
    let mut bytes = FIXTURE.to_vec();
    let pe = goblin::pe::PE::parse(&bytes)?;
    let optional = pe.header.dos_header.pe_pointer as usize + 24;
    let directory = optional + if pe.is_64 { 112 } else { 96 } + 13 * 8;
    bytes[directory..directory + 4].copy_from_slice(&0x7fff_f000u32.to_le_bytes());
    bytes[directory + 4..directory + 8].copy_from_slice(&32u32.to_le_bytes());
    assert!(binfera::extract::recovery::analyze(&bytes).is_err());
    let mut events = Vec::new();
    decompile_all(&bytes, &BatchOptions::default(), |event| {
        events.push(event);
        Ok(())
    })?;
    let Some(BatchEvent::Start {
        functions,
        warnings,
        ..
    }) = events.first()
    else {
        anyhow::bail!("missing inventory");
    };
    assert!(!functions.is_empty());
    assert!(warnings
        .iter()
        .any(|w| w.contains("Optional compatibility recovery failed")));
    assert!(warnings.iter().any(|w| w.contains("delay import")));
    for address in functions {
        assert!(events.iter().any(|event| matches!(event,
            BatchEvent::Function(f) if f.address == *address && f.text.as_ref().is_some_and(|t| !t.is_empty())
        )));
    }
    assert!(matches!(events.last(), Some(BatchEvent::Done { warnings })
        if warnings.iter().any(|w| w.contains("Optional compatibility recovery failed"))));
    Ok(())
}

#[test]
fn library_streams_inventory_functions_and_completion() -> Result<(), Box<dyn std::error::Error>> {
    let events = collect(BatchOptions::default())?;
    let Some(BatchEvent::Start { functions, .. }) = events.first() else {
        panic!("missing inventory")
    };
    let mut emitted = BTreeSet::new();
    for event in &events {
        if let BatchEvent::Function(function) = event {
            assert!(emitted.insert(function.address));
            assert!(function.text.is_some() || function.error.is_some());
            if let Some(graph) = &function.cfg {
                let listed: BTreeSet<_> = function.asm.iter().map(|r| r.0).collect();
                assert!(graph
                    .blocks
                    .iter()
                    .flat_map(|b| &b.instructions)
                    .all(|ad| listed.contains(ad)));
                let starts: BTreeSet<_> = graph.blocks.iter().map(|b| b.address).collect();
                assert!(graph
                    .edges
                    .iter()
                    .all(|e| starts.contains(&e.from) && starts.contains(&e.to)));
            }
        }
    }
    assert!(functions.iter().all(|ad| emitted.contains(ad)));
    assert!(matches!(events.last(), Some(BatchEvent::Done { .. })));
    assert!(!emitted.is_empty());
    Ok(())
}

#[test]
fn shards_partition_the_inventory() -> Result<(), Box<dyn std::error::Error>> {
    let mut inventories = Vec::new();
    let mut emitted = BTreeSet::new();
    for index in 0..2 {
        let events = collect(BatchOptions {
            shard: Some((index, 2)),
            ..Default::default()
        })?;
        for event in events {
            match event {
                BatchEvent::Start { functions, .. } => inventories.push(functions),
                BatchEvent::Function(function) if function.extra != Some(true) => {
                    assert!(emitted.insert(function.address))
                }
                _ => {}
            }
        }
    }
    assert_eq!(inventories.first(), inventories.get(1));
    assert_eq!(emitted, inventories[0].iter().copied().collect());
    Ok(())
}

#[test]
fn invalid_shards_and_callback_failure_stop_before_decompilation() {
    for shard in [(0, 0), (2, 2)] {
        let result = decompile_all(
            FIXTURE,
            &BatchOptions {
                shard: Some(shard),
                ..Default::default()
            },
            |_| panic!("invalid request emitted an event"),
        );
        assert!(matches!(result, Err(DecompileError::Request(_))));
    }
    let mut count = 0;
    let result = decompile_all(FIXTURE, &BatchOptions::default(), |_| {
        count += 1;
        Err(DecompileError::Output("consumer stopped".into()))
    });
    assert!(matches!(result, Err(DecompileError::Output(_))));
    assert_eq!(count, 1);
}

#[test]
fn managed_methods_use_the_same_stream_and_shard_policy() -> Result<(), Box<dyn std::error::Error>>
{
    let bytes =
        include_bytes!("../../tests/testfiles/dotnet/dd9098ff91717f4906afe9dafdfa2f52.exe_");
    let mut inventory = BTreeSet::new();
    let mut emitted = BTreeSet::new();
    for index in 0..2 {
        decompile_all(
            bytes,
            &BatchOptions {
                shard: Some((index, 2)),
                ..Default::default()
            },
            |event| {
                match event {
                    BatchEvent::Start {
                        functions, arch, ..
                    } => {
                        assert_eq!(arch.as_deref(), Some("cil"));
                        let functions = functions.into_iter().collect();
                        if index == 0 {
                            inventory = functions;
                        } else {
                            assert_eq!(inventory, functions);
                        }
                    }
                    BatchEvent::Function(function) => {
                        assert!(emitted.insert(function.address));
                        assert!(function.name.is_some());
                        assert!(!function.asm.is_empty());
                    }
                    _ => {}
                }
                Ok(())
            },
        )?;
    }
    assert!(!inventory.is_empty());
    assert_eq!(inventory, emitted);
    Ok(())
}

/// A deterministic work budget exercises scheduling without a machine-dependent deadline.
#[test]
fn limited_functions_settle_before_retries_and_retain_their_names() -> anyhow::Result<()> {
    use binfera::decompiler::{ResourceLimits, RetryPolicy};
    let options = BatchOptions {
        limits: ResourceLimits {
            max_work: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    let events = collect(options.clone())?;
    let settled = events
        .iter()
        .position(|e| matches!(e, BatchEvent::Settled))
        .ok_or_else(|| anyhow::anyhow!("missing settled event"))?;
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, BatchEvent::Settled))
            .count(),
        1
    );
    let BatchEvent::Start { names, .. } = &events[0] else {
        panic!("missing inventory")
    };
    let pending: Vec<_> = events[..settled]
        .iter()
        .filter_map(|event| match event {
            BatchEvent::Function(f) if f.retry_pending == Some(true) => Some(f),
            _ => None,
        })
        .collect();
    assert!(!pending.is_empty());
    assert!(pending.len() <= 16);
    for first in pending {
        assert!(first
            .error
            .as_deref()
            .is_some_and(|e| e.contains("work limit exceeded")));
        assert_eq!(first.name.as_ref(), names.get(&first.address));
        assert!(first.name.is_some());
        assert!(!first.asm.is_empty());
        assert!(events[settled + 1..].iter().any(|event| matches!(event,
            BatchEvent::Function(f) if f.address == first.address && f.resource_retry == Some(true)
                && f.retry_pending.is_none() && f.text.as_ref().is_some_and(|t| !t.is_empty()))));
    }
    let skipped = collect(BatchOptions {
        retry: RetryPolicy::Skip,
        ..options
    })?;
    assert!(skipped
        .iter()
        .any(|e| matches!(e, BatchEvent::Function(f) if f.retry_pending == Some(true))));
    assert!(!skipped
        .iter()
        .any(|e| matches!(e, BatchEvent::Function(f) if f.resource_retry == Some(true))));
    Ok(())
}
