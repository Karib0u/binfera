//! Source-built MSVC ABI fixtures, plus mutations of their metadata. Never executed.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use binfera::extract::image::LoadedImage;
use binfera::extract::recovery::{analyze_with_backend, RecoveryBackend, SeedKind};
use binfera::msvc_eh::ExceptionInfo;

const X86: &[u8] = include_bytes!("fixtures/msvc_eh/exceptions32.dll");
const X64: &[u8] = include_bytes!("fixtures/msvc_eh/exceptions64.dll");

fn offset(bytes: &[u8], address: u64) -> usize {
    let pe = goblin::pe::PE::parse(bytes).unwrap();
    let rva = address - pe.image_base;
    let section = pe
        .sections
        .iter()
        .find(|section| {
            rva >= u64::from(section.virtual_address)
                && rva < u64::from(section.virtual_address + section.size_of_raw_data)
        })
        .unwrap();
    (rva - u64::from(section.virtual_address) + u64::from(section.pointer_to_raw_data)) as usize
}
fn export(bytes: &[u8], name: &str) -> u64 {
    let pe = goblin::pe::PE::parse(bytes).unwrap();
    pe.image_base
        + pe.exports
            .iter()
            .find(|e| e.name == Some(name))
            .unwrap()
            .rva as u64
}
fn read(bytes: &[u8]) -> ExceptionInfo {
    ExceptionInfo::read(&LoadedImage::parse(bytes).unwrap())
}

#[test]
fn nested_catches_cleanup_and_parent_links() {
    for bytes in [X86, X64] {
        let analysis = analyze_with_backend(bytes, RecoveryBackend::Native).unwrap();
        let mut eh = ExceptionInfo::read(&analysis.image);
        assert!(eh.diagnostics.is_empty(), "{:?}", eh.diagnostics);
        eh.link_functions(&analysis);
        for info in eh.functions.values() {
            assert!(analysis.image.is_code_excluded(info.address));
            assert!(!analysis.functions.contains_key(&info.address));
        }
        let owner = export(bytes, "nested_catches");
        let tables = eh.for_function(owner);
        assert_eq!(tables.len(), 1, "{eh:#?}");
        let info = &tables[0];
        let labels = eh.contained_funclets(&analysis);
        assert_eq!(info.owners.iter().copied().collect::<Vec<_>>(), [owner]);
        assert_eq!(info.try_blocks.len(), 2);
        let types: Vec<_> = info
            .try_blocks
            .iter()
            .flat_map(|block| block.handlers.iter().map(|h| h.catch_type.as_str()))
            .collect();
        assert_eq!(types, ["Error", "int", "..."]);
        assert!(
            info.unwind
                .iter()
                .filter(|entry| entry.action.is_some())
                .count()
                >= 2
        );
        for target in info.targets() {
            assert!(analysis.seeds[&target].contains(&SeedKind::MsvcException));
            if let Some(owner) = labels.get(&target) {
                assert!(
                    !analysis.functions.contains_key(&target),
                    "in-body funclet {target:#x}"
                );
                assert!(
                    analysis.functions[owner]
                        .blocks
                        .iter()
                        .flat_map(|b| &b.insns)
                        .any(|i| i.address == target),
                    "missing handler label {target:#x}"
                );
            } else {
                assert!(
                    analysis.functions.contains_key(&target),
                    "missing handler {target:#x}"
                );
            }
            assert!(eh.names().contains_key(&target));
            assert!(eh
                .for_function(target)
                .iter()
                .any(|table| table.owners.contains(&owner)));
        }
        if bytes == X64 {
            assert!(!info.ip_states.is_empty());
            for block in &info.try_blocks {
                assert!(!info.protected_ranges(block).is_empty());
            }
        } else {
            assert!(info.ip_states.is_empty());
            assert!(info
                .try_blocks
                .iter()
                .all(|block| info.protected_ranges(block).is_empty()));
        }
        let cleanup = eh.for_function(export(bytes, "cleanup_only"));
        assert_eq!(cleanup.len(), 1);
        assert!(cleanup[0].try_blocks.is_empty());
        assert!(cleanup[0].unwind.iter().any(|entry| entry.action.is_some()));
        assert!(eh.for_function(export(bytes, "plain")).is_empty());
    }
}

#[test]
fn malformed_counts_pointers_and_cycles_reject_whole_table() {
    for original in [X86, X64] {
        let info = read(original)
            .functions
            .values()
            .find(|info| info.try_blocks.len() == 2)
            .unwrap()
            .clone();
        let table = offset(original, info.address);
        for (field, value) in [
            (4, u32::MAX),
            (8, u32::MAX),
            (12, 16_001),
            (16, 0),
            (20, u32::MAX),
            (24, u32::MAX),
        ] {
            let mut bytes = original.to_vec();
            bytes[table + field..table + field + 4].copy_from_slice(&value.to_le_bytes());
            // An unused IP map pointer is allowed on x86 (count == 0).
            if original == X86 && field == 24 {
                continue;
            }
            let eh = read(&bytes);
            assert!(!eh.functions.contains_key(&info.address), "field {field}");
            assert!(!eh.diagnostics.is_empty());
        }
        let mut bytes = original.to_vec();
        let raw = u32::from_le_bytes(bytes[table + 8..table + 12].try_into().unwrap());
        let map = if original == X64 {
            0x180000000 + u64::from(raw)
        } else {
            u64::from(raw)
        };
        let pos = offset(&bytes, map);
        bytes[pos..pos + 4].copy_from_slice(&0u32.to_le_bytes()); // state 0 cannot unwind to itself.
        assert!(!read(&bytes).functions.contains_key(&info.address));
    }
}

#[test]
fn directory_location_does_not_depend_on_section_name() {
    let mut bytes = X64.to_vec();
    let position = bytes
        .windows(8)
        .position(|window| window == b".pdata\0\0")
        .unwrap();
    bytes[position..position + 8].copy_from_slice(b".renamed");
    assert_eq!(read(&bytes).functions, read(X64).functions);
}

#[test]
fn bbt_flags_and_older_funcinfo_versions() {
    for original in [X86, X64] {
        let info = read(original)
            .functions
            .values()
            .find(|info| info.try_blocks.len() == 2)
            .unwrap()
            .clone();
        for version in 0..=2 {
            let mut bytes = original.to_vec();
            let start = offset(&bytes, info.address);
            bytes[start..start + 4].copy_from_slice(&(0x99930520u32 + version).to_le_bytes());
            let eh = read(&bytes);
            assert!(eh.diagnostics.is_empty(), "{:?}", eh.diagnostics);
            assert_eq!(eh.functions[&info.address].bbt_flags, 4);
            assert_eq!(eh.functions[&info.address].try_blocks, info.try_blocks);
        }
    }
}

#[test]
fn fh4_is_reported_without_interpreting_compressed_bytes_as_funcinfo() {
    let mut bytes = X64.to_vec();
    let position = bytes
        .windows(18)
        .position(|window| window == b"__CxxFrameHandler3")
        .unwrap();
    bytes[position + 17] = b'4';
    let eh = read(&bytes);
    assert!(eh.functions.is_empty());
    assert!(eh.diagnostics.iter().all(|message| message.contains("FH4")));
    assert!(!eh.diagnostics.is_empty());
}

#[test]
fn random_metadata_mutations_do_not_panic() {
    let mut random = 0x12345678u32;
    for original in [X86, X64] {
        let info = read(original)
            .functions
            .values()
            .find(|info| info.try_blocks.len() == 2)
            .unwrap()
            .clone();
        let table = offset(original, info.address);
        for _ in 0..256 {
            let mut bytes = original.to_vec();
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            let position = table + random as usize % 36;
            bytes[position] ^= (random >> 8) as u8;
            let _ = read(&bytes);
        }
    }
}

#[cfg(feature = "decompiler")]
#[test]
fn pseudocode_json_and_line_addresses_include_exception_metadata() {
    use binfera::decompiler::DecompilerSession;
    for bytes in [X86, X64] {
        let mut session = DecompilerSession::from_bytes(bytes).unwrap();
        let owner = export(bytes, "nested_catches");
        let result = session.decompile_function(owner).unwrap();
        assert!(
            result.text.contains("MSVC C++ EH FuncInfo"),
            "{}",
            result.text
        );
        assert!(result.text.contains("catch (Error)"));
        assert!(result.text.contains("catch (...)"));
        assert!(result.text.contains("unwind state"));
        assert_eq!(result.exception_handling.len(), 1);
        if !result.line_addresses.is_empty() {
            assert_eq!(result.text.split('\n').count(), result.line_addresses.len());
            assert!(result.line_addresses[0].is_empty());
        }
        let json = serde_json::to_value(&result).unwrap();
        assert!(json["exception_handling"][0]["try_blocks"].is_array());
        let handler = result.exception_handling[0].try_blocks[0].handlers[0].address;
        let catch = session.decompile_function(handler).unwrap();
        assert!(catch.name.unwrap().starts_with("catch_"));
        assert!(catch.text.contains(&format!("owner(s): {owner:#x}")));
        let plain = session.decompile_function(export(bytes, "plain")).unwrap();
        assert!(session
            .decompile_unit(&[owner])
            .unwrap_err()
            .to_string()
            .contains("exception handling"));
        assert!(plain.exception_handling.is_empty());
        assert!(!plain.text.contains("MSVC C++ EH"));
    }
}

#[test]
fn chained_unwind_links_to_parent_and_cycles_are_bounded() {
    let pe = goblin::pe::PE::parse(X64).unwrap();
    let directory = pe
        .header
        .optional_header
        .unwrap()
        .data_directories
        .get_exception_table()
        .unwrap()
        .virtual_address;
    let row = offset(X64, pe.image_base + u64::from(directory));
    let rdata = pe
        .sections
        .iter()
        .find(|section| section.name().unwrap() == ".rdata")
        .unwrap();
    let chain_rva = rdata.virtual_address + rdata.size_of_raw_data - 16;
    let chain = offset(X64, pe.image_base + u64::from(chain_rva));
    let mut bytes = X64.to_vec();
    // Extend the section's virtual extent into its existing raw padding so
    // the synthetic chain record is mapped, not merely present in the file.
    let section_header = bytes
        .windows(8)
        .position(|window| window == b".rdata\0\0")
        .unwrap();
    bytes[section_header + 8..section_header + 12]
        .copy_from_slice(&rdata.size_of_raw_data.to_le_bytes());
    let original: Vec<_> = bytes[row..row + 12].to_vec();
    bytes[chain..chain + 4].copy_from_slice(&[0x21, 0, 0, 0]);
    bytes[chain + 4..chain + 16].copy_from_slice(&original);
    bytes[row + 8..row + 12].copy_from_slice(&chain_rva.to_le_bytes());
    let eh = read(&bytes);
    assert!(eh.diagnostics.is_empty(), "{:?}", eh.diagnostics);
    assert_eq!(eh.functions, read(X64).functions);
    bytes[chain + 12..chain + 16].copy_from_slice(&chain_rva.to_le_bytes());
    assert!(read(&bytes)
        .diagnostics
        .iter()
        .any(|message| message.contains("unwind chain")));
}

#[test]
fn compatibility_recovery_does_not_use_new_exception_seeds() {
    for bytes in [X86, X64] {
        let analysis = analyze_with_backend(bytes, RecoveryBackend::VivisectCompat).unwrap();
        assert!(analysis
            .seeds
            .values()
            .all(|seeds| !seeds.contains(&SeedKind::MsvcException)));
    }
}

#[test]
fn rust_panic_catch_type_is_valid_msvc_metadata() {
    let original = read(X64);
    let descriptor = original
        .functions
        .values()
        .flat_map(|f| &f.try_blocks)
        .flat_map(|b| &b.handlers)
        .find_map(|h| {
            (h.catch_type == "Error")
                .then_some(h.type_descriptor)
                .flatten()
        })
        .unwrap();
    let mut bytes = X64.to_vec();
    let start = offset(X64, descriptor + 16);
    bytes[start..start + 11].copy_from_slice(b"rust_panic\0");
    let result = read(&bytes);
    assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
    assert!(result
        .functions
        .values()
        .flat_map(|f| &f.try_blocks)
        .flat_map(|b| &b.handlers)
        .any(|h| h.catch_type == "rust_panic"));
}
