#![cfg(feature = "decompiler")]

use binfera::decompiler::{DecompilerSession, ValueType};
use std::collections::BTreeMap;

fn symbols(bytes: &[u8]) -> anyhow::Result<BTreeMap<String, u64>> {
    let names = if bytes.starts_with(b"MZ") {
        let pe = goblin::pe::PE::parse(bytes)?;
        pe.exports
            .iter()
            .filter_map(|s| {
                s.name
                    .map(|name| (name.to_owned(), pe.image_base + s.rva as u64))
            })
            .collect::<Vec<_>>()
    } else {
        let elf = goblin::elf::Elf::parse(bytes)?;
        elf.syms
            .iter()
            .filter(|s| s.st_value != 0)
            .filter_map(|s| {
                elf.strtab
                    .get_at(s.st_name)
                    .map(|name| (name.to_owned(), s.st_value))
            })
            .collect()
    };
    Ok(names
        .into_iter()
        .map(|(raw, address)| (binfera::demangle::rust(&raw).unwrap_or(raw), address))
        .collect())
}

#[test]
fn rust_names_and_slices_on_pe_and_elf() -> anyhow::Result<()> {
    for bytes in [
        include_bytes!("fixtures/rust/strings-legacy.elf").as_slice(),
        include_bytes!("fixtures/rust/strings-v0.elf").as_slice(),
        include_bytes!("fixtures/rust/strings-legacy.exe").as_slice(),
        include_bytes!("fixtures/rust/strings-v0.exe").as_slice(),
    ] {
        let names = symbols(bytes)?;
        let address = names["rust_fixture::print_message"];
        let mut session = if bytes.starts_with(b"MZ") {
            DecompilerSession::from_pe(bytes)?
        } else {
            DecompilerSession::from_elf(bytes)?
        };
        session.set_signature(
            names["consume"],
            ValueType::U64,
            &[ValueType::CharPointer, ValueType::U64],
        )?;
        let output = session.decompile_function(address)?;
        println!("{}", output.text);
        assert_eq!(output.name.as_deref(), Some("rust_fixture::print_message"));
        assert!(output.text.contains("hello, caf"), "{}", output.text);
        assert!(!output.text.contains("firstsecond"), "{}", output.text);
        assert!(!output.unknown_callees, "{:?}", output.warnings);
        for text in ["first", "second"] {
            let literal =
                session.decompile_function(names[&format!("rust_fixture::print_{text}")])?;
            assert!(
                literal.text.contains(&format!("\"{text}\"")),
                "{}",
                literal.text
            );
        }
        let descriptor = session.decompile_function(names["rust_fixture::read_message"])?;
        assert!(
            descriptor.text.contains("data_ptr") && descriptor.text.contains("length"),
            "{}",
            descriptor.text
        );
        assert_eq!(session.decompile_function(address)?.text, output.text);
    }
    Ok(())
}
