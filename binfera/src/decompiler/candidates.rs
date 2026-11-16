//! Reconcile compatibility-only entries with positive native data/flow evidence.
use super::*;
use crate::extract::recovery::SeedKind;

/// Compatibility recovery can seed literals, switch tables and internal labels.
/// Keep uncertain entries, including code reached only through a data pointer.
pub fn rejected_compatibility_entries(
    native: &Analysis,
    compatibility: &Analysis,
) -> BTreeSet<u64> {
    let mut rejected = BTreeSet::new();
    for &address in compatibility.functions.keys() {
        if native.functions.contains_key(&address)
            || native.seeds.contains_key(&address)
            || native.callers.contains_key(&address)
        {
            continue;
        }
        // Compatibility accepts reserved ModRM aliases such as C7 /2 as MOV.
        // With no native entry or caller evidence, an invalid first instruction
        // is a false code guess, not a function for the native engine to lift.
        if native.image.decode_at(address).is_err() {
            rejected.insert(address);
            continue;
        }
        if !native.instructions.contains_key(&address) && !native.code_xrefs.contains_key(&address)
        {
            if let Some(references) = native.data_xrefs.get(&address) {
                if literal(&native.image, address)
                    || references
                        .iter()
                        .any(|&site| relative_table(&native.image, site, address))
                {
                    rejected.insert(address);
                }
            }
        } else if compatibility
            .seeds
            .get(&address)
            .is_some_and(|kinds| kinds.len() == 1 && kinds.contains(&SeedKind::PointerTarget))
            && !native.data_xrefs.contains_key(&address)
        {
            // All incoming branches must belong to the same recovered function
            // as the label. A cross-function jump can instead be a tail call.
            if let Some(references) = native.code_xrefs.get(&address) {
                if !references.is_empty()
                    && native.functions.values().any(|function| {
                        let contains = |address| {
                            function
                                .blocks
                                .iter()
                                .any(|block| block.insns.iter().any(|insn| insn.address == address))
                        };
                        contains(address) && references.iter().all(|&site| contains(site))
                    })
                {
                    rejected.insert(address);
                }
            }
        }
    }
    rejected
}

fn literal(image: &LoadedImage, address: u64) -> bool {
    let Some(bytes) = image.bytes_at(address, 256) else {
        return false;
    };
    let length = bytes
        .iter()
        .take_while(|b| b.is_ascii_graphic() || **b == b' ')
        .count();
    // Rust literals need not end in NUL. A long printable run, already used as
    // data with no native code reference, is enough to reject a code guess.
    length >= 32 || length >= 8 && bytes.get(length) == Some(&0)
}

fn relative_table(image: &LoadedImage, site: u64, address: u64) -> bool {
    if image.architecture != Architecture::X64 {
        return false;
    }
    let check = || -> Option<()> {
        let lea = image.decode_at(site).ok()?;
        let load = image.decode_at(lea.next_address).ok()?;
        let add = image.decode_at(load.next_address).ok()?;
        let jump = image.decode_at(add.next_address).ok()?;
        let (lea, load, add, jump) = (
            lea.x86_instruction(),
            load.x86_instruction(),
            add.x86_instruction(),
            jump.x86_instruction(),
        );
        let base = lea.op0_register();
        let value = load.op0_register();
        if lea.mnemonic() != Mnemonic::Lea
            || !lea.is_ip_rel_memory_operand()
            || lea.ip_rel_memory_address() != address
            || base.size() != 8
            || load.mnemonic() != Mnemonic::Movsxd
            || value.size() != 8
            || value == base
            || load.op1_kind() != OpKind::Memory
            || load.memory_base() != base
            || load.memory_index() == Register::None
            || load.memory_index_scale() != 4
            || load.memory_displacement64() != 0
            || load.memory_size().size() != 4
            || add.mnemonic() != Mnemonic::Add
            || add.op0_register() != value
            || add.op1_register() != base
            || jump.mnemonic() != Mnemonic::Jmp
            || jump.op0_register() != value
        {
            return None;
        }
        for offset in [0, 4, 8] {
            let raw = i32::from_le_bytes(
                image
                    .bytes_at(address.checked_add(offset)?, 4)?
                    .try_into()
                    .ok()?,
            );
            let target = address.checked_add_signed(i64::from(raw))?;
            if target == address || !image.is_executable_address(target) {
                return None;
            }
        }
        Some(())
    };
    check().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::image::SHELLCODE_BASE;
    use crate::extract::recovery::{analyze_shellcode, Function};

    #[test]
    fn invalid_compatibility_only_entry_is_not_promoted() -> anyhow::Result<()> {
        let mut bytes = vec![0xc3; 16];
        bytes.extend([0xc7, 0x52, 0xa6, 0xd3, 0x94, 0x3b, 0x9d, 0xc3]);
        let mut native = analyze_shellcode(&bytes, Architecture::X86)?;
        let address = SHELLCODE_BASE + 16;
        native.functions.remove(&address);
        native.seeds.remove(&address);
        native.callers.remove(&address);
        let mut compatibility = native.clone();
        compatibility.functions.insert(
            address,
            Function {
                addr: address,
                blocks: vec![],
            },
        );
        assert!(rejected_compatibility_entries(&native, &compatibility).contains(&address));
        native
            .seeds
            .insert(address, BTreeSet::from([SeedKind::Export]));
        assert!(!rejected_compatibility_entries(&native, &compatibility).contains(&address));
        Ok(())
    }

    #[test]
    fn data_evidence_rejects_literals_but_keeps_a_called_entry() -> anyhow::Result<()> {
        let mut bytes = vec![0xc3; 32];
        bytes.extend(b"GetThreadUILanguage\0");
        let mut native = analyze_shellcode(&bytes, Architecture::X64)?;
        let address = SHELLCODE_BASE + 32;
        native.functions.remove(&address);
        native.instructions.remove(&address);
        native.seeds.remove(&address);
        native.data_xrefs.insert(address, vec![SHELLCODE_BASE]);
        let mut compatibility = native.clone();
        compatibility.functions.insert(
            address,
            Function {
                addr: address,
                blocks: vec![],
            },
        );
        assert!(rejected_compatibility_entries(&native, &compatibility).contains(&address));
        native
            .callers
            .insert(address, BTreeSet::from([SHELLCODE_BASE]));
        assert!(!rejected_compatibility_entries(&native, &compatibility).contains(&address));
        Ok(())
    }

    #[test]
    fn table_requires_a_load_add_jump_and_executable_targets() {
        let mut bytes = vec![
            0x48, 0x8d, 0x0d, 25, 0, 0, 0, 0x48, 0x63, 0x04, 0x81, 0x48, 0x01, 0xc8, 0xff, 0xe0,
        ];
        bytes.resize(32, 0xc3);
        for offset in [-16i32, -15, -14] {
            bytes.extend(offset.to_le_bytes());
        }
        let image = LoadedImage::from_shellcode(&bytes, Architecture::X64);
        assert!(relative_table(&image, SHELLCODE_BASE, SHELLCODE_BASE + 32));
        bytes[15] = 0xe1; // Jump through the base instead of the computed target.
        let image = LoadedImage::from_shellcode(&bytes, Architecture::X64);
        assert!(!relative_table(&image, SHELLCODE_BASE, SHELLCODE_BASE + 32));
    }

    #[test]
    fn internal_label_requires_all_references_to_stay_in_its_function() -> anyhow::Result<()> {
        let base = SHELLCODE_BASE;
        let mut native = analyze_shellcode(&[0x31, 0xc0, 0xeb, 0, 0xc3], Architecture::X64)?;
        let label = base + 4;
        native.functions.remove(&label);
        native.seeds.remove(&label);
        native.data_xrefs.remove(&label);
        native.callers.remove(&label);
        native.code_xrefs.insert(label, vec![base + 2]);
        let mut compatibility = native.clone();
        compatibility.functions.insert(
            label,
            Function {
                addr: label,
                blocks: vec![],
            },
        );
        compatibility
            .seeds
            .insert(label, BTreeSet::from([SeedKind::PointerTarget]));
        assert!(rejected_compatibility_entries(&native, &compatibility).contains(&label));
        native.code_xrefs.insert(label, vec![base + 2, base + 100]);
        assert!(!rejected_compatibility_entries(&native, &compatibility).contains(&label));
        Ok(())
    }
}
