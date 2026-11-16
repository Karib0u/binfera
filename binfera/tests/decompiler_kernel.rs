#![cfg(feature = "decompiler")]
use binfera::decompiler::{CallingConvention, DecompilerSession};

const X86: &[u8] = include_bytes!("fixtures/kernel/imports32.sys");
const X64: &[u8] = include_bytes!("fixtures/kernel/imports64.sys");

fn address(sample: &[u8], name: &str) -> anyhow::Result<u64> {
    let pe = goblin::pe::PE::parse(sample)?;
    let export = pe
        .exports
        .iter()
        .find(|e| e.name == Some(name))
        .ok_or_else(|| anyhow::anyhow!("missing export {name}"))?;
    Ok(pe.image_base + export.rva as u64)
}

#[test]
fn kernel_and_native_imports_have_typed_arguments_on_both_widths() -> anyhow::Result<()> {
    for sample in [X86, X64] {
        let mut session = DecompilerSession::from_pe(sample)?;
        for (wrapper, import, arguments) in [
            ("allocate_pool", "ntoskrnl_ExAllocatePoolWithTag", 3),
            ("create_device", "ntoskrnl_IoCreateDevice", 7),
            ("initialize_string", "ntoskrnl_RtlInitUnicodeString", 2),
            ("complete_request", "ntoskrnl_IofCompleteRequest", 2),
            ("read_bus", "hal_HalGetBusDataByOffset", 6),
            ("allocate_network", "ndis_NdisAllocateMemoryWithTag", 3),
            ("start_filter", "fltmgr_FltStartFiltering", 1),
            ("create_file", "ntoskrnl_ZwCreateFile", 11),
            ("native_create_file", "ntdll_NtCreateFile", 11),
        ] {
            let entry = address(sample, wrapper)?;
            let output = session.decompile_function(entry)?;
            println!("{wrapper}: {}\n{:?}", output.text, output.warnings);
            assert!(!output.unknown_callees, "{}", output.text);
            let compact: String = output.text.chars().filter(|c| !c.is_whitespace()).collect();
            let call = compact
                .split(&format!("{import}("))
                .nth(1)
                .ok_or_else(|| anyhow::anyhow!("missing {import}: {}", output.text))?;
            let call = call.split(';').next().unwrap_or(call);
            assert_eq!(call.matches(',').count() + 1, arguments, "{}", output.text);
            let unit = session.decompile_unit(&[entry])?;
            assert!(
                unit.text.lines().any(|line| line.starts_with("extern ")
                    && line.contains(&format!("{import}("))
                    && !line.contains("GUESS")),
                "{}",
                unit.text
            );
            assert!(!unit.guesses.iter().any(|guess| guess.name == import));
        }
    }
    Ok(())
}

#[test]
fn unrelated_driver_module_keeps_unknown_prototype() -> anyhow::Result<()> {
    for sample in [X86, X64] {
        let mut analysis = binfera::extract::recovery::analyze_with_backend(
            sample,
            binfera::extract::recovery::RecoveryBackend::Native,
        )?;
        for name in analysis.image.import_locations.values_mut() {
            *name = name.replace("ntoskrnl.", "custom_driver.");
        }
        let mut session = DecompilerSession::from_analysis(
            &analysis,
            &Default::default(),
            if sample == X86 {
                CallingConvention::WindowsX86
            } else {
                CallingConvention::WindowsX64
            },
        )?;
        assert!(
            session
                .decompile_function(address(sample, "allocate_pool")?)?
                .unknown_callees
        );
    }
    Ok(())
}

#[test]
fn real_x86_driver_uses_fastcall_completion_and_stdcall_device_creation() -> anyhow::Result<()> {
    let sample = include_bytes!("../../tests/testfiles/Practical Malware Analysis Lab 10-03.sys_");
    let mut session = DecompilerSession::from_pe(sample)?;
    let completion = session.decompile_function(0x10606)?;
    println!("{}", completion.text);
    assert!(
        completion.text.contains("ntoskrnl_IofCompleteRequest("),
        "{}",
        completion.text
    );
    assert!(!completion.unknown_callees);
    let creation = session.decompile_function(0x10706)?;
    println!("{}", creation.text);
    assert!(
        creation.text.contains("ntoskrnl_IoCreateDevice"),
        "{}",
        creation.text
    );
    assert!(
        creation.text.contains("ntoskrnl_RtlInitUnicodeString("),
        "{}",
        creation.text
    );
    assert!(!creation.unknown_callees);
    Ok(())
}
