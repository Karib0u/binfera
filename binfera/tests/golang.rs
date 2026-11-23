//! The Go function table and build information on real binaries, one per table layout.
use binfera::extract::image::LoadedImage;
use binfera::extract::recovery::{self, SeedKind};
use binfera::golang::{self, pclntab::Layout, GoVersion};

fn read(sample: &[u8]) -> anyhow::Result<golang::GoBinary> {
    let image = LoadedImage::parse(sample)?;
    golang::parse(&image).ok_or_else(|| anyhow::anyhow!("not a Go binary"))
}

fn named(go: &golang::GoBinary, name: &str) -> Option<u64> {
    go.functions
        .functions
        .iter()
        .find(|function| function.name == name)
        .map(|function| function.entry)
}

#[test]
fn capability_recovery_uses_go_function_table() -> anyhow::Result<()> {
    for sample in [
        include_bytes!("../../tests/testfiles/4122acca2f9ea98fc3f3ad040688e4ce.exe_").as_slice(),
        include_bytes!(
            "../../tests/testfiles/3da7c2c70a2d93ac4643f20339d5c7d61388bddd77a4a5fd732311efad78e535.elf_"
        )
        .as_slice(),
    ] {
        let analysis = recovery::analyze(sample)?;
        let entry = named(&read(sample)?, "main.main")
            .ok_or_else(|| anyhow::anyhow!("missing main.main in the Go table"))?;
        assert!(analysis.seeds[&entry].contains(&SeedKind::GoFunctionTable));
        assert!(analysis.functions.contains_key(&entry));
    }
    Ok(())
}

struct Case {
    sample: &'static [u8],
    version: GoVersion,
    layout: Layout,
    /// The table's size, when the sample is pinned (the fixture can be rebuilt).
    functions: Option<usize>,
    name: &'static str,
    entry: Option<u64>,
}

#[test]
fn reads_each_table_layout() -> anyhow::Result<()> {
    let cases = [
        Case {
            sample: include_bytes!("../../tests/testfiles/49a34cfbeed733c24392c9217ef46bb6.exe_"),
            version: GoVersion::new(1, 14, 4),
            layout: Layout::Go12,
            functions: Some(5192),
            name: "main.ReleaseDC",
            entry: Some(0x617500),
        },
        Case {
            sample: include_bytes!("../../tests/testfiles/4122acca2f9ea98fc3f3ad040688e4ce.exe_"),
            version: GoVersion::new(1, 16, 2),
            layout: Layout::Go116,
            functions: Some(1996),
            name: "main.copyFile",
            entry: Some(0x4f9cc0),
        },
        Case {
            sample: include_bytes!(
                "../../tests/testfiles/3da7c2c70a2d93ac4643f20339d5c7d61388bddd77a4a5fd732311efad78e535.elf_"
            ),
            version: GoVersion::new(1, 22, 1),
            layout: Layout::Go120,
            functions: Some(1181),
            name: "main.main",
            entry: Some(0x80a6ee0),
        },
        Case {
            sample: include_bytes!("fixtures/go/register_abi.exe"),
            version: GoVersion::new(1, 27, 3),
            layout: Layout::Go120,
            functions: None,
            name: "main.(*Config).Ready",
            entry: None,
        },
    ];
    for case in cases {
        let go = read(case.sample)?;
        assert_eq!(go.build_version, Some(case.version));
        assert_eq!(go.version(), case.version);
        assert_eq!(go.functions.layout, case.layout);
        if let Some(count) = case.functions {
            assert_eq!(go.functions.functions.len(), count);
        }
        let found = named(&go, case.name).ok_or_else(|| anyhow::anyhow!("no {}", case.name))?;
        if let Some(entry) = case.entry {
            assert_eq!(found, entry, "{}", case.name);
        }
        // Entries are sorted, distinct and each ends where the next starts.
        for pair in go.functions.functions.windows(2) {
            assert!(pair[0].entry < pair[1].entry);
            assert!(pair[0].end <= pair[1].entry);
        }
    }
    Ok(())
}

#[test]
fn a_dump_without_build_information_takes_the_runtime_version_string() -> anyhow::Result<()> {
    // The build information sits in `.data`; blank its magic, as a dump that lost it would.
    let mut sample = include_bytes!("fixtures/go/register_abi.exe").to_vec();
    let at = sample
        .windows(14)
        .position(|w| w == b"\xff Go buildinf:")
        .ok_or_else(|| anyhow::anyhow!("no build information"))?;
    sample[at] = 0;
    let go = read(&sample)?;
    assert_eq!(go.build_version, None);
    assert_eq!(go.version_string, Some(GoVersion::new(1, 27, 3)));
    assert_eq!(go.version(), GoVersion::new(1, 27, 3));
    Ok(())
}

#[test]
fn a_c_program_is_not_go() -> anyhow::Result<()> {
    let image = LoadedImage::parse(include_bytes!("../../tests/decompiler/fixtures.dll"))?;
    assert!(golang::parse(&image).is_none());
    Ok(())
}

#[test]
fn garbled_116_layout_uses_register_stack_checks_only_without_a_version() -> anyhow::Result<()> {
    use binfera::extract::image::Architecture;
    let original = include_bytes!("../../tests/testfiles/4122acca2f9ea98fc3f3ad040688e4ce.exe_");
    let image = LoadedImage::parse(original)?;
    assert_eq!(image.architecture, Architecture::X64);
    let go = golang::parse(&image).ok_or_else(|| anyhow::anyhow!("Go table"))?;
    let mut sample = original.to_vec();
    for function in go.functions.functions.iter().take(2) {
        let offset = image
            .va_to_file_offset(function.entry)
            .ok_or_else(|| anyhow::anyhow!("entry"))? as usize;
        sample[offset..offset + 4].copy_from_slice(&[0x49, 0x3b, 0x66, 0x10]);
    }
    assert_eq!(read(&sample)?.version(), GoVersion::new(1, 16, 2));
    let mut hidden = original.to_vec();
    for index in 0..hidden.len().saturating_sub(8) {
        if hidden.get(index..index + 8) == Some(b"go1.16.2") {
            hidden[index..index + 8].copy_from_slice(b"unknown0");
            sample[index..index + 8].copy_from_slice(b"unknown0");
        }
    }
    assert_eq!(read(&hidden)?.version(), GoVersion::new(1, 16, 0));
    assert_eq!(read(&sample)?.version(), GoVersion::new(1, 17, 0));
    Ok(())
}
