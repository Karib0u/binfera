//! CLI subcommand for querying offline `.bxfam` family and trusted-software packs.

use std::fs::File;
use std::path::{Path, PathBuf};

use binfera::family::{
    extract_origin_strings, sketch_bytes, FamilyPack, FamilyPackSet, MatchConfig, PackHeader,
    LSH_BANDS, LSH_SLOTS_PER_BAND,
};

use crate::{CliError, E_CORRUPT_FILE, E_MISSING_FILE};

#[derive(clap::Subcommand)]
pub(crate) enum FamilyCommand {
    /// Match a binary against one or more `.bxfam` packs and print its Trusted / Malware / Shared / Unique breakdown.
    Match {
        /// Path to a `.bxfam` pack. Repeat to layer packs, base first: a function or string
        /// Trusted by any pack is Trusted, and later packs take precedence for Trusted names.
        #[arg(long = "pack")]
        packs: Vec<PathBuf>,
        /// Binary file to classify
        input: PathBuf,
        #[arg(long, default_value_t = 20)]
        min_instructions: u32,
        #[arg(long, default_value_t = 3)]
        min_exclusive: usize,
        #[arg(long, default_value_t = 3.0)]
        min_score: f64,
        #[arg(long, default_value_t = 0.15)]
        min_coverage: f64,
        #[arg(long, default_value_t = 4)]
        min_band_hits: u8,
    },
    /// Show a pack's header without loading its fingerprint tables.
    Info {
        /// Path to the `.bxfam` pack
        #[arg(long)]
        pack: Option<PathBuf>,
    },
}

pub(crate) fn run_family_command(
    cmd: &FamilyCommand,
    json: bool,
    apply_default_instruction_limit: bool,
) -> Result<(), CliError> {
    match cmd {
        FamilyCommand::Match {
            packs,
            input,
            min_instructions,
            min_exclusive,
            min_score,
            min_coverage,
            min_band_hits,
        } => run_match(
            &pack_paths(packs)?,
            input,
            MatchConfig {
                min_instructions: *min_instructions,
                min_exclusive_functions: *min_exclusive,
                min_score: *min_score,
                min_coverage: *min_coverage,
                min_band_hits: *min_band_hits,
                ..MatchConfig::default()
            },
            json,
            apply_default_instruction_limit,
        ),
        FamilyCommand::Info { pack } => run_info(&pack_path(pack.as_deref())?, json),
    }
}

fn pack_path(explicit: Option<&Path>) -> Result<PathBuf, CliError> {
    let explicit: Vec<PathBuf> = explicit.map(Path::to_path_buf).into_iter().collect();
    pack_paths(&explicit)?
        .into_iter()
        .next()
        .ok_or_else(missing_pack)
}

fn pack_paths(explicit: &[PathBuf]) -> Result<Vec<PathBuf>, CliError> {
    #[cfg(not(target_arch = "wasm32"))]
    let packs = binfera_project::resolve_family_packs(explicit);
    #[cfg(target_arch = "wasm32")]
    let packs = explicit.to_vec();
    if packs.is_empty() {
        Err(missing_pack())
    } else {
        Ok(packs)
    }
}

fn missing_pack() -> CliError {
    #[cfg(not(target_arch = "wasm32"))]
    {
        CliError::new(
            E_MISSING_FILE,
            format!(
                "no family pack found; use --pack <path>, set BINFERA_FAMILY_PACK (or a path list in BINFERA_FAMILY_PACKS), or place family.bxfam in {} or beside the binfera executable",
                binfera_project::data_dir().display()
            ),
        )
    }
    #[cfg(target_arch = "wasm32")]
    {
        CliError::new(E_MISSING_FILE, "no family pack supplied; use --pack <path>")
    }
}

fn run_info(path: &Path, json: bool) -> Result<(), CliError> {
    let reading = |e| CliError::new(E_MISSING_FILE, format!("reading {}: {e}", path.display()));
    let file = File::open(path).map_err(reading)?;
    let size = file.metadata().map_err(reading)?.len();
    let header = PackHeader::read(file)
        .map_err(|e| CliError::new(E_CORRUPT_FILE, format!("reading {}: {e}", path.display())))?;
    let stats = &header.stats;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "path": path.to_string_lossy(),
                "size": size,
                "format": header.format_name(),
                "format_version": header.format_version,
                "family_count": stats.families,
                "trusted_source_count": stats.trusted_sources,
                "trusted_shape_count": stats.trusted_shapes,
                "trusted_symbol_count": stats.trusted_symbols,
                "trusted_string_count": stats.trusted_strings,
                "malware_string_count": stats.malware_strings,
                "lsh": {
                    "enabled": header.lsh_enabled,
                    "bands": LSH_BANDS,
                    "slots_per_band": LSH_SLOTS_PER_BAND,
                    "band_records": stats.band_records,
                },
            })
        );
    } else {
        println!(
            "{} ({size} bytes, {})",
            path.display(),
            header.format_name()
        );
        println!(
            "{} families, {} trusted sources, {} trusted shapes",
            stats.families, stats.trusted_sources, stats.trusted_shapes
        );
        if header.format_version >= 3 {
            println!(
                "{} trusted symbols, {} trusted strings, {} exclusive malware strings",
                stats.trusted_symbols, stats.trusted_strings, stats.malware_strings
            );
        }
        if header.lsh_enabled {
            println!(
                "LSH enabled: {LSH_BANDS} bands of {LSH_SLOTS_PER_BAND} slots, {} records",
                stats.band_records
            );
        } else {
            println!("LSH disabled");
        }
    }
    Ok(())
}

fn run_match(
    pack_paths: &[PathBuf],
    input: &Path,
    config: MatchConfig,
    json: bool,
    apply_default_instruction_limit: bool,
) -> Result<(), CliError> {
    if apply_default_instruction_limit {
        binfera::extract::recovery::set_instruction_limit(Some(500_000));
    }
    let mut packs = FamilyPackSet::new();
    for pack_path in pack_paths {
        let pack_bytes = std::fs::read(pack_path).map_err(|e| {
            CliError::new(
                E_MISSING_FILE,
                format!("reading {}: {e}", pack_path.display()),
            )
        })?;
        let pack = FamilyPack::from_bytes(&pack_bytes)
            .map_err(|e| CliError::new(E_CORRUPT_FILE, format!("{}: {e}", pack_path.display())))?;
        let name = pack_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| pack_path.to_string_lossy().into_owned());
        packs.push(name, pack);
    }
    let sample_bytes = std::fs::read(input)
        .map_err(|e| CliError::new(E_MISSING_FILE, format!("reading {}: {e}", input.display())))?;
    let name = input
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let sketch = sketch_bytes(&sample_bytes, "", &name, false)
        .map_err(|e| CliError::new(E_CORRUPT_FILE, e.to_string()))?;
    let strings = packs
        .has_string_data()
        .then(|| extract_origin_strings(&sample_bytes));
    let report = packs.match_sample(&sketch, strings.as_deref(), &config);
    if json {
        let body = serde_json::to_string_pretty(&report)
            .map_err(|e| CliError::new(E_CORRUPT_FILE, e.to_string()))?;
        println!("{body}");
    } else {
        println!(
            "{}: {} functions ({} eligible) -> Trusted {:.1}% ({}), Malware {:.1}% ({}), Shared {:.1}% ({}), Unique {:.1}% ({})",
            name,
            report.total_functions,
            report.eligible_functions,
            report.breakdown.trusted_pct,
            report.trusted_functions,
            report.breakdown.malware_pct,
            report.family_matched_functions,
            report.breakdown.shared_pct,
            report.shared_malware_functions,
            report.breakdown.unique_pct,
            report.unique_functions,
        );
        if !report.trusted_sources.is_empty() {
            let sources: Vec<String> = report
                .trusted_sources
                .iter()
                .take(5)
                .map(|s| format!("{} ({})", s.source, s.functions))
                .collect();
            println!("  trusted: {}", sources.join(", "));
        }
        if report.families.is_empty() {
            println!("  malware: no family match above threshold");
        } else {
            for m in &report.families {
                println!(
                    "  malware: {:<28} score={:<6.2} excl={:<3} content={:<3} shape={:<3} fuzzy={:<3} coverage={:.1}%",
                    m.family,
                    m.score,
                    m.exclusive_functions,
                    m.exact_content_hits,
                    m.exact_shape_hits,
                    m.fuzzy_hits,
                    m.coverage * 100.0
                );
            }
        }
        if !report.trusted_symbols.is_empty() {
            let symbols: Vec<String> = report
                .trusted_symbols
                .iter()
                .take(5)
                .map(|s| format!("{:#x} {}", s.address, s.trusted_symbol))
                .collect();
            println!(
                "  trusted symbols: {} ({} total)",
                symbols.join(", "),
                report.trusted_symbols.len()
            );
        }
        if let Some(strings) = &report.strings {
            println!(
                "  strings (supporting evidence only): {} -> Trusted {:.1}% ({}), Malware {:.1}% ({}), Shared {:.1}% ({}), Unique {:.1}% ({})",
                strings.total_strings,
                strings.breakdown.trusted_pct,
                strings.trusted_strings,
                strings.breakdown.malware_pct,
                strings.malware_strings,
                strings.breakdown.shared_pct,
                strings.shared_strings,
                strings.breakdown.unique_pct,
                strings.unique_strings,
            );
            for f in strings.families.iter().take(3) {
                println!(
                    "    string reuse: {:<24} exclusive={:<3} shared={:<3}{}",
                    f.family,
                    f.exclusive_strings,
                    f.shared_strings,
                    if f.corroborates_code {
                        " (corroborates code)"
                    } else {
                        ""
                    }
                );
            }
            if let Some(hint) = &strings.string_only_hint {
                println!(
                    "    string-only hint (not a verdict): {} from {} exclusive strings",
                    hint.family, hint.exclusive_strings
                );
            }
        }
    }
    Ok(())
}
