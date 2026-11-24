//! CLI subcommand for querying offline `.bxfam` family and trusted-software packs.

use std::path::{Path, PathBuf};

use binfera::family::{sketch_bytes, FamilyPack, MatchConfig};

use crate::{CliError, E_CORRUPT_FILE, E_MISSING_FILE};

#[derive(clap::Subcommand)]
pub(crate) enum FamilyCommand {
    /// Match a binary against a `.bxfam` pack and print its Trusted / Malware / Shared / Unique breakdown.
    Match {
        /// Path to the `.bxfam` pack
        #[arg(long)]
        pack: PathBuf,
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
}

pub(crate) fn run_family_command(
    cmd: &FamilyCommand,
    json: bool,
    apply_default_instruction_limit: bool,
) -> Result<(), CliError> {
    match cmd {
        FamilyCommand::Match {
            pack,
            input,
            min_instructions,
            min_exclusive,
            min_score,
            min_coverage,
            min_band_hits,
        } => run_match(
            pack,
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
    }
}

fn run_match(
    pack_path: &Path,
    input: &Path,
    config: MatchConfig,
    json: bool,
    apply_default_instruction_limit: bool,
) -> Result<(), CliError> {
    if apply_default_instruction_limit {
        binfera::extract::recovery::set_instruction_limit(Some(500_000));
    }
    let pack_bytes = std::fs::read(pack_path).map_err(|e| {
        CliError::new(
            E_MISSING_FILE,
            format!("reading {}: {e}", pack_path.display()),
        )
    })?;
    let pack = FamilyPack::from_bytes(&pack_bytes)
        .map_err(|e| CliError::new(E_CORRUPT_FILE, e.to_string()))?;
    let sample_bytes = std::fs::read(input)
        .map_err(|e| CliError::new(E_MISSING_FILE, format!("reading {}: {e}", input.display())))?;
    let name = input
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let sketch = sketch_bytes(&sample_bytes, "", &name, false)
        .map_err(|e| CliError::new(E_CORRUPT_FILE, e.to_string()))?;
    let report = pack.match_sketch(&sketch, &config);
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
    }
    Ok(())
}
