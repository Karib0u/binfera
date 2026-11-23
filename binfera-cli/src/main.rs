#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::Parser;

use binfera::api::{self, AnalysisError, PhaseTimings};
use binfera::capabilities::{find_dynamic_capabilities, find_static_capabilities, MatchingRuleSet};
use binfera::diff::{self, DiffError, Fingerprint, FingerprintOptions, Verdict};
use binfera::engine::MatchResults;
use binfera::extract::recovery::RecoveryError;
use binfera::freeze::Freeze;
use binfera::parallel::{AnalysisOptions, Jobs};
use binfera::rd::{ResultDocument, ARCH_AUTO, OS_AUTO};
use binfera::render::{default, verbose, vverbose};
use binfera::rules::{load_rule_directory, Rule};

#[cfg(all(feature = "decompiler", not(target_arch = "wasm32")))]
mod decompile_workers;
#[cfg(not(target_arch = "wasm32"))]
mod embedded_rules;

// Supported input formats and native/managed detection are documented in docs/cli.md.
#[derive(Parser)]
#[command(name = "binfera", version = binfera::VERSION_STRING, about = "See what a binary does: capabilities, decompiled C and diffs for PE, ELF and Mach-O", long_about = None)]
struct Cli {
    /// path to file to analyze (PE, ELF, Mach-O, or a freeze file)
    ///
    /// Optional only so `binfera fetch-rules` can run without one; every
    /// analysis still requires it.
    input_file: Option<PathBuf>,

    /// download the pinned rules (an explicit action -- binfera never
    /// fetches anything while analysing a sample)
    #[command(subcommand)]
    command: Option<Command>,

    /// path to rule file or directory [default: ./rules, else rules/ beside
    /// the executable, else the rules built into this binary]
    #[arg(short = 'r', long = "rules", env = "BINFERA_RULES_DIR", global = true)]
    rules: Option<PathBuf>,

    /// path to a .sig/.pat file or directory used to identify library
    /// functions; embedded signatures are used by default
    #[arg(short = 's', long = "signatures")]
    signatures: Option<PathBuf>,

    /// select input format
    #[arg(short = 'f', long = "format", value_enum, default_value_t = Format::Auto, global = true)]
    format: Format,

    /// Decompile a supported native image function by virtual address (requires decompiler feature).
    /// Repeat the option for several functions; more than one needs --unit
    #[arg(long, value_parser = parse_function_address, conflicts_with_all = ["dump_code_layout", "dump_features", "dump_matches", "file_only", "rules", "signatures", "tag"])]
    decompile_function: Vec<u64>,

    /// Emulate one function by virtual address and emit JSON (requires decompiler feature).
    #[arg(long, value_parser = parse_function_address, conflicts_with_all = ["decompile_function", "decompile_all", "image_info", "dump_code_layout", "dump_features", "dump_matches", "file_only", "rules", "signatures", "tag"])]
    emulate: Option<u64>,

    /// Integer/pointer arguments, decimal or 0x-prefixed hex; repeat for each ABI slot.
    #[arg(long, requires = "emulate", value_parser = parse_emulation_value)]
    emulate_arg: Vec<u64>,

    /// Read a full emulation request as JSON from stdin.
    #[arg(long, requires = "emulate", conflicts_with = "emulate_arg")]
    emulate_request: bool,

    /// Execute each recovered call site, starting from its caller's entry.
    #[arg(long, requires = "emulate")]
    emulate_call_sites: bool,

    #[arg(long, requires = "emulate")]
    emulate_max_steps: Option<u64>,

    #[arg(long, requires = "emulate")]
    emulate_timeout_ms: Option<u32>,

    /// Maximum call sites to execute (1..128; default 32).
    #[arg(long, requires = "emulate_call_sites")]
    emulate_max_sites: Option<usize>,

    /// With --decompile-function: emit a self-contained C translation unit (prelude, types,
    /// callee prototypes from the type archive, marked guesses for the rest, the function
    /// bodies) that a C compiler accepts. With --json the guesses are listed
    #[arg(long, requires = "decompile_function")]
    unit: bool,

    /// Decompile every recovered function of a supported native image, streaming one JSON
    /// object per line (requires decompiler feature). Used by the web UI.
    #[arg(long, conflicts_with_all = ["decompile_function", "dump_code_layout", "dump_features", "dump_matches", "file_only", "rules", "signatures", "tag"])]
    decompile_all: bool,

    /// With --decompile-all: decompile only shard INDEX of COUNT (`INDEX/COUNT`, zero-based). Every
    /// shard lists all functions in its `start` record; the recovered functions are split round-robin,
    /// so running all COUNT shards (possibly in parallel) covers each of them once. A callee that
    /// recovery never listed is decompiled by each shard that finds it, so consumers must dedupe by address
    #[arg(long, value_name = "INDEX/COUNT", value_parser = parse_shard, requires = "decompile_all")]
    shard: Option<(usize, usize)>,

    /// Invocation-local recovery handoff used by the native worker pool.
    #[arg(long, hide = true, requires = "decompile_all")]
    decompile_cache: Option<PathBuf>,

    /// Leave resource-limited functions for an explicit retry.
    #[arg(long, requires = "decompile_all", conflicts_with = "decompile_retry")]
    no_resource_retry: bool,

    #[arg(long, hide = true, value_parser = parse_function_address, requires = "decompile_all", conflicts_with = "shard")]
    decompile_retry: Vec<u64>,

    /// With --decompile-all: add every seeded address's evidence kinds and the chained x64
    /// unwind fragments to the `start` record, for `scripts/bench/recovery.py`. Runs in-process
    #[arg(long, hide = true, requires = "decompile_all")]
    start_evidence: bool,

    /// Use longer resource limits for an explicitly selected function.
    #[arg(long, requires = "decompile_function")]
    resource_retry: bool,

    /// Emit normalized image headers, mappings, imports and exports without code recovery.
    #[arg(long, conflicts_with_all = ["decompile_all", "decompile_function", "dump_code_layout", "dump_features", "dump_matches", "file_only", "rules", "signatures", "tag"])]
    image_info: bool,

    /// Try x86/x64 raw code when image inspection finds no executable header.
    #[arg(long, requires = "image_info")]
    guess_shellcode: bool,

    /// emit JSON instead of text
    #[arg(short = 'j', long = "json", global = true)]
    json: bool,

    /// enable verbose result document (no effect with --json). Repeating
    /// the short flag (`-vv`, via clap's short-flag clustering) selects
    /// vverbose, matching upstream's separate `-v`/`-vv` flags.
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,

    /// enable very verbose result document (no effect with --json)
    #[arg(long = "vverbose")]
    vverbose: bool,

    /// filter on rule meta field values
    #[arg(short = 't', long = "tag")]
    tag: Option<String>,

    /// select sample OS: auto, linux, macos, windows
    #[arg(long = "os", default_value = OS_AUTO)]
    os: String,

    /// select sample architecture (binfera addition; upstream has no
    /// `--arch` flag)
    #[arg(long = "arch", default_value = ARCH_AUTO, global = true)]
    arch: String,

    /// disable all output but errors
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    /// number of threads used for rule parsing and for per-function feature
    /// extraction and matching [default: logical cores, capped by the work items].
    /// Capability results are byte-identical across job counts.
    /// With --decompile-all, use up to N native worker processes, capped at
    /// 16 and the available cores [default for decompilation: 1]. Recovery is
    /// prepared once; function records stream as workers finish.
    /// Native x86/x64 PE startup uses up to N threads to load bundled signatures
    /// [default: available cores, capped by the number of databases].
    #[arg(long = "jobs", value_name = "N", value_parser = parse_jobs, global = true)]
    jobs: Option<Jobs>,

    /// refuse a file once code recovery has decoded N instructions, before it runs out of memory
    /// (exit code 14). Memory grows with the instructions decoded, roughly 0.6 to 1.3 KB each.
    /// 0 removes the limit [default: no limit; 2500000 in the WebAssembly build]
    #[arg(long = "max-instructions", value_name = "N", global = true)]
    max_instructions: Option<usize>,

    /// print per-phase timings (rule loading, extraction, matching, result
    /// construction, total) to stderr
    #[arg(long = "timing")]
    timing: bool,

    /// print "<rule name>@<address>" lines (one per matched location),
    /// sorted for deterministic diffing -- a difftest debug surface, kept
    /// alongside `-j`.
    #[arg(long = "dump-matches", hide = true)]
    dump_matches: bool,

    /// print "<scope>\t<feature>\t<address>" lines (one per extracted
    /// global/file feature), sorted for deterministic diffing -- a difftest
    /// debug surface, the raw-feature-set counterpart to `--dump-matches`.
    #[arg(long = "dump-features", hide = true)]
    dump_features: bool,

    /// Keep raw PE/ELF analysis on the file-scope extractors, skipping code
    /// recovery. Used only by the file-scope differential gate.
    #[arg(long = "file-only", hide = true)]
    file_only: bool,

    /// Emit recovered functions, basic blocks, seeds, and diagnostics as
    /// deterministic JSON for the code-layout differential gate.
    #[arg(long = "dump-code-layout", hide = true)]
    dump_code_layout: bool,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Clone the pinned rules release into a directory (default:
    /// `./rules`), so `binfera` can find it without `-r`.
    ///
    /// Release archives already ship the rules; this is for `cargo install`
    /// users and source checkouts without the submodule. It runs `git`, and
    /// only when you ask -- analysis never reaches the network.
    FetchRules {
        /// where to clone into
        #[arg(default_value = "rules")]
        directory: PathBuf,

        /// rules release to fetch [default: the pinned one this binary
        /// targets]
        #[arg(long = "ref")]
        reference: Option<String>,
    },

    /// Run the local Model Context Protocol server on stdin/stdout.
    ///
    /// Lets an MCP client (Claude Code, Codex) open binaries, read decompiled code and save
    /// annotations and reports into persistent Binfera projects. No network listener is opened;
    /// logs go to stderr. Register with `claude mcp add --scope user binfera -- binfera mcp`.
    #[cfg(not(target_arch = "wasm32"))]
    Mcp,

    /// Compare two binaries: file structure, functions and capabilities.
    ///
    /// Each input is a binary or a file written by `binfera fingerprint`. Exits 0 when nothing
    /// compared differs, 1 when something does, and with the usual error codes otherwise.
    Diff {
        /// the older or reference file
        a: PathBuf,
        /// the file to compare with it
        b: PathBuf,

        /// skip rule matching; only file structure and functions are compared
        #[arg(long = "no-capabilities")]
        no_capabilities: bool,

        /// A's `--json` result document, instead of running the rules
        #[arg(
            long = "caps-a",
            alias = "capa-a",
            value_name = "FILE",
            requires = "caps_b"
        )]
        caps_a: Option<PathBuf>,

        /// B's `--json` result document, instead of running the rules
        #[arg(
            long = "caps-b",
            alias = "capa-b",
            value_name = "FILE",
            requires = "caps_a"
        )]
        caps_b: Option<PathBuf>,

        /// compare one pair of functions down to their instructions
        #[arg(long = "pair", value_name = "A:B", value_parser = parse_pair)]
        pair: Option<(u64, u64)>,

        /// with --pair: the function match as a JSON list of [a, b] addresses, for fingerprints
        /// that hold only the listings. Otherwise it is worked out from the inputs
        #[arg(long = "function-map", value_name = "FILE", requires = "pair")]
        function_map: Option<PathBuf>,
    },

    /// Write the facts `binfera diff` compares, one JSON object per line, to stdout.
    Fingerprint {
        input: PathBuf,

        /// leave out function listings, which `diff --pair` needs
        #[arg(long = "no-detail")]
        no_detail: bool,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Format {
    Auto,
    Pe,
    Elf,
    Sc32,
    Sc64,
    Freeze,
    Dotnet,
    /// A binfera extension: pinned capa has no Mach-O loader. `Auto` also
    /// detects it, after PE and ELF.
    Macho,
}

impl From<Format> for api::Format {
    fn from(f: Format) -> api::Format {
        match f {
            Format::Auto => api::Format::Auto,
            Format::Pe => api::Format::Pe,
            Format::Elf => api::Format::Elf,
            Format::Sc32 => api::Format::Sc32,
            Format::Sc64 => api::Format::Sc64,
            Format::Freeze => api::Format::Freeze,
            Format::Dotnet => api::Format::Dotnet,
            Format::Macho => api::Format::Macho,
        }
    }
}

// exit codes mirrored from capa/main.py's E_* constants. E_INVALID_SIG and
// E_INVALID_FILE_TYPE no longer appear here: both errors now originate
// inside `binfera::api`, which carries its own copies
// (`AnalysisError::exit_code`) -- see `impl From<AnalysisError> for
// CliError` below.
const E_MISSING_FILE: u8 = 11;
const E_INVALID_RULE: u8 = 12;
const E_CORRUPT_FILE: u8 = 13;
const E_FILE_LIMITATION: u8 = 14;

struct CliError {
    code: u8,
    message: String,
}

impl CliError {
    fn new(code: u8, message: impl Into<String>) -> CliError {
        CliError {
            code,
            message: message.into(),
        }
    }
}

/// `binfera::api::AnalysisError`'s message text and exit code already
/// reproduce what this binary produced for the same failure before the
/// analysis API was hoisted into the library -- see that type's doc comment.
impl From<AnalysisError> for CliError {
    fn from(e: AnalysisError) -> CliError {
        CliError::new(e.exit_code(), e.to_string())
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {}", e.message);
            ExitCode::from(e.code)
        }
    }
}

impl Cli {
    /// The rule directory to load, resolving the default when neither
    /// `--rules` nor `BINFERA_RULES_DIR` was given.
    ///
    /// `./rules` comes first: that is a source checkout with the capa-rules
    /// submodule initialised, and it is what every existing invocation means.
    /// The fallback is `rules/` beside the executable, which is how the release
    /// archive is laid out -- without it, an unpacked archive only works when
    /// the working directory happens to be the archive's own.
    fn rules_dir(&self) -> PathBuf {
        if let Some(explicit) = &self.rules {
            return explicit.clone();
        }
        // The variable's old name, still honoured.
        if let Some(legacy) = std::env::var_os("CAPA_RULES_DIR").filter(|v| !v.is_empty()) {
            return PathBuf::from(legacy);
        }
        // An empty folder (an uninitialised submodule, say) is not a rule set: skip it.
        let has_rules = |dir: &std::path::Path| {
            std::fs::read_dir(dir).is_ok_and(|mut entries| {
                entries.any(|e| e.is_ok_and(|e| !e.file_name().to_string_lossy().starts_with('.')))
            })
        };
        let cwd_rules = PathBuf::from("rules");
        if has_rules(&cwd_rules) {
            return cwd_rules;
        }
        if let Some(beside_exe) = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join("rules")))
            .filter(|beside_exe| has_rules(beside_exe))
        {
            return beside_exe;
        }
        // Last, the rules built into the binary, unpacked once into the data directory.
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(embedded) = embedded_rules::unpack() {
            return embedded;
        }
        cwd_rules
    }

    /// The analysis-shaped knobs `binfera::api` reads. `os`/`arch` collapse
    /// their `"auto"` CLI sentinel to `None` here -- `api`'s `AnalysisOptions`
    /// uses `Option` so [`AnalysisOptions::SERIAL`] can stay a `const` (see
    /// its doc comment); presentation flags (`--json`, verbosity, `--timing`,
    /// the `--dump-*` debug flags) stay on `Cli` and never reach this struct.
    fn analysis_options(&self) -> AnalysisOptions {
        AnalysisOptions {
            jobs: self.jobs.unwrap_or_else(Jobs::available),
            format: self.format.into(),
            os: (self.os != OS_AUTO).then(|| self.os.clone()),
            arch: (self.arch != ARCH_AUTO).then(|| self.arch.clone()),
            file_only: self.file_only,
            signatures_path: self.signatures.clone(),
        }
    }
}

/// `--shard`'s value parser: `INDEX/COUNT` with `INDEX < COUNT`.
fn parse_shard(raw: &str) -> Result<(usize, usize), String> {
    let invalid = || format!("`{raw}` is not a shard of the form INDEX/COUNT with INDEX < COUNT");
    let (index, count) = raw.split_once('/').ok_or_else(invalid)?;
    let index: usize = index.parse().map_err(|_| invalid())?;
    let count: usize = count.parse().map_err(|_| invalid())?;
    if count == 0 || index >= count {
        return Err(invalid());
    }
    Ok((index, count))
}

/// `--jobs`' value parser, so `--jobs 0` fails at argument-parsing time with
/// clap's own contextual message (flag name, offending value, and the reason)
/// rather than somewhere inside the analysis.
fn parse_jobs(raw: &str) -> Result<Jobs, String> {
    let count: usize = raw
        .parse()
        .map_err(|_| format!("`{raw}` is not a whole number of threads"))?;
    Jobs::new(count).map_err(|e| e.to_string())
}

/// Wall-clock time per analysis phase, printed by `--timing` and consumed by
/// `scripts/bench.py`. Separated because the phases scale differently:
/// rule loading is fixed per invocation, extraction and matching are the two
/// that `--jobs` can move, and only a split like this can show which one a
/// change actually affected.
///
/// `rules` and `total` are this binary's own bookkeeping (rule loading stays
/// a CLI-side step, ahead of `binfera::api`, per that module's doc
/// comment); the other four fold in from an [`api::PhaseTimings`] returned by
/// [`api::load_input`]/[`api::analyze_with_timings`].
#[derive(Default)]
struct Timings {
    rules: Duration,
    load_and_recover: Duration,
    extraction: Duration,
    matching: Duration,
    result: Duration,
    total: Duration,
}

impl Timings {
    fn report(&self) {
        for (phase, elapsed) in [
            ("rules", self.rules),
            ("load+recovery", self.load_and_recover),
            ("extraction", self.extraction),
            ("matching", self.matching),
            ("result", self.result),
            ("total", self.total),
        ] {
            eprintln!("timing\t{phase}\t{:.6}", elapsed.as_secs_f64());
        }
    }

    fn fold_phases(&mut self, phases: &PhaseTimings) {
        self.load_and_recover += phases.load_and_recover;
        self.extraction += phases.extraction;
        self.matching += phases.matching;
        self.result += phases.result;
    }
}

fn timed<T>(slot: &mut Duration, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let value = f();
    *slot += start.elapsed();
    value
}

fn run(cli: &Cli) -> Result<ExitCode, CliError> {
    if let Some(limit) = cli.max_instructions {
        binfera::extract::recovery::set_instruction_limit((limit > 0).then_some(limit));
    }

    match &cli.command {
        Some(Command::FetchRules {
            directory,
            reference,
        }) => {
            fetch_rules(directory, reference.as_deref())?;
            return Ok(ExitCode::SUCCESS);
        }
        #[cfg(not(target_arch = "wasm32"))]
        Some(Command::Mcp) => {
            let exe = std::env::current_exe().map_err(|e| {
                CliError::new(
                    E_CORRUPT_FILE,
                    format!("cannot locate the binfera executable: {e}"),
                )
            })?;
            binfera_mcp::serve_stdio(exe, binfera::VERSION_STRING)
                .map_err(|e| CliError::new(E_CORRUPT_FILE, format!("mcp server: {e}")))?;
            return Ok(ExitCode::SUCCESS);
        }
        Some(Command::Fingerprint { input, no_detail }) => {
            run_fingerprint(cli, input, !no_detail)?;
            return Ok(ExitCode::SUCCESS);
        }
        Some(Command::Diff {
            a,
            b,
            no_capabilities,
            caps_a,
            caps_b,
            pair,
            function_map,
        }) => {
            let capabilities = match (caps_a, caps_b) {
                (Some(left), Some(right)) => DiffCapabilities::Files(left, right),
                _ if *no_capabilities => DiffCapabilities::None,
                _ => DiffCapabilities::Rules,
            };
            return run_diff(cli, a, b, capabilities, *pair, function_map.as_deref());
        }
        None => {}
    }

    let started = Instant::now();
    let mut timings = Timings::default();
    let result = run_analysis(cli, &mut timings);
    timings.total = started.elapsed();
    if cli.timing && cli.decompile_function.is_empty() {
        timings.report();
    }
    result.map(|()| ExitCode::SUCCESS)
}

enum DiffCapabilities<'a> {
    None,
    Rules,
    Files(&'a PathBuf, &'a PathBuf),
}

/// `A:B`, two function addresses.
fn parse_pair(raw: &str) -> Result<(u64, u64), String> {
    let (a, b) = raw
        .split_once(':')
        .ok_or_else(|| format!("`{raw}` is not a pair of addresses of the form A:B"))?;
    Ok((parse_function_address(a)?, parse_function_address(b)?))
}

fn read_input(path: &std::path::Path) -> Result<Vec<u8>, CliError> {
    std::fs::read(path)
        .map_err(|e| CliError::new(E_MISSING_FILE, format!("reading {}: {e}", path.display())))
}

fn diff_error(error: DiffError) -> CliError {
    match error {
        DiffError::Analysis(error) => CliError::from(error),
        DiffError::Recovery(ref too_large @ RecoveryError::TooLarge { .. }) => {
            CliError::new(E_FILE_LIMITATION, too_large.to_string())
        }
        other => CliError::new(E_CORRUPT_FILE, other.to_string()),
    }
}

fn fingerprint_of(
    cli: &Cli,
    path: &std::path::Path,
    bytes: &[u8],
    detail: bool,
) -> Result<Fingerprint, CliError> {
    if diff::is_fingerprint(bytes) {
        return Fingerprint::read_ndjson(bytes).map_err(diff_error);
    }
    let options = FingerprintOptions {
        format: cli.format.into(),
        arch: (cli.arch != ARCH_AUTO).then(|| cli.arch.clone()),
        detail,
        name: path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
    };
    diff::fingerprint(bytes, &options).map_err(diff_error)
}

fn run_fingerprint(cli: &Cli, input: &std::path::Path, detail: bool) -> Result<(), CliError> {
    let bytes = read_input(input)?;
    let print = fingerprint_of(cli, input, &bytes, detail)?;
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    print.write_ndjson(&mut out).map_err(diff_error)
}

fn read_result_document(path: &std::path::Path) -> Result<ResultDocument, CliError> {
    let bytes = std::fs::read(path)
        .map_err(|e| CliError::new(E_MISSING_FILE, format!("reading {}: {e}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| CliError::new(E_CORRUPT_FILE, format!("reading {}: {e}", path.display())))
}

/// Runs the rules over both binaries. A failure on one sample is reported rather than fatal: the
/// rest of the comparison still stands.
fn diff_analyses(
    cli: &Cli,
    inputs: [(&std::path::Path, &[u8]); 2],
    warnings: &mut Vec<String>,
) -> Result<Option<(ResultDocument, ResultDocument)>, CliError> {
    if inputs.iter().any(|(_, bytes)| diff::is_fingerprint(bytes)) {
        warnings.push(
            "capabilities were not compared: a fingerprint has no code to run rules over; pass --caps-a and --caps-b"
                .to_string(),
        );
        return Ok(None);
    }
    let rules_dir = cli.rules_dir();
    if cli.rules.is_none() && !rules_dir.is_dir() {
        warnings.push(
            "capabilities were not compared: no rules found; pass --rules or run `binfera fetch-rules`"
                .to_string(),
        );
        return Ok(None);
    }
    let options = cli.analysis_options();
    let rules = load_rule_directory(&rules_dir, &options).map_err(|e| {
        CliError::new(
            E_INVALID_RULE,
            format!("loading rules from {}: {e}", rules_dir.display()),
        )
    })?;
    let ruleset = MatchingRuleSet::new(rules)
        .map_err(|e| CliError::new(E_INVALID_RULE, format!("building the rule set: {e}")))?;
    let rules_path = canonical_path_string(&rules_dir);
    let mut analyze = |(path, bytes): (&std::path::Path, &[u8])| {
        let input = api::Input {
            bytes,
            sample_path: canonical_path_string(path),
            rules_paths: vec![rules_path.clone()],
            argv: Some(Vec::new()),
        };
        api::analyze(&input, &ruleset, &options)
            .map_err(|e| {
                warnings.push(format!(
                    "capabilities were not compared: {}: {e}",
                    path.display()
                ))
            })
            .ok()
    };
    let [left, right] = inputs;
    Ok(analyze(left).zip(analyze(right)))
}

fn run_diff(
    cli: &Cli,
    a: &std::path::Path,
    b: &std::path::Path,
    capabilities: DiffCapabilities<'_>,
    pair: Option<(u64, u64)>,
    function_map: Option<&std::path::Path>,
) -> Result<ExitCode, CliError> {
    let (bytes_a, bytes_b) = (read_input(a)?, read_input(b)?);
    let detail = pair.is_some();
    let print_a = fingerprint_of(cli, a, &bytes_a, detail)?;
    let print_b = fingerprint_of(cli, b, &bytes_b, detail)?;

    if let Some((at_a, at_b)) = pair {
        let missing = |at: u64, path: &std::path::Path| {
            CliError::new(
                E_CORRUPT_FILE,
                format!("{} has no listing for function {at:#x}", path.display()),
            )
        };
        let left = print_a.details.get(&at_a).ok_or_else(|| missing(at_a, a))?;
        let right = print_b.details.get(&at_b).ok_or_else(|| missing(at_b, b))?;
        let forward: BTreeMap<u64, u64> = match function_map {
            Some(path) => {
                let bytes = std::fs::read(path).map_err(|e| {
                    CliError::new(E_MISSING_FILE, format!("reading {}: {e}", path.display()))
                })?;
                serde_json::from_slice::<Vec<(u64, u64)>>(&bytes)
                    .map_err(|e| {
                        CliError::new(E_CORRUPT_FILE, format!("reading {}: {e}", path.display()))
                    })?
                    .into_iter()
                    .collect()
            }
            None => diff::function_map(&print_a, &print_b),
        };
        let diff = diff::diff_functions(left, right, Some(&forward));
        if cli.json {
            serde_json::to_writer(std::io::stdout().lock(), &diff)
                .map_err(|e| CliError::new(E_CORRUPT_FILE, e.to_string()))?;
            println!();
        } else {
            print!("{}", binfera::render::diff::render_pair(&diff));
        }
        return Ok(ExitCode::SUCCESS);
    }

    let mut warnings = Vec::new();
    let documents = match capabilities {
        DiffCapabilities::None => None,
        DiffCapabilities::Files(left, right) => {
            Some((read_result_document(left)?, read_result_document(right)?))
        }
        DiffCapabilities::Rules => diff_analyses(
            cli,
            [(a, bytes_a.as_slice()), (b, bytes_b.as_slice())],
            &mut warnings,
        )?,
    };
    let mut document = diff::compare(
        &print_a,
        &print_b,
        documents.as_ref().map(|(left, right)| (left, right)),
    );
    document.warnings.extend(warnings);
    if cli.json {
        serde_json::to_writer(std::io::stdout().lock(), &document)
            .map_err(|e| CliError::new(E_CORRUPT_FILE, e.to_string()))?;
        println!();
    } else {
        print!("{}", binfera::render::diff::render(&document));
    }
    Ok(match document.verdict {
        Verdict::Changed => ExitCode::from(1),
        Verdict::Identical | Verdict::Equivalent => ExitCode::SUCCESS,
    })
}

/// `capa fetch-rules`: clone the pinned capa-rules release.
///
/// Shelling out to `git` rather than linking an HTTP or git client: this is a
/// one-shot convenience the user invoked by name, `git` is already installed
/// wherever a checkout came from, and a network stack inside the analysis
/// binary is exactly what "no auto-download at analysis time" is meant to
/// avoid having.
fn fetch_rules(directory: &std::path::Path, reference: Option<&str>) -> Result<(), CliError> {
    const RULES_REPO: &str = "https://github.com/mandiant/capa-rules.git";
    let reference = reference.unwrap_or(binfera::RULES_PIN);

    if directory.exists() {
        return Err(CliError::new(
            E_MISSING_FILE,
            format!(
                "{} already exists; remove it or pass another directory",
                directory.display()
            ),
        ));
    }

    eprintln!(
        "cloning {RULES_REPO} at {reference} into {}",
        directory.display()
    );
    let status = std::process::Command::new("git")
        .args(["clone", "--depth", "1", "--branch", reference, RULES_REPO])
        .arg(directory)
        .status()
        .map_err(|e| {
            CliError::new(
                E_MISSING_FILE,
                format!(
                    "running git: {e}\n`binfera fetch-rules` needs git on PATH; alternatively \
                         download the rules from {RULES_REPO} yourself and point -r at them."
                ),
            )
        })?;
    if !status.success() {
        return Err(CliError::new(
            E_MISSING_FILE,
            format!("git clone failed ({status})"),
        ));
    }
    eprintln!(
        "rules ready: {} (binfera {} uses rules {})",
        directory.display(),
        binfera::version(),
        binfera::RULES_PIN
    );
    Ok(())
}

/// Canonicalizes a path for `meta.sample.path`/`meta.analysis.rules`,
/// falling back to the given path unchanged if canonicalization fails (a
/// relative path under a working directory that's since moved, say) --
/// matches the pre-hoist behavior exactly.
fn canonical_path_string(path: &std::path::Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn run_analysis(cli: &Cli, timings: &mut Timings) -> Result<(), CliError> {
    let options = cli.analysis_options();

    let Some(input_file) = cli.input_file.as_ref() else {
        return Err(CliError::new(
            E_MISSING_FILE,
            "no input file given\nUsage: binfera [OPTIONS] <INPUT_FILE>, or `binfera fetch-rules` to \
             download the pinned rules first.",
        ));
    };

    if !input_file.exists() {
        return Err(CliError::new(
            E_MISSING_FILE,
            format!("input file does not exist: {}", input_file.display()),
        ));
    }

    let bytes = read_input(input_file)?;

    if cli.image_info {
        let info = match cli.format {
            Format::Sc32 => binfera::image_info::inspect_shellcode(&bytes, Some(false)),
            Format::Sc64 => binfera::image_info::inspect_shellcode(&bytes, Some(true)),
            _ if cli.guess_shellcode
                && !binfera::extract::looks_like_pe(&bytes)
                && !binfera::extract::looks_like_elf(&bytes)
                && !binfera::extract::looks_like_macho(&bytes) =>
            {
                binfera::image_info::inspect_shellcode(&bytes, None)
            }
            _ => binfera::image_info::inspect(&bytes, Some(&cli.arch)),
        }
        .map_err(|e| CliError::new(E_CORRUPT_FILE, e.to_string()))?;
        serde_json::to_writer(std::io::stdout().lock(), &info)
            .map_err(|e| CliError::new(E_CORRUPT_FILE, e.to_string()))?;
        println!();
        return Ok(());
    }

    if cli.emulate.is_some() || !cli.decompile_function.is_empty() || cli.dump_code_layout {
        let repaired = binfera::extract::elf::without_corrupt_section_headers(&bytes);
        let bytes = repaired.as_deref().unwrap_or(&bytes);
        if let Some(address) = cli.emulate {
            return run_emulation(cli, bytes, address);
        }
        if !cli.decompile_function.is_empty() {
            return run_decompilation(cli, bytes, &cli.decompile_function);
        }
        return print_code_layout(bytes);
    }
    if cli.decompile_all {
        return run_decompile_all(&bytes, cli);
    }

    let input = api::Input {
        bytes: &bytes,
        sample_path: canonical_path_string(input_file),
        rules_paths: vec![canonical_path_string(&cli.rules_dir())],
        argv: Some(std::env::args().skip(1).collect()),
    };

    if cli.dump_features {
        // `--dump-features` always wants the file-scope-only extraction,
        // regardless of `--file-only`'s own value -- mirrors the pre-hoist
        // `cli.file_only || cli.dump_features` dispatch in `load_input`.
        let dump_options = AnalysisOptions {
            file_only: true,
            ..options.clone()
        };
        let mut phases = PhaseTimings::default();
        let (parsed, _resolved_format) =
            api::load_input(input.bytes, &dump_options, &mut phases).map_err(CliError::from)?;
        timings.fold_phases(&phases);
        print_dump_features(&parsed.freeze);
        return Ok(());
    }

    let rules_dir = cli.rules_dir();
    let ruleset = timed(&mut timings.rules, || {
        let mut rules: Vec<Rule> = load_rule_directory(&rules_dir, &options).map_err(|e| {
            CliError::new(
                E_INVALID_RULE,
                format!(
                    "loading rules from {}: {e}\nPoint --rules (or BINFERA_RULES_DIR) at a directory \
                     of rules, or run `binfera fetch-rules`.",
                    rules_dir.display()
                ),
            )
        })?;

        if let Some(tag) = &cli.tag {
            rules = api::filter_rules_by_tag(rules, tag);
        }

        MatchingRuleSet::new(rules).map_err(|e| {
            CliError::new(
                E_INVALID_RULE,
                format!("building the matching rule set: {e}"),
            )
        })
    })?;

    if cli.dump_matches {
        let mut phases = PhaseTimings::default();
        let (parsed, _resolved_format) =
            api::load_input(input.bytes, &options, &mut phases).map_err(CliError::from)?;
        timings.fold_phases(&phases);
        let matches = timed(&mut timings.matching, || match &parsed.freeze {
            Freeze::Static(sf) => find_static_capabilities(&ruleset, sf, &options)
                .map(|c| c.matches)
                .map_err(|e| matching_failed(cli, e)),
            Freeze::Dynamic(df) => find_dynamic_capabilities(&ruleset, df)
                .map(|c| c.matches)
                .map_err(|e| matching_failed(cli, e)),
        })?;
        print_dump_matches(&ruleset, &matches);
        return Ok(());
    }

    let (doc, phases) =
        api::analyze_with_timings(&input, &ruleset, &options).map_err(CliError::from)?;
    timings.fold_phases(&phases);

    let vverbose_level = cli.vverbose || cli.verbose >= 2;
    let verbose_level = cli.verbose >= 1;

    let output = if cli.json {
        serde_json::to_string(&doc).map_err(|e| {
            CliError::new(E_CORRUPT_FILE, format!("serializing result document: {e}"))
        })?
    } else if vverbose_level {
        vverbose::render(&doc)
    } else if verbose_level {
        verbose::render(&doc)
    } else {
        default::render(&doc)
    };

    println!("{output}");
    Ok(())
}

/// Names the sample alongside whatever the matcher said, for the
/// `--dump-matches` debug surface -- the one remaining direct
/// `find_static_capabilities`/`find_dynamic_capabilities` call site left in
/// this binary (the normal path's matching happens inside
/// `binfera::api::analyze_with_timings`, which has its own copy of this
/// for the same reason: `find_dynamic_capabilities` and
/// `find_static_capabilities` return unrelated error types).
fn matching_failed(cli: &Cli, error: impl std::fmt::Display) -> CliError {
    let sample = cli
        .input_file
        .as_deref()
        .unwrap_or_else(|| std::path::Path::new("<no input file>"));
    CliError::new(
        E_CORRUPT_FILE,
        format!("matching {}: {error}", sample.display()),
    )
}

/// prints one deterministically sorted `"<rule name>@<address>"` line per
/// (rule, matched location) pair -- see `scripts/difftest.py` for the
/// counterpart that extracts the same shape from `capa -j`.
fn print_dump_matches(ruleset: &MatchingRuleSet, matches: &MatchResults) {
    let mut lines: Vec<(String, String)> = Vec::new();
    for (rule_name, results) in matches {
        if ruleset.get(rule_name).is_some_and(|r| r.is_subscope_rule()) {
            continue;
        }
        let mut addrs: Vec<binfera::address::Address> =
            results.iter().map(|(addr, _)| *addr).collect();
        addrs.sort();
        addrs.dedup();
        for addr in addrs {
            lines.push((rule_name.clone(), addr.canonical_key()));
        }
    }
    lines.sort();
    for (rule_name, addr) in lines {
        println!("{rule_name}@{addr}");
    }
}

/// prints one deterministically sorted `"<scope>\t<feature>\t<address>"`
/// line per extracted global/file feature -- see `scripts/difftest.py`'s
/// `--mode file-features` for the counterpart that extracts the same shape
/// from a Python-side dump script. Global features have no address (mirrors
/// the freeze wire format's `GlobalFeature`, which carries no address
/// field), so their line omits the trailing column entirely.
fn print_dump_features(parsed: &Freeze) {
    let Freeze::Static(sf) = parsed else {
        // dynamic (CAPE/etc.) inputs have no file-only-extractor
        // counterpart to diff against; this surface only concerns itself
        // with static PE/ELF extraction.
        return;
    };

    let mut lines: Vec<String> = Vec::new();
    for f in &sf.global_features {
        lines.push(format!("global\t{f}"));
    }
    for (addr, f) in &sf.file_features {
        lines.push(format!("file\t{f}\t{}", addr.canonical_key()));
    }
    for (function_addr, function) in &sf.functions {
        for (addr, feature) in &function.features {
            lines.push(format!(
                "function\t{}\t{feature}\t{}",
                function_addr.canonical_key(),
                addr.canonical_key()
            ));
        }
        for (block_addr, block) in &function.basic_blocks {
            for (addr, feature) in &block.features {
                lines.push(format!(
                    "basic block\t{}\t{}\t{feature}\t{}",
                    function_addr.canonical_key(),
                    block_addr.canonical_key(),
                    addr.canonical_key()
                ));
            }
            for (instruction_addr, instruction) in &block.instructions {
                for (addr, feature) in &instruction.features {
                    lines.push(format!(
                        "instruction\t{}\t{}\t{}\t{feature}\t{}",
                        function_addr.canonical_key(),
                        block_addr.canonical_key(),
                        instruction_addr.canonical_key(),
                        addr.canonical_key()
                    ));
                }
            }
        }
    }
    lines.sort();
    for line in lines {
        println!("{line}");
    }
}

fn print_code_layout(bytes: &[u8]) -> Result<(), CliError> {
    let analysis = binfera::extract::recovery::analyze(bytes).map_err(|error| {
        CliError::new(E_CORRUPT_FILE, format!("recovering code layout: {error}"))
    })?;
    let functions: Vec<_> = analysis
        .functions
        .values()
        .map(|function| {
            serde_json::json!({
                "address": function.addr,
                "instruction_count": function.blocks.iter().map(|block| block.insns.len()).sum::<usize>(),
                "basic_blocks": function.blocks.iter().map(|block| block.addr).collect::<Vec<_>>(),
                // Per-instruction addresses (not just the count) so the layout
                // oracle can compare instruction *ownership* per function, not a
                // global flattened set.
                "instructions": function.blocks.iter().flat_map(|block| block.insns.iter().map(|insn| insn.address)).collect::<Vec<_>>(),
                "calls": analysis.callees.get(&function.addr).map(|targets| targets.iter().copied().collect::<Vec<_>>()).unwrap_or_default(),
                "edges": function.blocks.iter().flat_map(|block| block.succs.iter().map(move |edge| serde_json::json!({
                    "source": block.addr,
                    "target": edge.target,
                    "kind": format!("{:?}", edge.kind),
                }))).collect::<Vec<_>>(),
                "noreturn": analysis.is_noreturn_va(function.addr),
            })
        })
        .collect();
    let seeds: Vec<_> = analysis
        .seeds
        .iter()
        .map(|(address, kinds)| {
            serde_json::json!({
                "address": address,
                "kinds": kinds.iter().map(|kind| format!("{kind:?}")).collect::<Vec<_>>(),
            })
        })
        .collect();
    let diagnostics: Vec<_> = analysis
        .diagnostics
        .iter()
        .map(|diagnostic| {
            serde_json::json!({
                "address": diagnostic.address,
                "message": diagnostic.message,
            })
        })
        .collect();
    let output = serde_json::json!({
        "functions": functions,
        "seeds": seeds,
        "diagnostics": diagnostics,
    });
    println!(
        "{}",
        serde_json::to_string(&output).map_err(|error| {
            CliError::new(E_CORRUPT_FILE, format!("serializing code layout: {error}"))
        })?
    );
    Ok(())
}

fn parse_function_address(value: &str) -> Result<u64, String> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    u64::from_str_radix(digits, 16)
        .map_err(|e| format!("invalid hexadecimal function address: {e}"))
}

fn parse_emulation_value(text: &str) -> Result<u64, String> {
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse(),
    }
    .map_err(|_| "expected an unsigned integer or 0x-prefixed hex value".into())
}

#[cfg(not(feature = "decompiler"))]
fn run_emulation(_: &Cli, _: &[u8], _: u64) -> Result<(), CliError> {
    Err(CliError::new(
        E_CORRUPT_FILE,
        "emulation is disabled; rebuild with --features decompiler",
    ))
}

#[cfg(feature = "decompiler")]
fn run_emulation(cli: &Cli, bytes: &[u8], address: u64) -> Result<(), CliError> {
    use binfera::emulate::{Emulator, Request};
    let error = |e: String| CliError::new(E_CORRUPT_FILE, e);
    let mut req = if cli.emulate_request {
        use std::io::Read;
        let mut input = Vec::new();
        std::io::stdin()
            .lock()
            .take(8 * 1024 * 1024 + 1)
            .read_to_end(&mut input)
            .map_err(|e| error(e.to_string()))?;
        if input.len() > 8 * 1024 * 1024 {
            return Err(error("emulation request exceeds 8 MiB".into()));
        }
        let req: Request = serde_json::from_slice(&input).map_err(|e| error(e.to_string()))?;
        if req.address != address {
            return Err(error("request address differs from --emulate".into()));
        }
        req
    } else {
        Request {
            address,
            args: cli.emulate_arg.clone(),
            ..Request::default()
        }
    };
    if let Some(steps) = cli.emulate_max_steps {
        req.max_steps = steps;
    }
    if let Some(timeout) = cli.emulate_timeout_ms {
        req.timeout_ms = timeout;
    }
    let mut emulator =
        Emulator::open(bytes, &decompiler_options(cli)).map_err(|e| error(e.to_string()))?;
    let result = if cli.emulate_call_sites {
        serde_json::to_value(
            emulator
                .call_sites(&req, cli.emulate_max_sites.unwrap_or(32))
                .map_err(|e| error(e.to_string()))?,
        )
    } else {
        serde_json::to_value(emulator.run(&req).map_err(|e| error(e.to_string()))?)
    }
    .map_err(|e| error(e.to_string()))?;
    if !cli.quiet {
        serde_json::to_writer(std::io::stdout().lock(), &result)
            .map_err(|e| error(e.to_string()))?;
        println!();
    }
    Ok(())
}

#[cfg(not(feature = "decompiler"))]
fn run_decompile_all(_: &[u8], _: &Cli) -> Result<(), CliError> {
    Err(CliError::new(
        E_CORRUPT_FILE,
        "native decompilation is disabled; rebuild with --features decompiler",
    ))
}

/// Serialize the library's batch events as NDJSON for native and browser callers.
#[cfg(feature = "decompiler")]
fn run_decompile_all(bytes: &[u8], cli: &Cli) -> Result<(), CliError> {
    use binfera::decompiler::{
        decompile_all_cached, decompile_all_with_signature_jobs, DecompileError,
    };
    use std::io::Write;
    let options = decompiler_options(cli);
    let signature_jobs = if cfg!(target_arch = "wasm32") || !cli.decompile_retry.is_empty() {
        Jobs::SERIAL
    } else {
        let available = Jobs::available();
        cli.jobs.unwrap_or(available).min(available)
    };
    #[cfg(not(target_arch = "wasm32"))]
    if cli.decompile_cache.is_none()
        && cli.decompile_retry.is_empty()
        && !cli.start_evidence
        && cli.jobs.is_some_and(|jobs| jobs.get() > 1)
        && decompile_workers::run(bytes, cli, &options, signature_jobs)?
    {
        return Ok(());
    }
    let mut out = std::io::stdout().lock();
    let emit = |mut event| {
        if !cli.timing {
            if let binfera::decompiler::BatchEvent::Function(record) = &mut event {
                record.timings = None;
            }
        }
        serde_json::to_writer(&mut out, &event)
            .map_err(|e| DecompileError::Output(e.to_string()))?;
        writeln!(out)
            .and_then(|()| out.flush())
            .map_err(|e| DecompileError::Output(e.to_string()))
    };
    match &cli.decompile_cache {
        Some(path) => decompile_all_cached(bytes, &options, path, emit),
        None => decompile_all_with_signature_jobs(bytes, &options, signature_jobs, emit),
    }
    .map_err(decompile_error)
}

#[cfg(feature = "decompiler")]
fn decompile_error(error: binfera::decompiler::DecompileError) -> CliError {
    let code = match error {
        binfera::decompiler::DecompileError::TooLarge(_) => E_FILE_LIMITATION,
        _ => E_CORRUPT_FILE,
    };
    CliError::new(code, error.to_string())
}

#[cfg(not(feature = "decompiler"))]
fn run_decompilation(_: &Cli, _: &[u8], _: &[u64]) -> Result<(), CliError> {
    Err(CliError::new(
        E_CORRUPT_FILE,
        "native decompilation is disabled; rebuild with --features decompiler",
    ))
}

#[cfg(feature = "decompiler")]
fn decompiler_options(cli: &Cli) -> binfera::decompiler::BatchOptions {
    binfera::decompiler::BatchOptions {
        format: cli.format.into(),
        arch: Some(cli.arch.clone()),
        os: Some(cli.os.clone()),
        shard: cli.shard,
        evidence: cli.start_evidence,
        limits: Default::default(),
        retry: if !cli.decompile_retry.is_empty() {
            binfera::decompiler::RetryPolicy::Only(cli.decompile_retry.clone())
        } else if cli.no_resource_retry {
            binfera::decompiler::RetryPolicy::Skip
        } else {
            binfera::decompiler::RetryPolicy::Deferred
        },
    }
}

#[cfg(feature = "decompiler")]
fn run_decompilation(cli: &Cli, bytes: &[u8], addresses: &[u64]) -> Result<(), CliError> {
    if !matches!(
        cli.format,
        Format::Auto | Format::Pe | Format::Elf | Format::Macho | Format::Sc32 | Format::Sc64
    ) || !matches!(
        cli.arch.as_str(),
        "auto"
            | "i386"
            | "amd64"
            | "aarch64"
            | "x86_64"
            | "arm64"
            | "arm64e"
            | "arm"
            | "thumb"
            | "mips"
            | "mipsel"
    ) || !matches!(
        cli.os.as_str(),
        "auto" | "windows" | "linux" | "macos" | "ios"
    ) {
        return Err(CliError::new(
            E_CORRUPT_FILE,
            "decompilation requires a supported native PE, ELF or Mach-O image (x86, x86-64, AArch64, ARM32/Thumb or MIPS32), or explicit sc32/sc64 raw code",
        ));
    }
    let error = decompile_error;
    let (mut session, _) = decompiler_options(cli).open(bytes).map_err(error)?;
    if cli.resource_retry {
        session
            .set_limits(binfera::decompiler::ResourceLimits::retry())
            .map_err(error)?;
    }
    if cli.unit {
        let unit = session.decompile_unit(addresses).map_err(error)?;
        if cli.quiet {
            return Ok(());
        }
        if cli.json {
            let mut json = serde_json::to_value(&unit)
                .map_err(|e| CliError::new(E_CORRUPT_FILE, e.to_string()))?;
            json["file_warnings"] = serde_json::json!(session.warnings());
            println!(
                "{}",
                serde_json::to_string_pretty(&json)
                    .map_err(|e| CliError::new(E_CORRUPT_FILE, e.to_string()))?
            );
        } else {
            print!("{}", unit.text);
            for warning in session.warnings() {
                eprintln!("warning: {warning}");
            }
            if !unit.guesses.is_empty() || unit.unrewritten > 0 {
                eprintln!(
                    "note: {} declarations are guesses and {} sub-piece accesses were not rewritten; use --json for the list",
                    unit.guesses.len(),
                    unit.unrewritten
                );
            }
        }
        return Ok(());
    }
    let [address] = addresses else {
        return Err(CliError::new(
            E_CORRUPT_FILE,
            "several functions need --unit",
        ));
    };
    let result = session.decompile_function(*address).map_err(error)?;
    if cli.quiet {
        return Ok(());
    }
    if cli.json {
        let mut json = serde_json::to_value(&result)
            .map_err(|e| CliError::new(E_CORRUPT_FILE, e.to_string()))?;
        json["file_warnings"] = serde_json::json!(session.warnings());
        if cli.resource_retry {
            json["lines"] = serde_json::json!(result.line_addresses);
            json["frame"] = serde_json::to_value(&result.frame)
                .map_err(|e| CliError::new(E_CORRUPT_FILE, e.to_string()))?;
        }
        // Keep default JSON deterministic, including across --jobs values.
        // The reusable API always returns timings; the CLI includes them on request.
        if !cli.timing {
            if let Some(object) = json.as_object_mut() {
                object.remove("timings");
            }
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&json)
                .map_err(|e| CliError::new(E_CORRUPT_FILE, e.to_string()))?
        );
    } else {
        print!("{}", result.text);
        for warning in session.warnings().iter().chain(&result.warnings) {
            eprintln!("warning: {warning}");
        }
        for note in &result.notes {
            eprintln!("note: {note}");
        }
        if cli.timing {
            eprintln!(
                "decompiler initialization: {:.3} ms; function: {:.3} ms",
                result.timings.initialization_ms, result.timings.decompilation_ms
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod shard_tests {
    use super::parse_shard;

    #[test]
    fn shard_must_name_an_index_inside_the_count() {
        assert_eq!(parse_shard("0/1"), Ok((0, 1)));
        assert_eq!(parse_shard("2/4"), Ok((2, 4)));
        for bad in ["4/4", "0/0", "1", "a/2", "1/b", "-1/2", ""] {
            assert!(parse_shard(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
