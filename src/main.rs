//! CLI entry point for secrets-scanner.
//!
//! This is a thin shell over the `secrets_scanner` library. It handles:
//! - CLI argument parsing (clap derive macros)
//! - Dispatching to the `scan`, `update-rules`, `validate-rules`, and `list-rules` subcommands
//! - Output formatting (`text`, `json`, `jsonl`, `sarif`)
//! - Exit codes: `0` = no findings, `1` = findings found, `2` = runtime error,
//!   `3` = invalid configuration/rules
//!
//! All scanning logic lives in the library crate (`src/lib.rs`).

use std::collections::HashSet;
use std::io::{self, Write};

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use log::{error, info};
use secrets_scanner::{BinaryPolicy, Finding, ScanConfig, ScanStats, Scanner};

mod format;
#[path = "safe_display.rs"]
mod safe_display;

// ─────────────────────────────────────────────
// CLI ARGUMENT DEFINITION
// ─────────────────────────────────────────────

/// A high-performance secrets scanner powered by Aho-Corasick and regex.
#[derive(Parser)]
#[command(
    name = "secrets-scanner",
    version,
    about = "Scan repositories and files for leaked secrets",
    long_about = "A multi-layer secrets scanner (memchr → Aho-Corasick → entropy → regex).\n\
                  Exit codes: 0 = clean, 1 = findings, 2 = error."
)]
struct Cli {
    /// Subcommand to run.
    #[command(subcommand)]
    command: Commands,
}

/// Available subcommands.
#[derive(Subcommand)]
enum Commands {
    /// Scan one or more files or directories for secrets.
    #[command(name = "scan")]
    Scan(ScanArgs),

    /// Update the scanning rules from upstream gitleaks.
    #[command(name = "update-rules", alias = "update")]
    UpdateRules {
        /// Only check for an update without downloading.
        #[arg(long)]
        check: bool,

        /// Override the upstream URL to pull rules from.
        #[arg(long, value_name = "URL")]
        url: Option<String>,
    },

    /// Validate one or more TOML rules files for structural and regex correctness.
    #[command(name = "validate-rules", alias = "validate")]
    ValidateRules {
        /// Paths to the TOML rules files to validate.
        /// Defaults to the three standard asset files.
        #[arg(
            default_values = &["assets/gitleaks.toml", "assets/local.toml", "assets/secrets-scanner.toml"]
        )]
        files: Vec<String>,
    },

    /// Merge all manifest sources into a single deterministic ruleset.
    #[command(name = "merge-rules")]
    MergeRules {
        /// Path to the source manifest.
        #[arg(long, default_value = "assets/sources.toml")]
        manifest: String,

        /// Include sources with `embed = false` (e.g. secrets-patterns-db).
        #[arg(long)]
        all: bool,

        /// Output path for the merged ruleset.
        #[arg(long, default_value = "assets/secrets-scanner.toml")]
        out: String,

        /// Optional path to write the JSON merge report (dedup details).
        #[arg(long, value_name = "PATH")]
        report: Option<String>,

        /// Validate and compare with `--out`; do not write the merged ruleset.
        #[arg(long)]
        check: bool,
    },

    /// List all loaded rules with their IDs, descriptions, and keyword counts.
    #[command(name = "list-rules")]
    ListRules {
        /// Path to a custom TOML rules file to list rules from.
        #[arg(long, value_name = "PATH")]
        rules: Option<String>,
    },

    /// Generate shell completions.
    #[command(name = "completions")]
    Completions {
        /// The shell to generate completions for.
        #[arg(value_enum)]
        shell: Shell,
    },
}

/// Arguments for the `scan` subcommand.
#[derive(Parser)]
struct ScanArgs {
    /// Paths to scan (files or directories). Defaults to current directory.
    #[arg(default_value = ".")]
    paths: Vec<String>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Disable secret redaction in output (shows raw matched text).
    #[arg(long)]
    no_redact: bool,

    /// Path to a custom TOML rules file. Overrides the three-tier rule loading.
    #[arg(long, value_name = "PATH")]
    rules: Option<String>,

    /// Suppress a specific rule by ID. May be specified multiple times.
    #[arg(long = "ignore-rule", value_name = "ID")]
    ignore_rules: Vec<String>,

    /// Override entropy thresholds for rules that define one.
    #[arg(long, value_name = "FLOAT")]
    min_entropy: Option<f64>,

    /// Maximum file size in bytes (files larger than this are skipped).
    #[arg(long, value_name = "BYTES", default_value_t = 2 * 1024 * 1024)]
    max_file_size: u64,

    /// Path to a previous JSON output file to suppress known findings.
    #[arg(long, value_name = "FILE")]
    baseline: Option<String>,

    /// Only scan files tracked by git (`git ls-files`).
    #[arg(long)]
    git: bool,

    /// Only scan files changed since the last commit (`git diff --name-only HEAD`).
    #[arg(long)]
    git_diff: bool,

    /// Base ref for diff scanning (e.g. origin/main); scans `<base>...HEAD`. Implies --git-diff.
    #[arg(long, value_name = "REF")]
    diff_base: Option<String>,

    /// In git mode, also scan untracked (but not ignored) files.
    #[arg(long)]
    include_untracked: bool,

    /// How to treat files detected as binary by content inspection.
    #[arg(long, value_enum, default_value_t = BinaryPolicyArg::Auto)]
    binary_policy: BinaryPolicyArg,

    /// Cap the number of files scanned (excess files are not scanned).
    #[arg(long, value_name = "N")]
    max_files: Option<usize>,

    /// Cap total findings reported across the scan.
    #[arg(long, value_name = "N")]
    max_findings: Option<usize>,

    /// Cap findings reported per file.
    #[arg(long, value_name = "N")]
    max_findings_per_file: Option<usize>,

    /// Do not print surrounding context lines (safe default for CI logs).
    #[arg(long)]
    no_context: bool,

    /// Write output to a file instead of stdout.
    #[arg(long, value_name = "FILE")]
    output: Option<String>,

    /// Do not exit non-zero when findings are present (still writes output).
    #[arg(long)]
    no_fail: bool,
}

/// Binary-file handling policy for the `scan` subcommand.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum BinaryPolicyArg {
    /// Skip binary-looking files unless they are source/secret-bearing.
    Auto,
    /// Always skip binary-looking files.
    Skip,
    /// Scan every file regardless of binary detection.
    Scan,
}

impl From<BinaryPolicyArg> for BinaryPolicy {
    fn from(p: BinaryPolicyArg) -> Self {
        match p {
            BinaryPolicyArg::Auto => BinaryPolicy::Auto,
            BinaryPolicyArg::Skip => BinaryPolicy::Skip,
            BinaryPolicyArg::Scan => BinaryPolicy::Scan,
        }
    }
}

/// Output format for the `scan` subcommand.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    /// Human-readable text (default).
    Text,
    /// JSON array of findings.
    Json,
    /// Newline-delimited JSON (one object per line).
    Jsonl,
    /// SARIF 2.1.0 (for GitHub Code Scanning).
    Sarif,
}

// ─────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_target(false)
        .format_module_path(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan(args) => handle_scan(args),
        Commands::UpdateRules { check, url } => handle_update(check, url),
        Commands::ValidateRules { files } => handle_validate(&files),
        Commands::MergeRules {
            manifest,
            all,
            out,
            report,
            check,
        } => handle_merge_rules(&manifest, all, &out, report.as_deref(), check),
        Commands::ListRules { rules } => handle_list_rules(rules.as_deref()),
        Commands::Completions { shell } => handle_completions(shell),
    }
}

// ─────────────────────────────────────────────
// SCAN HANDLER
// ─────────────────────────────────────────────

/// Handle the `scan` subcommand.
fn handle_scan(args: ScanArgs) {
    // A diff base implies diff scanning even without an explicit --git-diff.
    let git_diff = args.git_diff || args.diff_base.is_some();
    let config = ScanConfig {
        redact: !args.no_redact,
        min_entropy_override: args.min_entropy,
        max_file_size: args.max_file_size,
        git: args.git,
        git_diff,
        diff_base: args.diff_base.clone(),
        include_untracked: args.include_untracked,
        binary_policy: args.binary_policy.into(),
        max_files: args.max_files,
        // The CLI applies this after aggregating all input paths. Leaving it in
        // the library config would cap each root separately and log twice.
        max_findings: None,
        max_findings_per_file: args.max_findings_per_file,
    };

    // Build scanner from explicit rules file or three-tier loading. A bad rules
    // file or unparseable ruleset is an invalid-config error: exit 3.
    let scanner = if let Some(ref rules_path) = args.rules {
        match Scanner::from_file(rules_path) {
            Ok(s) => s.with_config(config),
            Err(e) => {
                error!("Failed to load rules from {rules_path}: {e}");
                std::process::exit(3);
            }
        }
    } else {
        match Scanner::new() {
            Ok(s) => s.with_config(config),
            Err(e) => {
                error!("Failed to load rules: {e}");
                std::process::exit(3);
            }
        }
    };

    info!(
        "[scanner] Loaded {} rules ({} keywords)",
        scanner.engine().rule_count(),
        scanner.engine().keyword_count(),
    );

    // Scan all provided paths, accumulating file-level stats for the summary.
    let start = std::time::Instant::now();
    let mut all_findings = Vec::new();
    let mut stats = ScanStats::default();

    for path in &args.paths {
        let (mut findings, s) = scanner.scan_path_with_stats(path);
        stats.files_scanned += s.files_scanned;
        stats.binary_skipped += s.binary_skipped;
        stats.oversized_skipped += s.oversized_skipped;
        stats.files_over_cap += s.files_over_cap;
        // Apply --ignore-rule filtering.
        if !args.ignore_rules.is_empty() {
            findings.retain(|f| !args.ignore_rules.contains(&f.rule_id));
        }
        all_findings.extend(findings);
    }

    // Apply --baseline filtering: suppress findings that existed in a prior scan.
    if let Some(ref baseline_path) = args.baseline {
        match std::fs::read_to_string(baseline_path) {
            Ok(content) => {
                // Treat an unparseable baseline as a hard error (exit 2), the same
                // as an unreadable one, rather than silently suppressing nothing.
                let baseline: Vec<Finding> = match serde_json::from_str(&content) {
                    Ok(b) => b,
                    Err(e) => {
                        error!("Failed to parse baseline JSON '{baseline_path}': {e}");
                        std::process::exit(2);
                    }
                };
                let known: HashSet<(String, usize, String)> = baseline
                    .into_iter()
                    .map(|f| (f.file, f.line, f.rule_id))
                    .collect();
                let before = all_findings.len();
                all_findings
                    .retain(|f| !known.contains(&(f.file.clone(), f.line, f.rule_id.clone())));
                let suppressed = before - all_findings.len();
                if suppressed > 0 {
                    info!("[scanner] Baseline suppressed {suppressed} known finding(s)");
                }
            }
            Err(e) => {
                error!("Failed to read baseline file '{baseline_path}': {e}");
                std::process::exit(2);
            }
        }
    }

    // Global findings cap. Truncation is logged so it never reads as full coverage.
    let mut findings_truncated = false;
    if let Some(cap) = args.max_findings {
        if all_findings.len() > cap {
            info!(
                "[scanner] Findings ({}) exceed --max-findings ({cap}); results truncated.",
                all_findings.len()
            );
            all_findings.truncate(cap);
            findings_truncated = true;
        }
    }

    let elapsed = start.elapsed();

    let unkeyworded_time = std::time::Duration::from_nanos(scanner.unkeyworded_scan_time_ns());
    if unkeyworded_time.as_nanos() > 0 {
        info!(
            "[scanner] Unkeyworded regex rules evaluation time: {:.2?}",
            unkeyworded_time
        );
    }

    // Output to a file or stdout. An output write failure is a runtime error: exit 2.
    let base = args.paths.first().map(String::as_str).unwrap_or(".");
    let show_context = !args.no_context;
    if let Err(e) = write_output(&args, &all_findings, base, show_context) {
        error!("Failed to write output: {e}");
        std::process::exit(2);
    }

    // Safe summary to stderr (file-level counts only — never echoes secrets).
    info!(
        "[scanner] Scanned {} path(s) in {:.2?} — {} file(s), {} finding(s); \
         skipped {} binary, {} oversized; {} over file-cap{}",
        args.paths.len(),
        elapsed,
        stats.files_scanned,
        all_findings.len(),
        stats.binary_skipped,
        stats.oversized_skipped,
        stats.files_over_cap,
        if findings_truncated {
            " (findings truncated)"
        } else {
            ""
        },
    );

    // Exit code: 1 = findings (unless --no-fail), 0 = clean.
    if !all_findings.is_empty() && !args.no_fail {
        std::process::exit(1);
    }
}

/// Write findings in the requested format to a file (`--output`) or stdout.
fn write_output(
    args: &ScanArgs,
    findings: &[Finding],
    base: &str,
    show_context: bool,
) -> io::Result<()> {
    match &args.output {
        Some(path) => {
            let mut f = std::fs::File::create(path)?;
            dispatch_format(&mut f, args.format, findings, base, show_context)
        }
        None => {
            let stdout = io::stdout();
            let mut lock = stdout.lock();
            dispatch_format(&mut lock, args.format, findings, base, show_context)
        }
    }
}

/// Dispatch to the format writer matching `format`.
fn dispatch_format(
    w: &mut dyn Write,
    format: OutputFormat,
    findings: &[Finding],
    base: &str,
    show_context: bool,
) -> io::Result<()> {
    match format {
        OutputFormat::Text => format::write_text(w, findings, show_context),
        OutputFormat::Json => format::write_json(w, findings, show_context),
        OutputFormat::Jsonl => format::write_jsonl(w, findings, show_context),
        OutputFormat::Sarif => format::write_sarif(w, findings, base),
    }
}

// ─────────────────────────────────────────────
// UPDATE HANDLER
// ─────────────────────────────────────────────

/// Handle the `update-rules` subcommand.
fn handle_update(check_only: bool, url: Option<String>) {
    match secrets_scanner::rules::updater::update_rules(check_only, url.as_deref()) {
        Ok(secrets_scanner::rules::updater::UpdateResult::AlreadyCurrent { sha256 }) => {
            println!("✅ Rules already up to date (SHA-256: {sha256})");
        }
        Ok(secrets_scanner::rules::updater::UpdateResult::Updated { sha256 }) => {
            println!("✅ Rules updated (SHA-256: {sha256})");
        }
        Ok(secrets_scanner::rules::updater::UpdateResult::UpdateAvailable {
            local_sha,
            remote_sha,
        }) => {
            println!("⚠️  Update available!");
            println!("   Local:  {local_sha}");
            println!("   Remote: {remote_sha}");
            println!("   Run without --check to apply.");
            std::process::exit(1);
        }
        Ok(secrets_scanner::rules::updater::UpdateResult::CheckedCurrent { sha256 }) => {
            println!("✅ Rules are current (SHA-256: {sha256})");
        }
        Err(e) => {
            error!("Update failed: {e}");
            std::process::exit(2);
        }
    }
}

// ─────────────────────────────────────────────
// VALIDATE HANDLER
// ─────────────────────────────────────────────

/// Handle the `validate-rules` subcommand.
fn handle_validate(files: &[String]) {
    let mut all_valid = true;
    for file in files {
        match std::fs::read_to_string(file) {
            Ok(content) => {
                match secrets_scanner::rules::validation::validate_rules_toml(&content) {
                    Ok(()) => {
                        println!("✅ {file} is valid");
                    }
                    Err(errors) => {
                        all_valid = false;
                        error!("{file} validation failed:");
                        for err in errors {
                            error!("  - {err}");
                        }
                    }
                }
            }
            Err(e) => {
                all_valid = false;
                error!("Failed to read {file}: {e}");
            }
        }
    }
    if !all_valid {
        std::process::exit(1);
    }
}

// ─────────────────────────────────────────────
// MERGE-RULES HANDLER
// ─────────────────────────────────────────────

/// Handle the `merge-rules` subcommand: read the manifest, merge the selected
/// sources via the shared core, validate, and write or check the combined ruleset.
///
/// This uses the SAME `merge_sources` core as `build.rs`, so a lean `merge-rules`
/// run and a default `cargo build` produce byte-identical output (the basis of
/// the CI drift check). Exit codes: `0` = success, `1` = stale in check mode,
/// `2` = error.
fn handle_merge_rules(
    manifest_path: &str,
    all: bool,
    out: &str,
    report_path: Option<&str>,
    check: bool,
) {
    use secrets_scanner::rules::{manifest, merge, validation};

    let manifest_src = match std::fs::read_to_string(manifest_path) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to read manifest {manifest_path}: {e}");
            std::process::exit(2);
        }
    };
    let parsed = match manifest::parse_manifest(&manifest_src) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to parse manifest {manifest_path}: {e}");
            std::process::exit(2);
        }
    };

    let selected = manifest::select_sources(
        &parsed,
        &manifest::SelectOptions {
            include_embed_false: all,
        },
    );

    let mut inputs = Vec::new();
    for src in &selected {
        // Sources without a TOML converter (e.g. kingfisher YAML) are skipped.
        if !src.file.ends_with(".toml") {
            info!(
                "[merge] skipping non-TOML source '{}' ({})",
                src.name, src.file
            );
            continue;
        }
        let content = match std::fs::read_to_string(&src.file) {
            Ok(c) => c,
            Err(e) if src.embed => {
                error!(
                    "Embedded source '{}' unreadable ({}): {e}",
                    src.name, src.file
                );
                std::process::exit(2);
            }
            Err(e) => {
                info!(
                    "[merge] optional source '{}' unreadable ({}): {e}",
                    src.name, e
                );
                continue;
            }
        };
        if let Err(errors) = validation::validate_rules_toml(&content) {
            error!("Source '{}' is invalid:", src.name);
            for err in errors {
                error!("  - {err}");
            }
            std::process::exit(2);
        }
        inputs.push(merge::MergeSource {
            name: src.name.clone(),
            priority: src.priority,
            toml: content,
        });
    }

    let (combined, report) = match merge::merge_sources(inputs) {
        Ok(pair) => pair,
        Err(e) => {
            error!("Merge failed: {e}");
            std::process::exit(2);
        }
    };
    if let Err(errors) = validation::validate_rules_toml(&combined) {
        error!("Merged ruleset is invalid:");
        for err in errors {
            error!("  - {err}");
        }
        std::process::exit(2);
    }

    // Summary of what the merge did.
    let dropped_exact = report.exact_regex_dups.iter().filter(|d| d.dropped).count();
    let conflict_exact = report.exact_regex_dups.len() - dropped_exact;
    println!(
        "Merged {} source(s): {} input rules -> {} output rules",
        report.sources.len(),
        report.total_input_rules,
        report.output_rules
    );
    println!(
        "  dropped: {} id collision(s), {} exact-regex duplicate(s)",
        report.id_collisions.len(),
        dropped_exact
    );
    println!(
        "  flagged for review: {} same-regex conflict(s), {} normalized near-dup(s)",
        conflict_exact,
        report.near_dups.len()
    );

    if let Some(path) = report_path {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => {
                if let Some(parent) = std::path::Path::new(path).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Err(e) = std::fs::write(path, json) {
                    error!("Failed to write report {path}: {e}");
                    std::process::exit(2);
                }
                println!("Wrote merge report to {path}");
            }
            Err(e) => {
                error!("Failed to serialize report: {e}");
                std::process::exit(2);
            }
        }
    }

    if check {
        match check_ruleset_current(std::path::Path::new(out), &combined) {
            Ok(RulesetCheckStatus::Current) => {
                println!("Check mode: {out} is current");
                return;
            }
            Ok(RulesetCheckStatus::Stale) => {
                error!("{out} is stale - run \"make merge-rules\" and commit.");
                std::process::exit(1);
            }
            Err(e) => {
                error!("Failed to read {out}: {e}");
                std::process::exit(2);
            }
        }
    }
    if let Err(e) = std::fs::write(out, &combined) {
        error!("Failed to write {out}: {e}");
        std::process::exit(2);
    }
    println!("Wrote merged ruleset to {out}");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RulesetCheckStatus {
    Current,
    Stale,
}

fn check_ruleset_current(
    path: &std::path::Path,
    expected: &str,
) -> Result<RulesetCheckStatus, std::io::Error> {
    match std::fs::read(path) {
        Ok(existing) if existing == expected.as_bytes() => Ok(RulesetCheckStatus::Current),
        Ok(_) => Ok(RulesetCheckStatus::Stale),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RulesetCheckStatus::Stale),
        Err(e) => Err(e),
    }
}

// ─────────────────────────────────────────────
// LIST-RULES HANDLER
// ─────────────────────────────────────────────

/// Handle the `list-rules` subcommand.
fn handle_list_rules(rules_path: Option<&str>) {
    let scanner = if let Some(path) = rules_path {
        match Scanner::from_file(path) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to load rules from {path}: {e}");
                std::process::exit(2);
            }
        }
    } else {
        match Scanner::new() {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to load rules: {e}");
                std::process::exit(2);
            }
        }
    };

    let rules = scanner.engine().rules();
    println!("{:<40} {:<8} DESCRIPTION", "RULE ID", "KEYWORDS");
    println!("{}", "-".repeat(90));
    for rule in &rules {
        println!(
            "{:<40} {:<8} {}",
            &rule.id,
            rule.keywords.len(),
            if rule.description.is_empty() {
                "(no description)"
            } else {
                &rule.description
            }
        );
    }
    println!("\n{} rule(s) loaded.", rules.len());
}

// ─────────────────────────────────────────────
// COMPLETIONS HANDLER
// ─────────────────────────────────────────────

/// Handle the `completions` subcommand.
fn handle_completions(shell: Shell) {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
}

// ─────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use secrets_scanner::{ScanConfig, Scanner};

    #[test]
    fn scanner_loads_from_bundled() {
        let scanner = Scanner::from_bundled().expect("should load bundled rules");
        assert!(scanner.engine().rule_count() > 100);
    }

    #[test]
    fn scanner_detects_planted_secret() {
        let scanner = Scanner::from_bundled()
            .expect("should load")
            .with_config(ScanConfig {
                redact: false,
                ..Default::default()
            });

        let content = "export GITHUB_TOKEN=ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde";
        let findings = scanner.scan_content("deploy.sh", content);
        assert!(!findings.is_empty(), "should detect GitHub PAT");
        assert_eq!(findings[0].rule_id, "github-pat");
    }

    #[test]
    fn json_string_escapes_special_chars() {
        assert_eq!(super::format::json_string("hello"), "\"hello\"");
        assert_eq!(
            super::format::json_string("say \"hi\""),
            "\"say \\\"hi\\\"\""
        );
        assert_eq!(super::format::json_string("new\nline"), "\"new\\nline\"");
        assert_eq!(super::format::json_string("tab\there"), "\"tab\\there\"");
    }

    #[test]
    fn ruleset_check_reports_current_for_matching_file() {
        let tmp = tempfile::NamedTempFile::new().expect("tmpfile");
        std::fs::write(tmp.path(), "merged rules").expect("write ruleset");

        let status = super::check_ruleset_current(tmp.path(), "merged rules").expect("check");

        assert_eq!(status, super::RulesetCheckStatus::Current);
    }

    #[test]
    fn ruleset_check_reports_stale_for_different_file() {
        let tmp = tempfile::NamedTempFile::new().expect("tmpfile");
        std::fs::write(tmp.path(), "old rules").expect("write ruleset");

        let status = super::check_ruleset_current(tmp.path(), "merged rules").expect("check");

        assert_eq!(status, super::RulesetCheckStatus::Stale);
    }

    #[test]
    fn ruleset_check_reports_stale_for_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("missing.toml");

        let status = super::check_ruleset_current(&missing, "merged rules").expect("check");

        assert_eq!(status, super::RulesetCheckStatus::Stale);
    }
}
