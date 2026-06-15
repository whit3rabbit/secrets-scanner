use clap::{Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use secrets_scanner::BinaryPolicy;

/// A high-performance secrets scanner powered by Aho-Corasick and regex.
#[derive(Parser)]
#[command(
    name = "secrets-scanner",
    version,
    about = "Scan repositories and files for leaked secrets",
    long_about = "A multi-layer secrets scanner (memchr → Aho-Corasick → entropy → regex).\n\
                  Exit codes: 0 = clean, 1 = findings, 2 = runtime error, 3 = invalid scan rules/config."
)]
pub(super) struct Cli {
    /// Subcommand to run.
    #[command(subcommand)]
    pub(super) command: Commands,
}

/// Available subcommands.
#[derive(Subcommand)]
pub(super) enum Commands {
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
pub(super) struct ScanArgs {
    /// Paths to scan (files or directories). Defaults to current directory.
    #[arg(default_value = ".")]
    pub(super) paths: Vec<String>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub(super) format: OutputFormat,

    /// Disable secret redaction in output (shows raw matched text).
    #[arg(long)]
    pub(super) no_redact: bool,

    /// Path to a custom TOML rules file. Overrides the three-tier rule loading.
    /// Validation is strict and all-or-nothing: if ANY rule fails to compile
    /// (e.g. uses look-around, which Rust's regex engine rejects) the whole file
    /// is rejected with exit 3, rather than silently scanning with a reduced
    /// rule set. Run `validate-rules <file>` to see which rule is at fault.
    #[arg(long, value_name = "PATH")]
    pub(super) rules: Option<String>,

    /// Suppress a specific rule by ID. May be specified multiple times.
    #[arg(long = "ignore-rule", value_name = "ID")]
    pub(super) ignore_rules: Vec<String>,

    /// Entropy floor for rules that define a threshold. Raises a rule's
    /// threshold to this value when higher; never lowers it (cannot weaken
    /// stricter rules).
    #[arg(long, value_name = "FLOAT")]
    pub(super) min_entropy: Option<f64>,

    /// Maximum file size in bytes (files larger than this are skipped).
    #[arg(long, value_name = "BYTES", default_value_t = 2 * 1024 * 1024)]
    pub(super) max_file_size: u64,

    /// Path to a previous JSON output or generated baseline file to suppress
    /// known findings. Matching uses SHA-256 v2 fingerprints (survives line
    /// moves), with a fallback to (file, line, rule) for baselines written before
    /// fingerprints existed. Regenerate older FNV-fingerprint baselines once.
    #[arg(long, value_name = "FILE")]
    pub(super) baseline: Option<String>,

    /// Write the current findings to FILE as a baseline (JSON) and exit 0
    /// without failing on findings. Use as the input to a later `--baseline`.
    /// This output is safer to commit/upload than normal JSON scan output because
    /// it drops context and force-redacts `matched` even under `--no-redact`.
    #[arg(long, value_name = "FILE", conflicts_with = "baseline")]
    pub(super) generate_baseline: Option<String>,

    /// Only scan files tracked by git (`git ls-files`).
    #[arg(long)]
    pub(super) git: bool,

    /// Only scan files changed since the last commit (`git diff --name-only HEAD`).
    #[arg(long)]
    pub(super) git_diff: bool,

    /// Base ref for diff scanning (e.g. origin/main); scans `<base>...HEAD`. Implies --git-diff.
    #[arg(long, value_name = "REF")]
    pub(super) diff_base: Option<String>,

    /// Scan only the content staged in the git index (`git cat-file`). Intended
    /// for pre-commit hooks: it scans the index blobs (what will be committed),
    /// not the working-tree files. Is its own git mode, so it is mutually
    /// exclusive with `--git`/`--git-diff`/`--diff-base`/`--include-untracked`.
    #[arg(long, conflicts_with_all = ["git", "git_diff", "diff_base", "include_untracked"])]
    pub(super) staged: bool,

    /// In git mode, also scan untracked (but not ignored) files.
    #[arg(long)]
    pub(super) include_untracked: bool,

    /// How to treat files detected as binary by content inspection.
    #[arg(long, value_enum, default_value_t = BinaryPolicyArg::Auto)]
    pub(super) binary_policy: BinaryPolicyArg,

    /// Cap the number of files scanned (excess files are not scanned).
    #[arg(long, value_name = "N")]
    pub(super) max_files: Option<usize>,

    /// Cap total findings reported across the scan.
    #[arg(long, value_name = "N")]
    pub(super) max_findings: Option<usize>,

    /// Cap findings reported per file.
    #[arg(long, value_name = "N")]
    pub(super) max_findings_per_file: Option<usize>,

    /// Do not print surrounding context lines (safe default for CI logs).
    #[arg(long)]
    pub(super) no_context: bool,

    /// Write output to a file instead of stdout.
    #[arg(long, value_name = "FILE")]
    pub(super) output: Option<String>,

    /// Do not exit non-zero when findings are present (still writes output).
    #[arg(long)]
    pub(super) no_fail: bool,
}

/// Binary-file handling policy for the `scan` subcommand.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(super) enum BinaryPolicyArg {
    /// Skip binary-looking files unless they are source/secret-bearing.
    Auto,
    /// Always skip binary-looking files.
    Skip,
    /// Scan skipped extensions too, and never skip based on binary detection.
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
pub(super) enum OutputFormat {
    /// Human-readable text (default).
    Text,
    /// JSON array of findings.
    Json,
    /// Newline-delimited JSON (one object per line).
    Jsonl,
    /// SARIF 2.1.0 (for GitHub Code Scanning).
    Sarif,
}

#[cfg(test)]
mod tests {
    use super::{Cli, Commands, ScanArgs};
    use clap::Parser;

    /// Parse argv and return the `scan` args, panicking on any other command.
    fn scan_args(argv: &[&str]) -> ScanArgs {
        match Cli::try_parse_from(argv)
            .expect("args should parse")
            .command
        {
            Commands::Scan(args) => args,
            _ => panic!("expected scan subcommand"),
        }
    }

    #[test]
    fn diff_base_alone_implies_git_diff() {
        // Regression: clap does not auto-imply, so `--diff-base` passed without
        // `--git-diff` must still derive git-diff mode rather than silently
        // falling back to a full directory walk that discards the base ref.
        let args = scan_args(&["secrets-scanner", "scan", ".", "--diff-base", "origin/main"]);
        assert!(!args.git_diff, "only --diff-base was passed");
        assert_eq!(args.diff_base.as_deref(), Some("origin/main"));
        assert!(
            super::super::scan::resolve_git_diff(&args),
            "--diff-base must imply git-diff mode"
        );
    }

    #[test]
    fn staged_conflicts_with_git() {
        // `--staged` is its own git mode; combined with `--git` (which would
        // otherwise silently win at runtime) it must be a parse error.
        assert!(
            Cli::try_parse_from(["secrets-scanner", "scan", ".", "--staged", "--git"]).is_err(),
            "--staged --git must conflict"
        );
    }

    #[test]
    fn staged_alone_parses() {
        assert!(scan_args(&["secrets-scanner", "scan", ".", "--staged"]).staged);
    }
}
