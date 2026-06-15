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
// `Scan` carries many flags so its variant is large, but `Commands` is parsed
// exactly once at startup and never stored in bulk, so the size asymmetry is
// irrelevant; boxing would only complicate the clap derive and dispatch.
#[allow(clippy::large_enum_variant)]
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

    /// Scan only files currently tracked by git (`git ls-files`). This is the
    /// current working-tree content of tracked files, NOT git history (a secret
    /// committed then removed from the tree is invisible here; use
    /// `--git-history`).
    #[arg(long)]
    pub(super) git_tracked: bool,

    /// Scan only the current working-tree content of files changed relative to a
    /// base (`git diff --name-only`). Scans whole files, not the added hunks.
    #[arg(long)]
    pub(super) changed_files: bool,

    /// Base ref for `--changed-files` (e.g. origin/main); scans `<base>...HEAD`.
    /// Implies --changed-files.
    #[arg(long, value_name = "REF")]
    pub(super) base: Option<String>,

    /// Scan the full git history as patches (`git log -p -U0`), attributing each
    /// finding to the commit that added it. Catches secrets committed then later
    /// removed. Always fails closed on git error (no walk fallback).
    #[arg(
        long,
        conflicts_with_all = ["git_tracked", "changed_files", "base", "staged", "include_untracked"]
    )]
    pub(super) git_history: bool,

    /// With --git-history, traverse all refs (`git log --all`).
    #[arg(long, requires = "git_history")]
    pub(super) all: bool,

    /// With --git-history, pass `--full-history` to `git log`.
    #[arg(long, requires = "git_history")]
    pub(super) full_history: bool,

    /// With --git-history, a raw operator-trusted option spliced into `git log`
    /// before `--` (e.g. "--since=2 weeks ago"). Each occurrence is passed as ONE
    /// argv entry verbatim (so quoted values keep their spaces); repeat the flag
    /// for multiple options. Never run through a shell. NOT for attacker input.
    // `allow_hyphen_values` is required because every real git-log option begins
    // with `-` (e.g. `--since=...`); without it clap rejects the value as an
    // unknown flag. Each occurrence still consumes exactly one value.
    #[arg(
        long,
        value_name = "OPT",
        requires = "git_history",
        action = clap::ArgAction::Append,
        allow_hyphen_values = true
    )]
    pub(super) log_opts: Vec<String>,

    /// Scan only the content staged in the git index (`git cat-file`). Intended
    /// for pre-commit hooks: it scans the index blobs (what will be committed),
    /// not the working-tree files. Is its own git mode, so it is mutually
    /// exclusive with the other git modes.
    #[arg(long, conflicts_with_all = ["git_tracked", "changed_files", "base", "include_untracked", "git_history"])]
    pub(super) staged: bool,

    /// In git mode, also scan untracked (but not ignored) files.
    #[arg(long)]
    pub(super) include_untracked: bool,

    /// What to do when an explicit git mode fails (git missing, not a repo).
    /// Default: fail closed (exit 2). `walk` restores the legacy fallback to a
    /// directory walk (which may widen scope to untracked/ignored files). Does
    /// not apply to --git-history, which always fails closed.
    #[arg(long, value_enum, value_name = "MODE")]
    pub(super) git_fallback: Option<GitFallbackArg>,

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

/// Fallback behavior when an explicit git mode fails.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(super) enum GitFallbackArg {
    /// Fall back to a recursive directory walk (legacy behavior; may widen scope
    /// to untracked/ignored files).
    Walk,
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
    fn base_alone_implies_changed_files() {
        // Regression: clap does not auto-imply, so `--base` passed without
        // `--changed-files` must still derive changed-files mode rather than
        // silently falling back to a full directory walk that discards the base.
        let args = scan_args(&["secrets-scanner", "scan", ".", "--base", "origin/main"]);
        assert!(!args.changed_files, "only --base was passed");
        assert_eq!(args.base.as_deref(), Some("origin/main"));
        assert!(
            super::super::scan::resolve_changed_files(&args),
            "--base must imply changed-files mode"
        );
    }

    #[test]
    fn staged_conflicts_with_git_tracked() {
        // `--staged` is its own git mode; combined with `--git-tracked` (which
        // would otherwise silently win at runtime) it must be a parse error.
        assert!(
            Cli::try_parse_from(["secrets-scanner", "scan", ".", "--staged", "--git-tracked"])
                .is_err(),
            "--staged --git-tracked must conflict"
        );
    }

    #[test]
    fn git_history_conflicts_with_other_git_modes() {
        for other in ["--git-tracked", "--changed-files", "--staged"] {
            assert!(
                Cli::try_parse_from(["secrets-scanner", "scan", ".", "--git-history", other])
                    .is_err(),
                "--git-history {other} must conflict"
            );
        }
    }

    #[test]
    fn history_options_require_git_history() {
        // `--all`/`--log-opts` are meaningless without history mode and must be
        // rejected so they cannot silently no-op.
        assert!(
            Cli::try_parse_from(["secrets-scanner", "scan", ".", "--all"]).is_err(),
            "--all requires --git-history"
        );
        assert!(
            Cli::try_parse_from(["secrets-scanner", "scan", ".", "--log-opts", "-c"]).is_err(),
            "--log-opts requires --git-history"
        );
    }

    #[test]
    fn old_git_flag_names_are_rejected() {
        // Clean break: the pre-rename flags must no longer parse.
        for old in ["--git", "--git-diff", "--diff-base"] {
            assert!(
                Cli::try_parse_from(["secrets-scanner", "scan", ".", old]).is_err(),
                "old flag {old} must be rejected after the rename"
            );
        }
    }

    #[test]
    fn staged_alone_parses() {
        assert!(scan_args(&["secrets-scanner", "scan", ".", "--staged"]).staged);
    }
}
