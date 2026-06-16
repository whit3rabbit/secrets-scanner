use clap::{ArgGroup, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use secrets_scanner::{BinaryPolicy, RedactionMode};

/// Parse a scan cap (`--max-files`, `--max-findings`, `--max-findings-per-file`)
/// as a strictly positive `usize`. Zero is rejected at the CLI boundary because a
/// zero cap silently turns a scan into an empty (clean-looking) result, which is
/// almost always a caller error in a security tool.
fn parse_positive_usize(s: &str) -> Result<usize, String> {
    match s.parse::<usize>() {
        Ok(0) => Err("value must be a positive integer (>= 1); 0 would scan nothing".to_string()),
        Ok(n) => Ok(n),
        Err(e) => Err(format!("invalid integer: {e}")),
    }
}

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

        /// Bypass the "already current" fast-path and always re-fetch, re-merge,
        /// and rewrite the cache. Conflicts with `--check`.
        #[arg(long, conflicts_with = "check")]
        force: bool,
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
// `--include-untracked` only has an effect inside a path-discovery git mode
// (`--git-tracked`/`--changed-files`/`--base`); on its own it was a silent
// no-op. Requiring this group makes it an explicit usage error instead, matching
// the Node binding's `includeUntracked requires gitTracked, changedFiles, or base`.
#[command(group(
    ArgGroup::new("git_path_scope")
        .args(["git_tracked", "changed_files", "base"])
        .multiple(true)
        .required(false)
))]
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

    /// Redaction style for the `matched` field: `partial` (keep first/last 4
    /// chars) or `full` (replace with a fixed marker that hides even the
    /// length). Ignored under `--no-redact` (raw text), which it conflicts with.
    #[arg(long, value_enum, default_value_t = RedactionModeArg::Partial, conflicts_with = "no_redact")]
    pub(super) redaction: RedactionModeArg,

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
    /// it drops context and replaces `matched` with a fixed `[REDACTED_SECRET]`
    /// marker for every finding, regardless of redaction mode.
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

    /// In git mode, also scan untracked (but not ignored) files. Requires a
    /// path-discovery git mode (`--git-tracked`, `--changed-files`, or `--base`);
    /// it has no effect otherwise and is rejected on its own.
    #[arg(long, requires = "git_path_scope")]
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
    /// Conflicts with `--generate-baseline`: dropping whole files would write a
    /// baseline missing their findings, which then silently fail to suppress on a
    /// later uncapped scan.
    #[arg(long, value_name = "N", value_parser = parse_positive_usize, conflicts_with = "generate_baseline")]
    pub(super) max_files: Option<usize>,

    /// Cap total findings reported across the scan. Conflicts with
    /// `--generate-baseline`: a capped baseline would silently fail to suppress
    /// findings beyond the cap on a later scan, so the combination is rejected
    /// rather than silently dropping the cap.
    #[arg(long, value_name = "N", value_parser = parse_positive_usize, conflicts_with = "generate_baseline")]
    pub(super) max_findings: Option<usize>,

    /// Cap findings reported per file. Conflicts with `--generate-baseline`: a
    /// per-file cap can drop findings from the baseline, which then silently fail
    /// to suppress on a later uncapped scan.
    #[arg(long, value_name = "N", value_parser = parse_positive_usize, conflicts_with = "generate_baseline")]
    pub(super) max_findings_per_file: Option<usize>,

    /// Do not honor inline `secrets-scanner:allow` / `gitleaks:allow` markers.
    /// By default a line carrying such a marker suppresses its finding. Disable
    /// this when scanning untrusted content (e.g. text whose author could append
    /// a marker to smuggle a secret past the scan).
    #[arg(long)]
    pub(super) no_allow_markers: bool,

    /// Do not print surrounding context lines (safe default for CI logs).
    #[arg(long)]
    pub(super) no_context: bool,

    /// Write output to a file instead of stdout.
    #[arg(long, value_name = "FILE")]
    pub(super) output: Option<String>,

    /// Do not exit non-zero when findings are present (still writes output).
    #[arg(long)]
    pub(super) no_fail: bool,

    /// Exit 2 if any file could not be read (incomplete coverage). Off by
    /// default: unreadable files are logged but do not fail the scan. Independent
    /// of `--no-fail` (which governs only the findings-present case). Output is
    /// still written first. Does not apply to `--generate-baseline`.
    #[arg(long)]
    pub(super) error_on_unreadable: bool,

    /// Exit 2 if any file was skipped by policy (binary or oversized). Off by
    /// default: such files are skipped intentionally, but a skipped file is "not
    /// scanned", not "scanned clean", so a strict caller can opt into failing on
    /// the coverage gap. Mirrors `--error-on-unreadable`; same exit-2 precedence;
    /// does not apply to `--generate-baseline`.
    #[arg(long)]
    pub(super) error_on_skipped: bool,

    /// Wall-clock budget (seconds) for `--git-history` patch scanning. `0`
    /// (default) means unlimited. When the deadline is exceeded the `git log`
    /// stream is stopped and the scan is reported as truncated (incomplete
    /// coverage) rather than running unbounded on a huge history.
    #[arg(
        long,
        value_name = "SECS",
        default_value_t = 0,
        requires = "git_history"
    )]
    pub(super) history_timeout: u64,
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

/// Redaction style for the `matched` field of findings (CLI mirror of
/// [`secrets_scanner::RedactionMode`]).
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(super) enum RedactionModeArg {
    /// Keep the first and last 4 characters; star the middle.
    Partial,
    /// Replace the whole match with a fixed marker that hides even the length.
    Full,
}

impl From<RedactionModeArg> for RedactionMode {
    fn from(m: RedactionModeArg) -> Self {
        match m {
            RedactionModeArg::Partial => RedactionMode::Partial,
            RedactionModeArg::Full => RedactionMode::Full,
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
#[path = "args_tests.rs"]
mod tests;
