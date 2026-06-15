//! Types for the secrets scanner module.

/// Maximum file size to scan (default: 2 MB). Larger files are skipped
/// as they're unlikely to contain secrets and would slow scanning.
pub const DEFAULT_MAX_FILE_SIZE: u64 = 2 * 1024 * 1024;

/// Default per-content finding cap for the hardened proxy preset. Bounds the
/// `findings` vector so a match-spam payload cannot exhaust memory.
pub const DEFAULT_PROXY_MAX_FINDINGS: usize = 1000;

/// Default `matched`-field length cap (in bytes) for the proxy preset. A match
/// longer than this is reported with a fixed summary marker instead of a
/// payload-length redaction string (closes the asterisk-amplification vector).
pub const DEFAULT_PROXY_MAX_MATCHED_LEN: usize = 256;

/// How to treat files that look like binary content.
///
/// Binary detection is content-based (NUL bytes / control-byte ratio), not just
/// extension-based, so it catches extensionless or mislabelled binaries in
/// hostile repositories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BinaryPolicy {
    /// Skip files that look binary unless their extension/name is on the
    /// source/secret-bearing allowlist (e.g. `.env`, `.pem`, `Dockerfile`).
    #[default]
    Auto,
    /// Always skip files that look binary (no allowlist override).
    Skip,
    /// Never skip on binary detection or skipped extensions; noisy directories,
    /// global allowlists, size caps, and symlink/file-type guards still apply.
    Scan,
}

/// Configuration for a scan operation.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Entropy floor for rules that define an entropy threshold. When set, a
    /// rule's effective threshold becomes `max(override, rule_threshold)`: the
    /// override can only *raise* a threshold (reducing false positives), never
    /// lower it (which would silently weaken stricter rules).
    pub min_entropy_override: Option<f64>,

    /// Maximum file size in bytes. Files larger than this are skipped.
    pub max_file_size: u64,

    /// Whether to redact matched secrets in findings.
    pub redact: bool,

    /// If true, only scan files currently tracked by git (`git ls-files`).
    /// This is the current working-tree content of tracked files, NOT git
    /// history: a secret committed then removed from the working tree is
    /// invisible here. Use `git_history` for history/patch scanning.
    pub git_tracked: bool,

    /// If true, only scan the current working-tree content of files changed
    /// relative to a base (`git diff --name-only`). Scans whole files, not the
    /// added hunks. Range is `<base>...HEAD` when `base` is set, else `HEAD`.
    pub changed_files: bool,

    /// Base ref for `changed_files` scanning. When set (and `changed_files` is
    /// true), scans `git diff --name-only <base>...HEAD` instead of `HEAD`.
    pub base: Option<String>,

    /// If true, scan the full git history as patches (`git log -p -U0`),
    /// attributing each finding to the commit that ADDED it. Catches secrets
    /// committed then later removed. Own git mode (mutually exclusive with the
    /// others). Always fails closed on git error regardless of
    /// `git_fallback_walk`.
    pub git_history: bool,

    /// With `git_history`, traverse all refs (`git log --all`).
    pub history_all: bool,

    /// With `git_history`, pass `--full-history`. Default-on for history mode.
    pub history_full: bool,

    /// With `git_history`, raw operator-trusted options spliced into the
    /// `git log` invocation before `--`. Each element is passed as ONE argv
    /// entry verbatim, so a value may legitimately contain spaces (e.g.
    /// `"--since=2 weeks ago"`); the list is never re-tokenized or passed
    /// through a shell. NOT attacker-controlled.
    pub history_log_opts: Vec<String>,

    /// If true, scan only files staged in the git index (`git diff --cached
    /// --name-only`). Intended for pre-commit hooks. Takes precedence over
    /// `changed_files`/`git_tracked` path selection.
    pub git_staged: bool,

    /// If true, also scan untracked-but-not-ignored files in git mode
    /// (`git ls-files --others --exclude-standard`).
    pub include_untracked: bool,

    /// When an explicit git mode fails (git missing, not a repo, command
    /// error), fall back to a recursive directory walk instead of failing
    /// closed. Default `false`: explicit git modes fail closed (the CLI maps it
    /// to exit 2) rather than silently widening scope to the whole tree. Has no
    /// effect on `git_history`, which always fails closed.
    pub git_fallback_walk: bool,

    /// How to handle files detected as binary by content inspection.
    pub binary_policy: BinaryPolicy,

    /// Cap on the number of files scanned. When exceeded, the path list is
    /// truncated and a warning is logged. `None` means unlimited.
    pub max_files: Option<usize>,

    /// Cap on total findings reported across the whole scan. `None` means unlimited.
    pub max_findings: Option<usize>,

    /// Cap on findings reported per file (per call to `scan_bytes`). `None`
    /// means unlimited.
    pub max_findings_per_file: Option<usize>,

    /// Whether inline allow markers (`secrets-scanner:allow` / `gitleaks:allow`)
    /// suppress a finding. `true` (default) matches gitleaks. Set `false` when
    /// scanning attacker-controlled content (e.g. a redaction proxy), where an
    /// attacker could otherwise append the marker to forward a secret in clear.
    pub honor_allow_markers: bool,

    /// Whether to capture surrounding context lines for each finding. `true`
    /// (default) populates `Finding::context_lines`. Set `false` in proxy mode:
    /// on newline-free input the whole payload is one line, so capture is an
    /// O(findings x payload) memory amplifier and is never forwarded anyway.
    pub capture_context: bool,

    /// Cap on the byte length of a finding's `matched` field. When set and a
    /// match exceeds it, `matched` becomes a fixed summary marker carrying no
    /// secret content. `None` (default) preserves the full redacted/raw match.
    pub max_matched_len: Option<usize>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            min_entropy_override: None,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            redact: true,
            git_tracked: false,
            changed_files: false,
            base: None,
            git_history: false,
            history_all: false,
            history_full: false,
            history_log_opts: Vec::new(),
            git_staged: false,
            include_untracked: false,
            git_fallback_walk: false,
            binary_policy: BinaryPolicy::default(),
            max_files: None,
            max_findings: None,
            max_findings_per_file: None,
            honor_allow_markers: true,
            capture_context: true,
            max_matched_len: None,
        }
    }
}

impl ScanConfig {
    /// Hardened preset for untrusted in-memory content (e.g. an LLM redaction
    /// proxy). It redacts, ignores attacker-supplied inline allow markers, skips
    /// context capture, and caps both finding count and `matched` length. Input
    /// size is bounded by `max_file_size` and enforced fail-closed by
    /// [`Scanner::scan_proxy`](crate::Scanner::scan_proxy). Raise any cap via
    /// [`Scanner::with_config`](crate::Scanner::with_config) when needed.
    pub fn proxy() -> Self {
        Self {
            redact: true,
            honor_allow_markers: false,
            capture_context: false,
            max_findings_per_file: Some(DEFAULT_PROXY_MAX_FINDINGS),
            max_matched_len: Some(DEFAULT_PROXY_MAX_MATCHED_LEN),
            ..Self::default()
        }
    }

    /// Whether this config satisfies the hardened posture that
    /// [`Scanner::scan_proxy`](crate::Scanner::scan_proxy) requires for untrusted
    /// content: redaction on, inline allow markers ignored, context capture off,
    /// and both the per-file finding cap and the `matched`-length cap set.
    ///
    /// Defined next to [`proxy`](Self::proxy) so the constructor and the
    /// enforcement check cannot drift — a new hardening field added to `proxy()`
    /// must be reflected here, or `scan_proxy` will fail closed by design.
    pub fn is_hardened(&self) -> bool {
        self.redact
            && !self.honor_allow_markers
            && !self.capture_context
            && self.max_findings_per_file.is_some()
            && self.max_matched_len.is_some()
    }
}

/// Aggregate counts from a directory/git scan, for safe CI summary reporting.
///
/// These are file-level counts (not finding counts) so a summary can be printed
/// without echoing any secret material.
#[derive(Debug, Clone, Default)]
pub struct ScanStats {
    /// Number of files actually read and content-scanned.
    pub files_scanned: usize,

    /// Files skipped because they looked binary (content heuristic).
    pub binary_skipped: usize,

    /// Files skipped because they exceeded `max_file_size`.
    pub oversized_skipped: usize,

    /// Files dropped because the `max_files` cap was reached.
    pub files_over_cap: usize,

    /// Files that could not be read (stat or read I/O error). These are NOT
    /// scanned, so a non-zero count means coverage is incomplete: a security
    /// summary must surface it rather than letting an unreadable file look the
    /// same as a scanned-and-clean one.
    pub errored: usize,

    /// True if git path discovery failed and the scan fell back to a recursive
    /// directory walk (only possible when `git_fallback_walk` is set). The
    /// fallback changes scope (it can pick up untracked or ignored files), so
    /// the summary flags it distinctly.
    pub git_fallback: bool,

    /// True if an explicit git mode failed and fallback-to-walk was NOT opted
    /// in, so nothing was scanned. The CLI maps this to exit 2 (fail closed):
    /// an unscannable git request must not look like a clean scan. Mutually
    /// exclusive with `git_fallback` per scanned path.
    pub git_failed: bool,
}

/// Scanner output that pairs findings with redacted content.
#[derive(Debug, Clone)]
pub struct ScanOutput<T> {
    /// Findings produced while scanning the original content.
    pub findings: Vec<Finding>,

    /// Content with matched secret byte ranges replaced by a redaction marker.
    pub redacted: T,
}

impl<T> ScanOutput<T> {
    /// Returns true when the scan produced at least one finding.
    pub fn has_findings(&self) -> bool {
        !self.findings.is_empty()
    }
}

/// A scan finding with full metadata from the matched rule.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    /// Path to the file containing the finding.
    pub file: String,

    /// 1-based line number within the file.
    pub line: usize,

    /// 1-based column (byte offset of the match within its line).
    #[serde(default)]
    pub col: usize,

    /// 1-based line number where the match ends.
    #[serde(default)]
    pub end_line: usize,

    /// 1-based column just past the end of the match (exclusive, SARIF-style).
    #[serde(default)]
    pub end_col: usize,

    /// 1-based start column in UTF-16 code units (SARIF's default `columnKind`,
    /// which GitHub code scanning assumes). Equals `col` for ASCII lines.
    #[serde(default)]
    pub col_utf16: usize,

    /// 1-based exclusive end column in UTF-16 code units. Equals `end_col` for
    /// ASCII lines.
    #[serde(default)]
    pub end_col_utf16: usize,

    /// The rule ID that matched (e.g., `"aws-access-token"`).
    pub rule_id: String,

    /// Human-readable description from the rule.
    #[serde(rename = "description")]
    pub rule_description: String,

    /// The matched text (redacted or raw depending on config).
    pub matched: String,

    /// Shannon entropy of the secret portion.
    pub entropy: f64,

    /// Byte offset of the full regex match start in the file.
    #[serde(default)]
    pub start_offset: usize,

    /// Byte offset of the full regex match end in the file.
    #[serde(default)]
    pub end_offset: usize,

    /// Byte offset of the detected secret start in the file.
    #[serde(default)]
    pub secret_start_offset: usize,

    /// Byte offset of the detected secret end in the file.
    #[serde(default)]
    pub secret_end_offset: usize,

    /// Line-tolerant SHA-256 fingerprint identifying the same secret across line
    /// moves (rule id + file + raw secret). Used for baseline suppression. Empty
    /// for findings deserialized from a pre-fingerprint baseline.
    #[serde(default)]
    pub fingerprint: String,

    /// Commit SHA that introduced this finding. Set only by `git_history` mode
    /// (the commit whose patch ADDED the matched line); `None` for working-tree
    /// and staged scans. Omitted from serialized output when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,

    /// Surrounding lines of context (±2 lines) as (line_number, content) pairs.
    /// Sorted in ascending line order. Always includes the matched line.
    #[serde(default)]
    pub context_lines: Vec<(usize, String)>,
}
