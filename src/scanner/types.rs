//! Types for the secrets scanner module.

/// Maximum file size to scan (default: 2 MB). Larger files are skipped
/// as they're unlikely to contain secrets and would slow scanning.
pub const DEFAULT_MAX_FILE_SIZE: u64 = 2 * 1024 * 1024;

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
    /// Never skip on binary detection; scan every file that passes other filters.
    Scan,
}

/// Configuration for a scan operation.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Entropy override for rules that define an entropy threshold.
    pub min_entropy_override: Option<f64>,

    /// Maximum file size in bytes. Files larger than this are skipped.
    pub max_file_size: u64,

    /// Whether to redact matched secrets in findings.
    pub redact: bool,

    /// If true, only scan files tracked by git (`git ls-files`).
    pub git: bool,

    /// If true, only scan files changed since the last commit (`git diff --name-only HEAD`).
    pub git_diff: bool,

    /// Base ref for diff scanning. When set (and `git_diff` is true), scans
    /// `git diff --name-only <diff_base>...HEAD` instead of `HEAD`.
    pub diff_base: Option<String>,

    /// If true, also scan untracked-but-not-ignored files in git mode
    /// (`git ls-files --others --exclude-standard`).
    pub include_untracked: bool,

    /// How to handle files detected as binary by content inspection.
    pub binary_policy: BinaryPolicy,

    /// Cap on the number of files scanned. When exceeded, the path list is
    /// truncated and a warning is logged. `None` means unlimited.
    pub max_files: Option<usize>,

    /// Cap on total findings reported across the whole scan. `None` means unlimited.
    pub max_findings: Option<usize>,

    /// Cap on findings reported per file. `None` means unlimited.
    pub max_findings_per_file: Option<usize>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            min_entropy_override: None,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            redact: true,
            git: false,
            git_diff: false,
            diff_base: None,
            include_untracked: false,
            binary_policy: BinaryPolicy::default(),
            max_files: None,
            max_findings: None,
            max_findings_per_file: None,
        }
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

    /// Surrounding lines of context (±2 lines) as (line_number, content) pairs.
    /// Sorted in ascending line order. Always includes the matched line.
    #[serde(default)]
    pub context_lines: Vec<(usize, String)>,
}
