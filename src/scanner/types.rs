//! Types for the secrets scanner module.

/// Maximum file size to scan (default: 2 MB). Larger files are skipped
/// as they're unlikely to contain secrets and would slow scanning.
pub const DEFAULT_MAX_FILE_SIZE: u64 = 2 * 1024 * 1024;

/// Configuration for a scan operation.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Global minimum entropy override. If set, overrides per-rule thresholds.
    pub min_entropy_override: Option<f64>,

    /// Maximum file size in bytes. Files larger than this are skipped.
    pub max_file_size: u64,

    /// Whether to redact matched secrets in findings.
    pub redact: bool,

    /// If true, only scan files tracked by git (`git ls-files`).
    pub git: bool,

    /// If true, only scan files changed since the last commit (`git diff --name-only HEAD`).
    pub git_diff: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            min_entropy_override: None,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            redact: true,
            git: false,
            git_diff: false,
        }
    }
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

    /// The rule ID that matched (e.g., `"aws-access-token"`).
    pub rule_id: String,

    /// Human-readable description from the rule.
    #[serde(rename = "description")]
    pub rule_description: String,

    /// The matched text (redacted or raw depending on config).
    pub matched: String,

    /// Shannon entropy of the secret portion.
    pub entropy: f64,

    /// Byte offset of the match start in the file.
    #[serde(default)]
    pub start_offset: usize,

    /// Byte offset of the match end in the file.
    #[serde(default)]
    pub end_offset: usize,

    /// Surrounding lines of context (±2 lines) as (line_number, content) pairs.
    /// Sorted in ascending line order. Always includes the matched line.
    #[serde(default)]
    pub context_lines: Vec<(usize, String)>,
}
