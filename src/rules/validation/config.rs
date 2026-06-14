//! rules/validation/config.rs — TOML deserialization configuration types.

use serde::Deserialize;

/// The condition defining how the allowlist criteria are evaluated.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum AllowlistCondition {
    /// Suppression triggers if any of the specified criteria match.
    #[serde(alias = "or", alias = "OR", alias = "Or")]
    #[default]
    Or,
    /// Suppression triggers only if all of the specified criteria match.
    #[serde(alias = "and", alias = "AND", alias = "And")]
    And,
}

/// The target portion of a finding against which the allowlist regexes are checked.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum RegexTarget {
    /// The secret value itself.
    #[serde(alias = "secret", alias = "SECRET", alias = "Secret")]
    #[default]
    Secret,
    /// The full match returned by the rule's regex.
    #[serde(alias = "match", alias = "MATCH", alias = "Match")]
    Match,
    /// The entire line of content where the finding occurred.
    #[serde(alias = "line", alias = "LINE", alias = "Line")]
    Line,
}

/// A per-rule allowlist entry from `[[rules.allowlists]]`.
#[allow(dead_code)] // Fields populated by serde; also used via build.rs #[path] include.
#[derive(Debug, Clone, Deserialize)]
pub struct AllowlistConfig {
    /// Human-readable description of this allowlist.
    #[serde(default)]
    pub description: Option<String>,

    /// Regex patterns that, if matched, suppress the finding.
    #[serde(default)]
    pub regexes: Vec<String>,

    /// What the allowlist regexes match against.
    #[serde(default, rename = "regexTarget")]
    pub regex_target: Option<RegexTarget>,

    /// Path patterns — if any match the file path, the rule is suppressed for that file.
    #[serde(default)]
    pub paths: Vec<String>,

    /// Stopwords — if any appear in the matched text, the finding is suppressed.
    #[serde(default)]
    pub stopwords: Vec<String>,

    /// The condition defining how the criteria are evaluated.
    #[serde(default)]
    pub condition: Option<AllowlistCondition>,
}

/// The global `[allowlist]` section.
#[allow(dead_code)] // Fields populated by serde; also used via build.rs #[path] include.
#[derive(Debug, Clone, Deserialize)]
pub struct GlobalAllowlist {
    /// Unique identifier for the allowlist.
    #[serde(default)]
    pub id: Option<String>,

    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,

    /// Path regexes — files matching any of these are skipped entirely.
    #[serde(default)]
    pub paths: Vec<String>,

    /// Regex patterns applied to every finding's matched text.
    #[serde(default)]
    pub regexes: Vec<String>,

    /// What the allowlist regexes match against.
    #[serde(default, rename = "regexTarget")]
    pub regex_target: Option<RegexTarget>,

    /// Stopwords applied globally.
    #[serde(default)]
    pub stopwords: Vec<String>,

    /// The condition defining how the criteria are evaluated.
    #[serde(default)]
    pub condition: Option<AllowlistCondition>,

    /// Rule IDs that this allowlist applies to. If empty, it applies globally to all rules.
    #[serde(default, rename = "targetRules")]
    pub target_rules: Vec<String>,
}

/// A single `[[rules]]` entry from the TOML config.
#[allow(dead_code)] // Fields populated by serde; also used via build.rs #[path] include.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    /// Unique rule identifier (e.g., `"aws-access-token"`).
    pub id: String,

    /// Human-readable description of what this rule detects.
    #[serde(default)]
    pub description: Option<String>,

    /// The detection regex pattern (optional).
    pub regex: Option<String>,

    /// Minimum entropy threshold for this rule. If unset, entropy gating is disabled.
    #[serde(default)]
    pub entropy: Option<f64>,

    /// Keywords that must appear in the file for this rule to fire.
    /// Fed into the Aho-Corasick automaton for fast pre-filtering.
    #[serde(default)]
    pub keywords: Vec<String>,

    /// Optional file path regex — rule only applies to files matching this pattern.
    #[serde(default)]
    pub path: Option<String>,

    /// Per-rule allowlists.
    #[serde(default)]
    pub allowlists: Vec<AllowlistConfig>,

    /// Optional capture group index for the secret.
    #[serde(default, rename = "secretGroup")]
    pub secret_group: Option<usize>,
}

/// Top-level TOML config structure (gitleaks-compatible).
#[allow(dead_code)] // Fields populated by serde; also used via build.rs #[path] include.
#[derive(Debug, Clone, Deserialize)]
pub struct RulesetConfig {
    /// Config title (e.g., `"gitleaks config"`).
    #[serde(default)]
    pub title: Option<String>,

    /// Minimum gitleaks version (informational, we ignore it).
    #[serde(default, rename = "minVersion")]
    pub min_version: Option<String>,

    /// Global allowlist applied to all rules (legacy single).
    #[serde(default)]
    pub allowlist: Option<GlobalAllowlist>,

    /// Multiple global/common allowlists.
    #[serde(default)]
    pub allowlists: Vec<GlobalAllowlist>,

    /// The list of detection rules.
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}
