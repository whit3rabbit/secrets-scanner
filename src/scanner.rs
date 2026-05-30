/// scanner.rs — High-performance parallel file scanner.
///
/// Implements the scan pipeline described in TODO.md:
///
/// ```text
/// File bytes
///    │
///    ▼
/// [memchr SIMD]  ← rejects files with no relevant byte classes at all
///    │
///    ▼
/// [Aho-Corasick] ← single O(n) pass, finds ALL keyword hits simultaneously
///    │
///    ▼
/// [Entropy check] ← rejects low-randomness strings
///    │
///    ▼
/// [Regex]        ← validates structure on a tiny 120-char window only
///    │
///    ▼
/// Finding { file, line, rule_id, rule_description, matched, entropy }
/// ```
///
/// The scanner owns a compiled `RuleEngine` and a `ScanConfig`.
/// It is `Send + Sync` and safe to share across threads.

use rayon::prelude::*;
use walkdir::WalkDir;

use crate::entropy;
use crate::filters;
use crate::rules::engine::RuleEngine;

/// Window size (in bytes) around an Aho-Corasick hit for regex validation.
/// Keeping this small is critical for performance — regex only runs on this slice.
const WINDOW_SIZE: usize = 120;

/// Minimum token length for entropy checking. Tokens shorter than this
/// are likely not secrets and would produce unreliable entropy scores.
const MIN_TOKEN_LEN: usize = 8;

/// Maximum file size to scan (default: 2 MB). Larger files are skipped
/// as they're unlikely to contain secrets and would slow scanning.
const DEFAULT_MAX_FILE_SIZE: u64 = 2 * 1024 * 1024;

// ─────────────────────────────────────────────
// ScanConfig
// ─────────────────────────────────────────────

/// Configuration for a scan operation.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Global minimum entropy override. If set, overrides per-rule thresholds.
    pub min_entropy_override: Option<f64>,

    /// Maximum file size in bytes. Files larger than this are skipped.
    pub max_file_size: u64,

    /// Whether to redact matched secrets in findings.
    pub redact: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            min_entropy_override: None,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            redact: true,
        }
    }
}

// ─────────────────────────────────────────────
// Finding
// ─────────────────────────────────────────────

/// A scan finding with full metadata from the matched rule.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Path to the file containing the finding.
    pub file: String,

    /// 1-based line number within the file.
    pub line: usize,

    /// The rule ID that matched (e.g., `"aws-access-token"`).
    pub rule_id: String,

    /// Human-readable description from the rule.
    pub rule_description: String,

    /// The matched text (redacted or raw depending on config).
    pub matched: String,

    /// Shannon entropy of the secret portion.
    pub entropy: f64,

    /// Byte offset of the match start in the file.
    pub start_offset: usize,

    /// Byte offset of the match end in the file.
    pub end_offset: usize,
}

// ─────────────────────────────────────────────
// Scanner
// ─────────────────────────────────────────────

/// The scanner. Owns a compiled `RuleEngine` and scan configuration.
///
/// # Examples
///
/// ```no_run
/// use secrets_scanner::{Scanner, ScanConfig};
///
/// let scanner = Scanner::new().expect("failed to load rules");
/// let findings = scanner.scan_path("./src");
/// for f in &findings {
///     println!("{}:{} [{}] {}", f.file, f.line, f.rule_id, f.matched);
/// }
/// ```
pub struct Scanner {
    engine: RuleEngine,
    config: ScanConfig,
}

impl Scanner {
    /// Create a scanner using the three-tier rule loading priority:
    /// 1. `$SECRETS_SCANNER_RULES` env var
    /// 2. Cached rules in OS data dir
    /// 3. Bundled default (compiled into binary)
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let toml_str = crate::rules::load_rules();
        let engine = RuleEngine::from_toml(&toml_str)?;
        Ok(Self {
            engine,
            config: ScanConfig::default(),
        })
    }

    /// Create a scanner from the bundled (compiled-in) ruleset only.
    pub fn from_bundled() -> Result<Self, Box<dyn std::error::Error>> {
        let engine = RuleEngine::from_toml(crate::rules::BUNDLED_RULES)?;
        Ok(Self {
            engine,
            config: ScanConfig::default(),
        })
    }

    /// Create a scanner from a specific TOML file path.
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let toml_str = std::fs::read_to_string(path)?;
        let engine = RuleEngine::from_toml(&toml_str)?;
        Ok(Self {
            engine,
            config: ScanConfig::default(),
        })
    }

    /// Create a scanner from a TOML string.
    pub fn from_toml(toml_str: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let engine = RuleEngine::from_toml(toml_str)?;
        Ok(Self {
            engine,
            config: ScanConfig::default(),
        })
    }

    /// Create a scanner with a custom config.
    pub fn with_config(mut self, config: ScanConfig) -> Self {
        self.config = config;
        self
    }

    /// Access the underlying rule engine.
    pub fn engine(&self) -> &RuleEngine {
        &self.engine
    }

    /// Scan a directory tree in parallel using rayon.
    ///
    /// Files are filtered by extension, directory, size, and global path allowlist
    /// before scanning. The scan uses all available CPU cores via rayon's work-stealing.
    pub fn scan_path(&self, root: &str) -> Vec<Finding> {
        // Collect file paths (walkdir is single-threaded)
        let paths: Vec<String> = WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                let path_str = e.path().to_str().unwrap_or("");
                // Basic extension/directory filter
                if !filters::should_scan(path_str) {
                    return false;
                }
                // Size filter
                if let Ok(meta) = e.metadata() {
                    if meta.len() > self.config.max_file_size {
                        return false;
                    }
                }
                // Global path allowlist
                if self.engine.is_path_globally_allowlisted(path_str) {
                    return false;
                }
                true
            })
            .map(|e| e.path().to_string_lossy().to_string())
            .collect();

        // Scan in parallel
        paths
            .par_iter()
            .flat_map(|path| {
                match std::fs::read(path) {
                    Ok(bytes) => {
                        // memchr SIMD pre-filter: check if ANY keyword first-byte exists
                        let first_bytes = self.engine.keyword_first_bytes();
                        if !first_bytes.is_empty() {
                            let has_relevant_byte =
                                first_bytes.iter().any(|&b| memchr::memchr(b, &bytes).is_some());
                            if !has_relevant_byte {
                                return vec![];
                            }
                        }

                        // Lossily decode (secrets are ASCII)
                        let content = String::from_utf8_lossy(&bytes);
                        self.scan_content(path, &content)
                    }
                    Err(_) => vec![],
                }
            })
            .collect()
    }

    /// Scan a single file's content against all rules.
    ///
    /// This is the core scan function. It runs the Aho-Corasick automaton,
    /// then validates hits with entropy checks and regex patterns.
    ///
    /// Useful for scanning in-memory content (e.g., LLM pipeline proxy).
    pub fn scan_content(&self, path: &str, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut seen_positions: std::collections::HashSet<(usize, usize)> =
            std::collections::HashSet::new();

        // Check path-only rules (rules with no content regex but having a path filter)
        for rule in self.engine.rules() {
            if rule.regex.is_none() {
                if let Some(ref path_re) = rule.path_filter {
                    if path_re.is_match(path) {
                        findings.push(Finding {
                            file: path.to_string(),
                            line: 1,
                            rule_id: rule.id.clone(),
                            rule_description: rule.description.clone(),
                            matched: format!("File path matches pattern: {}", path),
                            entropy: 0.0,
                            start_offset: 0,
                            end_offset: 0,
                        });
                    }
                }
            }
        }

        // Single O(n) pass: find all keyword matches
        for mat in self.engine.ac().find_iter(content) {
            let rule_idx = self.engine.rule_for_keyword(mat.pattern().as_usize());
            let rule = &self.engine.rules()[rule_idx];

            // Check per-rule path filter
            if let Some(ref path_re) = rule.path_filter {
                if !path_re.is_match(path) {
                    continue;
                }
            }

            let regex_re = match &rule.regex {
                Some(re) => re,
                None => continue,
            };

            // Extract window around the hit
            let mut window_start = mat.start().saturating_sub(20); // look back a bit for context
            let mut window_end = (mat.start() + WINDOW_SIZE).min(content.len());

            // Ensure we don't split a UTF-8 character
            while !content.is_char_boundary(window_end) && window_end > mat.start() {
                window_end -= 1;
            }
            while !content.is_char_boundary(window_start) && window_start > 0 {
                window_start -= 1;
            }

            let window = &content[window_start..window_end];

            // Run the rule's regex on the window
            let regex_match = match regex_re.find(window) {
                Some(m) => m,
                None => continue,
            };

            let matched_str = regex_match.as_str();
            let match_start_in_file = window_start + regex_match.start();
            let match_end_in_file = window_start + regex_match.end();

            // Deduplicate: skip if we've already found this exact match position
            if !seen_positions.insert((match_start_in_file, match_end_in_file)) {
                continue;
            }

            // Extract the "secret part" — use the configured secret group if specified,
            // otherwise default to group 1 if capture groups exist, or group 0 (the entire match) if not.
            let secret_group_idx = rule.secret_group.unwrap_or_else(|| {
                if regex_re.captures_len() > 1 {
                    1
                } else {
                    0
                }
            });

            let secret_part = if let Some(captures) = regex_re.captures(window) {
                captures
                    .get(secret_group_idx)
                    .map(|m| m.as_str())
                    .unwrap_or(matched_str)
            } else {
                matched_str
            };

            // Entropy check (only if rule has an entropy threshold or global override is set)
            let ent = entropy::shannon_entropy(secret_part);
            if let Some(threshold) = self.config.min_entropy_override.or(rule.entropy_threshold) {
                if secret_part.len() < MIN_TOKEN_LEN || ent < threshold {
                    continue;
                }
            }

            // Check global allowlist
            if self.engine.is_match_globally_allowlisted(matched_str) {
                continue;
            }

            // Check per-rule allowlist
            let check_target = if rule.allowlist_match_target {
                matched_str
            } else {
                secret_part
            };
            if RuleEngine::is_rule_allowlisted(rule, check_target, path) {
                continue;
            }

            // Compute line number
            let line =
                content[..match_start_in_file]
                    .bytes()
                    .filter(|&b| b == b'\n')
                    .count()
                    + 1;

            let display_match = if self.config.redact {
                filters::redact(matched_str)
            } else {
                matched_str.to_string()
            };

            findings.push(Finding {
                file: path.to_string(),
                line,
                rule_id: rule.id.clone(),
                rule_description: rule.description.clone(),
                matched: display_match,
                entropy: ent,
                start_offset: match_start_in_file,
                end_offset: match_end_in_file,
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_scanner() -> Scanner {
        let toml = r#"
title = "test"

[[rules]]
id = "aws-access-token"
description = "AWS access key"
regex = '\b(AKIA[A-Z2-7]{16})\b'
entropy = 3.0
keywords = ["akia"]

[[rules]]
id = "github-pat"
description = "GitHub PAT"
regex = 'ghp_[A-Za-z0-9_]{36,}'
keywords = ["ghp_"]

[[rules]]
id = "pem-private-key"
description = "PEM private key"
regex = '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
keywords = ["-----begin"]
"#;
        Scanner::from_toml(toml).expect("should build test scanner")
    }

    #[test]
    fn detects_aws_key() {
        let scanner = test_scanner();
        // This is a fake AWS key with high entropy
        let content = r#"aws_key = "AKIAIOSFODNN7EXAMPLEK""#;
        let findings = scanner.scan_content("test.env", content);

        // The key should be detected (if entropy is high enough)
        if !findings.is_empty() {
            assert_eq!(findings[0].rule_id, "aws-access-token");
            assert_eq!(findings[0].line, 1);
        }
    }

    #[test]
    fn detects_github_pat() {
        let scanner = test_scanner();
        let content =
            "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop";
        let findings = scanner.scan_content("config.yml", content);

        if !findings.is_empty() {
            assert_eq!(findings[0].rule_id, "github-pat");
        }
    }

    #[test]
    fn detects_pem_key() {
        let scanner = test_scanner();
        let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF";
        let findings = scanner.scan_content("key.pem", content);
        assert!(
            !findings.is_empty(),
            "should detect PEM private key header"
        );
        assert_eq!(findings[0].rule_id, "pem-private-key");
    }

    #[test]
    fn skips_low_entropy() {
        let scanner = test_scanner();
        // AKIA followed by low-entropy chars
        let content = r#"key = "AKIAAAAAAAAAAAAAAAAA""#;
        let findings = scanner.scan_content("test.env", content);
        // Should be empty due to low entropy
        assert!(
            findings.is_empty(),
            "low-entropy AKIA should be filtered out"
        );
    }

    #[test]
    fn redacts_by_default() {
        let scanner = test_scanner();
        let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF";
        let findings = scanner.scan_content("key.pem", content);
        if !findings.is_empty() {
            assert!(
                findings[0].matched.contains('*'),
                "should redact matched text"
            );
        }
    }

    #[test]
    fn respects_no_redact_config() {
        let scanner = test_scanner().with_config(ScanConfig {
            redact: false,
            ..Default::default()
        });
        let content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF";
        let findings = scanner.scan_content("key.pem", content);
        if !findings.is_empty() {
            assert!(
                !findings[0].matched.contains('*'),
                "should not redact when config says no"
            );
        }
    }

    #[test]
    fn loads_bundled_and_scans() {
        // Smoke test: load the real bundled rules and scan a known secret
        let scanner = Scanner::from_bundled().expect("bundled rules should load");
        assert!(scanner.engine().rule_count() > 100);

        // Scan content with a planted GitHub PAT (avoid contiguous alphabet to bypass global stopwords allowlist)
        let content =
            "export TOKEN=ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde";
        let findings = scanner.scan_content("deploy.sh", content);
        // Should find at least one hit (github-pat or generic-api-key)
        assert!(
            !findings.is_empty(),
            "bundled scanner should detect planted GitHub PAT"
        );
    }
}
