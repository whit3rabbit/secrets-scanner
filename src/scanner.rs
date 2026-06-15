//! scanner.rs — High-performance parallel file scanner.
//!
//! Implements the scan pipeline described in TODO.md:
//!
//! ```text
//! File bytes
//!    │
//!    ▼
//! [memchr SIMD]  ← skips keyworded-rule lookup when no keyword first bytes appear
//!    │
//!    ▼
//! [Aho-Corasick] ← single O(n) pass, finds candidate rules based on keywords
//!    │
//!    ▼
//! [Entropy check] ← rejects low-randomness strings
//!    │
//!    ▼
//! [Regex]        ← validates structure on the full content of candidate rules
//!    │
//!    ▼
//! Finding { file, line, rule_id, rule_description, matched, entropy }
//! ```
//!
//! The scanner owns a compiled `RuleEngine` and a `ScanConfig`.
//! It is `Send + Sync` and safe to share across threads.

use crate::error::{ProxyError, ScannerError};
use crate::rules::engine::RuleEngine;

mod matching;
mod output;
mod redaction;
mod types;
mod walk;
pub use types::{BinaryPolicy, Finding, ScanConfig, ScanOutput, ScanResult, ScanStats};

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
    /// Per-scan timing accumulator for the unkeyworded-rule pass. Compiled in
    /// only under the `bench` feature so the release build never pays for the
    /// `Instant::now()` calls in `scan_bytes`.
    #[cfg(feature = "bench")]
    unkeyworded_scan_time_ns: std::sync::atomic::AtomicU64,
}

impl Scanner {
    /// Build a scanner from a compiled engine with the default config. Single
    /// funnel for all constructors so the (feature-gated) bench field is
    /// initialised in exactly one place.
    fn from_engine(engine: RuleEngine) -> Self {
        Self {
            engine,
            config: ScanConfig::default(),
            #[cfg(feature = "bench")]
            unkeyworded_scan_time_ns: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Create a scanner using the three-tier rule loading priority:
    /// 1. `$SECRETS_SCANNER_RULES` env var
    /// 2. Cached rules in OS data dir
    /// 3. Bundled default (compiled into binary)
    pub fn new() -> Result<Self, ScannerError> {
        let toml_str = crate::rules::load_rules_for_scanner()?;
        Ok(Self::from_engine(RuleEngine::from_toml(&toml_str)?))
    }

    /// Create a scanner from the bundled (compiled-in) ruleset only.
    pub fn from_bundled() -> Result<Self, ScannerError> {
        Ok(Self::from_engine(RuleEngine::from_toml(
            crate::rules::BUNDLED_RULES,
        )?))
    }

    /// Create a scanner from a specific TOML file path.
    pub fn from_file(path: &str) -> Result<Self, ScannerError> {
        let toml_str = std::fs::read_to_string(path)?;
        Self::from_toml(&toml_str)
    }

    /// Create a scanner from a TOML string.
    ///
    /// Strict gate for explicit `--rules`/`from_file` rulesets: it fails loudly
    /// (rather than silently scanning with a reduced rule set) if the ruleset has
    /// any uncompilable regex, empty ID, or duplicate ID. `new`/`from_bundled`
    /// take the lenient [`RuleEngine::from_toml`] path because their
    /// bundled/cached tiers are validated at build/update time.
    ///
    /// A single parse+compile pass does both jobs: [`RuleEngine::from_toml_reporting`]
    /// builds the engine and reports everything it had to drop or that is
    /// structurally invalid, so this no longer re-parses the TOML and re-compiles
    /// every regex in a separate validation pass.
    pub fn from_toml(toml_str: &str) -> Result<Self, ScannerError> {
        let (engine, issues) = RuleEngine::from_toml_reporting(toml_str)?;
        if !issues.is_empty() {
            return Err(ScannerError::InvalidRules(issues));
        }
        Ok(Self::from_engine(engine))
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

    /// Returns the accumulated time spent on unkeyworded scans in nanoseconds.
    /// Only available under the `bench` feature.
    #[cfg(feature = "bench")]
    pub fn unkeyworded_scan_time_ns(&self) -> u64 {
        self.unkeyworded_scan_time_ns
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Resets the unkeyworded scan time benchmark to 0.
    /// Only available under the `bench` feature.
    #[cfg(feature = "bench")]
    pub fn reset_unkeyworded_scan_time(&self) {
        self.unkeyworded_scan_time_ns
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    /// Scan a directory tree in parallel using rayon.
    ///
    /// Files are filtered by extension, directory, size, and global path allowlist
    /// before scanning. The scan uses all available CPU cores via rayon's work-stealing.
    pub fn scan_path(&self, root: &str) -> Vec<Finding> {
        self.scan_path_with_stats(root).0
    }

    /// Like [`scan_path`](Self::scan_path) but also returns file-level
    /// [`ScanStats`] (files scanned, binary/oversized skipped, capped) so a
    /// caller can print a safe summary without echoing secret material.
    pub fn scan_path_with_stats(&self, root: &str) -> (Vec<Finding>, ScanStats) {
        walk::scan_path(self, root)
    }

    /// Scan a single file and return findings plus file-level [`ScanStats`].
    ///
    /// This uses the same hardened file-read path as directory walks: symlinks
    /// are rejected, reads are bounded by `max_file_size`, and binary content is
    /// skipped according to the configured [`BinaryPolicy`].
    pub fn scan_file_with_stats(&self, path: &str) -> (Vec<Finding>, ScanStats) {
        walk::scan_file(self, path)
    }

    /// Scan a single file's content against all rules.
    ///
    /// This is the core scan function. It runs the Aho-Corasick automaton,
    /// then validates hits with entropy checks and regex patterns.
    ///
    /// Useful for scanning in-memory content (e.g., LLM pipeline proxy).
    pub fn scan_content(&self, path: &str, content: &str) -> Vec<Finding> {
        self.scan_bytes(path, content.as_bytes())
    }

    /// Hardened entry point for scanning untrusted in-memory content (e.g. an
    /// LLM redaction proxy).
    ///
    /// Unlike [`scan_and_redact_bytes`](Self::scan_and_redact_bytes), this
    /// **fails closed**: if `content` exceeds `max_file_size` it returns
    /// [`ProxyError::InputTooLarge`] and produces no output, so an oversized
    /// payload can never be forwarded unscanned. Pair with
    /// [`ScanConfig::proxy`](crate::ScanConfig::proxy), which also disables
    /// attacker-controlled allow markers, skips context capture, and caps
    /// findings and `matched` length.
    ///
    /// This is enforced, not advisory: if the scanner's config is not hardened
    /// (redact off, allow markers honored, context captured, or caps unset) it
    /// returns [`ProxyError::NotHardened`] without scanning, so the untrusted
    /// path cannot be used un-hardened by accident.
    pub fn scan_proxy(&self, content: &[u8]) -> Result<ScanOutput<Vec<u8>>, ProxyError> {
        // Refuse to scan untrusted content with a soft config. `scan_bytes` and
        // `check_rule_match` read `self.config` directly, so the only way to keep
        // this entry point safe-by-construction (rather than relying on the caller
        // to remember `ScanConfig::proxy()`) is to fail closed when the posture is
        // not hardened. Caps are checked for presence, not exact value, so a caller
        // may raise them via `with_config` and still pass.
        if !self.config.is_hardened() {
            return Err(ProxyError::NotHardened);
        }
        if content.len() as u64 > self.config.max_file_size {
            return Err(ProxyError::InputTooLarge {
                size: content.len(),
                max: self.config.max_file_size,
            });
        }
        Ok(self.scan_and_redact_bytes("<proxy>", content))
    }

    /// Scan a byte slice against all rules.
    ///
    /// This operates directly on raw bytes to avoid heap allocations.
    pub fn scan_bytes(&self, path: &str, content: &[u8]) -> Vec<Finding> {
        self.scan_bytes_detailed(path, content).findings
    }

    /// Scan a byte slice and return every finding WITHOUT applying the per-file
    /// finding cap.
    ///
    /// Callers that derive payload output from the finding set (redaction) must
    /// use the full pre-cap set: the cap drops finding *entries*, but a dropped
    /// secret's bytes still live in `content`, so redacting off a truncated set
    /// would forward secrets past the cap in the clear. `scan_bytes` and
    /// `scan_and_redact_bytes` re-apply the cap themselves at the right point.
    fn scan_bytes_uncapped(&self, path: &str, content: &[u8]) -> Vec<Finding> {
        // Check global path allowlist first — skip entirely if path matches.
        if self.engine.is_path_globally_allowlisted(path) {
            return Vec::new();
        }

        let mut findings = Vec::new();

        // Check path-only rules without walking the whole ruleset per file.
        for rule in self.engine.path_only_rules() {
            if let Some(ref path_re) = rule.path_filter {
                if path_re.is_match(path) {
                    findings.push(Finding {
                        file: path.to_string(),
                        line: 1,
                        col: 1,
                        end_line: 1,
                        end_col: 1,
                        col_utf16: 1,
                        end_col_utf16: 1,
                        rule_id: rule.id.clone(),
                        rule_description: rule.description.clone(),
                        matched: format!("File path matches pattern: {}", path),
                        entropy: 0.0,
                        start_offset: 0,
                        end_offset: 0,
                        secret_start_offset: 0,
                        secret_end_offset: 0,
                        // Path-only rule: fingerprint over (rule, path) — no secret span.
                        fingerprint: crate::fingerprint::finding_fingerprint(
                            &rule.id,
                            path,
                            path.as_bytes(),
                        ),
                        commit: None,
                        context_lines: Vec::new(),
                    });
                }
            }
        }

        // 1. Determine candidate rules based on keywords (first pass). The
        // first-byte prefilter only skips keyworded rule work; unkeyworded
        // rules still run below.
        let mut candidate_rules = vec![false; self.engine.keyworded_rules().len()];
        if self.has_keyword_first_byte(content) {
            for mat in self.engine.ac().find_overlapping_iter(content) {
                for &rule_idx in self.engine.rules_for_keyword(mat.pattern().as_usize()) {
                    candidate_rules[rule_idx] = true;
                }
            }
        }

        // 2. Second pass: run candidate keyworded rule regexes across the content.
        for (rule_idx, rule) in self.engine.keyworded_rules().iter().enumerate() {
            if !candidate_rules[rule_idx] {
                continue;
            }
            if rule.regex.is_none() {
                continue;
            }

            matching::check_rule_match(self, rule, path, content, &mut findings);
        }

        // 3. Evaluate unkeyworded regex rules and benchmark their cost.
        #[cfg(feature = "bench")]
        let unkeyworded_start = std::time::Instant::now();
        if let Some(regex_set) = self.engine.unkeyworded_regex_set() {
            let rule_indices = self.engine.unkeyworded_regex_set_rule_indices();
            for set_idx in regex_set.matches(content).iter() {
                let rule_idx = rule_indices[set_idx];
                let rule = &self.engine.unkeyworded_rules()[rule_idx];
                matching::check_rule_match(self, rule, path, content, &mut findings);
            }
        } else {
            for rule in self.engine.unkeyworded_rules().iter() {
                if rule.regex.is_some() {
                    matching::check_rule_match(self, rule, path, content, &mut findings);
                }
            }
        }
        #[cfg(feature = "bench")]
        self.unkeyworded_scan_time_ns.fetch_add(
            unkeyworded_start.elapsed().as_nanos() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );

        // Redact secrets out of every finding's context window BEFORE the
        // per-file cap. `redact_context_lines` builds its secret ranges from the
        // finding set it is handed, so if the cap dropped a finding first, a
        // surviving finding's context could still contain the dropped secret's
        // raw bytes (two secrets within a few lines of each other). Redacting the
        // full set first means truncation only removes finding entries, never
        // redaction coverage.
        if self.config.redact && self.config.capture_context {
            matching::redact_context_lines(content, &mut findings);
        }

        findings
    }

    /// Apply the per-content finding cap (`max_findings_per_file`) in place.
    ///
    /// Enforced here (not only in the directory walk) so every caller of
    /// `scan_bytes` — including the in-memory proxy path — is bounded and cannot
    /// be starved by a match-spam payload. Callers that redact a payload from the
    /// finding set must do so on the pre-cap findings (see `scan_bytes_uncapped`)
    /// and call this only afterwards.
    fn apply_findings_cap(&self, path: &str, findings: &mut Vec<Finding>) -> bool {
        if let Some(cap) = self.config.max_findings_per_file {
            if findings.len() > cap {
                log::warn!(
                    "[scanner] Warning: {} finding(s) in '{}' truncated to \
                     --max-findings-per-file ({cap}).",
                    findings.len(),
                    crate::safe_display::sanitize_display(path),
                );
                findings.truncate(cap);
                return true;
            }
        }
        false
    }

    /// Returns true if content contains a possible first byte for any keyword.
    fn has_keyword_first_byte(&self, content: &[u8]) -> bool {
        let first_bytes = self.engine.keyword_first_bytes();
        !first_bytes.is_empty()
            && first_bytes.iter().any(|&b| {
                memchr::memchr(b, content).is_some()
                    || (b.is_ascii_alphabetic()
                        && memchr::memchr(b.to_ascii_uppercase(), content).is_some())
            })
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod redaction_tests;
