//! rules/engine.rs — Parse gitleaks-compatible TOML rules into a compiled scan engine.
//!
//! The engine deserializes the TOML ruleset into typed structs, compiles all
//! regexes once at startup, and builds a single Aho-Corasick automaton from
//! the union of all rule keywords. This enables O(n) scanning of file content
//! regardless of how many rules exist.
//!
//! # Architecture
//!
//! ```text
//! TOML string → RulesetConfig (serde) → RuleEngine (compiled)
//!                                          ├── AhoCorasick (all keywords)
//!                                          ├── keyword_map[ac_idx] → rule_idx
//!                                          └── Vec<CompiledRule> (regex + metadata)
//! ```

use aho_corasick::AhoCorasick;
use regex::Regex;

pub use crate::rules::allowlist::CompiledAllowlist;

#[path = "engine_builder.rs"]
mod builder;

/// A compiled rule ready for scanning. All regexes are pre-compiled.
#[derive(Debug)]
pub struct CompiledRule {
    /// Unique rule ID from the TOML config.
    pub id: String,

    /// Human-readable description.
    pub description: String,

    /// Compiled detection regex.
    pub regex: Option<regex::bytes::Regex>,

    /// Minimum entropy threshold. `None` disables entropy gating for this rule.
    pub entropy_threshold: Option<f64>,

    /// Keywords (lowercase) for this rule.
    pub keywords: Vec<String>,

    /// Compiled file-path filter regex (if the rule has a `path` field).
    pub path_filter: Option<Regex>,

    /// Per-rule allowlists.
    pub allowlists: Vec<CompiledAllowlist>,

    /// Optional capture group index for the secret.
    pub secret_group: Option<usize>,
}

#[derive(Clone, Copy)]
pub(super) enum RuleRef {
    Keyworded(usize),
    Unkeyworded(usize),
}

/// The compiled rule engine. Owns the Aho-Corasick automaton and all compiled rules.
///
/// # Usage
///
/// ```no_run
/// use secrets_scanner::rules::engine::RuleEngine;
///
/// let toml_str = std::fs::read_to_string("assets/secrets-scanner.toml").unwrap();
/// let engine = RuleEngine::from_toml(&toml_str).unwrap();
/// println!("Loaded {} rules with {} keywords", engine.rule_count(), engine.keyword_count());
/// ```
pub struct RuleEngine {
    /// Aho-Corasick automaton built from ALL keywords across all rules that have keywords.
    pub(super) ac: AhoCorasick,

    /// Maps AC pattern index → list of rule indices. Multiple keywords map to different rules.
    pub(super) keyword_to_rules: Vec<Vec<usize>>,

    /// Compiled rules that have keywords.
    pub(super) keyworded_rules: Vec<CompiledRule>,

    /// Compiled rules that do NOT have keywords.
    pub(super) unkeyworded_rules: Vec<CompiledRule>,

    /// RegexSet prefilter over unkeyworded rules that have content regexes.
    pub(super) unkeyworded_regex_set: Option<regex::bytes::RegexSet>,

    /// Maps RegexSet match indices back to `unkeyworded_rules` indices.
    pub(super) unkeyworded_set_rule_indices: Vec<usize>,

    /// Rules with only a path filter and no content regex.
    pub(super) path_only_rules: Vec<RuleRef>,

    /// Compiled global allowlists.
    pub(super) global_allowlists: Vec<CompiledAllowlist>,

    /// Pre-computed set of unique first bytes from all keywords,
    /// used for the memchr SIMD pre-filter.
    pub(super) keyword_first_bytes: Vec<u8>,
}

impl RuleEngine {
    /// Parse a TOML ruleset string and compile into a scan-ready engine.
    ///
    /// This is the main constructor. It:
    /// 1. Deserializes the TOML into `RulesetConfig`
    /// 2. Compiles all rule regexes (skipping rules with invalid regex)
    /// 3. Collects all keywords and builds a single Aho-Corasick automaton
    /// 4. Compiles global and per-rule allowlists
    ///
    /// # Errors
    ///
    /// Returns an error if the TOML is malformed or if the Aho-Corasick
    /// automaton cannot be built.
    pub fn from_toml(toml_str: &str) -> Result<Self, crate::error::ScannerError> {
        Ok(Self::from_toml_reporting(toml_str)?.0)
    }

    /// Like [`from_toml`], but also returns a list of human-readable issues
    /// describing everything the lenient build had to drop or that is
    /// structurally invalid: rules with an uncompilable detection regex,
    /// invalid path/allowlist/global-allowlist regexes, and empty/duplicate
    /// rule IDs. An empty `Vec` means the ruleset compiled cleanly with nothing
    /// skipped.
    ///
    /// This lets a strict caller (`Scanner::from_toml`) fail loudly on an
    /// explicit `--rules` file using the *same single* parse+compile pass that
    /// builds the engine, instead of paying for a separate full validation pass
    /// that re-parses the TOML and re-compiles every regex.
    ///
    /// [`from_toml`]: RuleEngine::from_toml
    ///
    /// # Errors
    ///
    /// Returns an error if the TOML is malformed or if the Aho-Corasick
    /// automaton cannot be built.
    pub fn from_toml_reporting(
        toml_str: &str,
    ) -> Result<(Self, Vec<String>), crate::error::ScannerError> {
        builder::build_from_toml(toml_str)
    }

    /// Returns a reference to the Aho-Corasick automaton.
    pub fn ac(&self) -> &AhoCorasick {
        &self.ac
    }

    /// Returns a list of references to all compiled rules (both keyworded and unkeyworded).
    pub fn rules(&self) -> Vec<&CompiledRule> {
        self.keyworded_rules
            .iter()
            .chain(self.unkeyworded_rules.iter())
            .collect()
    }

    /// Returns the compiled rules that have keywords.
    pub fn keyworded_rules(&self) -> &[CompiledRule] {
        &self.keyworded_rules
    }

    /// Returns the compiled rules that do NOT have keywords.
    pub fn unkeyworded_rules(&self) -> &[CompiledRule] {
        &self.unkeyworded_rules
    }

    /// Returns the optional RegexSet prefilter for unkeyworded content rules.
    pub fn unkeyworded_regex_set(&self) -> Option<&regex::bytes::RegexSet> {
        self.unkeyworded_regex_set.as_ref()
    }

    /// Maps RegexSet match indices back to [`Self::unkeyworded_rules`] indices.
    pub fn unkeyworded_regex_set_rule_indices(&self) -> &[usize] {
        &self.unkeyworded_set_rule_indices
    }

    /// Returns rules that match only on file path.
    pub fn path_only_rules(&self) -> impl Iterator<Item = &CompiledRule> {
        self.path_only_rules.iter().map(|rule_ref| match *rule_ref {
            RuleRef::Keyworded(idx) => &self.keyworded_rules[idx],
            RuleRef::Unkeyworded(idx) => &self.unkeyworded_rules[idx],
        })
    }

    /// Look up which rule indices a keyword AC match belongs to.
    pub fn rules_for_keyword(&self, ac_pattern_index: usize) -> &[usize] {
        &self.keyword_to_rules[ac_pattern_index]
    }

    /// Returns the global allowlists.
    pub fn global_allowlists(&self) -> &[CompiledAllowlist] {
        &self.global_allowlists
    }

    /// The set of unique first bytes from all keywords (for memchr pre-filter).
    pub fn keyword_first_bytes(&self) -> &[u8] {
        &self.keyword_first_bytes
    }

    /// Total number of compiled rules.
    pub fn rule_count(&self) -> usize {
        self.keyworded_rules.len() + self.unkeyworded_rules.len()
    }

    /// Total number of unique keywords in the AC automaton.
    pub fn keyword_count(&self) -> usize {
        self.keyword_to_rules.len()
    }

    /// Check if a file path is globally allowlisted (should be skipped).
    pub fn is_path_globally_allowlisted(&self, path: &str) -> bool {
        crate::rules::allowlist::is_path_globally_allowlisted(&self.global_allowlists, path)
    }

    /// Check if a matched byte slice is globally allowlisted.
    pub fn is_match_globally_allowlisted(
        &self,
        rule_id: &str,
        file_path: &str,
        line_bytes: &[u8],
        matched_bytes: &[u8],
        secret_bytes: &[u8],
    ) -> bool {
        crate::rules::allowlist::is_match_globally_allowlisted(
            &self.global_allowlists,
            rule_id,
            file_path,
            line_bytes,
            matched_bytes,
            secret_bytes,
        )
    }

    pub(crate) fn is_match_globally_allowlisted_cached(
        &self,
        rule_id: &str,
        allowlist_match: &mut crate::rules::allowlist::AllowlistMatch<'_>,
    ) -> bool {
        crate::rules::allowlist::is_match_globally_allowlisted_cached(
            &self.global_allowlists,
            rule_id,
            allowlist_match,
        )
    }

    /// Check if a finding is suppressed by a specific rule's allowlist.
    pub fn is_rule_allowlisted(
        rule: &CompiledRule,
        file_path: &str,
        line_bytes: &[u8],
        matched_bytes: &[u8],
        secret_bytes: &[u8],
    ) -> bool {
        crate::rules::allowlist::is_rule_allowlisted(
            rule,
            file_path,
            line_bytes,
            matched_bytes,
            secret_bytes,
        )
    }

    pub(crate) fn is_rule_allowlisted_cached(
        rule: &CompiledRule,
        allowlist_match: &mut crate::rules::allowlist::AllowlistMatch<'_>,
    ) -> bool {
        crate::rules::allowlist::is_rule_allowlisted_cached(rule, allowlist_match)
    }
}

#[cfg(test)]
#[path = "engine/tests.rs"]
mod tests;
