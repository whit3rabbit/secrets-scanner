//! rules/allowlist.rs — Compiled allowlist logic and evaluation.

use crate::rules::engine::CompiledRule;
use crate::rules::validation::{
    compile_bytes_regex, compile_regex, AllowlistCondition, AllowlistConfig, GlobalAllowlist,
    RegexTarget,
};
use regex::Regex;

pub(crate) struct AllowlistMatch<'a> {
    file_path: &'a str,
    line_bytes: &'a [u8],
    matched_bytes: &'a [u8],
    secret_bytes: &'a [u8],
    line_lower: Option<String>,
    matched_lower: Option<String>,
    secret_lower: Option<String>,
}

impl<'a> AllowlistMatch<'a> {
    pub(crate) fn new(
        file_path: &'a str,
        line_bytes: &'a [u8],
        matched_bytes: &'a [u8],
        secret_bytes: &'a [u8],
    ) -> Self {
        Self {
            file_path,
            line_bytes,
            matched_bytes,
            secret_bytes,
            line_lower: None,
            matched_lower: None,
            secret_lower: None,
        }
    }

    fn target_bytes(&self, target: RegexTarget) -> &'a [u8] {
        match target {
            RegexTarget::Secret => self.secret_bytes,
            RegexTarget::Match => self.matched_bytes,
            RegexTarget::Line => self.line_bytes,
        }
    }

    fn target_lower(&mut self, target: RegexTarget) -> &str {
        let bytes = match target {
            RegexTarget::Secret => self.secret_bytes,
            RegexTarget::Match => self.matched_bytes,
            RegexTarget::Line => self.line_bytes,
        };
        let slot = match target {
            RegexTarget::Secret => &mut self.secret_lower,
            RegexTarget::Match => &mut self.matched_lower,
            RegexTarget::Line => &mut self.line_lower,
        };
        slot.get_or_insert_with(|| String::from_utf8_lossy(bytes).to_lowercase())
            .as_str()
    }
}

/// A compiled allowlist rule.
#[derive(Debug)]
pub struct CompiledAllowlist {
    /// Human-readable description.
    pub description: Option<String>,

    /// Compiled path regexes — files matching any of these are skipped/suppressed.
    pub paths: Vec<Regex>,

    /// Compiled content regexes — findings matching any are suppressed.
    pub regexes: Vec<regex::bytes::Regex>,

    /// Stopwords (lowercase) — findings containing any of these are suppressed.
    pub stopwords: Vec<String>,

    /// The condition defining how the criteria are evaluated.
    pub condition: AllowlistCondition,

    /// What the allowlist regexes and stopwords match against.
    pub regex_target: RegexTarget,

    /// Rule IDs that this allowlist applies to. If empty, it applies globally/to all rules.
    pub target_rules: Vec<String>,
}

impl CompiledAllowlist {
    /// Compile a rule allowlist configuration.
    pub fn compile_rule_allowlist(al: &AllowlistConfig, rule_id: &str) -> Self {
        let mut paths = Vec::new();
        for pattern in &al.paths {
            match compile_regex(pattern) {
                Ok(re) => paths.push(re),
                Err(e) => {
                    log::warn!("rule '{}' has invalid allowlist path regex: {}", rule_id, e);
                }
            }
        }

        let mut regexes = Vec::new();
        for pattern in &al.regexes {
            match compile_bytes_regex(pattern) {
                Ok(re) => regexes.push(re),
                Err(e) => {
                    log::warn!(
                        "rule '{}' has invalid allowlist content regex: {}",
                        rule_id,
                        e
                    );
                }
            }
        }

        let stopwords = al.stopwords.iter().map(|sw| sw.to_lowercase()).collect();
        let condition = al.condition.unwrap_or(AllowlistCondition::Or);
        let regex_target = al.regex_target.unwrap_or(RegexTarget::Secret);

        Self {
            description: al.description.clone(),
            paths,
            regexes,
            stopwords,
            condition,
            regex_target,
            target_rules: Vec::new(),
        }
    }

    /// Compile the global allowlist section.
    pub fn compile_global_allowlist(al: &GlobalAllowlist) -> Self {
        let mut paths = Vec::new();
        for pattern in &al.paths {
            match compile_regex(pattern) {
                Ok(re) => paths.push(re),
                Err(e) => {
                    log::warn!("global allowlist has invalid path regex: {}", e);
                }
            }
        }

        let mut regexes = Vec::new();
        for pattern in &al.regexes {
            match compile_bytes_regex(pattern) {
                Ok(re) => regexes.push(re),
                Err(e) => {
                    log::warn!("global allowlist has invalid content regex: {}", e);
                }
            }
        }

        let stopwords = al.stopwords.iter().map(|sw| sw.to_lowercase()).collect();
        let condition = al.condition.unwrap_or(AllowlistCondition::Or);
        let regex_target = al.regex_target.unwrap_or(RegexTarget::Secret);

        Self {
            description: al.description.clone(),
            paths,
            regexes,
            stopwords,
            condition,
            regex_target,
            target_rules: al.target_rules.clone(),
        }
    }

    /// Evaluate allowlist criteria on a finding.
    pub fn evaluate(
        &self,
        file_path: &str,
        line_bytes: &[u8],
        matched_bytes: &[u8],
        secret_bytes: &[u8],
    ) -> bool {
        let mut allowlist_match =
            AllowlistMatch::new(file_path, line_bytes, matched_bytes, secret_bytes);
        self.evaluate_cached(&mut allowlist_match)
    }

    pub(crate) fn evaluate_cached(&self, allowlist_match: &mut AllowlistMatch<'_>) -> bool {
        if self.paths.is_empty() && self.regexes.is_empty() && self.stopwords.is_empty() {
            return false;
        }

        let path_matched = !self.paths.is_empty()
            && self
                .paths
                .iter()
                .any(|re| re.is_match(allowlist_match.file_path));

        let target_bytes = allowlist_match.target_bytes(self.regex_target);
        let regex_matched =
            !self.regexes.is_empty() && self.regexes.iter().any(|re| re.is_match(target_bytes));

        let stopword_matched = if self.stopwords.is_empty() {
            false
        } else {
            let target_lower = allowlist_match.target_lower(self.regex_target);
            self.stopwords.iter().any(|sw| target_lower.contains(sw))
        };

        match self.condition {
            AllowlistCondition::Or => path_matched || regex_matched || stopword_matched,
            AllowlistCondition::And => {
                if !self.paths.is_empty() && !path_matched {
                    return false;
                }
                if !self.regexes.is_empty() && !regex_matched {
                    return false;
                }
                if !self.stopwords.is_empty() && !stopword_matched {
                    return false;
                }
                true
            }
        }
    }
}

/// Check if a file path is globally allowlisted (should be skipped).
pub fn is_path_globally_allowlisted(global_allowlists: &[CompiledAllowlist], path: &str) -> bool {
    global_allowlists.iter().any(|al| {
        if !al.target_rules.is_empty() {
            return false;
        }
        let matches_path = al.paths.iter().any(|re| re.is_match(path));
        if matches_path {
            match al.condition {
                AllowlistCondition::Or => true,
                AllowlistCondition::And => al.regexes.is_empty() && al.stopwords.is_empty(),
            }
        } else {
            false
        }
    })
}

/// Check if a matched byte slice is globally allowlisted.
pub fn is_match_globally_allowlisted(
    global_allowlists: &[CompiledAllowlist],
    rule_id: &str,
    file_path: &str,
    line_bytes: &[u8],
    matched_bytes: &[u8],
    secret_bytes: &[u8],
) -> bool {
    let mut allowlist_match =
        AllowlistMatch::new(file_path, line_bytes, matched_bytes, secret_bytes);
    is_match_globally_allowlisted_cached(global_allowlists, rule_id, &mut allowlist_match)
}

pub(crate) fn is_match_globally_allowlisted_cached(
    global_allowlists: &[CompiledAllowlist],
    rule_id: &str,
    allowlist_match: &mut AllowlistMatch<'_>,
) -> bool {
    for al in global_allowlists {
        if !al.target_rules.is_empty() && !al.target_rules.iter().any(|r| r == rule_id) {
            continue;
        }

        if al.evaluate_cached(allowlist_match) {
            return true;
        }
    }
    false
}

/// Check if a finding is suppressed by a specific rule's allowlist.
pub fn is_rule_allowlisted(
    rule: &CompiledRule,
    file_path: &str,
    line_bytes: &[u8],
    matched_bytes: &[u8],
    secret_bytes: &[u8],
) -> bool {
    let mut allowlist_match =
        AllowlistMatch::new(file_path, line_bytes, matched_bytes, secret_bytes);
    is_rule_allowlisted_cached(rule, &mut allowlist_match)
}

pub(crate) fn is_rule_allowlisted_cached(
    rule: &CompiledRule,
    allowlist_match: &mut AllowlistMatch<'_>,
) -> bool {
    rule.allowlists
        .iter()
        .any(|al| al.evaluate_cached(allowlist_match))
}
