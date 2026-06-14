//! rules/merge.rs — TOML merging logic for rulesets.
//!
//! Merges N rule sources ordered by priority (highest first). Three dedup levels
//! are applied as lower-priority sources are folded in:
//!   1. id collision   — lower-priority rule dropped (higher priority already won)
//!   2. exact regex     — lower-priority rule with a byte-identical `regex` dropped
//!   3. normalized regex — near-duplicate; RECORDED ONLY, never dropped (advisory)
//!
//! The 2-way `merge_toml_rules(base, override)` is preserved as a thin wrapper so
//! `build.rs` and the runtime updater keep compiling unchanged.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::OnceLock;

use log::warn;

/// One source's raw TOML plus the metadata the merge needs.
pub struct MergeSource {
    /// Source name used in the merge report (e.g. "local", "gitleaks", "spdb").
    pub name: String,
    /// Merge priority. Higher wins id/regex collisions.
    pub priority: i64,
    /// Raw TOML file contents.
    pub toml: String,
}

/// Why a duplicate was recorded.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum DupKind {
    /// Two rules share an `id`. Lower-priority dropped.
    IdCollision,
    /// Two rules have byte-identical `regex`. Lower-priority dropped.
    ExactRegex,
    /// Two rules have equal *normalized* regex but differ raw. Recorded only.
    NormalizedRegex,
}

/// A single recorded duplicate event.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DupRecord {
    /// The kind of duplicate.
    pub kind: DupKind,
    /// The id of the rule that was kept (higher priority).
    pub kept_id: String,
    /// The source the kept rule came from.
    pub kept_source: String,
    /// The id of the rule that lost (equals `kept_id` for an id collision).
    pub dropped_id: String,
    /// The source the losing rule came from.
    pub dropped_source: String,
    /// `true` for id/exact collisions (the rule was dropped); `false` for near-dups.
    pub dropped: bool,
    /// The regex involved, when the rules had one.
    pub regex: Option<String>,
}

/// Structured outcome of a merge, suitable for JSON serialization.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct MergeReport {
    /// Sum of rules across all input sources (before dedup).
    pub total_input_rules: usize,
    /// Number of rules in the merged output.
    pub output_rules: usize,
    /// Id collisions (lower-priority rule dropped).
    pub id_collisions: Vec<DupRecord>,
    /// Exact-regex duplicates (lower-priority rule dropped).
    pub exact_regex_dups: Vec<DupRecord>,
    /// Normalized-regex near-duplicates (recorded only, NOT dropped).
    pub near_dups: Vec<DupRecord>,
    /// Source names in merge order (highest priority first).
    pub sources: Vec<String>,
}

// ── Regex normalization ───────────────────────────────────────────────────────

/// Normalize a regex for near-duplicate detection.
///
/// Mirrors `scripts/import_secrets_patterns_db.py::normalize_regex` byte-for-byte:
/// strip inline flags, word boundaries, and line anchors; collapse whitespace;
/// lowercase. Keep the two implementations in sync — a parity test pins this.
pub fn normalize_regex(regex: &str) -> String {
    // Inline flags `(?imsxu)` / `(?-imsxu)`, word boundaries `\b`/`\B`, anchors `^`/`$`.
    static STRIP_RE: OnceLock<regex::Regex> = OnceLock::new();
    static WS_RE: OnceLock<regex::Regex> = OnceLock::new();
    let strip = STRIP_RE.get_or_init(|| {
        regex::Regex::new(r"\(\?[imsxu]+\)|\(\?-[imsxu]+\)|\\[bB]|\^|\$")
            .expect("static normalize strip regex is valid")
    });
    let ws = WS_RE.get_or_init(|| regex::Regex::new(r"\s+").expect("static whitespace regex"));

    let stripped = strip.replace_all(regex, "");
    let collapsed = ws.replace_all(&stripped, "");
    collapsed.to_lowercase()
}

/// Lowercased keyword set of a rule (order-independent comparison).
fn keyword_set(rule: &toml::Value) -> BTreeSet<String> {
    rule.get("keywords")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|k| k.as_str())
                .map(|s| s.to_lowercase())
                .collect()
        })
        .unwrap_or_default()
}

/// Whether two rules detect identically, so dropping one cannot cause a missed
/// secret. Requires equal regex (checked by the caller) plus equal keywords,
/// `path`, `secretGroup`, and `entropy`. Keywords feed the Aho-Corasick
/// pre-filter and `path`/`entropy` gate matches, so a difference in any of these
/// means the two rules fire in different situations and BOTH must be kept.
fn detection_equivalent(a: &toml::Value, b: &toml::Value) -> bool {
    keyword_set(a) == keyword_set(b)
        && a.get("path") == b.get("path")
        && a.get("secretGroup") == b.get("secretGroup")
        && a.get("entropy") == b.get("entropy")
}

// ── N-source merge core ───────────────────────────────────────────────────────

/// Merge N sources, applying the three dedup levels. Returns the merged TOML
/// string and a structured report.
///
/// Sources are sorted by `priority` descending (name as a stable tie-break).
/// Rules from higher-priority sources are emitted first; an id or exact-regex
/// collision drops the lower-priority rule. Normalized near-duplicates are kept
/// but recorded for human review.
///
/// # Errors
///
/// Returns an error if any source is not valid TOML or the result cannot be
/// re-serialized.
pub fn merge_sources(
    sources: Vec<MergeSource>,
) -> Result<(String, MergeReport), Box<dyn std::error::Error>> {
    // Parse every source up front; keep (name, priority, table).
    let mut parsed: Vec<(String, i64, toml::Table)> = Vec::with_capacity(sources.len());
    for s in sources {
        let val: toml::Value = toml::from_str(&s.toml)?;
        let table = val
            .as_table()
            .cloned()
            .ok_or_else(|| format!("source '{}' is not a TOML table", s.name))?;
        parsed.push((s.name, s.priority, table));
    }

    // Highest priority first; name as a deterministic tie-break.
    parsed.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut report = MergeReport {
        sources: parsed.iter().map(|(n, _, _)| n.clone()).collect(),
        ..Default::default()
    };

    let mut result = toml::Table::new();
    let mut merged_rules: Vec<toml::Value> = Vec::new();
    let mut seen_ids: HashMap<String, String> = HashMap::new(); // id   -> source
    let mut seen_exact: HashMap<String, usize> = HashMap::new(); // regex -> merged_rules index
    let mut seen_norm: HashMap<String, String> = HashMap::new(); // norm  -> kept id

    // Rules + top-level scalar keys: iterate highest priority first.
    for (name, _prio, table) in &parsed {
        // Top-level keys (except rules/allowlists) — highest priority wins.
        for (k, v) in table {
            if k != "rules" && k != "allowlist" && k != "allowlists" {
                result.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }

        let Some(rules) = table.get("rules").and_then(|r| r.as_array()) else {
            continue;
        };
        for rule in rules {
            report.total_input_rules += 1;
            let id = rule
                .get("id")
                .and_then(|i| i.as_str())
                .unwrap_or_default()
                .to_string();
            let regex = rule
                .get("regex")
                .and_then(|r| r.as_str())
                .map(|s| s.to_string());

            // L1: id collision — higher priority already inserted this id.
            if let Some(kept_source) = seen_ids.get(&id) {
                warn!("rule '{id}' from '{name}' shadowed by higher-priority source");
                report.id_collisions.push(DupRecord {
                    kind: DupKind::IdCollision,
                    kept_id: id.clone(),
                    kept_source: kept_source.clone(),
                    dropped_id: id.clone(),
                    dropped_source: name.clone(),
                    dropped: true,
                    regex: regex.clone(),
                });
                continue;
            }

            // L2/L3: regex-based dedup (only when the rule has a regex).
            if let Some(ref rx) = regex {
                if let Some(&idx) = seen_exact.get(rx) {
                    // Same regex as an already-kept rule. Only safe to DROP when
                    // the two are detection-equivalent (same keywords/path/entropy/
                    // secretGroup); otherwise both must survive so we keep the
                    // rule and only flag the conflict for review.
                    let kept = &merged_rules[idx];
                    let kept_id = kept
                        .get("id")
                        .and_then(|i| i.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let equivalent = detection_equivalent(kept, rule);
                    report.exact_regex_dups.push(DupRecord {
                        kind: DupKind::ExactRegex,
                        kept_source: seen_ids.get(&kept_id).cloned().unwrap_or_default(),
                        kept_id,
                        dropped_id: id.clone(),
                        dropped_source: name.clone(),
                        dropped: equivalent,
                        regex: regex.clone(),
                    });
                    if equivalent {
                        continue;
                    }
                    // Conflicting same-regex rule: keep it; its regex/norm are
                    // already registered, so fall through without re-registering.
                } else {
                    let norm = normalize_regex(rx);
                    if let Some(kept_id) = seen_norm.get(&norm) {
                        // Near-duplicate: KEEP the rule, record for review only.
                        report.near_dups.push(DupRecord {
                            kind: DupKind::NormalizedRegex,
                            kept_id: kept_id.clone(),
                            kept_source: seen_ids.get(kept_id).cloned().unwrap_or_default(),
                            dropped_id: id.clone(),
                            dropped_source: name.clone(),
                            dropped: false,
                            regex: regex.clone(),
                        });
                    }
                    // Map this regex to the index it is about to occupy.
                    seen_exact.insert(rx.clone(), merged_rules.len());
                    seen_norm.entry(norm).or_insert_with(|| id.clone());
                }
            }

            seen_ids.insert(id, name.clone());
            merged_rules.push(rule.clone());
        }
    }

    report.output_rules = merged_rules.len();
    result.insert("rules".to_string(), toml::Value::Array(merged_rules));

    // Allowlists: fold in ASCENDING priority order to preserve the legacy
    // semantics (lowest source's singular `[allowlist]` is kept untouched; every
    // other source's allowlists are appended as `[[allowlists]]` entries, with an
    // id collision replacing the matching base entry).
    let mut allowlist_acc = toml::Table::new();
    for (_, _, table) in parsed.iter().rev() {
        if allowlist_acc.is_empty() {
            // Seed from the lowest-priority source so its `[allowlist]` is preserved.
            if let Some(al) = table.get("allowlist") {
                allowlist_acc.insert("allowlist".to_string(), al.clone());
            }
            if let Some(als) = table.get("allowlists") {
                allowlist_acc.insert("allowlists".to_string(), als.clone());
            }
        } else {
            merge_global_allowlists(&mut allowlist_acc, table);
        }
    }
    if let Some(al) = allowlist_acc.remove("allowlist") {
        result.insert("allowlist".to_string(), al);
    }
    if let Some(als) = allowlist_acc.remove("allowlists") {
        result.insert("allowlists".to_string(), als);
    }

    Ok((toml::to_string(&toml::Value::Table(result))?, report))
}

/// Merge two TOML rule strings. Rules in `override_toml` take precedence.
///
/// Thin wrapper over [`merge_sources`] with two sources so existing callers
/// (`build.rs`, the runtime updater) keep working unchanged.
///
/// # Errors
///
/// Returns an error if either input is not valid TOML.
pub fn merge_toml_rules(
    base_toml: &str,
    override_toml: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let (merged, _report) = merge_sources(vec![
        MergeSource {
            name: "override".to_string(),
            priority: 100,
            toml: override_toml.to_string(),
        },
        MergeSource {
            name: "base".to_string(),
            priority: 10,
            toml: base_toml.to_string(),
        },
    ])?;
    Ok(merged)
}

/// Merge the override's global allowlists into the base.
///
/// The engine treats the singular `[allowlist]` and each `[[allowlists]]` entry
/// as independent global allowlists. To preserve each one's own `condition` /
/// `regexTarget` (rather than fusing them under a single condition), every
/// override allowlist — whether declared as `[allowlist]` or `[[allowlists]]` —
/// is added to the base's `[[allowlists]]` array as a separate entry. An override
/// allowlist with an `id` replaces any base `[[allowlists]]` entry sharing that
/// `id`; the base's singular `[allowlist]` is left untouched.
fn merge_global_allowlists(base_table: &mut toml::Table, override_table: &toml::Table) {
    let mut override_als: Vec<toml::Value> = Vec::new();
    if let Some(al) = override_table.get("allowlist") {
        override_als.push(al.clone());
    }
    if let Some(arr) = override_table.get("allowlists").and_then(|v| v.as_array()) {
        override_als.extend(arr.iter().cloned());
    }
    if override_als.is_empty() {
        return;
    }

    // IDs declared by override allowlists replace base entries with the same id.
    let override_ids: HashSet<String> = override_als
        .iter()
        .filter_map(|al| al.get("id").and_then(|i| i.as_str()).map(|s| s.to_string()))
        .collect();

    // Start from base `[[allowlists]]`, dropping any whose id is overridden.
    let mut merged: Vec<toml::Value> = base_table
        .get("allowlists")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter(|al| {
                    al.get("id")
                        .and_then(|i| i.as_str())
                        .map(|id| !override_ids.contains(id))
                        .unwrap_or(true)
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    merged.extend(override_als);
    base_table.insert("allowlists".to_string(), toml::Value::Array(merged));
}

// Explicit `#[path]` so module resolution is unambiguous even when this file is
// pulled into build.rs via its own `#[path]` include (rustfmt otherwise looks in
// the wrong directory).
#[cfg(test)]
#[path = "merge/tests.rs"]
mod tests;
