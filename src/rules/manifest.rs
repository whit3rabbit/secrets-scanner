//! rules/manifest.rs — the rule-source manifest (`assets/sources.toml`).
//!
//! Declares every ruleset source, its merge priority, and whether it is embedded
//! into the default (lean) binary. This module is intentionally crate-independent
//! (only `serde`/`toml`/`std`) so `build.rs` can `#[path]`-include it the same way
//! it includes `merge.rs` and `validation.rs`. It MUST NOT reference `crate::`,
//! `super::`, `merge::`, or `validation::` — the file-reading and merge glue lives
//! at each call site (`build.rs` and the `merge-rules` CLI handler).

use serde::Deserialize;

/// A single rule source declared in the manifest.
#[derive(Debug, Clone, Deserialize)]
pub struct SourceEntry {
    /// Short source name, used in the merge report (e.g. "gitleaks", "local").
    pub name: String,
    /// Path to the source's TOML file, relative to the repo root.
    pub file: String,
    /// Merge priority. Higher wins id/regex collisions.
    pub priority: i64,
    /// Whether this source is embedded into the default (lean) binary.
    pub embed: bool,
    /// Optional upstream URL the source is refreshed from (informational).
    /// Unused by `build.rs`; allowed to be dead in that compilation context.
    #[serde(default)]
    #[allow(dead_code)]
    pub update_url: Option<String>,
}

/// The parsed `sources.toml` manifest.
#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    /// Manifest schema version (for forward compatibility).
    /// Unused by `build.rs`; allowed to be dead in that compilation context.
    #[serde(default)]
    #[allow(dead_code)]
    pub schema_version: u32,
    /// The declared sources (TOML `[[source]]` tables).
    #[serde(rename = "source", default)]
    pub sources: Vec<SourceEntry>,
}

/// Options controlling which sources are selected for a merge.
pub struct SelectOptions {
    /// When `true`, include sources with `embed = false` (opt-in rulesets).
    pub include_embed_false: bool,
}

/// Parse a manifest from a TOML string.
///
/// # Errors
///
/// Returns an error if the string is not valid manifest TOML.
pub fn parse_manifest(toml_str: &str) -> Result<Manifest, Box<dyn std::error::Error>> {
    Ok(toml::from_str(toml_str)?)
}

/// Select and order the sources to merge.
///
/// Filters by the `embed` flag (unless `include_embed_false` is set), then sorts
/// by priority descending (name as a stable tie-break) so the result matches the
/// merge order used by [`crate::rules::merge::merge_sources`].
pub fn select_sources(manifest: &Manifest, opts: &SelectOptions) -> Vec<SourceEntry> {
    let mut selected: Vec<SourceEntry> = manifest
        .sources
        .iter()
        .filter(|s| s.embed || opts.include_embed_false)
        .cloned()
        .collect();
    selected.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| a.name.cmp(&b.name))
    });
    selected
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
schema_version = 1

[[source]]
name = "gitleaks"
file = "assets/gitleaks.toml"
priority = 10
embed = true

[[source]]
name = "local"
file = "assets/local.toml"
priority = 100
embed = true

[[source]]
name = "spdb"
file = "assets/secrets-patterns-db.toml"
priority = 5
embed = false
"#;

    #[test]
    fn parses_all_sources() {
        let m = parse_manifest(SAMPLE).expect("parse");
        assert_eq!(m.schema_version, 1);
        assert_eq!(m.sources.len(), 3);
    }

    #[test]
    fn lean_selection_excludes_embed_false_and_sorts_by_priority() {
        let m = parse_manifest(SAMPLE).expect("parse");
        let sel = select_sources(
            &m,
            &SelectOptions {
                include_embed_false: false,
            },
        );
        let names: Vec<&str> = sel.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["local", "gitleaks"]); // spdb excluded, local first
    }

    #[test]
    fn full_selection_includes_embed_false() {
        let m = parse_manifest(SAMPLE).expect("parse");
        let sel = select_sources(
            &m,
            &SelectOptions {
                include_embed_false: true,
            },
        );
        let names: Vec<&str> = sel.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["local", "gitleaks", "spdb"]);
    }
}
