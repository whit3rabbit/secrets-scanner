/// rules/mod.rs — Rule-set loading with compile-time default + runtime updates.
//
// Priority order (highest → lowest):
//  1. User-override file: $SECRETS_SCANNER_RULES env var (any path)
//  2. Cached updated file in the OS data dir (~/.local/share/secrets-scanner/ on Linux,
//     ~/Library/Application Support/secrets-scanner/ on macOS,
//     %APPDATA%\secrets-scanner\ on Windows)
//  3. Compiled-in default (assets/gitleaks.toml embedded at build time)

pub mod engine;
pub mod updater;

/// The combined ruleset (gitleaks + local.toml) compiled into the binary.
/// Rebuilt whenever `assets/secrets-scanner.toml` changes (see build.rs).
pub const BUNDLED_RULES: &str = include_str!("../../assets/secrets-scanner.toml");

/// The local custom ruleset compiled into the binary.
pub const BUNDLED_LOCAL_RULES: &str = include_str!("../../assets/local.toml");

/// Helper to merge two TOML rule strings. Rules in `override_toml` take precedence.
pub(crate) fn merge_toml_rules(base_toml: &str, override_toml: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut base_val: toml::Value = toml::from_str(base_toml)?;
    let override_val: toml::Value = toml::from_str(override_toml)?;

    if let (Some(base_table), Some(override_table)) = (base_val.as_table_mut(), override_val.as_table()) {
        for (k, v) in override_table {
            if k != "rules" {
                base_table.insert(k.clone(), v.clone());
            }
        }

        if let Some(override_rules) = override_table.get("rules").and_then(|r| r.as_array()) {
            if let Some(base_rules) = base_table.get_mut("rules").and_then(|r| r.as_array_mut()) {
                let mut merged_rules = Vec::new();
                let mut local_rule_ids = std::collections::HashSet::new();

                for rule in override_rules {
                    if let Some(id) = rule.get("id").and_then(|i| i.as_str()) {
                        local_rule_ids.insert(id.to_string());
                    }
                }

                for rule in base_rules.iter() {
                    if let Some(id) = rule.get("id").and_then(|i| i.as_str()) {
                        if !local_rule_ids.contains(id) {
                            merged_rules.push(rule.clone());
                        }
                    } else {
                        merged_rules.push(rule.clone());
                    }
                }

                for rule in override_rules {
                    merged_rules.push(rule.clone());
                }

                base_table.insert("rules".to_string(), toml::Value::Array(merged_rules));
            } else {
                base_table.insert("rules".to_string(), toml::Value::Array(override_rules.clone()));
            }
        }
    }

    Ok(toml::to_string(&base_val)?)
}

/// Helper to locate and load custom/local rules from disk, falling back to the bundled one.
pub(crate) fn load_local_rules_for_merge() -> String {
    if let Ok(content) = std::fs::read_to_string("local.toml") {
        return content;
    }
    if let Ok(content) = std::fs::read_to_string("assets/local.toml") {
        return content;
    }
    if let Some(dir) = updater::data_dir() {
        let path = dir.join("local.toml");
        if let Ok(content) = std::fs::read_to_string(&path) {
            return content;
        }
    }
    BUNDLED_LOCAL_RULES.to_string()
}

/// Return the active TOML rule content as a string, following the priority
/// order documented above.  This is intentionally synchronous so callers do
/// not need an async runtime just to load rules at startup.
pub fn load_rules() -> String {
    // 1. Explicit override via environment variable
    if let Ok(path) = std::env::var("SECRETS_SCANNER_RULES") {
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                eprintln!("[rules] Using override from SECRETS_SCANNER_RULES={path}");
                return content;
            }
            Err(e) => eprintln!("[rules] Warning: SECRETS_SCANNER_RULES={path} unreadable: {e}"),
        }
    }

    // 2. Cached file written by the updater
    if let Some(cache_path) = updater::cached_rules_path() {
        match std::fs::read_to_string(&cache_path) {
            Ok(content) => {
                eprintln!("[rules] Using cached combined rules from {}", cache_path.display());
                return content;
            }
            Err(_) => {} // fall through to bundled default
        }
    }

    // 3. Bundled default (pre-merged at build time)
    eprintln!("[rules] Using bundled default combined rules (run `secrets-scanner update-rules` to refresh)");
    BUNDLED_RULES.to_string()
}
