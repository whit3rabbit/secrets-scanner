use log::{error, info};
use secrets_scanner::Scanner;

/// Handle the `update-rules` subcommand.
pub(super) fn handle_update(check_only: bool, url: Option<String>) {
    match secrets_scanner::rules::updater::update_rules(check_only, url.as_deref()) {
        Ok(secrets_scanner::rules::updater::UpdateResult::AlreadyCurrent { sha256 }) => {
            println!("✅ Rules already up to date (SHA-256: {sha256})");
        }
        Ok(secrets_scanner::rules::updater::UpdateResult::Updated { sha256 }) => {
            println!("✅ Rules updated (SHA-256: {sha256})");
        }
        Ok(secrets_scanner::rules::updater::UpdateResult::UpdateAvailable {
            local_sha,
            remote_sha,
        }) => {
            println!("⚠️  Update available!");
            println!("   Local:  {local_sha}");
            println!("   Remote: {remote_sha}");
            println!("   Run without --check to apply.");
            std::process::exit(1);
        }
        Ok(secrets_scanner::rules::updater::UpdateResult::CheckedCurrent { sha256 }) => {
            println!("✅ Rules are current (SHA-256: {sha256})");
        }
        Err(e) => {
            error!("Update failed: {e}");
            std::process::exit(2);
        }
    }
}

/// Handle the `validate-rules` subcommand.
///
/// Exit codes: 0 = all files valid; 1 = at least one file parsed but is
/// invalid (the command's own result, like a linter); 2 = at least one file
/// could not be read (an I/O/runtime error, matching `scan`/`list-rules`).
/// A read error takes precedence over invalid content, because an unreadable
/// file means validation could not run at all. Exit 3 stays reserved for
/// `scan`'s runtime rule-load failures that prevent scanning.
pub(super) fn handle_validate(files: &[String]) {
    let mut had_invalid = false;
    let mut had_read_error = false;
    for file in files {
        match std::fs::read_to_string(file) {
            Ok(content) => {
                match secrets_scanner::rules::validation::validate_rules_toml(&content) {
                    Ok(()) => {
                        println!("✅ {file} is valid");
                    }
                    Err(errors) => {
                        had_invalid = true;
                        error!("{file} validation failed:");
                        for err in errors {
                            error!("  - {err}");
                        }
                    }
                }
            }
            Err(e) => {
                had_read_error = true;
                error!("Failed to read {file}: {e}");
            }
        }
    }
    if had_read_error {
        std::process::exit(2);
    }
    if had_invalid {
        std::process::exit(1);
    }
}

/// Handle the `merge-rules` subcommand: read the manifest, merge the selected
/// sources via the shared core, validate, and write or check the combined ruleset.
///
/// This uses the SAME `merge_sources` core as `build.rs`, so a lean `merge-rules`
/// run and a default `cargo build` produce byte-identical output (the basis of
/// the CI drift check). Exit codes: `0` = success, `1` = stale in check mode,
/// `2` = error.
pub(super) fn handle_merge_rules(
    manifest_path: &str,
    all: bool,
    out: &str,
    report_path: Option<&str>,
    check: bool,
) {
    use secrets_scanner::rules::{manifest, merge, validation};

    let manifest_src = match std::fs::read_to_string(manifest_path) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to read manifest {manifest_path}: {e}");
            std::process::exit(2);
        }
    };
    let parsed = match manifest::parse_manifest(&manifest_src) {
        Ok(m) => m,
        Err(e) => {
            error!("Failed to parse manifest {manifest_path}: {e}");
            std::process::exit(2);
        }
    };

    let selected = manifest::select_sources(
        &parsed,
        &manifest::SelectOptions {
            include_embed_false: all,
        },
    );

    let mut inputs = Vec::new();
    for src in &selected {
        // Sources without a TOML converter (e.g. kingfisher YAML) are skipped.
        if !src.file.ends_with(".toml") {
            info!(
                "[merge] skipping non-TOML source '{}' ({})",
                src.name, src.file
            );
            continue;
        }
        let content = match std::fs::read_to_string(&src.file) {
            Ok(c) => c,
            Err(e) if src.embed => {
                error!(
                    "Embedded source '{}' unreadable ({}): {e}",
                    src.name, src.file
                );
                std::process::exit(2);
            }
            Err(e) => {
                info!(
                    "[merge] optional source '{}' unreadable ({}): {e}",
                    src.name, src.file
                );
                continue;
            }
        };
        if let Err(errors) = validation::validate_rules_toml(&content) {
            error!("Source '{}' is invalid:", src.name);
            for err in errors {
                error!("  - {err}");
            }
            std::process::exit(2);
        }
        inputs.push(merge::MergeSource {
            name: src.name.clone(),
            priority: src.priority,
            toml: content,
        });
    }

    let (combined, report) = match merge::merge_sources(inputs) {
        Ok(pair) => pair,
        Err(e) => {
            error!("Merge failed: {e}");
            std::process::exit(2);
        }
    };
    if let Err(errors) = validation::validate_rules_toml(&combined) {
        error!("Merged ruleset is invalid:");
        for err in errors {
            error!("  - {err}");
        }
        std::process::exit(2);
    }

    let dropped_exact = report.exact_regex_dups.iter().filter(|d| d.dropped).count();
    let conflict_exact = report.exact_regex_dups.len() - dropped_exact;
    println!(
        "Merged {} source(s): {} input rules -> {} output rules",
        report.sources.len(),
        report.total_input_rules,
        report.output_rules
    );
    println!(
        "  dropped: {} id collision(s), {} exact-regex duplicate(s)",
        report.id_collisions.len(),
        dropped_exact
    );
    println!(
        "  flagged for review: {} same-regex conflict(s), {} normalized near-dup(s)",
        conflict_exact,
        report.near_dups.len()
    );

    if let Some(path) = report_path {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => {
                if let Some(parent) = std::path::Path::new(path).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Err(e) = std::fs::write(path, json) {
                    error!("Failed to write report {path}: {e}");
                    std::process::exit(2);
                }
                println!("Wrote merge report to {path}");
            }
            Err(e) => {
                error!("Failed to serialize report: {e}");
                std::process::exit(2);
            }
        }
    }

    if check {
        match check_ruleset_current(std::path::Path::new(out), &combined) {
            Ok(RulesetCheckStatus::Current) => {
                println!("Check mode: {out} is current");
                return;
            }
            Ok(RulesetCheckStatus::Stale) => {
                error!("{out} is stale - run \"make merge-rules\" and commit.");
                std::process::exit(1);
            }
            Err(e) => {
                error!("Failed to read {out}: {e}");
                std::process::exit(2);
            }
        }
    }
    if let Err(e) = std::fs::write(out, &combined) {
        error!("Failed to write {out}: {e}");
        std::process::exit(2);
    }
    println!("Wrote merged ruleset to {out}");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RulesetCheckStatus {
    Current,
    Stale,
}

fn check_ruleset_current(
    path: &std::path::Path,
    expected: &str,
) -> Result<RulesetCheckStatus, std::io::Error> {
    match std::fs::read(path) {
        Ok(existing) if existing == expected.as_bytes() => Ok(RulesetCheckStatus::Current),
        Ok(_) => Ok(RulesetCheckStatus::Stale),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RulesetCheckStatus::Stale),
        Err(e) => Err(e),
    }
}

/// Handle the `list-rules` subcommand.
pub(super) fn handle_list_rules(rules_path: Option<&str>) {
    let scanner = if let Some(path) = rules_path {
        match Scanner::from_file(path) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to load rules from {path}: {e}");
                std::process::exit(2);
            }
        }
    } else {
        match Scanner::new() {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to load rules: {e}");
                std::process::exit(2);
            }
        }
    };

    let rules = scanner.engine().rules();
    println!("{:<40} {:<8} DESCRIPTION", "RULE ID", "KEYWORDS");
    println!("{}", "-".repeat(90));
    for rule in &rules {
        println!(
            "{:<40} {:<8} {}",
            &rule.id,
            rule.keywords.len(),
            if rule.description.is_empty() {
                "(no description)"
            } else {
                &rule.description
            }
        );
    }
    println!("\n{} rule(s) loaded.", rules.len());
}

#[cfg(test)]
mod tests {
    #[test]
    fn ruleset_check_reports_current_for_matching_file() {
        let tmp = tempfile::NamedTempFile::new().expect("tmpfile");
        std::fs::write(tmp.path(), "merged rules").expect("write ruleset");

        let status = super::check_ruleset_current(tmp.path(), "merged rules").expect("check");

        assert_eq!(status, super::RulesetCheckStatus::Current);
    }

    #[test]
    fn ruleset_check_reports_stale_for_different_file() {
        let tmp = tempfile::NamedTempFile::new().expect("tmpfile");
        std::fs::write(tmp.path(), "old rules").expect("write ruleset");

        let status = super::check_ruleset_current(tmp.path(), "merged rules").expect("check");

        assert_eq!(status, super::RulesetCheckStatus::Stale);
    }

    #[test]
    fn ruleset_check_reports_stale_for_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("missing.toml");

        let status = super::check_ruleset_current(&missing, "merged rules").expect("check");

        assert_eq!(status, super::RulesetCheckStatus::Stale);
    }
}
