//! Integration test validating all custom rules in assets/local.toml
//! against their generated mock secret fixtures.

use secrets_scanner::{ScanConfig, Scanner};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;

#[derive(Deserialize)]
struct RuleFixture {
    secret: String,
    test_content: String,
}

#[test]
fn validate_all_local_rules() {
    // 1. Initialize the scanner from the bundled ruleset.
    // The bundled ruleset includes the merged assets/local.toml rules.
    let scanner = Scanner::from_bundled().expect("bundled rules should load successfully");

    // Disable redaction so we can assert the matched value exactly,
    // and disable entropy check to allow short generated tokens to pass.
    let config = ScanConfig {
        redact: false,
        min_entropy_override: Some(0.0),
        ..Default::default()
    };
    let scanner = scanner.with_config(config);

    // 2. Load the generated fixtures from JSON.
    let fixtures_data = fs::read_to_string("tests/local_rules_fixtures.json").expect(
        "Failed to read tests/local_rules_fixtures.json. Run 'make generate-fixtures' first.",
    );
    let fixtures: HashMap<String, RuleFixture> =
        serde_json::from_str(&fixtures_data).expect("Failed to parse local rules fixtures JSON");

    assert!(!fixtures.is_empty(), "No fixtures loaded!");

    // 3. Find the set of loaded rule IDs from the scanner engine.
    let loaded_rule_ids: HashSet<String> = scanner
        .engine()
        .rules()
        .iter()
        .map(|r| r.id.clone())
        .collect();

    // 4. For each loaded rule that has a fixture, verify detection.
    let mut failures = Vec::new();
    let mut tested_count = 0;

    for (rule_id, fixture) in &fixtures {
        // Only test rules that are actually active/loaded in the engine.
        if !loaded_rule_ids.contains(rule_id) {
            continue;
        }
        tested_count += 1;

        // Wrap the test_content in padding to ensure look-behinds/look-aheads are satisfied.
        let content = format!("   {}   ", fixture.test_content);
        let filename = format!("test_{}.txt", rule_id);

        let findings = scanner.scan_content(&filename, &content);

        // Check if our specific rule fired.
        let found = findings.iter().any(|f| f.rule_id == *rule_id);
        if !found {
            failures.push((rule_id.clone(), fixture.secret.clone(), findings));
        }
    }

    // 5. Report failures.
    if !failures.is_empty() {
        eprintln!(
            "\n=== Custom Rule Match Validation Failed for {} rules ===",
            failures.len()
        );
        for (rule_id, secret, findings) in &failures {
            eprintln!("Rule '{}' did not fire on secret: '{}'", rule_id, secret);
            if findings.is_empty() {
                eprintln!("  -> No findings were detected at all.");
            } else {
                eprintln!("  -> Other findings were detected instead:");
                for f in findings {
                    eprintln!("     - Rule '{}' matched: '{}'", f.rule_id, f.matched);
                }
            }
        }
        panic!("Some custom rules failed validation. See output above.");
    }

    println!(
        "Successfully validated all {} active custom rules (out of {} total custom rules defined).",
        tested_count,
        fixtures.len()
    );
}
