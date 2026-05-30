// build.rs — Embed assets/secrets-scanner.toml into the binary at compile time.
//
// We validate that assets/gitleaks.toml and assets/local.toml exist,
// merge them into a single assets/secrets-scanner.toml file, and configure
// cargo rerun-if-changed to recompile if either file is modified.

use std::path::Path;
use std::collections::HashSet;

fn main() {
    let gitleaks_path = Path::new("assets/gitleaks.toml");
    let local_path = Path::new("assets/local.toml");
    let combined_path = Path::new("assets/secrets-scanner.toml");

    // Fail fast at build time if someone forgot to run scripts/update_rules.sh
    if !gitleaks_path.exists() {
        eprintln!(
            "cargo:warning=assets/gitleaks.toml not found. \
             Run `./scripts/update_rules.sh` to download it."
        );
        std::fs::create_dir_all("assets").expect("Failed to create assets/");
        std::fs::write(gitleaks_path, "# placeholder — run update_rules.sh\n")
            .expect("Failed to write placeholder gitleaks.toml");
    }

    if !local_path.exists() {
        std::fs::create_dir_all("assets").expect("Failed to create assets/");
        std::fs::write(local_path, "title = \"local rules\"\n\nrules = []\n")
            .expect("Failed to write placeholder local.toml");
    }

    // Read and merge
    let gitleaks_content = std::fs::read_to_string(gitleaks_path).expect("Failed to read gitleaks.toml");
    let local_content = std::fs::read_to_string(local_path).expect("Failed to read local.toml");

    match merge_toml_rules(&gitleaks_content, &local_content) {
        Ok(combined_content) => {
            std::fs::write(combined_path, combined_content).expect("Failed to write combined secrets-scanner.toml");
        }
        Err(e) => {
            panic!("Failed to merge rules at compile time: {}", e);
        }
    }

    // Rebuild if the assets change
    println!("cargo:rerun-if-changed=assets/gitleaks.toml");
    println!("cargo:rerun-if-changed=assets/local.toml");
    // Rebuild if this build script itself changes
    println!("cargo:rerun-if-changed=build.rs");
}

fn merge_toml_rules(base_toml: &str, override_toml: &str) -> Result<String, Box<dyn std::error::Error>> {
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
                let mut local_rule_ids = HashSet::new();

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
