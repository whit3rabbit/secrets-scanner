fn action_yml() -> String {
    // Normalize CRLF so the `\n`-containing substring assertions below hold
    // regardless of how git checked the file out (Windows autocrlf -> CRLF).
    std::fs::read_to_string(format!("{}/action.yml", env!("CARGO_MANIFEST_DIR")))
        .expect("action.yml should be readable")
        .replace("\r\n", "\n")
}

#[test]
fn action_metadata_uses_marketplace_safe_name_and_inputs() {
    let action = action_yml();

    assert!(action.contains("name: \"RSecrets Scanner\""));
    for input in [
        "git-history:",
        "history-timeout:",
        "rules-source:",
        "build-from-source:",
    ] {
        assert!(action.contains(input), "missing action input {input}");
    }
}

#[test]
fn action_build_from_source_uses_action_checkout_not_caller_repo() {
    let action = action_yml();

    assert!(action.contains("--manifest-path \"$GITHUB_ACTION_PATH/Cargo.toml\""));
    assert!(action.contains("binary=\"$GITHUB_ACTION_PATH/target/release/secrets-scanner\""));
}

#[test]
fn action_scan_modes_are_mutually_exclusive() {
    let action = action_yml();

    let history = action
        .find("if [ \"$IN_GIT_HISTORY\" = \"true\" ]; then")
        .expect("history branch should be first");
    let base = action
        .find("elif [ -n \"$IN_BASE\" ]; then")
        .expect("base branch should be second");
    let tracked = action
        .find("elif [ \"$IN_GIT_TRACKED\" = \"true\" ]; then")
        .expect("git-tracked branch should be last");

    assert!(history < base && base < tracked);
    assert!(!action.contains("[ \"$IN_GIT_TRACKED\" = \"true\" ] && args+=(--git-tracked)\n        [ -n \"$IN_BASE\" ] && args+=(--base \"$IN_BASE\")"));
}

#[test]
fn action_uses_bundled_rules_source_unless_config_is_set() {
    let action = action_yml();

    let config = action
        .find("if [ -n \"$IN_CONFIG\" ]; then")
        .expect("config branch should exist");
    let rules = action
        .find("else\n          args+=(--rules-source \"$IN_RULES_SOURCE\")")
        .expect("rules-source fallback should exist");

    assert!(config < rules);
}
