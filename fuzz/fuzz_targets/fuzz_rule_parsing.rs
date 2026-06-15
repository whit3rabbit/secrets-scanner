//! Fuzz target: feed arbitrary strings to the rule-parsing entry points.
//!
//! A scanner ingests attacker-influenced rule TOML (custom rules files, the
//! runtime updater) and arbitrary regex strings. This target exercises both the
//! validator and the engine builder, asserting that no input — malformed TOML,
//! pathological regex, huge patterns — causes a panic (errors are expected and
//! ignored).

#![no_main]

use libfuzzer_sys::fuzz_target;
use secrets_scanner::rules::validation::validate_rules_toml;
use secrets_scanner::Scanner;

fuzz_target!(|data: &str| {
    // Linter path: must never panic, only return Ok/Err.
    let _ = validate_rules_toml(data);
    // Engine build path: compiles regexes / builds the Aho-Corasick automaton.
    let _ = Scanner::from_toml(data);
});
