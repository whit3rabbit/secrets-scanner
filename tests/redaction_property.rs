//! Property test for the scanner's core promise: a detected secret never
//! appears verbatim in any redacted output.
//!
//! This exercises the library-level guarantee — the redacted `matched` field
//! and `scan_and_redact_content`. The CLI output writers (`text`/`json`) emit
//! only the already-redacted `matched`, and SARIF omits the matched value
//! entirely, so a safe `matched` is sufficient for the format layer.

use proptest::prelude::*;
use secrets_scanner::{ScanConfig, Scanner};

// A rule with no entropy gate so every generated token is detected.
const RULES: &str = r#"
title = "prop"
[[rules]]
id = "apikey"
description = "API key"
regex = 'apikey-[A-Za-z0-9]{20,40}'
keywords = ["apikey-"]
"#;

proptest! {
    #[test]
    fn redacted_output_never_contains_verbatim_secret(body in "[A-Za-z0-9]{20,40}") {
        let token = format!("apikey-{body}");
        let scanner = Scanner::from_toml(RULES)
            .expect("rules parse")
            .with_config(ScanConfig { redact: true, ..Default::default() });
        let content = format!("config:\n  key = {token}\n");

        let findings = scanner.scan_content("c.yaml", &content);
        prop_assert!(!findings.is_empty(), "token must be detected: {token}");
        for f in &findings {
            prop_assert!(
                !f.matched.contains(&token),
                "redacted `matched` leaked the verbatim secret: {}",
                f.matched
            );
        }

        let out = scanner.scan_and_redact_content("c.yaml", &content);
        prop_assert!(
            !out.redacted.contains(&token),
            "redacted content leaked the verbatim secret"
        );
    }
}
