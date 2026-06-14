//! secrets-scanner — A high-performance secrets detection library.
//!
//! This crate scans files and directories for leaked secrets (API keys, tokens,
//! private keys, etc.) using a multi-layered pipeline optimized for speed:
//!
//! 1. **memchr SIMD** — skips keyworded-rule lookup when no keyword first bytes appear
//! 2. **Aho-Corasick** — single O(n) pass finds all keyword hits
//! 3. **Entropy check** — rejects low-randomness strings
//! 4. **Regex** — validates structure for candidate rules
//!
//! Rules are loaded from a gitleaks-compatible TOML format (bundled at compile
//! time, with runtime update support).
//!
//! # Quick Start
//!
//! ```no_run
//! use secrets_scanner::{Scanner, ScanConfig, Finding};
//!
//! // Load rules using the three-tier priority system
//! let scanner = Scanner::new().expect("failed to load rules");
//!
//! // Scan a directory
//! let findings = scanner.scan_path("./src");
//! for f in &findings {
//!     println!("{}:{} [{}] {}", f.file, f.line, f.rule_id, f.matched);
//! }
//!
//! // Or scan in-memory content
//! let content = "export TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234567";
//! let findings = scanner.scan_content("deploy.sh", content);
//! ```

#![deny(clippy::unwrap_used)]
#![deny(missing_docs)]

/// Shannon entropy calculation utilities.
pub mod entropy;

/// File filtering and secret redaction utilities.
pub mod filters;

/// Rules loading, parsing, validation, and update modules.
pub mod rules;

/// High-performance parallel file scanner.
pub mod scanner;

pub use rules::engine::{CompiledRule, RuleEngine};
pub use rules::validation::{AllowlistConfig, GlobalAllowlist, RuleConfig, RulesetConfig};
pub use scanner::{BinaryPolicy, Finding, ScanConfig, ScanOutput, ScanStats, Scanner};
