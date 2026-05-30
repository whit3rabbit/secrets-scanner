/// secrets-scanner — A high-performance secrets detection library.
///
/// This crate scans files and directories for leaked secrets (API keys, tokens,
/// private keys, etc.) using a multi-layered pipeline optimized for speed:
///
/// 1. **memchr SIMD** — rejects files with no relevant byte classes
/// 2. **Aho-Corasick** — single O(n) pass finds all keyword hits
/// 3. **Entropy check** — rejects low-randomness strings
/// 4. **Regex** — validates structure on a small window around hits
///
/// Rules are loaded from a gitleaks-compatible TOML format (bundled at compile
/// time, with runtime update support).
///
/// # Quick Start
///
/// ```no_run
/// use secrets_scanner::{Scanner, ScanConfig, Finding};
///
/// // Load rules using the three-tier priority system
/// let scanner = Scanner::new().expect("failed to load rules");
///
/// // Scan a directory
/// let findings = scanner.scan_path("./src");
/// for f in &findings {
///     println!("{}:{} [{}] {}", f.file, f.line, f.rule_id, f.matched);
/// }
///
/// // Or scan in-memory content
/// let content = "export TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234567";
/// let findings = scanner.scan_content("deploy.sh", content);
/// ```

pub mod entropy;
pub mod filters;
pub mod rules;
pub mod scanner;

pub use scanner::{Finding, ScanConfig, Scanner};
pub use rules::engine::{CompiledRule, RuleEngine, RulesetConfig};
