//! File filtering and secret redaction utilities.
//!
//! Provides path-based filtering to skip binary files and noisy directories,
//! plus a redaction function for safe secret display.

/// Binary file extensions that should never be scanned.
const SKIP_EXTENSIONS: &[&str] = &[
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp", ".tiff", ".woff", ".woff2", ".ttf",
    ".eot", ".otf", ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".zst", ".exe", ".dll",
    ".so", ".dylib", ".bin", ".o", ".a", ".pyc", ".pyo", ".class", ".jar", ".war", ".mp3", ".mp4",
    ".avi", ".mov", ".mkv", ".flv", ".sqlite", ".db",
];

/// Directories that produce noisy or irrelevant scan results.
const SKIP_DIRECTORIES: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "dist",
    "vendor",
    ".cache",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    "build",
];

/// Number of leading bytes inspected by the binary-content heuristic.
pub const BINARY_SNIFF_LEN: usize = 8192;

/// Returns `true` if `prefix` looks like binary (non-text) content.
///
/// Heuristic, independent of file extension so it catches extensionless or
/// mislabelled binaries in hostile repositories:
/// * any NUL byte ⇒ binary;
/// * otherwise binary if more than 30% of the inspected bytes are control bytes
///   (outside `\t \n \r` and the printable range).
///
/// An empty prefix is treated as text (never binary).
///
/// # Examples
///
/// ```
/// use secrets_scanner::filters::is_probably_binary;
///
/// assert!(is_probably_binary(b"\x00\x01\x02"));
/// assert!(!is_probably_binary(b"export TOKEN=abc"));
/// assert!(!is_probably_binary(b""));
/// ```
pub fn is_probably_binary(prefix: &[u8]) -> bool {
    if prefix.is_empty() {
        return false;
    }
    if prefix.contains(&0) {
        return true;
    }
    let suspicious = prefix
        .iter()
        .filter(|&&b| b < 0x09 || (b > 0x0D && b < 0x20))
        .count();
    suspicious * 100 / prefix.len() > 30
}

/// Returns `true` if `path` is a source-like or secret-bearing file that should
/// be content-scanned even when the binary heuristic flags it (`BinaryPolicy::Auto`).
///
/// Covers common config/secret files (`.env*`, `.pem`, `.key`, `.json`,
/// `.yaml`/`.yml`, `.toml`, `.properties`, `.npmrc`, `.pypirc`) and the
/// `Dockerfile`/`Makefile` family by name.
///
/// # Examples
///
/// ```
/// use secrets_scanner::filters::is_source_allowlisted;
///
/// assert!(is_source_allowlisted("config/.env.production"));
/// assert!(is_source_allowlisted("deploy/private.pem"));
/// assert!(is_source_allowlisted("Dockerfile"));
/// assert!(!is_source_allowlisted("logo.png"));
/// ```
pub fn is_source_allowlisted(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_lowercase();
    let filename = normalized.rsplit('/').next().unwrap_or(normalized.as_str());

    const ALLOWLIST_EXTENSIONS: &[&str] = &[
        ".pem",
        ".key",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".properties",
    ];
    if ALLOWLIST_EXTENSIONS.iter().any(|e| filename.ends_with(e)) {
        return true;
    }

    filename.starts_with(".env")
        || filename == ".npmrc"
        || filename == ".pypirc"
        || filename == "dockerfile"
        || filename.starts_with("dockerfile.")
        || filename == "makefile"
}

/// Returns `true` if the file at `path` should be scanned.
///
/// Skips binary extensions and noisy directories.
///
/// # Examples
///
/// ```
/// use secrets_scanner::filters::should_scan;
///
/// assert!(should_scan("src/config.rs"));
/// assert!(should_scan(".env.production"));
/// assert!(!should_scan("image.png"));
/// assert!(!should_scan("node_modules/lodash/index.js"));
/// ```
pub fn should_scan(path: &str) -> bool {
    should_scan_with_extension_filter(path, true)
}

pub(crate) fn should_scan_with_extension_filter(path: &str, skip_extensions: bool) -> bool {
    let normalized = path.replace('\\', "/").to_lowercase();
    if skip_extensions && SKIP_EXTENSIONS.iter().any(|e| normalized.ends_with(e)) {
        return false;
    }
    if normalized
        .split('/')
        .rev()
        .skip(1)
        .any(|component| SKIP_DIRECTORIES.contains(&component))
    {
        return false;
    }
    true
}

/// Redact the middle of a matched secret, preserving the first and last 4 characters.
///
/// For secrets ≤ 12 characters, the entire string is replaced with asterisks.
///
/// # Examples
///
/// ```
/// use secrets_scanner::filters::redact;
///
/// let r = redact("AKIAIOSFODNN7EXAMPLE123");
/// assert!(r.starts_with("AKIA"));
/// assert!(r.ends_with("E123"));
/// assert!(r.contains("***"));
///
/// let short = redact("short");
/// assert_eq!(short, "*****");
/// ```
pub fn redact(s: &str) -> String {
    let char_count = s.chars().count();
    if char_count <= 12 {
        return "*".repeat(char_count);
    }
    let keep = 4;
    let prefix: String = s.chars().take(keep).collect();
    let suffix: String = s
        .chars()
        .rev()
        .take(keep)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{}{}{}", prefix, "*".repeat(char_count - keep * 2), suffix,)
}

/// Fully redact a matched secret to a fixed marker that reveals nothing, not
/// even its length. Used by [`crate::scanner::types::RedactionMode::Full`].
///
/// # Examples
///
/// ```
/// use secrets_scanner::filters::redact_full;
///
/// assert_eq!(redact_full("AKIAIOSFODNN7EXAMPLE123"), "[REDACTED]");
/// assert_eq!(redact_full("short"), "[REDACTED]");
/// ```
pub fn redact_full(_s: &str) -> String {
    "[REDACTED]".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_binary_extensions() {
        assert!(!should_scan("image.png"));
        assert!(!should_scan("IMAGE.PNG"));
        assert!(!should_scan("archive.tar.gz"));
        assert!(!should_scan("data.sqlite"));
    }

    #[test]
    fn skips_noisy_directories() {
        assert!(!should_scan("node_modules/lodash/index.js"));
        assert!(!should_scan(r"node_modules\lodash\index.js"));
        assert!(!should_scan("project/.git/config"));
        assert!(!should_scan("project/target/debug/binary"));
        assert!(should_scan("src/mytarget/file.rs"));
    }

    #[test]
    fn allows_source_files() {
        assert!(should_scan("src/config.rs"));
        assert!(should_scan(".env.production"));
        assert!(should_scan("docker-compose.yml"));
        assert!(should_scan("Makefile"));
    }

    #[test]
    fn allows_files_named_like_noisy_directories() {
        for name in ["build", "dist", "vendor", "venv", "target"] {
            assert!(should_scan(name), "root file named {name} should scan");
            assert!(
                should_scan(&format!("scripts/{name}")),
                "leaf file named {name} should scan"
            );
            assert!(
                !should_scan(&format!("{name}/secret.txt")),
                "directory named {name} should stay skipped"
            );
        }
    }

    #[test]
    fn redacts_long_secrets() {
        let r = redact("AKIAIOSFODNN7EXAMPLE123");
        assert!(r.starts_with("AKIA"));
        assert!(r.ends_with("E123"));
        assert!(r.contains("***"));
        assert_eq!(r.len(), "AKIAIOSFODNN7EXAMPLE123".len());
    }

    #[test]
    fn redacts_short_secrets_fully() {
        assert_eq!(redact("short"), "*****");
        // Boundary: `char_count <= 12` is fully starred. 12 chars hits the edge;
        // 13 chars crosses into prefix/suffix partial redaction.
        assert_eq!(redact("twelvechars!").chars().count(), 12);
        assert_eq!(redact("twelvechars!"), "************");
        assert_eq!(redact("thirteenchars"), "thir*****hars");
    }

    #[test]
    fn redact_full_returns_length_hiding_marker() {
        // Full mode must reveal nothing, including length: same marker regardless
        // of input.
        assert_eq!(redact_full("AKIAIOSFODNN7EXAMPLE123"), "[REDACTED]");
        assert_eq!(redact_full("short"), "[REDACTED]");
        assert_eq!(redact_full(""), "[REDACTED]");
    }

    #[test]
    fn redacts_unicode_without_byte_boundary_panic() {
        let redacted = redact("秘密秘密秘密秘密秘密秘密秘密");
        assert!(redacted.starts_with("秘密秘密"));
        assert!(redacted.ends_with("秘密秘密"));
        assert!(redacted.contains('*'));
    }
}
