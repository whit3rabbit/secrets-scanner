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
    "node_modules/",
    ".git/",
    "target/",
    "dist/",
    "vendor/",
    ".cache/",
    "__pycache__/",
    ".venv/",
    "venv/",
    ".tox/",
    "build/",
];

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
    if SKIP_EXTENSIONS.iter().any(|e| path.ends_with(e)) {
        return false;
    }
    if SKIP_DIRECTORIES.iter().any(|d| path.contains(d)) {
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
    if s.len() <= 12 {
        return "*".repeat(s.len());
    }
    let keep = 4;
    format!(
        "{}{}{}",
        &s[..keep],
        "*".repeat(s.len() - keep * 2),
        &s[s.len() - keep..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_binary_extensions() {
        assert!(!should_scan("image.png"));
        assert!(!should_scan("archive.tar.gz"));
        assert!(!should_scan("data.sqlite"));
    }

    #[test]
    fn skips_noisy_directories() {
        assert!(!should_scan("node_modules/lodash/index.js"));
        assert!(!should_scan("project/.git/config"));
        assert!(!should_scan("project/target/debug/binary"));
    }

    #[test]
    fn allows_source_files() {
        assert!(should_scan("src/config.rs"));
        assert!(should_scan(".env.production"));
        assert!(should_scan("docker-compose.yml"));
        assert!(should_scan("Makefile"));
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
        assert_eq!(redact("exactly12ch"), "***********");
    }
}
