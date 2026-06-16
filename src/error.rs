//! Typed errors for fallible library entry points.
//!
//! Replaces `Box<dyn std::error::Error>` on the scanner/engine constructors so a
//! library caller can distinguish, for example, an unreadable rules file (`Io`)
//! from malformed rule TOML (`Toml`) from an automaton build failure
//! (`AhoCorasick`) without string-matching the message.

/// Errors that can occur while loading rules and constructing a scanner.
#[derive(Debug, thiserror::Error)]
pub enum ScannerError {
    /// An I/O error (e.g. the rules file could not be read).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The rules TOML parsed structurally but failed strict scanner validation.
    #[error("invalid rules:\n- {}", .0.join("\n- "))]
    InvalidRules(Vec<String>),

    /// The rules TOML could not be parsed into the expected structure.
    #[error("invalid rules TOML: {0}")]
    Toml(#[from] toml::de::Error),

    /// The Aho-Corasick keyword automaton could not be built.
    #[error("failed to build keyword automaton: {0}")]
    AhoCorasick(#[from] aho_corasick::BuildError),
}

/// Reasons a path scan did not cover every requested file or commit.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CoverageError {
    /// Git path discovery failed and no walk fallback was used.
    #[error("git mode failed; coverage is incomplete")]
    GitFailed,

    /// A history scan stopped because its wall-clock budget expired.
    #[error("git history scan timed out; commits were left unscanned")]
    HistoryTimedOut,

    /// One or more files could not be read.
    #[error("{count} file(s) could not be read")]
    UnreadableFiles {
        /// Number of unreadable files.
        count: usize,
    },

    /// One or more files were skipped by binary or size policy.
    #[error("{count} file(s) skipped by policy")]
    PolicySkipped {
        /// Total policy-skipped file count.
        count: usize,
        /// Files skipped because they looked binary.
        binary: usize,
        /// Files skipped because they exceeded the size cap.
        oversized: usize,
    },

    /// The file cap dropped one or more files before scanning.
    #[error("{count} file(s) were dropped by --max-files")]
    FileCapReached {
        /// Number of files dropped by the cap.
        count: usize,
    },
}

/// Errors from the hardened proxy entry point ([`Scanner::scan_proxy`]).
///
/// Distinct from [`ScannerError`] (a setup/rule-loading failure): these are
/// per-request rejections of untrusted input. The proxy fails closed, so a
/// caller must treat an `Err` as "do not forward this content".
///
/// [`Scanner::scan_proxy`]: crate::Scanner::scan_proxy
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// Input exceeded the configured `max_file_size`. The content was neither
    /// scanned nor redacted, so it must not be forwarded.
    #[error("input too large: {size} bytes exceeds max {max}")]
    InputTooLarge {
        /// Size of the rejected input in bytes.
        size: usize,
        /// The configured maximum (`ScanConfig::max_file_size`) in bytes.
        max: u64,
    },

    /// The scanner's config is not hardened for untrusted input, so the proxy
    /// path refuses to run rather than scan attacker-controlled content with a
    /// soft posture (honoring inline allow markers, capturing whole-payload
    /// context, or leaving findings/`matched` uncapped). Build the scanner with
    /// [`ScanConfig::proxy`](crate::ScanConfig::proxy) (caps may be raised via
    /// [`Scanner::with_config`](crate::Scanner::with_config)).
    #[error(
        "scanner is not hardened for proxy use: configure it with ScanConfig::proxy() \
         (require redact=true, honor_allow_markers=false, capture_context=false, \
         and max_findings_per_file/max_matched_len set)"
    )]
    NotHardened,
}
