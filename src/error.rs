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
