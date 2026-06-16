/// Errors that can occur while checking or updating runtime rules.
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    /// Rule update URLs must be HTTPS.
    #[error("rule update URL must use https://")]
    NonHttpsUrl,

    /// The HTTP request failed.
    #[cfg(feature = "updater")]
    #[error("failed to fetch rules from {url}: {source}")]
    Fetch {
        /// URL that failed.
        url: String,
        /// HTTP client error.
        #[source]
        source: Box<ureq::Error>,
    },

    /// The response body exceeded the configured byte cap.
    #[error("rules download too large: {actual} exceeds {max} bytes")]
    DownloadTooLarge {
        /// Observed byte count.
        actual: u64,
        /// Maximum allowed byte count.
        max: u64,
    },

    /// Reading the response body failed.
    #[error("failed to read rules download body: {0}")]
    ReadBody(#[source] std::io::Error),

    /// Downloaded rules were not valid UTF-8.
    #[error("downloaded rules are not valid UTF-8: {0}")]
    NonUtf8(#[from] std::string::FromUtf8Error),

    /// Downloaded upstream rules failed validation.
    #[error("downloaded upstream rules are invalid:\n- {}", .0.join("\n- "))]
    InvalidUpstreamRules(Vec<String>),

    /// Merged rules failed validation.
    #[error("merged ruleset is invalid:\n- {}", .0.join("\n- "))]
    InvalidMergedRules(Vec<String>),

    /// Local custom rules could not be loaded strictly.
    #[cfg(feature = "updater")]
    #[error(transparent)]
    LocalRules(#[from] super::super::LocalRulesError),

    /// The OS data directory could not be determined.
    #[error("cannot determine application data directory")]
    DataDirUnavailable,

    /// Writing the local rules cache failed.
    #[error("failed to write rules cache: {0}")]
    CacheWrite(#[source] std::io::Error),

    /// Rule merging failed.
    #[error("failed to merge rules: {0}")]
    Merge(#[from] super::super::merge::MergeError),

    /// The binary was built without updater support.
    #[error(
        "Built without the `updater` feature. Rebuild with `cargo build --features updater` \
         or run `./scripts/update_rules.sh` manually."
    )]
    Disabled,
}
