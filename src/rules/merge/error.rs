/// Errors that can occur while merging rule sources.
#[derive(Debug)]
pub enum MergeError {
    /// A source could not be parsed as TOML.
    SourceToml {
        /// Source name from the merge input.
        source: String,
        /// TOML parser error.
        source_error: toml::de::Error,
    },
    /// A source parsed but was not a top-level TOML table.
    SourceNotTable {
        /// Source name from the merge input.
        source: String,
    },
    /// The merged TOML could not be serialized.
    Serialize(toml::ser::Error),
}

impl std::fmt::Display for MergeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SourceToml {
                source,
                source_error,
            } => write!(f, "source '{source}' is invalid TOML: {source_error}"),
            Self::SourceNotTable { source } => {
                write!(f, "source '{source}' is not a TOML table")
            }
            Self::Serialize(error) => write!(f, "failed to serialize merged TOML: {error}"),
        }
    }
}

impl std::error::Error for MergeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SourceToml { source_error, .. } => Some(source_error),
            Self::Serialize(error) => Some(error),
            Self::SourceNotTable { .. } => None,
        }
    }
}
