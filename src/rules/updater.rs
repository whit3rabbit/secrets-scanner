//! rules/updater.rs — Runtime update mechanism for gitleaks rules.
//
// Usage from your CLI:
//
//   secrets-scanner update-rules            # download latest, save to cache
//   secrets-scanner update-rules --check    # print version info, no write
//
// The updater uses only the standard library for HTTP on nightly feature gates;
// for stable Rust we vendor a small `ureq` (or `minreq`) call so there is no
// async runtime requirement.  This file uses `ureq` via the optional feature
// flag `"updater"` declared in Cargo.toml.

use std::path::PathBuf;

#[cfg(feature = "updater")]
use log::info;

#[path = "updater/error.rs"]
mod error;
pub use error::UpdateError;

#[cfg(feature = "updater")]
#[path = "updater/cache.rs"]
mod cache;
#[cfg(all(test, feature = "updater"))]
use cache::temp_path_for;
#[cfg(feature = "updater")]
use cache::write_cache_atomically;

/// URL of the upstream gitleaks ruleset.
pub const UPSTREAM_URL: &str =
    "https://raw.githubusercontent.com/gitleaks/gitleaks/refs/heads/master/config/gitleaks.toml";

/// Version file stored alongside the cached rules to record the upstream SHA-256.
const VERSION_FILE: &str = "secrets-scanner.toml.sha256";

/// Integrity file for the actual merged cached rules content.
const CACHE_SHA_FILE: &str = "secrets-scanner.toml.cache.sha256";

/// Sidecar recording the SHA-256 of the local merge input that produced the
/// cached ruleset. The "already current" fast-path matches on the UPSTREAM SHA
/// only; without this a local-rules edit (e.g. `assets/local.toml`) while
/// upstream is unchanged would leave the cache stale yet report "already current".
const LOCAL_SHA_FILE: &str = "secrets-scanner.toml.local.sha256";

#[cfg(feature = "updater")]
const UPDATE_CONNECT_TIMEOUT_SECS: u64 = 10;
#[cfg(feature = "updater")]
const UPDATE_READ_TIMEOUT_SECS: u64 = 30;
#[cfg(feature = "updater")]
const UPDATE_WRITE_TIMEOUT_SECS: u64 = 10;
#[cfg(feature = "updater")]
const UPDATE_TOTAL_TIMEOUT_SECS: u64 = 60;
#[cfg(feature = "updater")]
const MAX_RULES_DOWNLOAD_BYTES: u64 = 20 * 1024 * 1024;

// ── OS data directory ─────────────────────────────────────────────────────────

/// Returns the platform-appropriate user data directory for this application.
///
/// | OS      | Path                                              |
/// |---------|---------------------------------------------------|
/// | macOS   | `~/Library/Application Support/secrets-scanner/` |
/// | Linux   | `~/.local/share/secrets-scanner/`                 |
/// | Windows | `%APPDATA%\secrets-scanner\`                      |
pub fn data_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    let base = dirs_next().map(|p| p.join("Library/Application Support"));
    #[cfg(target_os = "linux")]
    let base = {
        let xdg = std::env::var("XDG_DATA_HOME").ok().map(PathBuf::from);
        xdg.or_else(|| home_dir().map(|p| p.join(".local/share")))
    };
    #[cfg(target_os = "windows")]
    let base = std::env::var("APPDATA").ok().map(PathBuf::from);
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let base = home_dir().map(|p| p.join(".secrets-scanner"));

    base.map(|p| p.join("secrets-scanner"))
}

#[cfg(not(target_os = "windows"))]
fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

#[cfg(target_os = "macos")]
fn dirs_next() -> Option<PathBuf> {
    home_dir()
}

/// Full path to the cached `secrets-scanner.toml` that the updater writes to.
pub fn cached_rules_path() -> Option<PathBuf> {
    data_dir().map(|d| d.join("secrets-scanner.toml"))
}

/// Full path to the SHA-256 sidecar file.
pub fn cached_sha_path() -> Option<PathBuf> {
    data_dir().map(|d| d.join(VERSION_FILE))
}

/// Full path to the cached rules content SHA-256 sidecar file.
pub fn cached_content_sha_path() -> Option<PathBuf> {
    data_dir().map(|d| d.join(CACHE_SHA_FILE))
}

/// Full path to the local-input SHA-256 sidecar file.
pub fn cached_local_sha_path() -> Option<PathBuf> {
    data_dir().map(|d| d.join(LOCAL_SHA_FILE))
}

// ── SHA-256 helper ────────────────────────────────────────────────────────────

/// Compute the SHA-256 digest of `data` and return it as a lowercase hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    hex::encode(digest)
}

/// Verify that `content` matches the cached rules content SHA-256 sidecar.
pub fn verify_cached_rules_content(content: &str) -> Result<(), String> {
    let sha_path =
        cached_content_sha_path().ok_or_else(|| "cannot determine data directory".to_string())?;
    let expected = std::fs::read_to_string(&sha_path)
        .map_err(|e| format!("could not read {}: {e}", sha_path.display()))?;
    let expected = expected.trim();
    let actual = sha256_hex(content.as_bytes());
    if expected == actual {
        Ok(())
    } else {
        Err(format!(
            "SHA-256 mismatch: expected {expected}, actual {actual}"
        ))
    }
}

// ── HTTP fetch (ureq, feature-gated) ─────────────────────────────────────────

/// Result of an update operation.
#[derive(Debug)]
pub enum UpdateResult {
    /// Rules were already up to date.
    AlreadyCurrent {
        /// SHA-256 hex digest of the current (unchanged) ruleset.
        sha256: String,
    },
    /// Rules were updated to a new version.
    Updated {
        /// SHA-256 hex digest of the newly downloaded ruleset.
        sha256: String,
    },
    /// Only a check was performed; an update is available.
    UpdateAvailable {
        /// SHA-256 of the locally cached ruleset.
        local_sha: String,
        /// SHA-256 of the remote (upstream) ruleset.
        remote_sha: String,
    },
    /// Only a check was performed; rules are current.
    CheckedCurrent {
        /// SHA-256 hex digest of the current ruleset.
        sha256: String,
    },
}

/// Download the latest rules and save them to the user data directory.
///
/// * `check_only` — if `true`, report whether an update is available but do
///   not write anything to disk.
/// * `custom_url` — if `Some`, pull rules from this URL instead of the default.
/// * `force` — if `true`, bypass the "already current" fast-path and always
///   re-fetch, re-merge, and rewrite the cache.
///
/// This function is synchronous and has no async runtime requirement.
/// It requires the `updater` feature to be enabled in `Cargo.toml` so that
/// the `ureq` dependency is compiled in.
#[cfg(feature = "updater")]
pub fn update_rules(
    check_only: bool,
    custom_url: Option<&str>,
    force: bool,
) -> Result<UpdateResult, UpdateError> {
    let url = custom_url.unwrap_or(UPSTREAM_URL);
    validate_update_url(url)?;
    info!("[updater] Fetching rules from {url}");

    let body = fetch_rules_body(url)?;

    let remote_sha = sha256_hex(&body);
    info!("[updater] Remote SHA-256: {remote_sha}");

    // Read cached upstream SHA if present
    let local_sha = cached_sha_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    if !local_sha.is_empty() {
        info!("[updater] Local  SHA-256: {local_sha}");
    }

    // Load the local merge input now so its SHA can participate in the staleness
    // decision: the cache is stale not only when upstream changed but also when
    // the local rules changed (which the upstream-SHA fast-path alone misses).
    let local_toml = super::load_local_rules_for_merge()?.into_content();
    let local_input_sha = sha256_hex(local_toml.as_bytes());
    let cached_local_input_sha = cached_local_sha_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let is_current = !force
        && remote_sha == local_sha
        && local_input_sha == cached_local_input_sha
        && cached_rules_content_is_verified();

    if is_current {
        return Ok(if check_only {
            UpdateResult::CheckedCurrent { sha256: remote_sha }
        } else {
            UpdateResult::AlreadyCurrent { sha256: remote_sha }
        });
    }

    if check_only {
        return Ok(UpdateResult::UpdateAvailable {
            local_sha,
            remote_sha,
        });
    }

    let rules_path = cached_rules_path().ok_or(UpdateError::DataDirUnavailable)?;
    let sha_path = cached_sha_path().ok_or(UpdateError::DataDirUnavailable)?;
    let cache_sha_path = cached_content_sha_path().ok_or(UpdateError::DataDirUnavailable)?;
    let local_sha_path = cached_local_sha_path().ok_or(UpdateError::DataDirUnavailable)?;

    // Merge the downloaded upstream rules with local custom rules
    let upstream_toml = String::from_utf8(body)?;

    // Validate upstream rules before merging
    if let Err(errors) = super::validation::validate_rules_toml(&upstream_toml) {
        return Err(UpdateError::InvalidUpstreamRules(errors));
    }

    // Reuse `local_toml` loaded above for the staleness check.
    let merged_toml = super::merge::merge_toml_rules(&upstream_toml, &local_toml)?;

    // Validate merged rules after merging
    if let Err(errors) = super::validation::validate_rules_toml(&merged_toml) {
        return Err(UpdateError::InvalidMergedRules(errors));
    }

    if let Some(parent) = rules_path.parent() {
        std::fs::create_dir_all(parent).map_err(UpdateError::CacheWrite)?;
    }

    // `cache_sha` is the MERGED content's SHA: it goes to the integrity sidecar
    // (CACHE_SHA_FILE) and is what `verify_cached_rules_content` checks against the
    // cached file on the next scan.
    let cache_sha = sha256_hex(merged_toml.as_bytes());
    write_cache_atomically(
        &rules_path,
        &merged_toml,
        &sha_path,
        // Record the UPSTREAM body's SHA (not the merged SHA) in the staleness
        // sidecar (VERSION_FILE): the staleness check compares this against a
        // freshly fetched upstream SHA, so it must be the same quantity or the
        // "already current" path becomes unreachable.
        &remote_sha,
        &cache_sha_path,
        &cache_sha,
        &local_sha_path,
        &local_input_sha,
    )?;

    info!("[updater] Combined rules saved to {}", rules_path.display());
    Ok(UpdateResult::Updated { sha256: remote_sha })
}

#[cfg(feature = "updater")]
fn fetch_rules_body(url: &str) -> Result<Vec<u8>, UpdateError> {
    use std::time::Duration;

    let agent = ureq::AgentBuilder::new()
        .https_only(true)
        .timeout_connect(Duration::from_secs(UPDATE_CONNECT_TIMEOUT_SECS))
        .timeout_read(Duration::from_secs(UPDATE_READ_TIMEOUT_SECS))
        .timeout_write(Duration::from_secs(UPDATE_WRITE_TIMEOUT_SECS))
        .timeout(Duration::from_secs(UPDATE_TOTAL_TIMEOUT_SECS))
        .build();
    let response = agent.get(url).call().map_err(|source| UpdateError::Fetch {
        url: url.to_string(),
        source: Box::new(source),
    })?;
    reject_large_content_length(response.header("Content-Length"), MAX_RULES_DOWNLOAD_BYTES)?;
    read_capped_body(response.into_reader(), MAX_RULES_DOWNLOAD_BYTES)
}

#[cfg(feature = "updater")]
fn reject_large_content_length(content_length: Option<&str>, max: u64) -> Result<(), UpdateError> {
    if let Some(value) = content_length {
        if let Ok(length) = value.trim().parse::<u64>() {
            if length > max {
                return Err(UpdateError::DownloadTooLarge {
                    actual: length,
                    max,
                });
            }
        }
    }
    Ok(())
}

#[cfg(feature = "updater")]
fn read_capped_body<R: std::io::Read>(reader: R, max: u64) -> Result<Vec<u8>, UpdateError> {
    use std::io::Read;

    let mut body = Vec::new();
    let mut limited = reader.take(max.saturating_add(1));
    limited
        .read_to_end(&mut body)
        .map_err(UpdateError::ReadBody)?;
    if body.len() as u64 > max {
        return Err(UpdateError::DownloadTooLarge {
            actual: body.len() as u64,
            max,
        });
    }
    Ok(body)
}

#[cfg(feature = "updater")]
fn validate_update_url(url: &str) -> Result<(), UpdateError> {
    let is_https = url
        .get(..8)
        .map(|prefix| prefix.eq_ignore_ascii_case("https://"))
        .unwrap_or(false);
    if is_https {
        Ok(())
    } else {
        Err(UpdateError::NonHttpsUrl)
    }
}

#[cfg(feature = "updater")]
fn cached_rules_content_is_verified() -> bool {
    cached_rules_path()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .is_some_and(|content| verify_cached_rules_content(&content).is_ok())
}

/// Stub used when the `updater` feature is disabled.  Returns an error
/// message directing the user to rebuild with the feature enabled or use
/// the shell script.
#[cfg(not(feature = "updater"))]
pub fn update_rules(
    _check_only: bool,
    _custom_url: Option<&str>,
    _force: bool,
) -> Result<UpdateResult, UpdateError> {
    Err(UpdateError::Disabled)
}

#[cfg(all(test, feature = "updater"))]
#[path = "updater_tests.rs"]
mod tests;
