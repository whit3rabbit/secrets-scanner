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

/// URL of the upstream gitleaks ruleset.
pub const UPSTREAM_URL: &str =
    "https://raw.githubusercontent.com/gitleaks/gitleaks/refs/heads/master/config/gitleaks.toml";

/// Version file stored alongside the cached rules to record the SHA-256 and
/// download timestamp.
const VERSION_FILE: &str = "secrets-scanner.toml.sha256";

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

// ── SHA-256 helper ────────────────────────────────────────────────────────────

/// Compute the SHA-256 digest of `data` and return it as a lowercase hex string.
///
/// When built with the `updater` feature this uses the `sha2` crate (pure Rust).
/// Without the feature an error will be raised at the call site because the
/// feature-gated `update_rules` function will not compile.
#[cfg(feature = "updater")]
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    hex::encode(digest)
}

/// Fallback stub used when the `updater` feature is disabled.
///
/// This should never be called at runtime in a non-updater build, but it
/// allows the symbol to exist so downstream code that references it compiles.
#[cfg(not(feature = "updater"))]
pub fn sha256_hex(_data: &[u8]) -> String {
    String::from("updater-feature-disabled")
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
///
/// This function is synchronous and has no async runtime requirement.
/// It requires the `updater` feature to be enabled in `Cargo.toml` so that
/// the `ureq` dependency is compiled in.
#[cfg(feature = "updater")]
pub fn update_rules(
    check_only: bool,
    custom_url: Option<&str>,
) -> Result<UpdateResult, Box<dyn std::error::Error>> {
    use std::io::Read;

    let url = custom_url.unwrap_or(UPSTREAM_URL);
    info!("[updater] Fetching rules from {url}");

    let response = ureq::get(url).call()?;
    let mut body = Vec::new();
    response.into_reader().read_to_end(&mut body)?;

    let remote_sha = sha256_hex(&body);
    info!("[updater] Remote SHA-256: {remote_sha}");

    // Read local SHA if cached
    let local_sha = cached_sha_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    if !local_sha.is_empty() {
        info!("[updater] Local  SHA-256: {local_sha}");
    }

    if remote_sha == local_sha {
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

    let rules_path = cached_rules_path().ok_or("Cannot determine data directory")?;
    let sha_path = cached_sha_path().ok_or("Cannot determine data directory")?;

    // Merge the downloaded upstream rules with local custom rules
    let upstream_toml = String::from_utf8(body)?;

    // Validate upstream rules before merging
    if let Err(errors) = super::validation::validate_rules_toml(&upstream_toml) {
        return Err(format!(
            "Downloaded upstream rules are invalid:\n- {}",
            errors.join("\n- ")
        )
        .into());
    }

    let local_toml = super::load_local_rules_for_merge();
    let merged_toml = super::merge::merge_toml_rules(&upstream_toml, &local_toml)?;

    // Validate merged rules after merging
    if let Err(errors) = super::validation::validate_rules_toml(&merged_toml) {
        return Err(format!("Merged ruleset is invalid:\n- {}", errors.join("\n- ")).into());
    }

    if let Some(parent) = rules_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Record the UPSTREAM body's SHA (not the merged SHA): the staleness check
    // compares this against a freshly fetched upstream SHA, so it must be the
    // same quantity or the "already current" path becomes unreachable.
    write_pair_atomically(&rules_path, &merged_toml, &sha_path, &remote_sha)?;

    info!("[updater] Combined rules saved to {}", rules_path.display());
    Ok(UpdateResult::Updated { sha256: remote_sha })
}

#[cfg(feature = "updater")]
fn write_pair_atomically(
    rules_path: &std::path::Path,
    rules_content: &str,
    sha_path: &std::path::Path,
    sha_content: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let rules_tmp = temp_path_for(rules_path);
    let sha_tmp = temp_path_for(sha_path);

    std::fs::write(&rules_tmp, rules_content)?;
    std::fs::write(&sha_tmp, sha_content)?;

    std::fs::rename(&rules_tmp, rules_path)?;
    if let Err(e) = std::fs::rename(&sha_tmp, sha_path) {
        let _ = std::fs::remove_file(&sha_tmp);
        return Err(e.into());
    }

    Ok(())
}

#[cfg(feature = "updater")]
fn temp_path_for(path: &std::path::Path) -> PathBuf {
    let mut tmp = path.to_path_buf();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("secrets-scanner.tmp");
    tmp.set_file_name(format!("{file_name}.tmp.{}", std::process::id()));
    tmp
}

/// Stub used when the `updater` feature is disabled.  Returns an error
/// message directing the user to rebuild with the feature enabled or use
/// the shell script.
#[cfg(not(feature = "updater"))]
pub fn update_rules(
    _check_only: bool,
    _custom_url: Option<&str>,
) -> Result<UpdateResult, Box<dyn std::error::Error>> {
    Err("Built without the `updater` feature. \
         Rebuild with `cargo build --features updater` or run \
         `./scripts/update_rules.sh` manually."
        .into())
}

#[cfg(all(test, feature = "updater"))]
mod tests {
    use super::*;

    #[test]
    fn atomic_pair_write_writes_rules_before_sha_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rules_path = dir.path().join("secrets-scanner.toml");
        let sha_path = dir.path().join("secrets-scanner.toml.sha256");

        write_pair_atomically(&rules_path, "rules-v1", &sha_path, "remote-sha")
            .expect("atomic write");

        assert_eq!(
            std::fs::read_to_string(&rules_path).expect("rules"),
            "rules-v1"
        );
        assert_eq!(
            std::fs::read_to_string(&sha_path).expect("sha"),
            "remote-sha"
        );
        assert!(!temp_path_for(&rules_path).exists());
        assert!(!temp_path_for(&sha_path).exists());
    }
}
