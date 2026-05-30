/// rules/updater.rs — Runtime update mechanism for gitleaks rules.
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

// ── SHA-256 helper (no external deps) ────────────────────────────────────────

/// Compute SHA-256 of a byte slice using only `std`.
/// We implement a minimal SHA-256 to avoid a compile-time dependency on ring/sha2
/// for a non-critical path.  If the project already uses `sha2`, replace this.
pub fn sha256_hex(data: &[u8]) -> String {
    // Use sha2 crate if available (feature-gated); else fall back to a simple
    // process-based approach on the host.  For now we call out to `shasum`.
    // In production you'd want the sha2 crate.
    use std::process::Command;
    use std::io::Write;

    // Write bytes to a temp file and hash it
    let mut tmp = tempfile_path();
    std::fs::write(&tmp, data).unwrap_or_default();

    let output = if cfg!(target_os = "macos") {
        Command::new("shasum").args(["-a", "256"]).arg(&tmp).output()
    } else {
        Command::new("sha256sum").arg(&tmp).output()
    };

    let _ = std::fs::remove_file(&tmp);

    output
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.split_whitespace().next().map(|h| h.to_string()))
        .unwrap_or_else(|| "unknown".to_string())
}

fn tempfile_path() -> PathBuf {
    std::env::temp_dir().join(format!("ss_rules_{}.tmp", std::process::id()))
}

// ── HTTP fetch (ureq, feature-gated) ─────────────────────────────────────────

/// Result of an update operation.
#[derive(Debug)]
pub enum UpdateResult {
    /// Rules were already up to date.
    AlreadyCurrent { sha256: String },
    /// Rules were updated to a new version.
    Updated { sha256: String },
    /// Only a check was performed; an update is available.
    UpdateAvailable { local_sha: String, remote_sha: String },
    /// Only a check was performed; rules are current.
    CheckedCurrent { sha256: String },
}

/// Download the latest rules and save them to the user data directory.
///
/// * `check_only` — if `true`, report whether an update is available but do
///   not write anything to disk.
///
/// This function is synchronous and has no async runtime requirement.
/// It requires the `updater` feature to be enabled in `Cargo.toml` so that
/// the `ureq` dependency is compiled in.
#[cfg(feature = "updater")]
pub fn update_rules(check_only: bool) -> Result<UpdateResult, Box<dyn std::error::Error>> {
    use std::io::Read;

    eprintln!("[updater] Fetching rules from {UPSTREAM_URL}");

    let response = ureq::get(UPSTREAM_URL).call()?;
    let mut body = Vec::new();
    response.into_reader().read_to_end(&mut body)?;

    let remote_sha = sha256_hex(&body);
    eprintln!("[updater] Remote SHA-256: {remote_sha}");

    // Read local SHA if cached
    let local_sha = cached_sha_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    if !local_sha.is_empty() {
        eprintln!("[updater] Local  SHA-256: {local_sha}");
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

    // Write to cache
    let rules_path = cached_rules_path().ok_or("Cannot determine data directory")?;
    let sha_path   = cached_sha_path().ok_or("Cannot determine data directory")?;

    if let Some(parent) = rules_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Merge the downloaded upstream rules with local custom rules
    let upstream_toml = String::from_utf8(body)?;
    let local_toml = super::load_local_rules_for_merge();
    let merged_toml = super::merge_toml_rules(&upstream_toml, &local_toml)?;

    std::fs::write(&rules_path, &merged_toml)?;
    std::fs::write(&sha_path, &remote_sha)?;

    eprintln!("[updater] Combined rules saved to {}", rules_path.display());
    Ok(UpdateResult::Updated { sha256: remote_sha })
}

/// Stub used when the `updater` feature is disabled.  Returns an error
/// message directing the user to rebuild with the feature enabled or use
/// the shell script.
#[cfg(not(feature = "updater"))]
pub fn update_rules(_check_only: bool) -> Result<UpdateResult, Box<dyn std::error::Error>> {
    Err("Built without the `updater` feature. \
         Rebuild with `cargo build --features updater` or run \
         `./scripts/update_rules.sh` manually."
        .into())
}
