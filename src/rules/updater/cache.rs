use std::path::{Path, PathBuf};

use super::UpdateError;

#[allow(clippy::too_many_arguments)]
pub(super) fn write_cache_atomically(
    rules_path: &Path,
    rules_content: &str,
    sha_path: &Path,
    sha_content: &str,
    cache_sha_path: &Path,
    cache_sha_content: &str,
    local_sha_path: &Path,
    local_sha_content: &str,
) -> Result<(), UpdateError> {
    let rules_tmp = temp_path_for(rules_path);
    let sha_tmp = temp_path_for(sha_path);
    let cache_sha_tmp = temp_path_for(cache_sha_path);
    let local_sha_tmp = temp_path_for(local_sha_path);

    std::fs::write(&rules_tmp, rules_content).map_err(UpdateError::CacheWrite)?;
    std::fs::write(&sha_tmp, sha_content).map_err(UpdateError::CacheWrite)?;
    std::fs::write(&cache_sha_tmp, cache_sha_content).map_err(UpdateError::CacheWrite)?;
    std::fs::write(&local_sha_tmp, local_sha_content).map_err(UpdateError::CacheWrite)?;

    std::fs::rename(&rules_tmp, rules_path).map_err(UpdateError::CacheWrite)?;
    if let Err(e) = std::fs::rename(&sha_tmp, sha_path) {
        let _ = std::fs::remove_file(&sha_tmp);
        let _ = std::fs::remove_file(&cache_sha_tmp);
        let _ = std::fs::remove_file(&local_sha_tmp);
        return Err(UpdateError::CacheWrite(e));
    }
    if let Err(e) = std::fs::rename(&cache_sha_tmp, cache_sha_path) {
        let _ = std::fs::remove_file(&cache_sha_tmp);
        let _ = std::fs::remove_file(&local_sha_tmp);
        return Err(UpdateError::CacheWrite(e));
    }
    if let Err(e) = std::fs::rename(&local_sha_tmp, local_sha_path) {
        let _ = std::fs::remove_file(&local_sha_tmp);
        return Err(UpdateError::CacheWrite(e));
    }

    Ok(())
}

pub(super) fn temp_path_for(path: &Path) -> PathBuf {
    let mut tmp = path.to_path_buf();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("secrets-scanner.tmp");
    tmp.set_file_name(format!("{file_name}.tmp.{}", std::process::id()));
    tmp
}
