use napi::bindgen_prelude::Result;
use napi_derive::napi;
use secrets_scanner::{BinaryPolicy, RedactionMode, ScanConfig as RustScanConfig};

use crate::errors::napi_error;

const JS_MAX_SAFE_INTEGER_F64: f64 = 9_007_199_254_740_991.0;

#[derive(Default)]
#[napi(object)]
pub struct NativeScanConfig {
    pub proxy: Option<bool>,
    pub redact: Option<bool>,
    pub redaction_mode: Option<String>,
    pub min_entropy: Option<f64>,
    pub max_file_size: Option<f64>,
    pub max_findings_per_file: Option<f64>,
    pub max_matched_len: Option<f64>,
    pub binary_policy: Option<String>,
    pub max_files: Option<f64>,
    pub max_findings: Option<f64>,
    pub git_tracked: Option<bool>,
    pub changed_files: Option<bool>,
    pub base: Option<String>,
    pub git_history: Option<bool>,
    pub history_all: Option<bool>,
    pub history_full: Option<bool>,
    pub history_log_opts: Option<Vec<String>>,
    pub history_timeout_secs: Option<f64>,
    pub git_staged: Option<bool>,
    pub include_untracked: Option<bool>,
    pub git_fallback_walk: Option<bool>,
    pub capture_context: Option<bool>,
}

pub fn config_to_rust(config: Option<NativeScanConfig>) -> Result<RustScanConfig> {
    let Some(config) = config else {
        return Ok(RustScanConfig::default());
    };
    validate_proxy_config(&config)?;
    validate_git_mode_config(&config)?;

    let mut rust = if config.proxy.unwrap_or(false) {
        RustScanConfig::proxy()
    } else {
        RustScanConfig::default()
    };

    if let Some(redact) = config.redact {
        rust.redact = redact;
    }

    if let Some(redaction_mode) = config.redaction_mode {
        rust.redaction_mode = parse_redaction_mode(&redaction_mode)?;
    }

    if let Some(min_entropy) = config.min_entropy {
        if !min_entropy.is_finite() || min_entropy < 0.0 {
            return Err(napi_error(
                "INVALID_CONFIG",
                "scan config contains an invalid minEntropy",
            ));
        }
        rust.min_entropy_override = Some(min_entropy);
    }

    if let Some(max_file_size) = config.max_file_size {
        rust.max_file_size = number_to_u64("maxFileSize", max_file_size)?;
    }

    if let Some(max_findings_per_file) = config.max_findings_per_file {
        rust.max_findings_per_file = Some(number_to_usize(
            "maxFindingsPerFile",
            max_findings_per_file,
        )?);
    }

    if let Some(max_matched_len) = config.max_matched_len {
        rust.max_matched_len = Some(number_to_usize("maxMatchedLen", max_matched_len)?);
    }

    if let Some(binary_policy) = config.binary_policy {
        rust.binary_policy = parse_binary_policy(&binary_policy)?;
    }

    if let Some(max_files) = config.max_files {
        rust.max_files = Some(number_to_usize("maxFiles", max_files)?);
    }

    if let Some(max_findings) = config.max_findings {
        rust.max_findings = Some(number_to_usize("maxFindings", max_findings)?);
    }

    rust.git_tracked = config.git_tracked.unwrap_or(false);
    rust.changed_files = config.changed_files.unwrap_or(false);
    if let Some(base) = config.base {
        rust.base = Some(base);
        rust.changed_files = true;
    }
    rust.git_history = config.git_history.unwrap_or(false);
    rust.history_all = config.history_all.unwrap_or(false);
    rust.history_full = rust.git_history || config.history_full.unwrap_or(false);
    rust.history_log_opts = config.history_log_opts.unwrap_or_default();
    if let Some(history_timeout_secs) = config.history_timeout_secs {
        rust.history_timeout_secs = number_to_u64("historyTimeoutSecs", history_timeout_secs)?;
    }
    rust.git_staged = config.git_staged.unwrap_or(false);
    rust.include_untracked = config.include_untracked.unwrap_or(false);
    rust.git_fallback_walk = config.git_fallback_walk.unwrap_or(false);
    if let Some(capture_context) = config.capture_context {
        rust.capture_context = capture_context;
    }

    Ok(rust)
}

fn validate_proxy_config(config: &NativeScanConfig) -> Result<()> {
    if !config.proxy.unwrap_or(false) {
        return Ok(());
    }

    let forbidden = [
        ("redact", config.redact.is_some()),
        ("redactionMode", config.redaction_mode.is_some()),
        ("binaryPolicy", config.binary_policy.is_some()),
        ("maxFiles", config.max_files.is_some()),
        ("maxFindings", config.max_findings.is_some()),
        ("gitTracked", config.git_tracked.is_some()),
        ("changedFiles", config.changed_files.is_some()),
        ("base", config.base.is_some()),
        ("gitHistory", config.git_history.is_some()),
        ("historyAll", config.history_all.is_some()),
        ("historyFull", config.history_full.is_some()),
        ("historyLogOpts", config.history_log_opts.is_some()),
        ("historyTimeoutSecs", config.history_timeout_secs.is_some()),
        ("gitStaged", config.git_staged.is_some()),
        ("includeUntracked", config.include_untracked.is_some()),
        ("gitFallbackWalk", config.git_fallback_walk.is_some()),
        ("captureContext", config.capture_context.is_some()),
    ];

    for (field, present) in forbidden {
        if present {
            return Err(napi_error(
                "INVALID_CONFIG",
                &format!("proxy scan config does not accept {field}"),
            ));
        }
    }

    Ok(())
}

fn validate_git_mode_config(config: &NativeScanConfig) -> Result<()> {
    let git_history = config.git_history.unwrap_or(false);
    let git_staged = config.git_staged.unwrap_or(false);
    let git_tracked = config.git_tracked.unwrap_or(false);
    let changed_files = config.changed_files.unwrap_or(false);
    let has_base = config.base.is_some();
    let include_untracked = config.include_untracked.unwrap_or(false);
    let has_history_opts = config.history_all.unwrap_or(false)
        || config.history_full.unwrap_or(false)
        || config.history_timeout_secs.is_some()
        || config
            .history_log_opts
            .as_ref()
            .is_some_and(|opts| !opts.is_empty());

    if has_history_opts && !git_history {
        return Err(napi_error(
            "INVALID_CONFIG",
            "history options require gitHistory",
        ));
    }
    if git_history && (git_tracked || changed_files || has_base || git_staged || include_untracked)
    {
        return Err(napi_error(
            "INVALID_CONFIG",
            "gitHistory conflicts with other git scan modes",
        ));
    }
    if git_staged && (git_tracked || changed_files || has_base || include_untracked) {
        return Err(napi_error(
            "INVALID_CONFIG",
            "gitStaged conflicts with other git scan modes",
        ));
    }
    if git_tracked && (changed_files || has_base) {
        return Err(napi_error(
            "INVALID_CONFIG",
            "gitTracked conflicts with changedFiles and base",
        ));
    }
    if include_untracked && !(git_tracked || changed_files || has_base) {
        return Err(napi_error(
            "INVALID_CONFIG",
            "includeUntracked requires gitTracked, changedFiles, or base",
        ));
    }
    Ok(())
}

fn parse_redaction_mode(value: &str) -> Result<RedactionMode> {
    match value {
        "partial" => Ok(RedactionMode::Partial),
        "full" => Ok(RedactionMode::Full),
        _ => Err(napi_error(
            "INVALID_CONFIG",
            "redactionMode must be one of partial or full",
        )),
    }
}

fn parse_binary_policy(value: &str) -> Result<BinaryPolicy> {
    match value {
        "auto" => Ok(BinaryPolicy::Auto),
        "skip" => Ok(BinaryPolicy::Skip),
        "scan" => Ok(BinaryPolicy::Scan),
        _ => Err(napi_error(
            "INVALID_CONFIG",
            "binaryPolicy must be one of auto, skip, or scan",
        )),
    }
}

pub fn number_to_u64(field: &str, value: f64) -> Result<u64> {
    if !is_safe_integer(value) {
        return Err(napi_error(
            "INVALID_CONFIG",
            &format!("{field} must be a non-negative safe integer"),
        ));
    }
    Ok(value as u64)
}

pub fn number_to_usize(field: &str, value: f64) -> Result<usize> {
    if !is_safe_integer(value) || value > usize::MAX as f64 {
        return Err(napi_error(
            "INVALID_CONFIG",
            &format!("{field} must be a non-negative safe integer"),
        ));
    }
    Ok(value as usize)
}

fn is_safe_integer(value: f64) -> bool {
    value.is_finite() && value >= 0.0 && value.fract() == 0.0 && value <= JS_MAX_SAFE_INTEGER_F64
}

#[cfg(test)]
mod tests {
    use super::{config_to_rust, number_to_u64, number_to_usize, NativeScanConfig};

    #[test]
    fn rejects_config_values_above_js_safe_integer() {
        let value = 9_007_199_254_740_992.0;
        assert!(number_to_u64("maxFileSize", value).is_err());
        assert!(number_to_usize("maxFindings", value).is_err());
    }

    #[test]
    fn rejects_fractional_negative_and_non_finite_config_numbers() {
        for value in [1.5, -1.0, f64::INFINITY, f64::NAN] {
            assert!(number_to_u64("maxFileSize", value).is_err());
            assert!(number_to_usize("maxFindings", value).is_err());
        }
    }

    #[test]
    fn git_history_implies_full_history() {
        let config = NativeScanConfig {
            git_history: Some(true),
            ..NativeScanConfig::default()
        };

        let rust = config_to_rust(Some(config)).expect("config should convert");

        assert!(rust.git_history);
        assert!(rust.history_full);
    }

    #[test]
    fn proxy_config_rejects_forbidden_fields() {
        for config in [
            NativeScanConfig {
                proxy: Some(true),
                redact: Some(false),
                ..NativeScanConfig::default()
            },
            NativeScanConfig {
                proxy: Some(true),
                binary_policy: Some("scan".to_string()),
                ..NativeScanConfig::default()
            },
            NativeScanConfig {
                proxy: Some(true),
                max_files: Some(1.0),
                ..NativeScanConfig::default()
            },
            NativeScanConfig {
                proxy: Some(true),
                git_history: Some(true),
                ..NativeScanConfig::default()
            },
            NativeScanConfig {
                proxy: Some(true),
                history_timeout_secs: Some(1.0),
                ..NativeScanConfig::default()
            },
            NativeScanConfig {
                proxy: Some(true),
                capture_context: Some(false),
                ..NativeScanConfig::default()
            },
        ] {
            assert!(config_to_rust(Some(config)).is_err());
        }
    }

    #[test]
    fn proxy_config_accepts_hardening_caps() {
        let config = NativeScanConfig {
            proxy: Some(true),
            min_entropy: Some(4.0),
            max_file_size: Some(1024.0),
            max_findings_per_file: Some(10.0),
            max_matched_len: Some(128.0),
            ..NativeScanConfig::default()
        };

        let rust = config_to_rust(Some(config)).expect("proxy config should convert");

        assert!(rust.is_hardened());
        assert_eq!(rust.max_file_size, 1024);
        assert_eq!(rust.min_entropy_override, Some(4.0));
        assert_eq!(rust.max_findings_per_file, Some(10));
        assert_eq!(rust.max_matched_len, Some(128));
    }

    #[test]
    fn rejects_ambiguous_git_scope_config() {
        for config in [
            NativeScanConfig {
                include_untracked: Some(true),
                ..NativeScanConfig::default()
            },
            NativeScanConfig {
                git_tracked: Some(true),
                changed_files: Some(true),
                ..NativeScanConfig::default()
            },
            NativeScanConfig {
                git_tracked: Some(true),
                base: Some("origin/main".to_string()),
                ..NativeScanConfig::default()
            },
            NativeScanConfig {
                history_timeout_secs: Some(1.0),
                ..NativeScanConfig::default()
            },
        ] {
            assert!(config_to_rust(Some(config)).is_err());
        }
    }

    #[test]
    fn accepts_history_timeout_and_capture_context_for_normal_scans() {
        let config = NativeScanConfig {
            git_history: Some(true),
            history_timeout_secs: Some(5.0),
            capture_context: Some(false),
            ..NativeScanConfig::default()
        };

        let rust = config_to_rust(Some(config)).expect("config should convert");

        assert!(rust.git_history);
        assert_eq!(rust.history_timeout_secs, 5);
        assert!(!rust.capture_context);
    }
}
