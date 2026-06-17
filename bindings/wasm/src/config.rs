use js_sys::Reflect;
use secrets_scanner::{RedactionMode, ScanConfig};
use wasm_bindgen::prelude::*;

use crate::error::js_error;

const JS_MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

pub enum ConfigMode {
    Normal,
    Proxy,
}

pub fn config_to_rust(config: Option<JsValue>, mode: ConfigMode) -> Result<ScanConfig, JsValue> {
    let Some(config) = config.filter(|value| !value.is_null() && !value.is_undefined()) else {
        return Ok(match mode {
            ConfigMode::Normal => ScanConfig::default(),
            ConfigMode::Proxy => ScanConfig::proxy(),
        });
    };

    reject_native_only_fields(&config)?;

    match mode {
        ConfigMode::Normal => normal_config_to_rust(&config),
        ConfigMode::Proxy => proxy_config_to_rust(&config),
    }
}

fn normal_config_to_rust(config: &JsValue) -> Result<ScanConfig, JsValue> {
    reject_fields(
        config,
        &["proxy"],
        "Scanner.bundled/fromToml do not accept proxy; use Scanner.proxy()",
    )?;

    let mut rust = ScanConfig::default();
    apply_common_config(config, &mut rust)?;

    if let Some(redact) = optional_bool(config, "redact")? {
        rust.redact = redact;
    }
    if let Some(redaction_mode) = optional_string(config, "redactionMode")? {
        rust.redaction_mode = parse_redaction_mode(&redaction_mode)?;
    }
    if let Some(capture_context) = optional_bool(config, "captureContext")? {
        rust.capture_context = capture_context;
    }

    Ok(rust)
}

fn proxy_config_to_rust(config: &JsValue) -> Result<ScanConfig, JsValue> {
    reject_fields(
        config,
        &["redact", "redactionMode", "captureContext", "proxy"],
        "Scanner.proxy config only accepts proxy-safe caps",
    )?;

    let mut rust = ScanConfig::proxy();
    apply_common_config(config, &mut rust)?;
    Ok(rust)
}

fn apply_common_config(config: &JsValue, rust: &mut ScanConfig) -> Result<(), JsValue> {
    if let Some(min_entropy) = optional_number(config, "minEntropy")? {
        if !min_entropy.is_finite() || min_entropy < 0.0 {
            return Err(js_error(
                "INVALID_CONFIG",
                "minEntropy must be a non-negative finite number",
            ));
        }
        rust.min_entropy_override = Some(min_entropy);
    }
    if let Some(max_file_size) = optional_number(config, "maxFileSize")? {
        rust.max_file_size = positive_number_to_u64("maxFileSize", max_file_size)?;
    }
    if let Some(max_findings_per_file) = optional_number(config, "maxFindingsPerFile")? {
        rust.max_findings_per_file = Some(positive_number_to_usize(
            "maxFindingsPerFile",
            max_findings_per_file,
        )?);
    }
    if let Some(max_matched_len) = optional_number(config, "maxMatchedLen")? {
        rust.max_matched_len = Some(positive_number_to_usize("maxMatchedLen", max_matched_len)?);
    }
    Ok(())
}

fn reject_native_only_fields(config: &JsValue) -> Result<(), JsValue> {
    reject_fields(
        config,
        &[
            "binaryPolicy",
            "maxFiles",
            "maxFindings",
            "gitTracked",
            "changedFiles",
            "base",
            "gitHistory",
            "historyAll",
            "historyFull",
            "historyLogOpts",
            "historyTimeoutSecs",
            "gitStaged",
            "includeUntracked",
            "gitFallbackWalk",
        ],
        "WASM bindings only support in-memory scans",
    )
}

fn reject_fields(config: &JsValue, fields: &[&str], message: &str) -> Result<(), JsValue> {
    for field in fields {
        if optional_value(config, field)?.is_some() {
            return Err(js_error(
                "INVALID_CONFIG",
                &format!("{message}; unsupported field: {field}"),
            ));
        }
    }
    Ok(())
}

fn optional_bool(config: &JsValue, field: &str) -> Result<Option<bool>, JsValue> {
    let Some(value) = optional_value(config, field)? else {
        return Ok(None);
    };
    value.as_bool().map(Some).ok_or_else(|| {
        js_error(
            "INVALID_CONFIG",
            &format!("{field} must be a boolean when provided"),
        )
    })
}

fn optional_number(config: &JsValue, field: &str) -> Result<Option<f64>, JsValue> {
    let Some(value) = optional_value(config, field)? else {
        return Ok(None);
    };
    value.as_f64().map(Some).ok_or_else(|| {
        js_error(
            "INVALID_CONFIG",
            &format!("{field} must be a number when provided"),
        )
    })
}

fn optional_string(config: &JsValue, field: &str) -> Result<Option<String>, JsValue> {
    let Some(value) = optional_value(config, field)? else {
        return Ok(None);
    };
    value.as_string().map(Some).ok_or_else(|| {
        js_error(
            "INVALID_CONFIG",
            &format!("{field} must be a string when provided"),
        )
    })
}

fn optional_value(config: &JsValue, field: &str) -> Result<Option<JsValue>, JsValue> {
    let value = Reflect::get(config, &JsValue::from_str(field)).map_err(|_| {
        js_error(
            "INVALID_CONFIG",
            &format!("could not read config field: {field}"),
        )
    })?;
    if value.is_undefined() || value.is_null() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

fn parse_redaction_mode(value: &str) -> Result<RedactionMode, JsValue> {
    match value {
        "partial" => Ok(RedactionMode::Partial),
        "full" => Ok(RedactionMode::Full),
        _ => Err(js_error(
            "INVALID_CONFIG",
            "redactionMode must be one of partial or full",
        )),
    }
}

fn positive_number_to_u64(field: &str, value: f64) -> Result<u64, JsValue> {
    if !is_safe_integer(value) || value == 0.0 {
        return Err(js_error(
            "INVALID_CONFIG",
            &format!("{field} must be a positive safe integer"),
        ));
    }
    Ok(value as u64)
}

fn positive_number_to_usize(field: &str, value: f64) -> Result<usize, JsValue> {
    if !is_safe_integer(value) || value == 0.0 || value > usize::MAX as f64 {
        return Err(js_error(
            "INVALID_CONFIG",
            &format!("{field} must be a positive safe integer"),
        ));
    }
    Ok(value as usize)
}

fn is_safe_integer(value: f64) -> bool {
    value.is_finite() && value >= 0.0 && value.fract() == 0.0 && value <= JS_MAX_SAFE_INTEGER
}
