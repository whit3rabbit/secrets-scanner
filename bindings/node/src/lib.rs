use napi::bindgen_prelude::{Buffer, Result};
use napi::{Error, Status};
use napi_derive::napi;
use secrets_scanner::{
    Finding, ProxyError, ScanConfig as RustScanConfig, Scanner as RustScanner, ScannerError,
};

#[napi(object)]
pub struct NativeScanConfig {
    pub proxy: Option<bool>,
    pub redact: Option<bool>,
    pub min_entropy: Option<f64>,
    pub max_file_size: Option<f64>,
    pub max_findings_per_file: Option<f64>,
    pub max_matched_len: Option<f64>,
}

#[napi(object)]
pub struct NativeContextLine {
    pub line: f64,
    pub content: String,
}

#[napi(object)]
pub struct NativeFinding {
    pub file: String,
    pub line: f64,
    pub col: f64,
    pub end_line: f64,
    pub end_col: f64,
    pub col_utf16: f64,
    pub end_col_utf16: f64,
    pub rule_id: String,
    pub description: String,
    pub matched: String,
    pub entropy: f64,
    pub start_offset: f64,
    pub end_offset: f64,
    pub secret_start_offset: f64,
    pub secret_end_offset: f64,
    pub fingerprint: String,
    pub context_lines: Vec<NativeContextLine>,
}

#[napi(object)]
pub struct NativeStringRedactionResult {
    pub findings: Vec<NativeFinding>,
    pub redacted: String,
    pub has_findings: bool,
}

#[napi(object)]
pub struct NativeByteRedactionResult {
    pub findings: Vec<NativeFinding>,
    pub redacted: Buffer,
    pub has_findings: bool,
}

#[napi(js_name = "NativeScanner")]
pub struct NativeScanner {
    inner: RustScanner,
}

#[napi]
impl NativeScanner {
    #[napi(factory)]
    pub fn bundled(config: Option<NativeScanConfig>) -> Result<Self> {
        let scanner = RustScanner::from_bundled()
            .map_err(to_napi_error)?
            .with_config(config_to_rust(config)?);

        Ok(Self { inner: scanner })
    }

    #[napi(factory)]
    pub fn from_default_rules(config: Option<NativeScanConfig>) -> Result<Self> {
        let scanner = RustScanner::new()
            .map_err(to_napi_error)?
            .with_config(config_to_rust(config)?);

        Ok(Self { inner: scanner })
    }

    #[napi(factory)]
    pub fn from_rules_file(path: String, config: Option<NativeScanConfig>) -> Result<Self> {
        let scanner = RustScanner::from_file(&path)
            .map_err(to_napi_error)?
            .with_config(config_to_rust(config)?);

        Ok(Self { inner: scanner })
    }

    #[napi(factory)]
    pub fn from_toml(toml: String, config: Option<NativeScanConfig>) -> Result<Self> {
        let scanner = RustScanner::from_toml(&toml)
            .map_err(to_napi_error)?
            .with_config(config_to_rust(config)?);

        Ok(Self { inner: scanner })
    }

    #[napi]
    pub fn scan_content(&self, path: String, content: String) -> Result<Vec<NativeFinding>> {
        findings_to_native(self.inner.scan_content(&path, &content))
    }

    #[napi]
    pub fn scan_and_redact_content(
        &self,
        path: String,
        content: String,
    ) -> Result<NativeStringRedactionResult> {
        let output = self.inner.scan_and_redact_content(&path, &content);
        let has_findings = output.has_findings();

        Ok(NativeStringRedactionResult {
            findings: findings_to_native(output.findings)?,
            redacted: output.redacted,
            has_findings,
        })
    }

    #[napi]
    pub fn scan_bytes(&self, path: String, content: Buffer) -> Result<Vec<NativeFinding>> {
        findings_to_native(self.inner.scan_bytes(&path, &content))
    }

    #[napi]
    pub fn scan_and_redact_bytes(
        &self,
        path: String,
        content: Buffer,
    ) -> Result<NativeByteRedactionResult> {
        let output = self.inner.scan_and_redact_bytes(&path, &content);
        let has_findings = output.has_findings();

        Ok(NativeByteRedactionResult {
            findings: findings_to_native(output.findings)?,
            redacted: output.redacted.into(),
            has_findings,
        })
    }

    #[napi]
    pub fn scan_proxy(&self, content: Buffer) -> Result<NativeByteRedactionResult> {
        let output = self
            .inner
            .scan_proxy(&content)
            .map_err(to_napi_proxy_error)?;
        let has_findings = output.has_findings();

        Ok(NativeByteRedactionResult {
            findings: findings_to_native(output.findings)?,
            redacted: output.redacted.into(),
            has_findings,
        })
    }
}

fn config_to_rust(config: Option<NativeScanConfig>) -> Result<RustScanConfig> {
    let Some(config) = config else {
        return Ok(RustScanConfig::default());
    };
    let mut rust = if config.proxy.unwrap_or(false) {
        RustScanConfig::proxy()
    } else {
        RustScanConfig::default()
    };

    if let Some(redact) = config.redact {
        rust.redact = redact;
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

    Ok(rust)
}

fn findings_to_native(findings: Vec<Finding>) -> Result<Vec<NativeFinding>> {
    findings.into_iter().map(finding_to_native).collect()
}

fn finding_to_native(finding: Finding) -> Result<NativeFinding> {
    Ok(NativeFinding {
        file: finding.file,
        line: to_js_number("line", finding.line)?,
        col: to_js_number("col", finding.col)?,
        end_line: to_js_number("endLine", finding.end_line)?,
        end_col: to_js_number("endCol", finding.end_col)?,
        col_utf16: to_js_number("colUtf16", finding.col_utf16)?,
        end_col_utf16: to_js_number("endColUtf16", finding.end_col_utf16)?,
        rule_id: finding.rule_id,
        description: finding.rule_description,
        matched: finding.matched,
        entropy: finding.entropy,
        start_offset: to_js_number("startOffset", finding.start_offset)?,
        end_offset: to_js_number("endOffset", finding.end_offset)?,
        secret_start_offset: to_js_number("secretStartOffset", finding.secret_start_offset)?,
        secret_end_offset: to_js_number("secretEndOffset", finding.secret_end_offset)?,
        fingerprint: finding.fingerprint,
        context_lines: finding
            .context_lines
            .into_iter()
            .map(|(line, content)| {
                Ok(NativeContextLine {
                    line: to_js_number("contextLine.line", line)?,
                content,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    })
}

fn to_js_number(field: &str, value: usize) -> Result<f64> {
    const MAX_SAFE_INTEGER: usize = 9_007_199_254_740_991;
    if value > MAX_SAFE_INTEGER {
        return Err(napi_error(
            "POSITION_OVERFLOW",
            &format!("{field} exceeds JavaScript's max safe integer"),
        ));
    }
    Ok(value as f64)
}

fn to_napi_error(error: ScannerError) -> Error {
    match error {
        ScannerError::InvalidRules(_) => napi_error("INVALID_RULES", "invalid scanner rules"),
        ScannerError::Toml(_) => napi_error("INVALID_RULES_TOML", "invalid scanner rules TOML"),
        ScannerError::Io(_) => napi_error("IO", "scanner rules could not be read"),
        ScannerError::AhoCorasick(_) => {
            napi_error("ENGINE_BUILD", "scanner engine could not be built")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::to_js_number;

    #[test]
    fn converts_positions_above_u32_without_clamping() {
        let value = u32::MAX as usize + 1;
        assert_eq!(to_js_number("startOffset", value).expect("number"), value as f64);
    }

    #[test]
    fn rejects_positions_above_js_safe_integer() {
        let err = to_js_number("startOffset", 9_007_199_254_740_992)
            .expect_err("overflow should error");
        assert_eq!(err.status, napi::Status::GenericFailure);
        assert!(
            err.reason.contains("max safe integer"),
            "unexpected error: {err:?}"
        );
    }
}

fn to_napi_proxy_error(error: ProxyError) -> Error {
    match error {
        ProxyError::InputTooLarge { .. } => napi_error(
            "INPUT_TOO_LARGE",
            "proxy input exceeds configured maxFileSize",
        ),
        ProxyError::NotHardened => napi_error(
            "NOT_HARDENED",
            "scanner is not hardened for proxy use; build it with the proxy config \
             (e.g. Scanner.proxy())",
        ),
    }
}

fn number_to_u64(field: &str, value: f64) -> Result<u64> {
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value > u64::MAX as f64 {
        return Err(napi_error(
            "INVALID_CONFIG",
            &format!("scan config contains an invalid {field}"),
        ));
    }
    Ok(value as u64)
}

fn number_to_usize(field: &str, value: f64) -> Result<usize> {
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value > usize::MAX as f64 {
        return Err(napi_error(
            "INVALID_CONFIG",
            &format!("scan config contains an invalid {field}"),
        ));
    }
    Ok(value as usize)
}

fn napi_error(code: &str, message: &str) -> Error {
    Error::new(Status::GenericFailure, format!("{code}: {message}"))
}
