use napi::bindgen_prelude::{Buffer, Result};
use napi_derive::napi;
use secrets_scanner::{Finding, ScanOutput, ScanResult, ScanStats};

use crate::errors::napi_error;

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
    pub commit: Option<String>,
    pub context_lines: Vec<NativeContextLine>,
}

#[napi(object)]
pub struct NativeScanResult {
    pub findings: Vec<NativeFinding>,
    pub has_findings: bool,
    pub findings_truncated: bool,
}

#[napi(object)]
pub struct NativeStringRedactionResult {
    pub findings: Vec<NativeFinding>,
    pub redacted: String,
    pub has_findings: bool,
    pub findings_truncated: bool,
}

#[napi(object)]
pub struct NativeByteRedactionResult {
    pub findings: Vec<NativeFinding>,
    pub redacted: Buffer,
    pub has_findings: bool,
    pub findings_truncated: bool,
}

#[napi(object)]
pub struct NativeScanStats {
    pub files_scanned: f64,
    pub binary_skipped: f64,
    pub oversized_skipped: f64,
    pub files_over_cap: f64,
    pub errored: f64,
    pub git_fallback: bool,
    pub git_failed: bool,
    pub findings_truncated: bool,
}

#[napi(object)]
pub struct NativePathScanResult {
    pub findings: Vec<NativeFinding>,
    pub stats: NativeScanStats,
    pub incomplete: bool,
    pub has_findings: bool,
    pub findings_truncated: bool,
}

pub struct ByteRedactionParts {
    pub findings: Vec<NativeFinding>,
    pub redacted: Vec<u8>,
    pub has_findings: bool,
    pub findings_truncated: bool,
}

pub fn findings_to_native(findings: Vec<Finding>) -> Result<Vec<NativeFinding>> {
    findings.into_iter().map(finding_to_native).collect()
}

pub fn scan_result_to_native(result: ScanResult) -> Result<NativeScanResult> {
    let has_findings = result.has_findings();
    Ok(NativeScanResult {
        findings: findings_to_native(result.findings)?,
        has_findings,
        findings_truncated: result.findings_truncated,
    })
}

pub fn string_output_to_native(output: ScanOutput<String>) -> Result<NativeStringRedactionResult> {
    let has_findings = output.has_findings();
    Ok(NativeStringRedactionResult {
        findings: findings_to_native(output.findings)?,
        redacted: output.redacted,
        has_findings,
        findings_truncated: output.findings_truncated,
    })
}

pub fn byte_output_to_parts(output: ScanOutput<Vec<u8>>) -> Result<ByteRedactionParts> {
    let has_findings = output.has_findings();
    Ok(ByteRedactionParts {
        findings: findings_to_native(output.findings)?,
        redacted: output.redacted,
        has_findings,
        findings_truncated: output.findings_truncated,
    })
}

pub fn byte_parts_to_native(parts: ByteRedactionParts) -> NativeByteRedactionResult {
    NativeByteRedactionResult {
        findings: parts.findings,
        redacted: parts.redacted.into(),
        has_findings: parts.has_findings,
        findings_truncated: parts.findings_truncated,
    }
}

pub fn path_result_to_native(
    findings: Vec<Finding>,
    stats: ScanStats,
) -> Result<NativePathScanResult> {
    let has_findings = !findings.is_empty();
    let findings_truncated = stats.findings_truncated;
    let incomplete =
        stats.errored > 0 || stats.files_over_cap > 0 || stats.git_failed || stats.git_fallback;
    Ok(NativePathScanResult {
        findings: findings_to_native(findings)?,
        stats: stats_to_native(stats)?,
        incomplete,
        has_findings,
        findings_truncated,
    })
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
        commit: finding.commit,
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

fn stats_to_native(stats: ScanStats) -> Result<NativeScanStats> {
    Ok(NativeScanStats {
        files_scanned: to_js_number("filesScanned", stats.files_scanned)?,
        binary_skipped: to_js_number("binarySkipped", stats.binary_skipped)?,
        oversized_skipped: to_js_number("oversizedSkipped", stats.oversized_skipped)?,
        files_over_cap: to_js_number("filesOverCap", stats.files_over_cap)?,
        errored: to_js_number("errored", stats.errored)?,
        git_fallback: stats.git_fallback,
        git_failed: stats.git_failed,
        findings_truncated: stats.findings_truncated,
    })
}

pub fn to_js_number(field: &str, value: usize) -> Result<f64> {
    const MAX_SAFE_INTEGER: usize = 9_007_199_254_740_991;
    if value > MAX_SAFE_INTEGER {
        return Err(napi_error(
            "POSITION_OVERFLOW",
            &format!("{field} exceeds JavaScript's max safe integer"),
        ));
    }
    Ok(value as f64)
}

#[cfg(test)]
mod tests {
    use super::to_js_number;

    #[test]
    fn converts_positions_above_u32_without_clamping() {
        let value = u32::MAX as usize + 1;
        assert_eq!(
            to_js_number("startOffset", value).expect("number"),
            value as f64
        );
    }

    #[test]
    fn rejects_positions_above_js_safe_integer() {
        let err =
            to_js_number("startOffset", 9_007_199_254_740_992).expect_err("overflow should error");
        assert_eq!(err.status, napi::Status::GenericFailure);
        assert!(
            err.reason.contains("max safe integer"),
            "unexpected error: {err:?}"
        );
    }
}
