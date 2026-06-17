use js_sys::{Array, Object, Reflect, Uint8Array};
use secrets_scanner::{Finding, ScanOutput, ScanResult};
use wasm_bindgen::prelude::*;

use crate::error::js_error;

const JS_MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

pub fn findings_to_js(findings: Vec<Finding>) -> Result<JsValue, JsValue> {
    let array = Array::new();
    for finding in findings {
        array.push(&finding_to_js(finding)?);
    }
    Ok(array.into())
}

pub fn scan_result_to_js(result: ScanResult) -> Result<JsValue, JsValue> {
    let object = Object::new();
    let has_findings = result.has_findings();
    set_value(&object, "findings", &findings_to_js(result.findings)?)?;
    set_bool(&object, "hasFindings", has_findings)?;
    set_bool(&object, "findingsTruncated", result.findings_truncated)?;
    Ok(object.into())
}

pub fn scan_output_to_js(output: ScanOutput<String>) -> Result<JsValue, JsValue> {
    let object = Object::new();
    let has_findings = output.has_findings();
    set_value(&object, "findings", &findings_to_js(output.findings)?)?;
    set_str(&object, "redacted", &output.redacted)?;
    set_bool(&object, "hasFindings", has_findings)?;
    set_bool(&object, "findingsTruncated", output.findings_truncated)?;
    Ok(object.into())
}

pub fn byte_output_to_js(output: ScanOutput<Vec<u8>>) -> Result<JsValue, JsValue> {
    let object = Object::new();
    let has_findings = output.has_findings();
    set_value(&object, "findings", &findings_to_js(output.findings)?)?;
    set_value(&object, "redacted", &uint8_array(output.redacted)?)?;
    set_bool(&object, "hasFindings", has_findings)?;
    set_bool(&object, "findingsTruncated", output.findings_truncated)?;
    Ok(object.into())
}

fn finding_to_js(finding: Finding) -> Result<JsValue, JsValue> {
    let object = Object::new();
    set_str(&object, "file", &finding.file)?;
    set_usize(&object, "line", finding.line)?;
    set_usize(&object, "col", finding.col)?;
    set_usize(&object, "endLine", finding.end_line)?;
    set_usize(&object, "endCol", finding.end_col)?;
    set_usize(&object, "colUtf16", finding.col_utf16)?;
    set_usize(&object, "endColUtf16", finding.end_col_utf16)?;
    set_str(&object, "ruleId", &finding.rule_id)?;
    set_str(&object, "description", &finding.rule_description)?;
    set_str(&object, "matched", &finding.matched)?;
    set_num(&object, "entropy", finding.entropy)?;
    set_usize(&object, "startOffset", finding.start_offset)?;
    set_usize(&object, "endOffset", finding.end_offset)?;
    set_usize(&object, "secretStartOffset", finding.secret_start_offset)?;
    set_usize(&object, "secretEndOffset", finding.secret_end_offset)?;
    set_str(&object, "fingerprint", &finding.fingerprint)?;
    if let Some(commit) = finding.commit {
        set_str(&object, "commit", &commit)?;
    }
    set_value(
        &object,
        "contextLines",
        &context_lines_to_js(finding.context_lines)?,
    )?;
    Ok(object.into())
}

fn context_lines_to_js(context_lines: Vec<(usize, String)>) -> Result<JsValue, JsValue> {
    let array = Array::new();
    for (line, content) in context_lines {
        let object = Object::new();
        set_usize(&object, "line", line)?;
        set_str(&object, "content", &content)?;
        array.push(&object);
    }
    Ok(array.into())
}

fn uint8_array(bytes: Vec<u8>) -> Result<JsValue, JsValue> {
    let len: u32 = bytes
        .len()
        .try_into()
        .map_err(|_| js_error("POSITION_OVERFLOW", "redacted byte output is too large"))?;
    let array = Uint8Array::new_with_length(len);
    array.copy_from(&bytes);
    Ok(array.into())
}

fn set_bool(object: &Object, key: &str, value: bool) -> Result<(), JsValue> {
    set_value(object, key, &JsValue::from_bool(value))
}

fn set_num(object: &Object, key: &str, value: f64) -> Result<(), JsValue> {
    set_value(object, key, &JsValue::from_f64(value))
}

fn set_str(object: &Object, key: &str, value: &str) -> Result<(), JsValue> {
    set_value(object, key, &JsValue::from_str(value))
}

fn set_usize(object: &Object, key: &str, value: usize) -> Result<(), JsValue> {
    if value as f64 > JS_MAX_SAFE_INTEGER {
        return Err(js_error(
            "POSITION_OVERFLOW",
            &format!("{key} exceeds JavaScript's max safe integer"),
        ));
    }
    set_num(object, key, value as f64)
}

fn set_value(object: &Object, key: &str, value: &JsValue) -> Result<(), JsValue> {
    let ok = Reflect::set(object, &JsValue::from_str(key), value)
        .map_err(|_| js_error("NATIVE_ERROR", "failed to construct JavaScript result"))?;
    if ok {
        Ok(())
    } else {
        Err(js_error(
            "NATIVE_ERROR",
            "JavaScript result object rejected a property write",
        ))
    }
}
