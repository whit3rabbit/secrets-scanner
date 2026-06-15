use napi::{Error, Status};
use secrets_scanner::{ProxyError, ScannerError};

pub fn to_napi_error(error: ScannerError) -> Error {
    match error {
        ScannerError::InvalidRules(issues) => napi_error_with_details(
            "INVALID_RULES",
            "invalid scanner rules",
            &format!("{{\"issues\":{}}}", json_string_array(&issues)),
        ),
        ScannerError::Toml(_) => napi_error("INVALID_RULES_TOML", "invalid scanner rules TOML"),
        ScannerError::Io(_) => napi_error("IO", "scanner rules could not be read"),
        ScannerError::AhoCorasick(_) => {
            napi_error("ENGINE_BUILD", "scanner engine could not be built")
        }
    }
}

pub fn to_napi_proxy_error(error: ProxyError) -> Error {
    match error {
        ProxyError::InputTooLarge { size, max } => input_too_large_error(size, max),
        ProxyError::NotHardened => napi_error(
            "NOT_HARDENED",
            "scanner is not hardened for proxy use; build it with the proxy config \
             (e.g. Scanner.proxy())",
        ),
    }
}

pub fn input_too_large_error(size: usize, max: u64) -> Error {
    napi_error_with_details(
        "INPUT_TOO_LARGE",
        "input exceeds configured maxFileSize",
        &format!("{{\"size\":{size},\"maxFileSize\":{max}}}"),
    )
}

pub fn ensure_input_within_limit(size: usize, max: u64) -> Result<(), Error> {
    if size as u64 > max {
        return Err(input_too_large_error(size, max));
    }
    Ok(())
}

pub fn napi_error(code: &str, message: &str) -> Error {
    Error::new(Status::GenericFailure, format!("{code}: {message}"))
}

fn napi_error_with_details(code: &str, message: &str, details: &str) -> Error {
    Error::new(
        Status::GenericFailure,
        format!("{code}: {message}; details={details}"),
    )
}

fn json_string_array(values: &[String]) -> String {
    let mut out = String::from("[");
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&json_escape(value));
        out.push('"');
    }
    out.push(']');
    out
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::input_too_large_error;

    #[test]
    fn input_too_large_error_contains_safe_details() {
        let err = input_too_large_error(12, 8);
        assert!(err.reason.contains("INPUT_TOO_LARGE:"));
        assert!(err.reason.contains("\"size\":12"));
        assert!(err.reason.contains("\"maxFileSize\":8"));
    }
}
