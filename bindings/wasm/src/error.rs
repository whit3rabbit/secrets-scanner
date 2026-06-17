use js_sys::{Error, Reflect};
use secrets_scanner::{ProxyError, ScannerError};
use wasm_bindgen::prelude::*;

pub fn scanner_error(error: ScannerError) -> JsValue {
    match error {
        ScannerError::InvalidRules(issues) => js_error_with_details(
            "INVALID_RULES",
            "invalid scanner rules",
            Some(format!("[{}]", issues.join(","))),
        ),
        ScannerError::Toml(_) => js_error("INVALID_RULES_TOML", "invalid scanner rules TOML"),
        ScannerError::Io(_) => js_error("IO", "scanner rules could not be read"),
        ScannerError::AhoCorasick(_) => {
            js_error("ENGINE_BUILD", "scanner engine could not be built")
        }
    }
}

pub fn proxy_error(error: ProxyError) -> JsValue {
    match error {
        ProxyError::InputTooLarge { size, max } => js_error_with_details(
            "INPUT_TOO_LARGE",
            "input exceeds configured maxFileSize",
            Some(format!("{{\"size\":{size},\"maxFileSize\":{max}}}")),
        ),
        ProxyError::NotHardened => js_error(
            "NOT_HARDENED",
            "scanner is not hardened for proxy use; use Scanner.proxy()",
        ),
    }
}

pub fn input_too_large(size: usize, max: u64) -> JsValue {
    js_error_with_details(
        "INPUT_TOO_LARGE",
        "input exceeds configured maxFileSize",
        Some(format!("{{\"size\":{size},\"maxFileSize\":{max}}}")),
    )
}

pub fn js_error(code: &str, message: &str) -> JsValue {
    js_error_with_details(code, message, None)
}

fn js_error_with_details(code: &str, message: &str, details: Option<String>) -> JsValue {
    let error = Error::new(message);
    let value = JsValue::from(error);
    let _ = Reflect::set(&value, &JsValue::from_str("code"), &JsValue::from_str(code));
    if let Some(details) = details {
        let _ = Reflect::set(
            &value,
            &JsValue::from_str("details"),
            &JsValue::from_str(&details),
        );
    }
    value
}
