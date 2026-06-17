//! Browser and edge WebAssembly bindings for in-memory secrets scanning.

use js_sys::Uint8Array;
use secrets_scanner::Scanner as RustScanner;
use wasm_bindgen::prelude::*;

mod config;
mod error;
mod value;

use config::{config_to_rust, ConfigMode};
use error::{input_too_large, proxy_error, scanner_error};
use value::{byte_output_to_js, findings_to_js, scan_output_to_js, scan_result_to_js};

/// In-memory secrets scanner exposed to JavaScript through WebAssembly.
#[wasm_bindgen]
pub struct Scanner {
    inner: RustScanner,
    max_file_size: u64,
}

#[wasm_bindgen]
impl Scanner {
    /// Create a scanner from the bundled ruleset.
    #[wasm_bindgen]
    pub fn bundled(config: Option<JsValue>) -> Result<Scanner, JsValue> {
        build_scanner(RustScanner::from_bundled, config, ConfigMode::Normal)
    }

    /// Create a scanner from a TOML ruleset string.
    #[wasm_bindgen(js_name = fromToml)]
    pub fn from_toml(toml: &str, config: Option<JsValue>) -> Result<Scanner, JsValue> {
        build_scanner(|| RustScanner::from_toml(toml), config, ConfigMode::Normal)
    }

    /// Create a hardened bundled-rules scanner for untrusted payload redaction.
    #[wasm_bindgen]
    pub fn proxy(config: Option<JsValue>) -> Result<Scanner, JsValue> {
        build_scanner(RustScanner::from_bundled, config, ConfigMode::Proxy)
    }

    /// Scan UTF-8 content and return finding objects.
    #[wasm_bindgen(js_name = scanContent)]
    pub fn scan_content(&self, path: &str, content: &str) -> Result<JsValue, JsValue> {
        ensure_input_within_limit(content.len(), self.max_file_size)?;
        findings_to_js(self.inner.scan_content(path, content))
    }

    /// Scan UTF-8 content and return findings plus truncation metadata.
    #[wasm_bindgen(js_name = scanContentDetailed)]
    pub fn scan_content_detailed(&self, path: &str, content: &str) -> Result<JsValue, JsValue> {
        ensure_input_within_limit(content.len(), self.max_file_size)?;
        scan_result_to_js(self.inner.scan_content_detailed(path, content))
    }

    /// Scan UTF-8 content and return findings plus redacted content.
    #[wasm_bindgen(js_name = scanAndRedactContent)]
    pub fn scan_and_redact_content(&self, path: &str, content: &str) -> Result<JsValue, JsValue> {
        ensure_input_within_limit(content.len(), self.max_file_size)?;
        scan_output_to_js(self.inner.scan_and_redact_content(path, content))
    }

    /// Scan bytes and return finding objects.
    #[wasm_bindgen(js_name = scanBytes)]
    pub fn scan_bytes(&self, path: &str, content: Uint8Array) -> Result<JsValue, JsValue> {
        ensure_input_within_limit(content.length() as usize, self.max_file_size)?;
        let bytes = content.to_vec();
        findings_to_js(self.inner.scan_bytes(path, &bytes))
    }

    /// Redact an untrusted byte payload with hardened proxy settings.
    #[wasm_bindgen(js_name = scanProxy)]
    pub fn scan_proxy(&self, content: Uint8Array) -> Result<JsValue, JsValue> {
        ensure_input_within_limit(content.length() as usize, self.max_file_size)?;
        let bytes = content.to_vec();
        self.inner
            .scan_proxy(&bytes)
            .map_err(proxy_error)
            .and_then(byte_output_to_js)
    }
}

fn build_scanner(
    build: impl FnOnce() -> Result<RustScanner, secrets_scanner::ScannerError>,
    config: Option<JsValue>,
    mode: ConfigMode,
) -> Result<Scanner, JsValue> {
    let rust_config = config_to_rust(config, mode)?;
    let max_file_size = rust_config.max_file_size;
    let scanner = build().map_err(scanner_error)?.with_config(rust_config);
    Ok(Scanner {
        inner: scanner,
        max_file_size,
    })
}

fn ensure_input_within_limit(size: usize, max: u64) -> Result<(), JsValue> {
    if size as u64 > max {
        Err(input_too_large(size, max))
    } else {
        Ok(())
    }
}
