use std::sync::Arc;

use napi::bindgen_prelude::{AsyncTask, Buffer, Result};
use napi_derive::napi;
use secrets_scanner::Scanner as RustScanner;

mod async_tasks;
mod config;
mod errors;
mod native_types;

use async_tasks::{
    PathTask, ProxyTask, RedactBytesTask, RedactContentTask, ScanBytesDetailedTask, ScanBytesTask,
    ScanContentDetailedTask, ScanContentTask,
};
use config::{config_to_rust, NativeScanConfig};
use errors::{ensure_input_within_limit, to_napi_error, to_napi_proxy_error};
use native_types::{
    byte_output_to_parts, byte_parts_to_native, findings_to_native, path_result_to_native,
    scan_result_to_native, string_output_to_native, NativeByteRedactionResult, NativeFinding,
    NativePathScanResult, NativeScanResult, NativeStringRedactionResult,
};

#[napi(js_name = "NativeScanner")]
pub struct NativeScanner {
    inner: Arc<RustScanner>,
    max_file_size: u64,
}

#[napi]
impl NativeScanner {
    #[napi(factory)]
    pub fn bundled(config: Option<NativeScanConfig>) -> Result<Self> {
        build_scanner(RustScanner::from_bundled, config)
    }

    #[napi(factory)]
    pub fn from_default_rules(config: Option<NativeScanConfig>) -> Result<Self> {
        build_scanner(RustScanner::new, config)
    }

    #[napi(factory)]
    pub fn from_rules_file(path: String, config: Option<NativeScanConfig>) -> Result<Self> {
        build_scanner(|| RustScanner::from_file(&path), config)
    }

    #[napi(factory)]
    pub fn from_toml(toml: String, config: Option<NativeScanConfig>) -> Result<Self> {
        build_scanner(|| RustScanner::from_toml(&toml), config)
    }

    #[napi]
    pub fn scan_content(&self, path: String, content: String) -> Result<Vec<NativeFinding>> {
        ensure_input_within_limit(content.len(), self.max_file_size)?;
        findings_to_native(self.inner.scan_content(&path, &content))
    }

    #[napi]
    pub fn scan_content_detailed(&self, path: String, content: String) -> Result<NativeScanResult> {
        ensure_input_within_limit(content.len(), self.max_file_size)?;
        scan_result_to_native(self.inner.scan_content_detailed(&path, &content))
    }

    #[napi]
    pub fn scan_and_redact_content(
        &self,
        path: String,
        content: String,
    ) -> Result<NativeStringRedactionResult> {
        ensure_input_within_limit(content.len(), self.max_file_size)?;
        string_output_to_native(self.inner.scan_and_redact_content(&path, &content))
    }

    #[napi]
    pub fn scan_bytes(&self, path: String, content: Buffer) -> Result<Vec<NativeFinding>> {
        ensure_input_within_limit(content.len(), self.max_file_size)?;
        findings_to_native(self.inner.scan_bytes(&path, &content))
    }

    #[napi]
    pub fn scan_bytes_detailed(&self, path: String, content: Buffer) -> Result<NativeScanResult> {
        ensure_input_within_limit(content.len(), self.max_file_size)?;
        scan_result_to_native(self.inner.scan_bytes_detailed(&path, &content))
    }

    #[napi]
    pub fn scan_and_redact_bytes(
        &self,
        path: String,
        content: Buffer,
    ) -> Result<NativeByteRedactionResult> {
        ensure_input_within_limit(content.len(), self.max_file_size)?;
        let parts = byte_output_to_parts(self.inner.scan_and_redact_bytes(&path, &content))?;
        Ok(byte_parts_to_native(parts))
    }

    #[napi]
    pub fn scan_proxy(&self, content: Buffer) -> Result<NativeByteRedactionResult> {
        let output = self
            .inner
            .scan_proxy(&content)
            .map_err(to_napi_proxy_error)?;
        Ok(byte_parts_to_native(byte_output_to_parts(output)?))
    }

    #[napi]
    pub fn scan_file(&self, path: String) -> Result<NativePathScanResult> {
        let (findings, stats) = self.inner.scan_file_with_stats(&path);
        path_result_to_native(findings, stats)
    }

    #[napi]
    pub fn scan_path(&self, path: String) -> Result<NativePathScanResult> {
        let (findings, stats) = self.inner.scan_path_with_stats(&path);
        path_result_to_native(findings, stats)
    }

    #[napi]
    pub fn scan_content_async(&self, path: String, content: String) -> AsyncTask<ScanContentTask> {
        AsyncTask::new(ScanContentTask {
            scanner: Arc::clone(&self.inner),
            path,
            content,
            max_file_size: self.max_file_size,
        })
    }

    #[napi]
    pub fn scan_content_detailed_async(
        &self,
        path: String,
        content: String,
    ) -> AsyncTask<ScanContentDetailedTask> {
        AsyncTask::new(ScanContentDetailedTask {
            scanner: Arc::clone(&self.inner),
            path,
            content,
            max_file_size: self.max_file_size,
        })
    }

    #[napi]
    pub fn scan_and_redact_content_async(
        &self,
        path: String,
        content: String,
    ) -> AsyncTask<RedactContentTask> {
        AsyncTask::new(RedactContentTask {
            scanner: Arc::clone(&self.inner),
            path,
            content,
            max_file_size: self.max_file_size,
        })
    }

    #[napi]
    pub fn scan_bytes_async(&self, path: String, content: Buffer) -> AsyncTask<ScanBytesTask> {
        AsyncTask::new(ScanBytesTask {
            scanner: Arc::clone(&self.inner),
            path,
            content: content.to_vec(),
            max_file_size: self.max_file_size,
        })
    }

    #[napi]
    pub fn scan_bytes_detailed_async(
        &self,
        path: String,
        content: Buffer,
    ) -> AsyncTask<ScanBytesDetailedTask> {
        AsyncTask::new(ScanBytesDetailedTask {
            scanner: Arc::clone(&self.inner),
            path,
            content: content.to_vec(),
            max_file_size: self.max_file_size,
        })
    }

    #[napi]
    pub fn scan_and_redact_bytes_async(
        &self,
        path: String,
        content: Buffer,
    ) -> AsyncTask<RedactBytesTask> {
        AsyncTask::new(RedactBytesTask {
            scanner: Arc::clone(&self.inner),
            path,
            content: content.to_vec(),
            max_file_size: self.max_file_size,
        })
    }

    #[napi]
    pub fn scan_proxy_async(&self, content: Buffer) -> AsyncTask<ProxyTask> {
        AsyncTask::new(ProxyTask {
            scanner: Arc::clone(&self.inner),
            content: content.to_vec(),
        })
    }

    #[napi]
    pub fn scan_file_async(&self, path: String) -> AsyncTask<PathTask> {
        AsyncTask::new(PathTask {
            scanner: Arc::clone(&self.inner),
            path,
            file_only: true,
        })
    }

    #[napi]
    pub fn scan_path_async(&self, path: String) -> AsyncTask<PathTask> {
        AsyncTask::new(PathTask {
            scanner: Arc::clone(&self.inner),
            path,
            file_only: false,
        })
    }
}

fn build_scanner(
    build: impl FnOnce() -> std::result::Result<RustScanner, secrets_scanner::ScannerError>,
    config: Option<NativeScanConfig>,
) -> Result<NativeScanner> {
    let rust_config = config_to_rust(config)?;
    let max_file_size = rust_config.max_file_size;
    let scanner = build().map_err(to_napi_error)?.with_config(rust_config);
    Ok(NativeScanner {
        inner: Arc::new(scanner),
        max_file_size,
    })
}
