use std::sync::Arc;

use napi::bindgen_prelude::Result;
use napi::{Env, Task};
use secrets_scanner::Scanner as RustScanner;

use crate::errors::{ensure_input_within_limit, to_napi_proxy_error};
use crate::native_types::{
    byte_output_to_parts, byte_parts_to_native, findings_to_native, path_result_to_native,
    scan_result_to_native, string_output_to_native, ByteRedactionParts, NativeByteRedactionResult,
    NativeFinding, NativePathScanResult, NativeScanResult, NativeStringRedactionResult,
};

pub struct ScanContentTask {
    pub scanner: Arc<RustScanner>,
    pub path: String,
    pub content: String,
    pub max_file_size: u64,
}

impl Task for ScanContentTask {
    type Output = Vec<NativeFinding>;
    type JsValue = Vec<NativeFinding>;

    fn compute(&mut self) -> Result<Self::Output> {
        ensure_input_within_limit(self.content.len(), self.max_file_size)?;
        findings_to_native(self.scanner.scan_content(&self.path, &self.content))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct ScanContentDetailedTask {
    pub scanner: Arc<RustScanner>,
    pub path: String,
    pub content: String,
    pub max_file_size: u64,
}

impl Task for ScanContentDetailedTask {
    type Output = NativeScanResult;
    type JsValue = NativeScanResult;

    fn compute(&mut self) -> Result<Self::Output> {
        ensure_input_within_limit(self.content.len(), self.max_file_size)?;
        scan_result_to_native(
            self.scanner
                .scan_content_detailed(&self.path, &self.content),
        )
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct RedactContentTask {
    pub scanner: Arc<RustScanner>,
    pub path: String,
    pub content: String,
    pub max_file_size: u64,
}

impl Task for RedactContentTask {
    type Output = NativeStringRedactionResult;
    type JsValue = NativeStringRedactionResult;

    fn compute(&mut self) -> Result<Self::Output> {
        ensure_input_within_limit(self.content.len(), self.max_file_size)?;
        string_output_to_native(
            self.scanner
                .scan_and_redact_content(&self.path, &self.content),
        )
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct ScanBytesTask {
    pub scanner: Arc<RustScanner>,
    pub path: String,
    pub content: Vec<u8>,
    pub max_file_size: u64,
}

impl Task for ScanBytesTask {
    type Output = Vec<NativeFinding>;
    type JsValue = Vec<NativeFinding>;

    fn compute(&mut self) -> Result<Self::Output> {
        ensure_input_within_limit(self.content.len(), self.max_file_size)?;
        findings_to_native(self.scanner.scan_bytes(&self.path, &self.content))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct ScanBytesDetailedTask {
    pub scanner: Arc<RustScanner>,
    pub path: String,
    pub content: Vec<u8>,
    pub max_file_size: u64,
}

impl Task for ScanBytesDetailedTask {
    type Output = NativeScanResult;
    type JsValue = NativeScanResult;

    fn compute(&mut self) -> Result<Self::Output> {
        ensure_input_within_limit(self.content.len(), self.max_file_size)?;
        scan_result_to_native(self.scanner.scan_bytes_detailed(&self.path, &self.content))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct RedactBytesTask {
    pub scanner: Arc<RustScanner>,
    pub path: String,
    pub content: Vec<u8>,
    pub max_file_size: u64,
}

impl Task for RedactBytesTask {
    type Output = ByteRedactionParts;
    type JsValue = NativeByteRedactionResult;

    fn compute(&mut self) -> Result<Self::Output> {
        ensure_input_within_limit(self.content.len(), self.max_file_size)?;
        byte_output_to_parts(
            self.scanner
                .scan_and_redact_bytes(&self.path, &self.content),
        )
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(byte_parts_to_native(output))
    }
}

pub struct ProxyTask {
    pub scanner: Arc<RustScanner>,
    pub content: Vec<u8>,
}

impl Task for ProxyTask {
    type Output = ByteRedactionParts;
    type JsValue = NativeByteRedactionResult;

    fn compute(&mut self) -> Result<Self::Output> {
        let output = self
            .scanner
            .scan_proxy(&self.content)
            .map_err(to_napi_proxy_error)?;
        byte_output_to_parts(output)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(byte_parts_to_native(output))
    }
}

pub struct PathTask {
    pub scanner: Arc<RustScanner>,
    pub path: String,
    pub file_only: bool,
}

impl Task for PathTask {
    type Output = NativePathScanResult;
    type JsValue = NativePathScanResult;

    fn compute(&mut self) -> Result<Self::Output> {
        let (findings, stats) = if self.file_only {
            self.scanner.scan_file_with_stats(&self.path)
        } else {
            self.scanner.scan_path_with_stats(&self.path)
        };
        path_result_to_native(findings, stats)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}
