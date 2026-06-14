//! Fuzz target: feed arbitrary bytes to Scanner::scan_bytes.
//!
//! Ensures the scanner never panics on arbitrary input data.

#![no_main]

use libfuzzer_sys::fuzz_target;
use secrets_scanner::Scanner;

fuzz_target!(|data: &[u8]| {
    // Use from_bundled for reproducibility — it only uses compiled-in rules.
    let Ok(scanner) = Scanner::from_bundled() else {
        return;
    };
    let _findings = scanner.scan_bytes("fuzz.bin", data);
});
