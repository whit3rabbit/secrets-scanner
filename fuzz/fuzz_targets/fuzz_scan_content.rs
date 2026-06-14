//! Fuzz target: feed arbitrary UTF-8 content to Scanner::scan_content.
//!
//! Tests that valid UTF-8 (even garbage) never causes a panic in the
//! string-based scan entry point.

#![no_main]

use libfuzzer_sys::fuzz_target;
use secrets_scanner::Scanner;

fuzz_target!(|data: &str| {
    let Ok(scanner) = Scanner::from_bundled() else {
        return;
    };
    let _findings = scanner.scan_content("fuzz.txt", data);
});
