//! Benchmark harness for secrets-scanner.
//!
//! Measures rule engine construction and scanning throughput
//! over representative file sizes and contents.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use secrets_scanner::{ScanConfig, Scanner};

/// Benchmark construction of the scanner from bundled rules.
fn bench_scanner_new(c: &mut Criterion) {
    c.bench_function("scanner/from_bundled", |b| {
        b.iter(|| {
            let scanner = Scanner::from_bundled().expect("bundled rules should load");
            black_box(scanner);
        });
    });
}

/// Benchmark scanning a small file with a planted secret.
fn bench_scan_small_file(c: &mut Criterion) {
    let scanner = Scanner::from_bundled()
        .expect("bundled rules should load")
        .with_config(ScanConfig {
            redact: false,
            ..Default::default()
        });

    let content = "export GITHUB_TOKEN=ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde\n";

    c.bench_function("scan/small_file", |b| {
        b.iter(|| {
            let findings = scanner.scan_content(black_box("test.sh"), black_box(content));
            black_box(findings);
        });
    });
}

/// Benchmark scanning a medium file with multiple secrets.
fn bench_scan_medium_file(c: &mut Criterion) {
    let scanner = Scanner::from_bundled()
        .expect("bundled rules should load")
        .with_config(ScanConfig {
            redact: false,
            ..Default::default()
        });

    // Build ~1KB of content with a secret embedded
    let mut content = String::with_capacity(1024);
    for _ in 0..20 {
        content.push_str("some_config_key = \"normal_value\"\n");
    }
    content.push_str("export GITHUB_TOKEN=ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde\n");
    for _ in 0..20 {
        content.push_str("another_normal_key = 42\n");
    }

    c.bench_function("scan/medium_file", |b| {
        b.iter(|| {
            let findings = scanner.scan_content(black_box("config.sh"), black_box(&content));
            black_box(findings);
        });
    });
}

/// Benchmark scanning a large file (10KB) with no secrets to measure the keyword gate.
fn bench_scan_large_file_no_secrets(c: &mut Criterion) {
    let scanner = Scanner::from_bundled()
        .expect("bundled rules should load")
        .with_config(ScanConfig {
            redact: false,
            ..Default::default()
        });

    let mut content = String::with_capacity(10_240);
    for i in 0..256 {
        content.push_str(&format!("line_{i}: some benign configuration value\n"));
    }

    c.bench_function("scan/large_no_secrets", |b| {
        b.iter(|| {
            let findings = scanner.scan_content(black_box("large.txt"), black_box(&content));
            black_box(findings);
        });
    });
}

criterion_group!(
    name = scan;
    config = Criterion::default().significance_level(0.02);
    targets = bench_scanner_new, bench_scan_small_file, bench_scan_medium_file, bench_scan_large_file_no_secrets
);
criterion_main!(scan);
