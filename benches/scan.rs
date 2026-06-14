//! Benchmark harness for secrets-scanner.
//!
//! Measures rule engine construction and scanning throughput
//! over representative file sizes and contents.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use secrets_scanner::rules::merge::{merge_sources, MergeSource};
use secrets_scanner::{ScanConfig, Scanner};

// ── incremental-ruleset benchmarks ──────────────────────────────────────────
// Compare scan/build cost as each ruleset is layered on: core (gitleaks+local),
// then +kingfisher (the lean default), then +secrets-patterns-db (full). The
// merge priorities mirror assets/sources.toml so dedup behaves identically.

/// One source file + its manifest priority, relative to the crate root.
struct Source {
    name: &'static str,
    file: &'static str,
    priority: i64,
}

const LOCAL: Source = Source {
    name: "local",
    file: "assets/local.toml",
    priority: 100,
};
const GITLEAKS: Source = Source {
    name: "gitleaks",
    file: "assets/gitleaks.toml",
    priority: 10,
};
const KINGFISHER: Source = Source {
    name: "kingfisher",
    file: "assets/kingfisher-rules.toml",
    priority: 7,
};
const SPDB: Source = Source {
    name: "spdb",
    file: "assets/secrets-patterns-db.toml",
    priority: 5,
};

/// The three cumulative ruleset configurations, smallest first.
fn ruleset_configs() -> Vec<(&'static str, Vec<Source>)> {
    vec![
        ("core", vec![LOCAL, GITLEAKS]),
        ("core+kingfisher", vec![LOCAL, GITLEAKS, KINGFISHER]),
        ("full", vec![LOCAL, GITLEAKS, KINGFISHER, SPDB]),
    ]
}

/// Merge the given sources into a single ruleset TOML, the same way build.rs does.
fn merge_ruleset(sources: &[Source]) -> String {
    let inputs: Vec<MergeSource> = sources
        .iter()
        .map(|s| {
            let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), s.file);
            let toml =
                std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
            MergeSource {
                name: s.name.to_string(),
                priority: s.priority,
                toml,
            }
        })
        .collect();
    let (merged, _report) = merge_sources(inputs).expect("merge should succeed");
    merged
}

/// Representative ~8KB corpus: mostly benign config, two planted secrets.
fn corpus() -> String {
    let mut content = String::with_capacity(8192);
    for i in 0..200 {
        content.push_str(&format!(
            "line_{i}: some benign configuration value = {i}\n"
        ));
    }
    content.push_str("export GITHUB_TOKEN=ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde\n");
    content.push_str("ably_key = appid123.keyid987:AbCdEfGhIjKlMnOpQrStUvWx\n");
    content
}

/// Engine construction (regex compilation) cost as rulesets are layered on.
fn bench_ruleset_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("ruleset/build");
    for (label, sources) in ruleset_configs() {
        let merged = merge_ruleset(&sources);
        group.bench_with_input(BenchmarkId::from_parameter(label), &merged, |b, toml| {
            b.iter(|| {
                let scanner = Scanner::from_toml(black_box(toml)).expect("build");
                black_box(scanner);
            });
        });
    }
    group.finish();
}

/// Scan throughput on a fixed corpus as rulesets are layered on (keyword-gate +
/// regex cost). Throughput is reported in bytes so larger rulesets are comparable.
fn bench_ruleset_scan(c: &mut Criterion) {
    let content = corpus();
    let mut group = c.benchmark_group("ruleset/scan");
    group.throughput(Throughput::Bytes(content.len() as u64));
    for (label, sources) in ruleset_configs() {
        let scanner = Scanner::from_toml(&merge_ruleset(&sources))
            .expect("build")
            .with_config(ScanConfig {
                redact: false,
                ..Default::default()
            });
        group.bench_with_input(BenchmarkId::from_parameter(label), &content, |b, c| {
            b.iter(|| {
                let findings = scanner.scan_content(black_box("corpus.txt"), black_box(c));
                black_box(findings);
            });
        });
    }
    group.finish();
}

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
criterion_group!(
    name = rulesets;
    config = Criterion::default().significance_level(0.02);
    targets = bench_ruleset_build, bench_ruleset_scan
);
criterion_main!(scan, rulesets);
