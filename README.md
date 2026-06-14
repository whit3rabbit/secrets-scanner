# secrets-scanner

A high-performance Rust library and CLI for detecting leaked secrets in source code, configuration files, and pipelines.

[![CI](https://github.com/whit3rabbit/secrets-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/whit3rabbit/secrets-scanner/actions/workflows/ci.yml)

---

## Features

- **Multi-layer pipeline**: memchr SIMD → Aho-Corasick → Shannon entropy → Regex
- **200+ rules** based on [gitleaks](https://github.com/gitleaks/gitleaks), plus custom rules
- **Parallel scanning** via rayon (uses all CPU cores)
- **Flexible output**: text, JSON, JSONL, SARIF (GitHub Code Scanning)
- **CI-ready exit codes**: `0` = clean, `1` = findings, `2` = error
- **Runtime rule updates** without recompiling (optional `updater` feature)
- **Custom rules** in the same TOML format as gitleaks
- **Git-aware scanning**: `--git` (tracked files) or `--git-diff` (changed files)
- **Baseline suppression**: `--baseline` to suppress known findings from prior scans
- **Context lines**: `context_lines` field in findings with surrounding lines (±2)
- **Shell completions**: `completions bash|zsh|fish|...

---

## Quick Start

### Binary (CLI)

```bash
# Build (lean release binary, no runtime updater)
cargo build --release

# Scan the current directory
./target/release/secrets-scanner scan .

# Scan specific paths
./target/release/secrets-scanner scan src/ config/ .env

# Output as JSON
./target/release/secrets-scanner scan --format json . > findings.json

# Output as SARIF for GitHub Code Scanning
./target/release/secrets-scanner scan --format sarif . > results.sarif
```

### Library

```rust
use secrets_scanner::{Finding, ScanConfig, ScanOutput, Scanner};

// Load rules (three-tier priority: env var -> cached -> bundled)
let scanner = Scanner::new()?;

// Scan a directory tree (parallel)
let findings = scanner.scan_path("./src");

// Or scan in-memory content (e.g. in an LLM pipeline proxy)
let content = "export TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234567";
let output = scanner.scan_and_redact_content("deploy.sh", content);

if output.has_findings() {
    // Decide whether to block, audit, or forward output.redacted.
}

for f in &output.findings {
    println!("{}:{} [{}] {}", f.file, f.line, f.rule_id, f.matched);
}
```

---

## Installation

```bash
# From source
cargo install --path .

# Or with the runtime rule-updater feature
cargo install --path . --features updater
```

---

## CLI Reference

```
secrets-scanner <SUBCOMMAND>

Subcommands:
  scan            Scan files/directories for secrets
  update-rules    Download the latest gitleaks ruleset
  validate-rules  Validate TOML rules files
  list-rules      List all loaded rules
  completions     Generate shell completions

scan options:
  [PATHS...]                Files or directories to scan (default: .)
  --format <FORMAT>         text | json | jsonl | sarif  [default: text]
  --no-redact               Show raw matched secrets (not redacted)
  --rules <PATH>            Load rules from this TOML file
  --ignore-rule <ID>        Suppress a specific rule (repeatable)
  --min-entropy <FLOAT>     Override the global entropy floor
  --max-file-size <BYTES>   Skip files larger than this (default: 2MB)
  --baseline <FILE>         Suppress findings present in a prior JSON output
  --git                     Only scan files tracked by git
  --git-diff                Only scan files changed since the last commit

update-rules options:
  --check                   Report update availability without downloading
  --url <URL>               Pull from a custom URL or private mirror

validate-rules [FILES...]   Validate TOML rules (default: bundled assets)
list-rules [--rules <PATH>] List all rules from a TOML file or default rules
completions <SHELL>         Generate shell completions (bash/zsh/fish/powershell/elvish)
```

---

## Scan Pipeline

```
File bytes
   │
   ▼
[memchr SIMD]  ← skips keyworded-rule lookup when no keyword first bytes appear
   │
   ▼
[Aho-Corasick] ← single O(n) pass, finds ALL keyword hits simultaneously
   │
   ▼
[Entropy check] ← rejects "password = changeme", keeps high-randomness strings
   │
   ▼
[Regex]        ← validates structure across candidate content
   │
   ▼
Finding { file, line, rule_id, matched (redacted), entropy }
```

---

## Custom Rules (`assets/local.toml`)

Add your own detection rules in the same format as gitleaks. They are merged with the upstream ruleset at build time and custom rules take precedence.

```toml
title = "local custom rules"

[[rules]]
id = "my-internal-api-key"
description = "Internal API key for Example Corp services"
# Detection regex — applied after keyword pre-screening marks the rule as a candidate
regex = 'MYCO_[A-Za-z0-9]{32,64}'
# Keywords fed into the Aho-Corasick pre-filter (lowercase)
keywords = ["myco_"]
# Optional: only fire on specific entropy (bits/byte)
entropy = 3.5
# Optional: only apply this rule to matching file paths
# path = '\.env$'

# Optional: allowlist — suppress the finding in specific cases
[[rules.allowlists]]
description = "Ignore test fixtures"
paths = ['test_fixtures/', '_test\.go$']
stopwords = ["example", "placeholder", "changeme"]
regexes = ['^MYCO_0{32}']
```

### Rule format reference

| Field | Type | Description |
|---|---|---|
| `id` | string | **Required.** Unique rule identifier. |
| `description` | string | Human-readable description. |
| `regex` | string | Detection regex (Rust `regex` crate syntax). |
| `keywords` | `[string]` | Keywords for Aho-Corasick pre-filter (fast path). |
| `entropy` | float | Minimum Shannon entropy for the secret portion. |
| `path` | string | Regex — only apply to files whose path matches. |
| `secretGroup` | int | Capture group index to use as the "secret" for entropy/redaction (default: 1). |
| `[[rules.allowlists]]` | array | Per-rule suppress conditions. |
| `allowlists[].paths` | `[string]` | Suppress if the file path matches any pattern. |
| `allowlists[].stopwords` | `[string]` | Suppress if the matched text contains any word. |
| `allowlists[].regexes` | `[string]` | Suppress if the matched text matches any pattern. |

---

## Rule Updates

### Build-time (updates the committed `assets/gitleaks.toml`)

```bash
# Download latest upstream rules
./scripts/update_rules.sh

# Or via Makefile
make update-rules

# Check if an update is available (exit 1 = update available)
make check-rules
```

### Kingfisher import (separate YAML artifact)

Kingfisher rules are imported as `assets/kingfisher-rules.yml`. This file is
kept separate from the gitleaks-compatible TOML rules.

```bash
# Clone Kingfisher, deduplicate by rule id, and write the artifact
python3 scripts/update_kingfisher_rules.py

# Check whether the committed artifact is current
python3 scripts/update_kingfisher_rules.py --check
```

### Runtime (no recompile, requires `--features updater`)

```bash
# Build with the updater feature
cargo build --features updater

# Download and cache rules to OS data dir
./target/debug/secrets-scanner update-rules

# Check only
./target/debug/secrets-scanner update-rules --check
```

Cached rules are stored in the OS user-data directory:

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/secrets-scanner/secrets-scanner.toml` |
| Linux | `~/.local/share/secrets-scanner/secrets-scanner.toml` |
| Windows | `%APPDATA%\secrets-scanner\secrets-scanner.toml` |

---

## CI Integration

```yaml
# .github/workflows/secrets.yml
- name: Scan for secrets
  run: |
    cargo build --release
    ./target/release/secrets-scanner scan .
  # Exit code 1 = findings → CI fails automatically
```

### SARIF upload (GitHub Code Scanning)

```yaml
- name: Scan (SARIF)
  run: ./target/release/secrets-scanner scan --format sarif . > results.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Check for rule drift

```yaml
- name: Check gitleaks rules are up to date
  run: ./scripts/update_rules.sh --check
```

---

## Pre-commit Hook

Configure via `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/whit3rabbit/secrets-scanner
    rev: v0.1.0
    hooks:
      - id: secrets-scanner
```

This scans all staged files for secrets before each commit.

---

## Development

```bash
# Run tests
make test

# Run clippy
make clippy

# Format
make fmt

# Full CI suite
make ci

# Validate rules
make validate-rules
```

---

## License

MIT — see [LICENSE](LICENSE).
