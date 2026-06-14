# secrets-scanner

A high-performance Rust library and CLI for detecting leaked secrets in source code, configuration files, and pipelines.

[![CI](https://github.com/whit3rabbit/secrets-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/whit3rabbit/secrets-scanner/actions/workflows/ci.yml)

---

## Features

- **Multi-layer pipeline**: memchr SIMD → Aho-Corasick → Shannon entropy → Regex
- **~990 active rules** by default (gitleaks + custom + [Kingfisher](https://github.com/mongodb/kingfisher)); more via `--features full-ruleset`
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

### Shell Script (macOS / Linux)

You can install `secrets-scanner` automatically using the installation script:

```bash
curl -fsSL https://raw.githubusercontent.com/whit3rabbit/secrets-scanner/main/install.sh | bash
```

The script will automatically detect your operating system and architecture and attempt the following installation methods in order:
1. **Homebrew Cask** (macOS only): If `brew` is installed, it runs `brew install --cask whit3rabbit/tap/secrets-scanner`.
2. **Cargo / cargo-binstall**: If `cargo` is installed, it uses `cargo-binstall` if present, or falls back to compiling from source via `cargo install secrets_scanner`.
3. **GitHub Release Binary**: Downloads the pre-built release binary for your OS and architecture, installs it to `~/.secrets-scanner/bin`, and provides instructions to update your `PATH`.

*Note: If the repository is currently private or no releases have been published yet, you can force the installation of a specific version by running:*
```bash
curl -fsSL https://raw.githubusercontent.com/whit3rabbit/secrets-scanner/main/install.sh | VERSION=0.1.0 bash
```

### PowerShell (Windows)

For Windows, run the following command in PowerShell:

```powershell
irm https://raw.githubusercontent.com/whit3rabbit/secrets-scanner/main/install.ps1 | iex
```

This script will:
1. **Cargo / cargo-binstall**: Detect and use `cargo` / `cargo-binstall` if available to build or fetch the tool.
2. **GitHub Release Binary**: Fall back to downloading the Windows `x86_64` executable from GitHub Releases, placing it in `$HOME\.secrets-scanner\bin` and appending it to your User `PATH` environment variable.

*Note: You can force a specific version to download by setting the `VERSION` environment variable beforehand:*
```powershell
$env:VERSION="0.1.0"; irm https://raw.githubusercontent.com/whit3rabbit/secrets-scanner/main/install.ps1 | iex
```

### From Source

You can also install directly from source using Cargo:

```bash
# Install the default lean binary
cargo install secrets_scanner

# Or build with the runtime rule-updater feature enabled (requires HTTP client dependency)
cargo install secrets_scanner --features updater
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
  --min-entropy <FLOAT>     Override per-rule entropy thresholds
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

## Rulesets

Rules are declared in a manifest (`assets/sources.toml`) and merged at build time by
priority (higher wins id/regex collisions). The default lean build embeds **local +
gitleaks + kingfisher**; `secrets-patterns-db` is opt-in via `--features full-ruleset`.
Counts are raw `[[rules]]` entries; many are disabled at load because they use
look-around, which Rust's `regex` engine rejects (see "active" below).

| Ruleset | Upstream | Raw rules | Size | Priority | Default build |
|---|---|--:|--:|--:|:--:|
| [`local`](docs/rulesets/local.md) | hand-curated (`assets/local.toml`) | 240 | 76 KB | 100 | ✅ embedded |
| [`gitleaks`](docs/rulesets/gitleaks.md) | [gitleaks](https://github.com/gitleaks/gitleaks) | 222 | 96 KB | 10 | ✅ embedded |
| [`kingfisher`](docs/rulesets/kingfisher.md) | [MongoDB Kingfisher](https://github.com/mongodb/kingfisher) | 755¹ | 240 KB | 7 | ✅ embedded |
| [`secrets-patterns-db`](docs/rulesets/spdb.md) | [mazen160/secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db) | 1599 | 360 KB | 5 | ⬚ `--features full-ruleset` |

¹ Kingfisher is converted from 951 YAML rules to TOML by `scripts/convert_kingfisher_rules.py`:
`visible:false` helper rules are skipped, rules already covered by gitleaks/local are removed by
behavioral dedup, and patterns the Rust engine can't compile are dropped.

**Merged totals** (after id-collision + detection-equivalent dedup, then look-around disabling):

| Build | Sources | Merged | Active (compiled) |
|---|---|--:|--:|
| lean default | local + gitleaks + kingfisher | 1136 | 987 |
| `--features full-ruleset` | + secrets-patterns-db | 2735 | 2586 |

Regenerate the merged ruleset with `make merge-rules`; inspect cross-source duplicates with
`make find-dups`.

Raw provider files live under `assets/`; `assets/sources.toml` declares source
metadata, merge priority, and default-build inclusion. The committed
`assets/secrets-scanner.toml` file is the lean merged artifact generated by
`make merge-rules` for review and drift checks.

The per-ruleset docs in `docs/rulesets/` are generated with `make ruleset-docs`.
Each page lists raw provider rules, synthetic examples, regexes, and whether the
current scanner can load the rule. `Active` means
`secrets-scanner list-rules --rules <source>` can compile and load the rule;
unsupported rules remain documented because they still exist in the raw source.

### Related projects and rule sources

These projects and references are useful for comparing rule coverage, detector design, and
secret-scanning workflows. They are informational; this scanner does not import or support all
of them.

| Project | Link | Notes |
|---|---|---|
| secrets-patterns-db | [mazen160/secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db) | Regex catalog already available through this repo's `full-ruleset` feature. |
| MongoDB Kingfisher | [mongodb/kingfisher](https://github.com/mongodb/kingfisher) | Rust scanner and rule source already converted into this repo's default ruleset. |
| TruffleHog | [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) | Detector and credential verification logic for many secret types. |
| Nosey Parker | [praetorian-inc/noseyparker](https://github.com/praetorian-inc/noseyparker) | Rule-based scanner with Git history scanning and capture-oriented patterns. |
| secretlint | [secretlint/secretlint](https://github.com/secretlint/secretlint) | Package-based linting ecosystem with provider-specific rules. |
| detect-secrets | [Yelp/detect-secrets](https://github.com/Yelp/detect-secrets) | Baseline-oriented workflow for suppressing existing findings and blocking new leaks. |
| Whispers | [Skyscanner/whispers](https://github.com/Skyscanner/whispers) | Structured config parsing for formats such as YAML, JSON, npmrc, pypirc, and Dockerfiles. |
| ggshield / GitGuardian | [GitGuardian/ggshield](https://github.com/GitGuardian/ggshield) | CLI and pre-commit tooling backed by GitGuardian's detector set. |
| Semgrep Secrets | [Semgrep Secrets docs](https://semgrep.dev/docs/semgrep-secrets/conceptual-overview) | Secret scanning with semantic analysis, validation, and entropy checks. |
| GitHub secret scanning patterns | [GitHub supported patterns](https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns#supported-secrets) | Provider/type coverage reference for GitHub secret scanning. |

### Ruleset benchmark results

Measured on macOS 26.5.1, Apple M4 Max, 14 logical CPUs, 36 GiB RAM, rustc 1.96.0,
release profile with LTO. Runtime rows are medians of 3 CLI runs over a warm 512 MiB
benign text corpus with no findings. `wall` is the full CLI process time, including
rule file load and regex/Aho-Corasick construction; `scan` is the scanner's logged
time after rule construction. RSS and CPU come from `/usr/bin/time -l`.
Throughput uses `scan` time. CPU is `(user + sys) / wall`, so values above 100%
mean the process used more than one core.

Binary size is affected only by what is embedded at build time:

| Build | Embedded sources | Binary size |
|---|---|--:|
| `cargo build --release` | local + gitleaks + kingfisher | 3.28 MiB |
| `cargo build --release --features full-ruleset` | local + gitleaks + kingfisher + secrets-patterns-db | 3.56 MiB |

Selecting a smaller ruleset with `--rules <PATH>` changes load time, memory use, and
scan behavior, but does not shrink the compiled binary.

| Runtime ruleset | Merged TOML | Merged rules | Active rules | Keywords | wall | scan | Throughput | Peak RSS | CPU |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| gitleaks | 95.4 KiB | 222 | 222 | 244 | 1.69 s | 86.6 ms | 5.9 GiB/s | 660 MiB | 143% |
| gitleaks + local | 134.0 KiB | 382 | 233 | 262 | 1.58 s | 72.3 ms | 6.9 GiB/s | 662 MiB | 147% |
| gitleaks + local + kingfisher (default) | 354.5 KiB | 1136 | 987 | 750 | 1.84 s | 75.5 ms | 6.6 GiB/s | 761 MiB | 140% |
| full (+ secrets-patterns-db) | 649.9 KiB | 2735 | 2586 | 1500 | 2.08 s | 221.2 ms | 2.3 GiB/s | 856 MiB | 215% |

Interpretation: `local` adds coverage with almost no measured memory penalty because
many overlapping rules are deduplicated or disabled by Rust `regex` compatibility.
`kingfisher` is the default broad-coverage step and adds about 100 MiB RSS in this
benchmark. `secrets-patterns-db` roughly triples active rules versus the default,
adds another about 95 MiB RSS, and is the first option here with a clear scan-time
cost. Use it when maximum coverage matters more than memory and false-positive budget.

---

## Custom Rules (`assets/local.toml`)

Add your own detection rules in `assets/local.toml` using the same format as
gitleaks. They are merged with the upstream ruleset at build time and custom
rules take precedence. After editing local rules, run `make ruleset-docs` to
refresh rule docs and `make merge-rules` to refresh the committed lean merge.

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
| `entropy` | float | Minimum Shannon entropy for the secret portion. Omit to disable entropy gating. |
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
