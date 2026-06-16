# secrets-scanner

A high-performance Rust library and CLI for detecting leaked secrets in source code, configuration files, and pipelines.

[![CI](https://github.com/whit3rabbit/secrets-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/whit3rabbit/secrets-scanner/actions/workflows/ci.yml)

---

## Features

- **Fast multi-stage scanning**: Uses a `memchr` prefilter, case-insensitive Aho-Corasick matching, entropy gating, and Rust `regex` validation to minimize CPU overhead.
- **Gitleaks-compatible TOML rules**: Loads rules from a gitleaks-style TOML configuration. Supports custom rules via `--rules` or `SECRETS_SCANNER_RULES`.
- **Manifest-driven bundled rules**: Combines local, gitleaks, and kingfisher rulesets at compile time, validated and deduped by priority.
- **Safe-by-default scanning**: Redacts matched secrets, rejects symlinks, uses bounded file reads, and automatically skips binary files.
- **Git-aware scanning**: Scan git-tracked files (`--git-tracked`), changed files (`--changed-files` / `--base`), full history patches (`--git-history`, finds secrets committed then removed), staged index blobs (`--staged`), or untracked files (`--include-untracked`). Explicit git modes fail closed on git error (opt back in with `--git-fallback=walk`).
- **CI-friendly output**: Exports to text, JSON, JSONL, and SARIF formats. Supports suppressions, baselines, and scan scope limits.
- **CLI and automation**: Complete CLI toolset with completions, GitHub Action, pre-commit hook, Docker image, and Homebrew cask packaging.
- **Rust and Node.js libraries**: Use the Rust crate directly or install the Node.js binding package `@whit3rabbit/rsecrets-scanner`.
- **Optional runtime updates**: Download and update rule configurations dynamically to the OS user-data directory via the `--features updater` build.
- **Developer tooling**: Includes built-in rule validation, merge check validation, duplicate-rule detectors, benchmarks, and fuzz targets.

---

## Quick Start

### 1. Install

#### macOS / Linux (Shell)
```bash
curl -fsSL https://raw.githubusercontent.com/whit3rabbit/secrets-scanner/main/install.sh | bash
```

#### Windows (PowerShell)
```powershell
irm https://raw.githubusercontent.com/whit3rabbit/secrets-scanner/main/install.ps1 | iex
```

*(For other installation methods like Homebrew tap or Cargo, see [Installation Options](#installation-options) below).*

### 2. Run a Scan

Once installed and in your `PATH`, run `secrets-scanner` directly:

```bash
# Scan the current directory
secrets-scanner scan .

# Scan specific paths
secrets-scanner scan src/ config/ .env

# Output as JSON
secrets-scanner scan --format json . > findings.json

# Output as SARIF for GitHub Code Scanning
secrets-scanner scan --format sarif . > results.sarif
```

### 3. Use as a Library

To integrate `secrets-scanner` into your Rust codebase, add it to your `Cargo.toml`:

```toml
[dependencies]
secrets-scanner = "0.1.0"
```

#### Parallel Directory Scanning
Scan a directory tree in parallel using default rules:

```rust
use secrets_scanner::Scanner;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load rules (priority: SECRETS_SCANNER_RULES env -> cached in user-data -> bundled fallback)
    let scanner = Scanner::new()?;

    // Scan a directory tree
    let findings = scanner.scan_path("./src");

    for f in &findings {
        println!("{}:{} [{}] {}", f.file, f.line, f.rule_id, f.matched);
    }
    Ok(())
}
```

#### In-Memory Scan & Redaction
Check for secrets and redact them from a string or file content:

```rust
use secrets_scanner::Scanner;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = Scanner::new()?;
    let content = "export STRIPE_KEY=sk_live_51234567890abcdefghijklmnopqrstuvwxyz";

    let output = scanner.scan_and_redact_content("config.env", content);
    if output.has_findings() {
        println!("Redacted content:\n{}", output.redacted);
    }
    Ok(())
}
```

#### Hardened LLM / Proxy Integration
For untrusted inputs (e.g. proxying user prompts or LLM generated payloads), use the hardened `scan_proxy` interface. This API is **fail-closed** (returns an error on oversized input) and enforces a hardened `ScanConfig::proxy()` setup (enforces redaction, disables allow markers, caps maximum findings, and limits matched length to prevent memory amplification/bypass attacks).

```rust
use secrets_scanner::{ScanConfig, Scanner};

fn handle_untrusted_input(payload: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Create a scanner configured for proxy hardened mode.
    let scanner = Scanner::from_bundled()?.with_config(ScanConfig::proxy());

    // scan_proxy returns Err(ProxyError::InputTooLarge) if input exceeds config.max_file_size
    // It also fails with Err(ProxyError::NotHardened) if the config is not secure.
    let output = scanner.scan_proxy(payload)?;

    // If findings were detected, the output contains redacted bytes
    if output.has_findings() {
        eprintln!("Detected and redacted {} secret(s).", output.findings.len());
    }

    // Return the safe, redacted payload
    Ok(output.redacted)
}
```

#### Loading Custom Rules
Load a scanner from your own gitleaks-style TOML instead of the bundled rules.
`from_file` / `from_toml` use a strict gate: they fail loudly on an empty/duplicate
rule id or an uncompilable regex (`ScannerError::InvalidRules`), rather than silently
scanning with a reduced rule set.

```rust
use secrets_scanner::{Scanner, ScannerError};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // From a path on disk...
    let scanner = Scanner::from_file("my-rules.toml")?;

    // ...or from an in-memory TOML string.
    let toml = r#"
        title = "custom rules"

        [[rules]]
        id = "acme-api-key"
        description = "ACME service API key"
        regex = 'ACME_[A-Za-z0-9]{32}'
        keywords = ["acme_"]
        entropy = 3.5
    "#;
    match Scanner::from_toml(toml) {
        Ok(s) => { let _ = s.scan_path("./src"); }
        // InvalidRules carries one message per rejected rule.
        Err(ScannerError::InvalidRules(issues)) => {
            for issue in issues {
                eprintln!("rejected rule: {issue}");
            }
        }
        Err(e) => return Err(e.into()),
    }

    let _ = scanner;
    Ok(())
}
```

#### Custom Scan Configuration
Tune scan behavior with [`ScanConfig`] and attach it via `with_config`. Every field
has a safe default; override only what you need.

```rust
use secrets_scanner::{BinaryPolicy, ScanConfig, Scanner};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ScanConfig {
        // Only *raise* a rule's entropy threshold (never weakens a stricter rule).
        min_entropy_override: Some(4.0),
        // Skip files larger than 1 MiB.
        max_file_size: 1024 * 1024,
        // Never skip on binary detection (still honors size/symlink guards).
        binary_policy: BinaryPolicy::Scan,
        // Bound the result set for hostile/huge inputs.
        max_findings: Some(500),
        max_findings_per_file: Some(50),
        ..ScanConfig::default()
    };

    let scanner = Scanner::new()?.with_config(config);
    let findings = scanner.scan_path("./");
    println!("{} finding(s)", findings.len());
    Ok(())
}
```

#### Git-Aware Scanning
The same `git ls-files` / `git log -p` modes the CLI exposes are available from the
library through `ScanConfig`. Explicit git modes fail closed on git error unless you
set `git_fallback_walk`.

```rust
use secrets_scanner::{ScanConfig, Scanner};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Scan only git-tracked working-tree content.
    let tracked = Scanner::new()?.with_config(ScanConfig {
        git_tracked: true,
        ..ScanConfig::default()
    });
    for f in tracked.scan_path(".") {
        println!("{}:{} [{}]", f.file, f.line, f.rule_id);
    }

    // Scan full history; each finding is attributed to the commit that ADDED it
    // (catches secrets committed then later removed).
    let history = Scanner::new()?.with_config(ScanConfig {
        git_history: true,
        // Optional wall-clock budget; 0 = unlimited.
        history_timeout_secs: 30,
        ..ScanConfig::default()
    });
    for f in history.scan_path(".") {
        if let Some(commit) = &f.commit {
            println!("{commit} {}:{} [{}]", f.file, f.line, f.rule_id);
        }
    }
    Ok(())
}
```

#### CI Summary with Scan Stats
`scan_path_with_stats` returns file-level [`ScanStats`] alongside findings, so a CI
job can print a safe summary (counts only, no secret material) and distinguish a
scanned-and-clean file from one that was skipped or unreadable.

```rust
use secrets_scanner::Scanner;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = Scanner::new()?;
    let (findings, stats) = scanner.scan_path_with_stats("./src");

    eprintln!(
        "scanned {} file(s): {} finding(s), {} binary, {} oversized, {} unreadable",
        stats.files_scanned,
        findings.len(),
        stats.binary_skipped,
        stats.oversized_skipped,
        stats.errored,
    );

    // `errored > 0` means coverage was incomplete: treat it as a hard failure
    // rather than a clean result.
    if stats.errored > 0 {
        std::process::exit(2);
    }
    Ok(())
}
```

#### Inspecting Findings
Each [`Finding`] carries full location and identity metadata. The `fingerprint`
(line-tolerant SHA-256 over rule id + file + raw secret) is the stable key used for
baseline suppression and SARIF `partialFingerprints`.

```rust
use secrets_scanner::Scanner;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = Scanner::new()?;
    for f in scanner.scan_content("config.env", "AWS_SECRET=AKIAIOSFODNN7EXAMPLE") {
        println!("rule        : {} ({})", f.rule_id, f.rule_description);
        println!("location    : {}:{}:{}", f.file, f.line, f.col);
        println!("entropy     : {:.2}", f.entropy);
        println!("fingerprint : {}", f.fingerprint);
        // `matched` is redacted by default; build with `redact: false` for raw text.
        println!("matched     : {}", f.matched);
    }
    Ok(())
}
```

### 4. Use from Node.js

The Node.js binding package is `@whit3rabbit/rsecrets-scanner`, not
`secrets-scanner`. It is a library binding over the same Rust implementation; it
does not install the CLI binary.

```bash
npm install @whit3rabbit/rsecrets-scanner
```

```js
const { Scanner } = require("@whit3rabbit/rsecrets-scanner");

const scanner = Scanner.proxy({ maxFileSize: 1024 * 1024 });
const result = scanner.scanProxy(
  Buffer.from("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234567")
);

if (result.hasFindings) {
  const safePayload = Buffer.from(result.redacted).toString("utf8");
  // Forward safePayload instead of the original input.
}
```

`Scanner.proxy()` maps to Rust `ScanConfig::proxy()`, and `scanProxy()`
maps to Rust `Scanner::scan_proxy()`: oversized input and non-hardened configs
fail closed. See [`bindings/node/README.md`](bindings/node/README.md) for the
full Node API, source-build instructions, and current native packaging limits.

---

## Installation Options

<details>
<summary>Automated Installer Scripts (macOS, Linux, Windows)</summary>

### macOS / Linux
```bash
curl -fsSL https://raw.githubusercontent.com/whit3rabbit/secrets-scanner/main/install.sh | bash
```
This script detects your OS/Architecture and installs in order of preference:
1. **Homebrew Cask**: If `brew` is installed, runs `brew install --cask whit3rabbit/tap/secrets-scanner`.
2. **Cargo / cargo-binstall**: If `cargo` is installed, uses `cargo-binstall` (if present) or `cargo install secrets_scanner`.
3. **GitHub Release Binary**: Downloads the pre-built release binary, installs to `~/.secrets-scanner/bin`, and prompts you to update your `PATH`.

*Note: For private or pre-release setups, force download a specific version using the `VERSION` env variable:*
```bash
curl -fsSL https://raw.githubusercontent.com/whit3rabbit/secrets-scanner/main/install.sh | VERSION=0.1.0 bash
```

### Windows
```powershell
irm https://raw.githubusercontent.com/whit3rabbit/secrets-scanner/main/install.ps1 | iex
```
This script installs in order of preference:
1. **Cargo / cargo-binstall**: Detects and uses `cargo` / `cargo-binstall` if available.
2. **GitHub Release Binary**: Downloads the Windows binary, places it in `$HOME\.secrets-scanner\bin`, and appends the directory to your User `PATH` persistently.

*Note: Force a specific version using `$env:VERSION`:*
```powershell
$env:VERSION="0.1.0"; irm https://raw.githubusercontent.com/whit3rabbit/secrets-scanner/main/install.ps1 | iex
```
</details>

### Homebrew Tap (macOS)
To install using Homebrew directly:
```bash
# Add the tap
brew tap whit3rabbit/tap

# Install formula
brew install secrets-scanner

# Or install the Cask version (recommended)
brew install --cask whit3rabbit/tap/secrets-scanner
```

### Cargo / cargo-binstall
If you have Cargo installed:
```bash
# Install the pre-built binary quickly with cargo-binstall
cargo binstall secrets_scanner

# Build and install from crates.io
cargo install secrets_scanner

# Build and install with runtime updater support (optional features)
cargo install secrets_scanner --features updater
```

### Node.js Binding Package
For Node.js applications, install the scoped binding package:

```bash
npm install @whit3rabbit/rsecrets-scanner
```

This is not the CLI package. It loads a native NAPI-RS `.node` artifact and
wraps the Rust `secrets_scanner` crate. Current npm packaging ships the native
artifact built for the publish target; if no artifact matches your platform,
build from a checkout with:

```bash
cd bindings/node
npm install
npm run build
```

### Manual Download
1. Download the pre-built binary matching your platform from [GitHub Releases](https://github.com/whit3rabbit/secrets-scanner/releases).
2. Move it to a directory in your `PATH` (e.g. `/usr/local/bin/` on macOS/Linux).
3. Mark it as executable: `chmod +x /usr/local/bin/secrets-scanner`

---

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
  --baseline <FILE>         Suppress findings present in a generated baseline
  --git-tracked             Only scan files currently tracked by git
  --changed-files           Only scan current content of files changed vs a base
  --base <REF>              Base ref for --changed-files (implies it); scans <base>...HEAD
  --git-history             Scan full git history (git log -p); finds removed secrets
  --all                     With --git-history, traverse all refs
  --full-history            With --git-history, pass --full-history
  --log-opts <OPTS>         With --git-history, raw git log options (operator-trusted)
  --staged                  Scan staged index blobs (pre-commit)
  --include-untracked       In git mode, also scan untracked (non-ignored) files
  --git-fallback <MODE>     On git failure: fail closed (default) or `walk` (legacy)

update-rules options:
  --check                   Report update availability without downloading
  --url <URL>               Pull from a custom URL or private mirror

validate-rules [FILES...]   Validate TOML rules (default: bundled assets)
list-rules [--rules <PATH>] List all rules from a TOML file or default rules
completions <SHELL>         Generate shell completions (bash/zsh/fish/powershell/elvish)
```

Generated baselines use SHA-256 v2 fingerprints over rule id, file path, and the
raw secret bytes. Baselines generated by older FNV-based builds should be
regenerated once; old fingerprints will not suppress new findings.

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
secrets-scanner + gitleaks + kingfisher**; `secrets-patterns-db` is opt-in via `--features full-ruleset`.
Counts are raw `[[rules]]` entries; many are disabled at load because they use
look-around, which Rust's `regex` engine rejects (see "active" below).

| Ruleset | Upstream Source | License | Raw rules | Size | Priority | Default Build |
|---|---|---|--:|--:|--:|:--:|
| [`local`](docs/rulesets/local.md) | custom developer overrides ([`assets/local.toml`](assets/local.toml)) | MIT | 1 | <1 KB | 100 | ✅ embedded |
| [`secrets-scanner`](docs/rulesets/secrets-scanner.md) | hand-curated rules ([`assets/secrets-scanner-rules.toml`](assets/secrets-scanner-rules.toml)) | MIT | 14 | 7 KB | 90 | ✅ embedded |
| [`gitleaks`](docs/rulesets/gitleaks.md) | [gitleaks](https://github.com/gitleaks/gitleaks) ([`assets/gitleaks.toml`](assets/gitleaks.toml)) | MIT | 222 | 96 KB | 10 | ✅ embedded |
| [`kingfisher`](docs/rulesets/kingfisher.md) | [MongoDB Kingfisher](https://github.com/mongodb/kingfisher) ([`assets/kingfisher-rules.toml`](assets/kingfisher-rules.toml)) | Apache-2.0 | 755¹ | 240 KB | 7 | ✅ embedded |
| [`secrets-patterns-db`](docs/rulesets/spdb.md) | [mazen160/secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db) ([`assets/secrets-patterns-db.toml`](assets/secrets-patterns-db.toml)) | CC-BY-4.0 / AGPL-3.0² | 1599 | 360 KB | 5 | ⬚ `--features full-ruleset` |

¹ Kingfisher is converted from 951 YAML rules to TOML by `scripts/convert_kingfisher_rules.py`:
`visible:false` helper rules are skipped, rules already covered by gitleaks/local are removed by
behavioral dedup, and patterns the Rust engine can't compile are dropped.

² The `secrets-patterns-db` repository is primarily CC-BY-4.0, but it contains rules derived from TruffleHog which are licensed under the copyleft AGPL-3.0.

> [!IMPORTANT]
> **License Implications of Combining Rulesets**
>
> Combining rulesets with different license terms can change the overall licensing agreement of the resulting output, cache, or embedded binary depending on their types:
> - **Permissive Mix (Default):** The default lean build combines `local` (MIT), `secrets-scanner` (MIT), `gitleaks` (MIT), and `kingfisher` (Apache-2.0). These permissive licenses are compatible and allow standard distribution and usage.
> - **Copyleft Impact (Full Ruleset):** When compiling with `--features full-ruleset` (which embeds `secrets-patterns-db`), the combined work includes rules covered by the AGPL-3.0. If you distribute this compiled binary or run it as a network service (e.g., in a cloud-based API or proxy pipeline), you must comply with the source-sharing obligations of the AGPL-3.0.

**Merged totals** (after id-collision + detection-equivalent dedup, then look-around disabling):

| Build | Sources | Merged | Active (compiled) | Embedded Ruleset / Output File |
|---|---|--:|--:|---|
| lean default | local + secrets-scanner + gitleaks + kingfisher | 988 | 988 | [`assets/secrets-scanner.toml`](assets/secrets-scanner.toml) (committed & embedded by default) |
| `--features full-ruleset` | + secrets-patterns-db | 2587 | 2587 | `$OUT_DIR/secrets-scanner.toml` (embedded at compile time) |

Regenerate the merged ruleset with `make merge-rules`; inspect cross-source duplicates with
`make find-dups`.

Raw provider files live under [`assets/`](assets/); [`assets/sources.toml`](assets/sources.toml) declares source
metadata, merge priority, and default-build inclusion. The committed
[`assets/secrets-scanner.toml`](assets/secrets-scanner.toml) file is the lean merged artifact generated by
`make merge-rules` for review and drift checks.

The per-ruleset documentation pages in [`docs/rulesets/`](docs/rulesets/) are generated with `make ruleset-docs`, referencing the actual rules defined in the `*.toml` files under `assets/`:
- **local**: Documented in [`local.md`](docs/rulesets/local.md) ── Actual rules in [`assets/local.toml`](assets/local.toml)
- **secrets-scanner**: Documented in [`secrets-scanner.md`](docs/rulesets/secrets-scanner.md) ── Actual rules in [`assets/secrets-scanner-rules.toml`](assets/secrets-scanner-rules.toml)
- **gitleaks**: Documented in [`gitleaks.md`](docs/rulesets/gitleaks.md) ── Actual rules in [`assets/gitleaks.toml`](assets/gitleaks.toml)
- **kingfisher**: Documented in [`kingfisher.md`](docs/rulesets/kingfisher.md) ── Actual rules in [`assets/kingfisher-rules.toml`](assets/kingfisher-rules.toml)
- **secrets-patterns-db**: Documented in [`spdb.md`](docs/rulesets/spdb.md) ── Actual rules in [`assets/secrets-patterns-db.toml`](assets/secrets-patterns-db.toml)

Each reference page lists raw provider rules, synthetic examples, regexes, and whether the current scanner can load the rule. `Active` means `secrets-scanner list-rules --rules <source>` can compile and load the rule; unsupported rules remain documented because they still exist in the raw source.

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
| `cargo build --release` | local + secrets-scanner + gitleaks + kingfisher | 3.28 MiB |
| `cargo build --release --features full-ruleset` | local + secrets-scanner + gitleaks + kingfisher + secrets-patterns-db | 3.56 MiB |

Selecting a smaller ruleset with `--rules <PATH>` changes load time, memory use, and
scan behavior, but does not shrink the compiled binary.

| Runtime ruleset | Merged TOML | Merged rules | Active rules | Keywords | wall | scan | Throughput | Peak RSS | CPU |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| gitleaks | 95.4 KiB | 222 | 222 | 244 | 1.69 s | 86.6 ms | 5.9 GiB/s | 660 MiB | 143% |
| gitleaks + local + secrets-scanner | 104.1 KiB | 237 | 237 | 258 | 1.58 s | 72.3 ms | 6.9 GiB/s | 662 MiB | 147% |
| gitleaks + local + secrets-scanner + kingfisher (default) | 311.2 KiB | 988 | 988 | 751 | 1.84 s | 75.5 ms | 6.6 GiB/s | 761 MiB | 140% |
| full (+ secrets-patterns-db) | 686.0 KiB | 2587 | 2587 | 1501 | 2.08 s | 221.2 ms | 2.3 GiB/s | 856 MiB | 215% |

Interpretation: `local` and `secrets-scanner` add coverage with almost no measured memory penalty because
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

## GitHub Action

The bundled composite action (`action.yml`) installs the prebuilt release
binary, verifies it against the release `SHA256SUMS`, and runs `scan` with a
safe-by-default posture (redaction enabled by default, `--no-context`, bounded
reads, deterministic exit). It emits SARIF for GitHub code scanning.

```yaml
# .github/workflows/secrets.yml
permissions:
  contents: read
  security-events: write   # required for the SARIF upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0    # full history for `git-tracked`/`base`

      - id: scan
        uses: whit3rabbit/secrets-scanner@v0.1.0   # pin a released tag
        with:
          fail-on-findings: false   # gate via SARIF instead of failing the job

      - name: Upload SARIF
        if: always() && steps.scan.outputs.sarif-file != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.scan.outputs.sarif-file }}
```

A runnable copy lives at `.github/workflows/secrets-scan.yml` (it dogfoods the
action with `uses: ./`). The action downloads a *released* binary, so pin a tag
that exists (`@vX.Y.Z`); `@main` or a local `uses: ./` falls back to the latest
release.

### Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Path to scan. |
| `config` | – | Optional custom TOML rules file (`--rules`). |
| `fail-on-findings` | `true` | Fail the job on findings. Set `false` to upload SARIF and gate separately. |
| `sarif` | `true` | Write SARIF output. |
| `sarif-file` | `secrets-scanner.sarif` | SARIF output path. |
| `git-tracked` | `true` | Scan only git-tracked files (`--git-tracked`). |
| `base` | – | Base ref for changed-files scanning, e.g. `origin/${{ github.base_ref }}`. |
| `max-file-size` | `2097152` | Max file size in bytes. |
| `binary-policy` | `auto` | Binary handling: `auto \| skip \| scan`. |
| `version` | – | Release to install (e.g. `v0.1.0`). Defaults to the action ref, else warns and uses latest. |
| `extra-args` | – | Newline-delimited extra args appended to `scan`. |

### Outputs

| Output | Description |
|---|---|
| `sarif-file` | Path to the written SARIF file (empty when `sarif: false`). |

To gate pull requests on only the changed code, set
`base: origin/${{ github.base_ref }}`. Use `if: always()` on the upload
step (or `fail-on-findings: false` plus a separate gate) so SARIF still uploads
when findings are present.

---

## Docker

For non-GitHub CI (GitLab, Jenkins) or local use, build a lean static image
(musl, no runtime updater; rebuild to refresh rules):

```bash
docker build -t secrets-scanner:dev .
docker run --rm -v "$PWD:/repo" secrets-scanner:dev scan /repo --git-tracked
```

The runtime image bundles `git`, so the safe-default `--git-tracked` mode works
inside the container. Write SARIF to the mounted volume to collect it on the host:

```bash
docker run --rm -v "$PWD:/repo" secrets-scanner:dev \
  scan /repo --git-tracked --format sarif --output /repo/results.sarif
```

GitLab CI example:

```yaml
secrets-scan:
  image: secrets-scanner:dev   # or a registry tag you build/push
  script:
    - secrets-scanner scan . --git-tracked --format sarif --output gl.sarif
  artifacts:
    when: always
    paths: [gl.sarif]
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

This runs `secrets-scanner scan . --staged --redact --no-context` before each commit.
The hook scans staged index blobs, not working-tree filenames, so a secret staged
then removed from the working tree is still caught.

---

## Agent Skills and Plugins

This repository bundles compatible agent skills and `SOUL.md` personality core rules for multiple AI agent runtimes to prevent secrets from being leaked during agent-assisted development:

### Claude Code Plugin
This repo doubles as a [Claude Code](https://claude.com/claude-code) plugin marketplace. Install the plugin and Claude can install/uninstall the scanner, set up a fail-closed git pre-commit hook, or run scans on request:

```
/plugin marketplace add whit3rabbit/secrets-scanner
/plugin install secrets-scanner@whit3rabbit
```

The plugin bundles a skill (`plugins/secrets-scanner/`) with helper scripts for install/uninstall and managing a native `scan . --staged --redact --no-context` pre-commit hook. It does not replace the binary install above; it drives the same CLI on your behalf.

### Codex Plugin
This repo also carries a repo-local Codex marketplace at `.agents/plugins/marketplace.json` and a Codex plugin manifest at `plugins/secrets-scanner/.codex-plugin/plugin.json`:

```bash
codex plugin marketplace add .agents/plugins
codex plugin add secrets-scanner@whit3rabbit
```

The Codex plugin exposes the same install, uninstall, staged hook, scan, and proxy-integration guidance as the Claude plugin.

### Hermes Agent and OpenClaw Skills
Hermes and OpenClaw consume skill directories directly. From a checkout of this repo:

```bash
hermes skills install whit3rabbit/secrets-scanner/plugins/secrets-scanner/skills/secrets-scanner
openclaw skills install ./plugins/secrets-scanner/skills/secrets-scanner
```

The repo also includes project-scoped copies and `SOUL.md` identity files for local development:

- **OpenClaw:** Configured under `.openclaw/` (loaded from `.openclaw/skills/secrets-scanner/` and [.openclaw/SOUL.md](.openclaw/SOUL.md)).
- **Hermes Agent:** Configured under `.hermes/` (loaded from `.hermes/skills/secrets-scanner/` and [.hermes/SOUL.md](.hermes/SOUL.md)).
- **Codex Agent:** Configured under `.codex/` (loaded from `.codex/skills/secrets-scanner/` and [.codex/SOUL.md](.codex/SOUL.md)).

The bundled `SOUL.md` files define the agent's core values, character, and behavioral boundaries, instructing it to always check for credentials, verify pre-commit setups, and strictly redact raw keys from any console outputs or file edits.

For proxy-style LLM or gateway integrations, use the Rust `Scanner::scan_proxy` API or the Node binding's `Scanner.proxy().scanProxyAsync(...)`. Agent skills can document and call those APIs, but they do not transparently intercept all Hermes/OpenClaw traffic without a separate runtime integration.

---

## Development

### Building from Source

To build and test the codebase from a local checkout:

```bash
# Clone the repository
git clone https://github.com/whit3rabbit/secrets-scanner.git
cd secrets-scanner

# Build the debug binary (lean profile, no runtime updater)
cargo build

# Build with the runtime rule-updater feature (ureq HTTP client)
cargo build --features updater

# Build with the full ruleset (includes secrets-patterns-db)
cargo build --features full-ruleset

# Build optimized release binary
cargo build --release
```

### Build features

The default build embeds the bundled ruleset at compile time and does not include
the runtime HTTP updater.

```bash
cargo build --release
```

To enable `secrets-scanner update-rules`, build with:

```bash
cargo build --release --features updater
```

Docker images embed rules at image build time. Rebuild the image to refresh rules.

To build with the expanded ruleset (including `secrets-patterns-db`):

```bash
cargo build --release --features full-ruleset
```


### Running Tests and Lints

We use a Makefile to simplify developer workflows:

```bash
# Run the automated test suite
make test

# Run Clippy lints
make clippy

# Run rustfmt format checks
make fmt-check

# Run full CI suite (combines build, test, lint, and ruleset checks)
make ci
```

### Ruleset Validation and Merging

When updating custom rules in `assets/local.toml` or upstream sets:

```bash
# Validate TOML structure and regex compile safety
make validate-rules

# Re-merge assets and generate target/merge-report.json
make merge-rules
```

---

## License

MIT — see [LICENSE](LICENSE).
