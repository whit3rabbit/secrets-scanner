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
- **Rust, Node.js, and WASM libraries**: Use the Rust crate directly, install the native Node.js binding package `@whit3rabbit/rsecrets-scanner`, or use the browser/edge WASM package `@whit3rabbit/rsecrets-scanner-wasm`.
- **Optional runtime updates**: Download and update rule configurations dynamically to the OS user-data directory via the `--features updater` build.
- **Developer tooling**: Includes built-in rule validation, merge check validation, duplicate-rule detectors, benchmarks, and fuzz targets.

---

## Quick Start

### 1. Install

#### macOS / Linux (Shell)
```bash
curl -fsSL https://raw.githubusercontent.com/whit3rabbit/secrets-scanner/main/install.sh | bash
```

#### macOS (Homebrew Cask)
```bash
brew install --cask whit3rabbit/tap/secrets-scanner
```

#### Windows (PowerShell)
```powershell
irm https://raw.githubusercontent.com/whit3rabbit/secrets-scanner/main/install.ps1 | iex
```

*(For other installation methods like Homebrew Cask or Cargo, see [Installation Options](#installation-options) below).*

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

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
secrets-scanner = "0.1.0"
```

`Scanner::new()` loads rules in priority order (`SECRETS_SCANNER_RULES` env → cached
in user-data → bundled fallback). Every snippet below is a complete body for a
function returning `Result<_, Box<dyn std::error::Error>>`.

#### Scan a directory tree (parallel)

```rust
use secrets_scanner::Scanner;

let scanner = Scanner::new()?;
for f in scanner.scan_path("./src") {
    println!("{}:{} [{}] {}", f.file, f.line, f.rule_id, f.matched);
}
```

#### Redact secrets from in-memory content

```rust
use secrets_scanner::Scanner;

let scanner = Scanner::new()?;
let out = scanner.scan_and_redact_content("config.env", "STRIPE_KEY=sk_live_51abc...");
if out.has_findings() {
    println!("{}", out.redacted); // safe to log/forward
}
```

#### Filter untrusted LLM / proxy traffic (hardened)

`scan_proxy` is **fail-closed**: oversized input returns `ProxyError::InputTooLarge`,
and a non-hardened config returns `ProxyError::NotHardened`. `ScanConfig::proxy()`
enforces redaction, disables allow-markers, and caps findings/matched length.

```rust
use secrets_scanner::{ScanConfig, Scanner};

let scanner = Scanner::from_bundled()?.with_config(ScanConfig::proxy());
let out = scanner.scan_proxy(payload)?; // payload: &[u8]
// Forward out.redacted instead of the raw input.
```

#### Load your own rules

`from_file` / `from_toml` fail loudly (`ScannerError::InvalidRules`) on a duplicate
id or uncompilable regex, rather than silently scanning with fewer rules.

```rust
use secrets_scanner::{Scanner, ScannerError};

let toml = r#"
    [[rules]]
    id = "acme-api-key"
    regex = 'ACME_[A-Za-z0-9]{32}'
    keywords = ["acme_"]
    entropy = 3.5
"#;
match Scanner::from_toml(toml) {
    Ok(scanner) => { scanner.scan_path("./src"); }
    Err(ScannerError::InvalidRules(issues)) => issues.iter().for_each(|i| eprintln!("{i}")),
    Err(e) => return Err(e.into()),
}
```

#### Tune scan behavior

Every `ScanConfig` field has a safe default; override only what you need and attach
it with `with_config`.

```rust
use secrets_scanner::{BinaryPolicy, ScanConfig, Scanner};

let scanner = Scanner::new()?.with_config(ScanConfig {
    min_entropy_override: Some(4.0), // only *raises* a rule's threshold
    max_file_size: 1024 * 1024,
    binary_policy: BinaryPolicy::Scan,
    max_findings: Some(500),
    ..ScanConfig::default()
});
let findings = scanner.scan_path(".");
```

#### Git-aware scanning

The CLI's `git ls-files` / `git log -p` modes are available via `ScanConfig`.
Explicit git modes fail closed on git error unless you set `git_fallback_walk`.

```rust
use secrets_scanner::{ScanConfig, Scanner};

// Working-tree content of git-tracked files only.
Scanner::new()?.with_config(ScanConfig { git_tracked: true, ..Default::default() })
    .scan_path(".");

// Full history; each finding carries the commit that ADDED it (catches removed secrets).
let history = Scanner::new()?.with_config(ScanConfig {
    git_history: true,
    history_timeout_secs: 30, // wall-clock budget; 0 = unlimited
    ..Default::default()
});
for f in history.scan_path(".") {
    if let Some(c) = &f.commit { println!("{c} {}:{}", f.file, f.line); }
}
```

#### CI summary with scan stats

`scan_path_with_stats` returns file-level [`ScanStats`] so CI can print a
secret-free summary and tell a scanned-clean file from a skipped or unreadable one.

```rust
use secrets_scanner::Scanner;

let (findings, stats) = Scanner::new()?.scan_path_with_stats("./src");
eprintln!(
    "{} file(s), {} finding(s), {} binary, {} oversized, {} unreadable",
    stats.files_scanned, findings.len(),
    stats.binary_skipped, stats.oversized_skipped, stats.errored,
);
// errored > 0 means incomplete coverage: fail rather than report clean.
if stats.errored > 0 { std::process::exit(2); }
```

#### Inspect a finding

Each [`Finding`] carries location, identity, and a `fingerprint` (line-tolerant
SHA-256 over rule id + file + raw secret) — the stable key for baselines and SARIF.

```rust
use secrets_scanner::Scanner;

for f in Scanner::new()?.scan_content("config.env", "AWS_SECRET=AKIAIOSFODNN7EXAMPLE") {
    println!("{} ({}) {}:{}:{}", f.rule_id, f.rule_description, f.file, f.line, f.col);
    println!("entropy {:.2}  fingerprint {}", f.entropy, f.fingerprint);
    println!("matched {}", f.matched); // redacted by default
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

### 5. Use from Browser / Edge WASM

The browser/edge WASM package is `@whit3rabbit/rsecrets-scanner-wasm`. It exposes
only in-memory scanning and redaction APIs. It does not read files, shell out to
git, use the rules cache, run the updater, or provide a CLI.

```bash
npm install @whit3rabbit/rsecrets-scanner-wasm
```

```js
import init, { Scanner } from "@whit3rabbit/rsecrets-scanner-wasm";

await init();

const scanner = Scanner.proxy({ maxFileSize: 1024 * 1024 });
const payload = new TextEncoder().encode("key=value");
const result = scanner.scanProxy(payload);

if (result.hasFindings) {
  const safePayload = new TextDecoder().decode(result.redacted);
  // Forward safePayload instead of the original input.
}
```

Use `Scanner.bundled()` once and reuse it; compiling the full bundled ruleset is
memory-heavy in browser runtimes. For constrained contexts, prefer
`Scanner.fromToml()` with a focused ruleset when full bundled coverage is not
required. See [`bindings/wasm/README.md`](bindings/wasm/README.md) for the API
and [`bindings/wasm/FUTURE.md`](bindings/wasm/FUTURE.md) for the measured size,
memory, speed, and security follow-ups.

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

### Homebrew Cask (macOS)
The tap ships a Cask that installs the prebuilt release binary and links it onto your `PATH`:
```bash
# One-liner (auto-taps whit3rabbit/tap)
brew install --cask whit3rabbit/tap/secrets-scanner

# Or tap first, then install
brew tap whit3rabbit/tap
brew install --cask secrets-scanner
```

Verify and upgrade:
```bash
secrets-scanner --version
brew upgrade --cask secrets-scanner
brew uninstall --cask secrets-scanner
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

Measured on macOS 26.5.1, Apple M4 Max (arm64), 14 logical CPUs, 36 GiB RAM,
rustc 1.96.0, release profile with LTO. Re-measured 2026-06-15 with the
reproducible harness in [`scripts/benchmark.sh`](scripts/benchmark.sh) (portable
across BSD `/usr/bin/time -l` and GNU `time -v`, so the same script drives both the
native and Docker passes below).

Runtime rows are medians of 3 CLI runs over a warm 512 MiB benign corpus (512 files
of ~1 MiB, no findings). `wall` is the full CLI process time, including rule file
load and regex/Aho-Corasick construction; `scan` is the scanner's logged time after
rule construction. Throughput uses `scan` time and is **sensitive to keyword
density**: this benign corpus has near-zero rule-keyword hits, so it exercises the
keyword-gate fast path rather than the worst case where most content is a regex
candidate. CPU is `(user + sys) / wall`, so values above 100% mean the scan used
more than one core (rayon parallelizes across files).

Binary size (native macOS arm64 build) is affected only by what is embedded at
build time:

| Build | Embedded sources | Binary size |
|---|---|--:|
| `cargo build --release` | local + secrets-scanner + gitleaks + kingfisher | 3.49 MiB |
| `cargo build --release --features full-ruleset` | + secrets-patterns-db | 3.78 MiB |

Selecting a smaller ruleset with `--rules <PATH>` changes load time, memory use, and
scan behavior, but does not shrink the compiled binary.

**Native (macOS, Apple M4 Max), `/usr/bin/time -l`:**

| Runtime ruleset | Merged TOML | Rules | Keywords | wall | scan | Throughput | Peak RSS | CPU |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| gitleaks | 95.4 KiB | 222 | 244 | 1.48 s | 75.8 ms | 6.6 GiB/s | 661 MiB | 150% |
| gitleaks + local + secrets-scanner | 90.9 KiB | 234 | 263 | 1.47 s | 75.7 ms | 6.6 GiB/s | 663 MiB | 150% |
| gitleaks + local + secrets-scanner + kingfisher (default) | 311.4 KiB | 988 | 751 | 1.71 s | 83.1 ms | 6.0 GiB/s | 762 MiB | 143% |
| full (+ secrets-patterns-db) | 606.8 KiB | 2587 | 1501 | 1.98 s | 213.1 ms | 2.3 GiB/s | 856 MiB | 196% |

All rules listed are active (compiled): the merge already drops patterns Rust's
`regex` engine cannot compile, so merged count equals active count here.

**Docker (lean musl image, Docker Desktop Linux VM on the same M4 Max, arm64), GNU
`/usr/bin/time -v`:** same ruleset metadata as above; the corpus is generated inside
the container to avoid bind-mount I/O. These numbers reflect the VM + musl runtime,
so throughput is lower and RSS smaller than the native build. This is the container
artifact (`docker run secrets-scanner …`), **not** a bare-metal Linux measurement.

| Runtime ruleset | wall | scan | Throughput | Peak RSS | CPU |
|---|--:|--:|--:|--:|--:|
| gitleaks | 1.74 s | 113.6 ms | 4.4 GiB/s | 585 MiB | 161% |
| gitleaks + local + secrets-scanner | 1.72 s | 109.6 ms | 4.6 GiB/s | 582 MiB | 159% |
| gitleaks + local + secrets-scanner + kingfisher (default) | 1.99 s | 110.3 ms | 4.5 GiB/s | 680 MiB | 154% |
| full (+ secrets-patterns-db) | 2.27 s | 195.8 ms | 2.6 GiB/s | 758 MiB | 201% |

Interpretation: `local` and `secrets-scanner` add coverage with almost no measured
memory or scan penalty because many overlapping rules are deduplicated or disabled by
Rust `regex` compatibility. `kingfisher` is the default broad-coverage step and adds
about 100 MiB RSS. `secrets-patterns-db` roughly triples active rules versus the
default, adds another about 95 MiB RSS, and is the first option with a clear scan-time
cost (about 2.5x the default). Use it when maximum coverage matters more than memory
and false-positive budget. The Docker rows run the same binary logic under the Docker
Desktop VM with a musl allocator: scan throughput drops about 25-30% versus native and
peak RSS is roughly 80 MiB lower, but the relative ordering of rulesets is unchanged.

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

The bundled composite action (`action.yml`, published as **RSecrets Scanner**)
installs the prebuilt release binary, verifies it against the release
`SHA256SUMS`, and runs `scan` with a safe-by-default posture (redaction enabled
by default, `--no-context`, bounded reads, deterministic exit). It emits SARIF
for GitHub code scanning and uses the bundled rules by default so self-hosted
runners do not accidentally pick up stale OS-cache rules. Linux and macOS
runners are supported.

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
          fetch-depth: 0    # full history for `git-tracked`, `base`, or history scans

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
action with `uses: ./`). Before the first release exists, use
`build-from-source: true` after installing Rust. For consumers, pin a tag that
exists (`@vX.Y.Z`); `@main` falls back to the latest release and is
non-reproducible.

### Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Path to scan. |
| `config` | – | Optional custom TOML rules file (`--rules`). |
| `rules-source` | `bundled` | Rule source when `config` is unset: `bundled` for deterministic CI or `auto` for env/cache/bundled priority. |
| `fail-on-findings` | `true` | Fail the job on findings. Set `false` to upload SARIF and gate separately. |
| `sarif` | `true` | Write SARIF output. |
| `sarif-file` | `secrets-scanner.sarif` | SARIF output path. |
| `git-tracked` | `true` | Scan only git-tracked files (`--git-tracked`). |
| `base` | – | Base ref for changed-files scanning, e.g. `origin/${{ github.base_ref }}`. Takes precedence over `git-tracked`. |
| `git-history` | `false` | Scan git history patches (`--git-history`) instead of current tree paths. |
| `history-timeout` | `300` | Wall-clock budget in seconds for `git-history` scans. |
| `max-file-size` | `2097152` | Max file size in bytes. |
| `binary-policy` | `auto` | Binary handling: `auto \| skip \| scan`. |
| `version` | – | Release to install (e.g. `v0.1.0`). Defaults to the action ref, else warns and uses latest. |
| `build-from-source` | `false` | Build the scanner from the action checkout instead of downloading a release. Requires Rust. |
| `extra-args` | – | Newline-delimited extra args appended to `scan`. |

### Outputs

| Output | Description |
|---|---|
| `sarif-file` | Path to the written SARIF file (empty when `sarif: false`). |

To gate pull requests on only the changed code, set
`base: origin/${{ github.base_ref }}`; the action automatically skips
`--git-tracked` for that run. For Gitleaks-style history coverage, set
`git-history: true` and keep `fetch-depth: 0`. Use `if: always()` on the upload
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

### Built-in skill installer (`install-skill`)
The binary can install its own agent skill into 20+ runtimes via the [`agent-config`](https://crates.io/crates/agent-config) library, with atomic writes, first-touch `.bak` backups, an ownership ledger, idempotent reinstalls, and reversible uninstall:

```bash
# Install into your user home (default scope), repeatable --agent
secrets-scanner install-skill --agent claude --agent codex

# Install into a specific project instead of home
secrets-scanner install-skill --agent claude --local /path/to/repo

# Preview without writing anything
secrets-scanner install-skill --agent claude --dry-run

# Remove (only skills this tool owns)
secrets-scanner uninstall-skill --agent claude
```

`--agent` is required and validated against the agent-config registry (run with an unknown id to print the supported list, e.g. `claude`, `codex`, `hermes`, `openclaw`, `cursor`, `gemini`, …). Each runtime's skill lands in its own location (`claude` → `.claude/skills/`, `codex`/`openclaw` → `.agents/skills/`, etc.). This renders one shared `SKILL.md` per runtime; the hand-tuned committed copies under `.claude/`/`.codex/`/`.hermes/`/`.openclaw/` are maintained separately.

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
