# `secrets-scanner` — Road to Great

> Priority tiers: **P0** (blocking), **P1** (high value), **P2** (nice to have)

---

## 🏗️ Core Architecture

- [x] **P0** Create `src/lib.rs` — wire together `entropy`, `filters`, `rules::engine`, expose a public `scan_content(path, content, engine)` function returning `Vec<Finding>`
- [x] **P0** Create `src/main.rs` — CLI entry point using `clap` derive, subcommands: `scan <path>`, `update-rules [--check]`, `list-rules`
- [x] **P0** Define a `Finding` struct: `{ rule_id, description, file, line, col, matched, secret_redacted, entropy }` — derive `Debug`, `Serialize`
- [x] **P0** Implement the core scan loop in a `scanner.rs` module: walk files → filter → keyword pre-screen (Aho-Corasick) → regex match → entropy gate → allowlist checks → emit findings
- [x] **P1** Add `build.rs` — at build time, merge `assets/secrets-scanner.toml` + `assets/local.toml` via `merge_toml_rules()` and verify it parses cleanly; fail the build on broken TOML

---

## 🔍 Scan Engine

- [x] **P0** Wire memchr SIMD pre-filter: before running the AC automaton on a line, check `keyword_first_bytes` with `memchr::memchr_iter` — skip lines with no candidate bytes
  - Note: implemented as a `memchr::memchr` loop over the first-byte set (`src/scanner/walk.rs`); functionally equivalent to a single `memchr_iter` pass.
- [x] **P0** Line-number tracking — byte offset → line number mapping so `Finding.line` is accurate
- [x] **P0** Apply `filters::should_scan` before opening any file
- [x] **P0** Apply global path allowlist (`engine.is_path_globally_allowlisted`) before scanning
- [x] **P1** Support `secretGroup` capture — when `CompiledRule.secret_group` is `Some(n)`, extract group `n` as the secret; fall back to group 1, then full match
- [x] **P1** Per-rule `path` filter — skip the rule entirely if the file path doesn't match `path_filter`
- [x] **P1** Apply per-rule allowlist path entries (currently `_file_path` is unused in `is_rule_allowlisted`) — actually check `allowlist.paths` against the file path
- [x] **P1** Per-rule `allowlist_match_target` — when `true`, run allowlist regexes against the full matched line, not just the captured group
- [x] **P2** Context lines — include ±2 surrounding lines in `Finding` for richer output
- [x] **P2** Git-aware mode: scan only files tracked/changed by git (`git ls-files` or `git diff`) rather than walking the whole tree

---

## ⚡ Performance

- [x] **P0** Parallel file scanning with `rayon::par_iter` over the `walkdir` results — collect findings into a thread-safe aggregator
- [x] **P1** Memory-map large files (`memmap2` crate) instead of `fs::read_to_string` — avoids heap allocation for big files
  - Note: intentionally NOT using `memmap2`. `src/scanner/walk.rs` reads with owned `std::fs::read` so the scanner is immune to SIGBUS if a file is truncated concurrently during the scan. A size cap (default 2 MB) bounds the allocation.
- [x] **P1** Avoid per-line `String` allocation — scan byte slices directly, only allocate for actual findings
- [x] **P2** Benchmark harness (`benches/scan.rs` with `criterion`) against a corpus of real files
- [x] **P2** Profile and tune AC automaton construction — consider `AhoCorasickKind::DFA` for faster search at the cost of larger automaton

---

## 🧪 Testing

- [x] **P0** Integration test: `tests/scan_integration.rs` — create temp files with known secrets, run the scanner, assert findings match expected rule IDs
- [x] **P0** Test entropy gate: confirm low-entropy matches (e.g. `password = "changeme"`) are suppressed
- [x] **P0** Test global allowlist path suppression end-to-end
- [x] **P1** Test per-rule allowlist suppression (stopwords, regexes, path)
- [x] **P1** Test `secretGroup` extraction with a multi-capture-group regex
- [x] **P1** Test `redact()` output in `Finding` serialization — no raw secrets in JSON output
- [x] **P1** Snapshot tests for the bundled ruleset: store `rule_count` and `keyword_count` as fixtures, fail if they drop unexpectedly (catches accidental rule deletion)
- [x] **P2** Fuzz `scan_content` with `cargo-fuzz` — random file content should never panic

---

## 🖥️ CLI UX

- [x] **P0** `scan` subcommand: accepts one or more paths (files or directories), streams findings to stdout
- [x] **P0** `--format` flag: `text` (default, human-readable), `json`, `jsonl`, `sarif` (for GitHub Code Scanning integration)
- [x] **P0** Exit code: `0` = no findings, `1` = findings found, `2` = error — so CI pipelines can gate on it
- [x] **P1** `--no-redact` flag (for trusted local use) to show full matched secrets
- [x] **P1** `--rules` flag to specify a custom TOML path at runtime (complement to `SECRETS_SCANNER_RULES` env var)
- [x] **P1** `--ignore-rule <id>` flag to suppress specific rules without editing TOML
- [x] **P1** `--min-entropy <f64>` flag to override the global entropy floor at runtime
- [x] **P1** `list-rules` subcommand: tabular output of all loaded rules with ID, description, keyword count
- [x] **P1** Progress output (to stderr) when scanning large trees — rule count, file count, finding count
- [x] **P2** `--baseline <file>` flag: load a prior scan's JSON output and only report new findings (suppress known issues)
- [x] **P2** Shell completions: `secrets-scanner completions <shell>` (clap's `generate` feature)

---

## 🔄 Updater

- [x] **P0** Make `update-rules` actually callable from `main.rs` — wire the `UpdateResult` variants to human-readable output
- [x] **P1** Replace the `sha256_hex` shell-out with the `sha2` crate — the current `shasum` process spawn is fragile and slow
- [x] **P1** Add `--url <url>` flag to `update-rules` to pull from a fork or private mirror
- [x] **P2** Automatic staleness check on startup: if cached rules are >7 days old, print a hint suggesting `update-rules`
- [x] **P2** Checksum the merged TOML after download, not just the upstream file, so local merges are also verified

---

## 📦 Packaging & Distribution

- [x] **P1** `assets/local.toml` — document the schema and provide a commented example rule so users know how to add custom rules
- [x] **P1** `README.md` — quickstart, install instructions, usage examples, CI snippet, `local.toml` guide
- [x] **P1** GitHub Actions CI: `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`, matrix over Linux/macOS/Windows
- [x] **P1** Release workflow: `cargo-dist` or manual workflow to build static binaries for `x86_64-unknown-linux-musl`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`
- [x] **P2** Publish to `crates.io` — add `[package]` metadata: `description`, `license`, `repository`, `keywords`, `categories`
- [x] **P2** Homebrew formula or `cargo-binstall` manifest for easy install
- [x] **P2** Pre-commit hook integration: document usage in `README.md`, provide a `.pre-commit-hooks.yaml`

---

## 🛡️ Correctness & Safety

- [x] **P1** Validate that `secret_group` index is within bounds of the regex's capture groups at compile time — warn and fall back rather than panic
- [x] **P1** Handle non-UTF-8 files gracefully — use `read_to_end` + `String::from_utf8_lossy` instead of `read_to_string` to avoid hard errors on Latin-1 files
- [x] **P1** Add a file size cap (e.g. skip files > 10 MB) to prevent OOM on accidentally-scanned binary blobs that slip past the extension filter
- [x] **P2** Verify `merge_toml_rules` preserves the global `[allowlist]` from the override when both base and override define one (currently only base's allowlist is kept)
- [x] **P2** Detect and warn on duplicate rule IDs after merging

---

## 🧹 Code Quality

- [x] **P1** Move `rules/` out of a floating directory — ensure it lives under `src/rules/` and is declared as `mod rules` in `lib.rs`
- [x] **P1** Add `#[deny(clippy::unwrap_used)]` and eliminate panicking paths in library code
- [x] **P1** Add `#[deny(missing_docs)]` to the lib root — all public items should have doc comments (most already do)
- [x] **P2** Audit `eprintln!` calls — replace with a proper logging facade (`tracing` or `log`) so library users can control verbosity
- [x] **P2** CHANGELOG.md starting at `v0.1.0`

The pipeline
```
File bytes
   │
   ▼
[memchr SIMD]  ← skips keyworded-rule lookup when no keyword first bytes appear
   │
   ▼
[Aho-Corasick] ← single O(n) pass, finds ALL prefix hits simultaneously
   │
   ▼
[Entropy check] ← rejects "password = changeme", keeps high-randomness strings
   │
   ▼
[Regex]        ← validates structure across candidate content
   │
   ▼
Finding { file, line, matched (redacted), entropy }
```
Key design decisions

AhoCorasick is built once, shared across threads — it's Send + Sync so rayon can use it from every worker without cloning.
Regex only runs for candidate keyworded rules plus required unkeyworded rules. This keeps the slow layer bounded by rule candidacy without missing matches outside a fixed keyword window.
memchr gates keyworded candidate discovery before AC. It must not reject whole files because unkeyworded rules still run.
rayon::par_iter gives you work-stealing parallelism across all CPU cores with zero boilerplate — scanning 10k files uses all your cores automatically.


## Database

Pull rules from:

- CLI should be able to download rules from a URL
https://raw.githubusercontent.com/gitleaks/gitleaks/refs/heads/master/config/gitleaks.toml

- We should maintain our own custom rules in same format for compatibility with gitleaks. (TOML Format)
- After downloading merge into one rule set
- We shold be able to parse that one rule set


## SQLite vs TOML for Regex Rules in Rust

For **loading into memory**, the comparison looks like this:

### Cold Read (disk → memory)

| Method | Speed | Why |
|---|---|---|
| TOML file | **Faster** | Single sequential read + parse; no query overhead |
| SQLite | Slower | Database engine init, page parsing, B-tree traversal |

### Already-in-Memory Lookup

| Method | Speed | Why |
|---|---|---|
| `HashMap<String, Regex>` | **Fastest** | O(1) hash lookup |
| `Vec<(String, Regex)>` | Fast | O(n) linear scan, but cache-friendly for small sets |
| SQLite in-memory (`:memory:`) | Slowest | SQL parsing + query planner overhead per lookup |

---

## Fastest Approach for Rust

**Load from TOML at startup → compile regexes → store in a `HashMap`.**

```toml
# rules.toml
[rules]
email = "^[\\w.+-]+@[\\w-]+\\.[\\w.]+$"
phone = "^\\+?[1-9]\\d{1,14}$"
zip   = "^\\d{5}(-\\d{4})?$"
```

```rust
use std::collections::HashMap;
use regex::Regex;
use serde::Deserialize;

#[derive(Deserialize)]
struct Config {
    rules: HashMap<String, String>,
}

struct RuleEngine {
    patterns: HashMap<String, Regex>,
}

impl RuleEngine {
    fn load(path: &str) -> Self {
        let content = std::fs::read_to_string(path).unwrap();
        let config: Config = toml::from_str(&content).unwrap();

        let patterns = config.rules
            .into_iter()
            .map(|(name, pattern)| {
                let re = Regex::new(&pattern).expect("Invalid regex");
                (name, re)
            })
            .collect();

        Self { patterns }
    }

    fn matches(&self, rule: &str, input: &str) -> Option<bool> {
        self.patterns.get(rule).map(|re| re.is_match(input))
    }
}
```

---

## When SQLite *Would* Make Sense

Use SQLite if you need:
- **Dynamic updates** at runtime (add/remove rules without restart)
- **Large rule sets** (thousands) where you only load a subset at a time
- **Metadata** alongside rules (priority, tags, owner, enabled flag)
- **Concurrent writers** from multiple processes

---

## Summary Recommendation

| Scenario | Use |
|---|---|
| Rules are static / change with deploys | **TOML → HashMap\<String, Regex\>** |
| Rules are dynamic / admin-editable | SQLite → load subset into HashMap on demand |
| Sub-millisecond lookup after load | **Compiled `Regex` in HashMap** — the file format doesn't matter once in memory |

The bottleneck in regex workflows is almost never the lookup — it's the **`Regex::new()` compilation cost**. Compile once at startup, reuse forever.
