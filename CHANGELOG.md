# Changelog

## Unreleased

### Added
- Inline suppression: a line containing `secrets-scanner:allow` or
  `gitleaks:allow` skips that finding (first line only for multi-line matches).
- `--staged` scan mode for pre-commit hooks: scans the **index blob content**
  (`git cat-file`) that is about to be committed, not the working-tree files.
  Mutually exclusive with `--git-diff`/`--diff-base`/`--include-untracked`.
- `--generate-baseline <file>` writes current findings as a baseline and exits 0.
- `ScanStats.errored` (unreadable-file count) and `git_fallback` flag, surfaced
  in the CLI summary so incomplete coverage is never silent.
- `bench` cargo feature gating the per-scan timing instrumentation (off in the
  lean release build).
- Fuzz target `fuzz_rule_parsing` over `validate_rules_toml` / `Scanner::from_toml`.
- `ScannerError` typed error enum and `fingerprint` module (public).
- `RuleEngine::from_toml_reporting` — builds the engine and returns the list of
  rules/regexes it had to drop plus structural ID issues, so a strict caller can
  reject without a second validation pass.
- Direct tests for `sanitize_display`, SARIF region/columns, `walk.rs` internals,
  and a property test asserting redacted output never contains the verbatim secret.

### Changed
- **Breaking (library):** `Scanner::{new, from_bundled, from_file, from_toml}`
  and `RuleEngine::from_toml` now return `Result<_, ScannerError>` instead of
  `Box<dyn Error>`. `from_toml`/`from_file` now validate rules up front and
  return `ScannerError::InvalidRules`.
- `--baseline` matching is now line-tolerant (fingerprint over rule + file + raw
  secret), with a fallback to the legacy `(file, line, rule)` tuple.
- `--min-entropy` is now a floor: it only raises a rule's threshold, never lowers
  it (was a replacement that could weaken stricter rules).
- SARIF `startColumn`/`endColumn` are emitted in UTF-16 code units (SARIF's
  default `columnKind`, which GitHub code scanning assumes).
- `walk.rs` warnings standardized on `log::warn!` (were `eprintln!`).
- **Breaking (action):** the `extra-args` input is now newline-delimited (one
  argument per line) instead of whitespace-split, so values may contain spaces.
  Migrate `extra-args: "--max-findings 50"` to one token per line
  (`--max-findings` then `50`), or `--max-findings=50` on a single line.
- A custom `--rules` file is now all-or-nothing: if any rule fails to compile the
  whole file is rejected (exit 3) rather than silently scanning with fewer rules.
  Run `validate-rules <file>` to find the offending rule.
- `Scanner::from_toml` now does the strict-validation and the engine build in a
  single parse+compile pass (via `RuleEngine::from_toml_reporting`) instead of
  parsing the TOML twice and compiling every regex twice. Behavior is unchanged;
  the same invalid regex / empty ID / duplicate ID still rejects the ruleset.

### Fixed
- `--staged` previously scanned working-tree bytes of staged paths, so a secret
  staged then removed from the working copy (or staged via `git add -p`) was
  missed. It now reads the index blob, and excludes staged deletions.
- UTF-16 SARIF column computation no longer re-decodes the line prefix per
  finding (was O(n²) on long single-line/minified files); an all-ASCII line now
  computes columns in O(1).
- Directory-walk traversal errors (e.g. an unreadable subdirectory) are now
  counted in `ScanStats.errored` instead of being silently dropped, closing a
  gap in the honest-coverage reporting.
- `--generate-baseline` now redacts the `matched` field even under `--no-redact`,
  so baselines committed to a repo or uploaded as CI artifacts never contain raw
  secrets (suppression keys on the fingerprint, not the matched text).
- Multi-path SARIF output relativizes against the current directory, so absolute
  paths from absolute path arguments are no longer emitted as absolute URIs that
  GitHub code scanning cannot resolve.
- SARIF `startLine` is clamped to `>= 1`, so a `line == 0` finding cannot emit an
  invalid region.

## v0.1.0 (2026-06-14)

Initial release.

### Core scanning
- Multi-layer scan pipeline: memchr SIMD pre-filter, Aho-Corasick keyword matching, Shannon entropy gating, regex capture
- Parallel file scanning with Rayon work-stealing
- Memory-mapped file support for large files
- Gitleaks-compatible TOML ruleset configuration
- Three-tier rule loading: env var, OS data dir cache, bundled defaults
- Runtime rule updater (HTTP download via `ureq`, feature-gated)
- Build-time TOML merge and validation

### CLI
- Subcommands: `scan`, `update-rules`, `validate-rules`, `list-rules`
- Output formats: text, JSON, JSONL, SARIF 2.1.0
- Configurable: custom rules path, rule exclusions, entropy threshold, file size cap, redaction toggle

### Rules engine
- Keyword-based Aho-Corasick automaton with case-insensitive matching
- Per-rule and global allowlists (paths, regexes, stopwords, conditions)
- `secretGroup` capture group extraction
- Regex validation with look-around detection and fallback
- Unkeyworded fallback rule evaluation with benchmark timing

### Quality
- `#[deny(clippy::unwrap_used)]` and `#[deny(missing_docs)]` enforced
- 40+ unit and integration tests
- CI matrix: Linux, macOS, Windows
