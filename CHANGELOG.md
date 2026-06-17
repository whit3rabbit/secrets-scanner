# Changelog

## Unreleased

## v0.2.2 (2026-06-16)

### Changed
- Version bump to republish the GitHub Action to the Marketplace. No code or
  ruleset changes versus v0.2.1.

## v0.2.1 (2026-06-16)

### Fixed
- npm bindings (`@whit3rabbit/rsecrets-scanner`) now publish as a single
  multi-platform "fat" package that bundles every platform's prebuilt binary
  (macOS arm64/x64, Linux x64/arm64 gnu, Windows x64) and selects the matching
  one at runtime. Fixes the `EBADPLATFORM` failure that blocked the 0.2.0 npm
  publish (the package previously pinned `os`/`cpu` to darwin/arm64 while
  publishing from a Linux runner).
- The runtime loader (`lib/loader.js`) resolves the abi-suffixed binary for the
  host (with glibc-vs-musl detection on Linux); a host without a matching
  prebuilt gets a clear `NATIVE_BINDING_NOT_FOUND`.

### Changed
- `publish.yml` rebuilt as a 5-target native build matrix plus a single-package
  publish job using npm **trusted publishing (OIDC)** (no token), with a
  fail-safe `workflow_dispatch` dry-run mode.

## v0.2.0 (2026-06-16)

### Added
- `install-skill` / `uninstall-skill` CLI subcommands: install or remove the
  bundled agent skill into supported runtimes via the `agent-config` crate
  (`--agent <id>`, `--local [PATH]`, `--dry-run`). Uninstall only removes skills
  carrying the `secrets-scanner` owner tag.
- `--rules-source <bundled|auto>` on `scan`: select the embedded ruleset
  explicitly (`bundled`) or use the standard env/cache/bundled priority order
  (`auto`, the default). An explicit `--rules <file>` still takes precedence.
- GitHub Action (`action.yml`) inputs: `rules-source` (defaults to `bundled` for
  deterministic CI), `git-history` + `history-timeout` (Gitleaks-style history
  scanning), and `build-from-source` (build the scanner from the action checkout
  for dogfooding before a release exists). Scan modes are now mutually exclusive
  (`git-history` > `base` > `git-tracked`). The action is published as
  "RSecrets Scanner".
- Benchmark harness documentation and an auto-generated benign corpus
  (`scripts/gen_corpus.sh`, `scripts/benchmark.sh`).

### Changed
- Hardened all scanner-written output files (`--output`, `--generate-baseline`):
  created `0600` and opened with `O_NOFOLLOW | O_CLOEXEC`, then verified to be a
  regular file, so a planted symlink or pre-existing fifo/device/dir at the
  output path is rejected rather than followed/truncated.
- Stricter rule-predicate validation during rule loading.
- Refactored rule loading and updated scan tests.
- Bumped pinned GitHub Actions to current major versions across CI/release
  workflows (`checkout@v6`, `setup-node@v6`, `upload/download-artifact`,
  `action-gh-release@v3`, `codeql-action@v4`, etc.).

## v0.1.0 (2026-06-15)

Initial release.

### Added
- Claude Code plugin and marketplace (`plugins/secrets-scanner/`,
  `.claude-plugin/marketplace.json`): a bundled skill that installs/uninstalls
  the scanner, sets up a native `scan --staged` git pre-commit hook, or runs
  scans on demand. Install with
  `/plugin marketplace add whit3rabbit/secrets-scanner` then
  `/plugin install secrets-scanner@whit3rabbit`.
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
