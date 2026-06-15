# Secrets Scanner

- A Rust library/binary that pulls rules from gitleaks and custom secret lookups to scan code
repos, or act as a proxy to intercept secrets (e.g. in LLM pipelines).

- First is to build as a library scanner. Then as a CLI. Users should be able to integrate scanner into their own codebase.

---

## Coding Guidelines

- Safety first, speed second
- `CLAUDE.md` is a symlink to `AGENTS.md` — edit `AGENTS.md` (the `Write` tool refuses symlinks).
- Files included by `build.rs` via `#[path]` (`merge.rs`, `validation.rs`, `manifest.rs`) must stay crate-independent: no `crate::`/`super::`, only std + `[build-dependencies]` (serde/toml/regex/log).
- A `#[cfg(test)] mod tests;` in any file that `build.rs` `#[path]`-includes needs an explicit `#[path = "..."]`, or `cargo fmt` fails to resolve the submodule.
- Keep source files ≤ 400 lines; split tests into a dedicated `tests/` module when a file exceeds this. When *non-test* code exceeds 400 lines, extract a cohesive concern into a sibling file declared `#[path = "x.rs"] mod x;` — a child module reuses the parent's private items (structs, fns, fields) via `super::` (e.g. `walk_staged.rs` inside `walk.rs`).
- Document every public function, struct, and trait with a `///` doc comment.
- Prefer `--features updater` builds for development; the default (no feature) build is the lean release artifact.
- The `bench` feature gates per-scan timing instrumentation; run `cargo test --features bench` to exercise bench-gated tests (default builds show expected rust-analyzer "inactive-code" hints on those lines — not errors).
- No `unwrap()` in library code — use `?` or explicit error handling.

---

## Commands

| Command | Purpose |
|---|---|
| `make ci` | Full local gate: fmt, clippy, tests, rule drift/validation, merge drift, full build |
| `make test-updater` | Run tests with the runtime updater feature enabled |
| `make merge-rules-check` | Verify committed `assets/secrets-scanner.toml` matches the lean manifest merge |
| `make build-full` | Build with `--features full-ruleset` |
| `cargo test --bin secrets-scanner --features updater` | Fast focused check for binary/CLI refactors |
| `cargo run -- scan <path> --git` | Run a scan locally (safe-default git mode) |
| `cargo run -- completions <shell>` | Generate shell completions (bash/zsh/fish/...) |

---

## Project Structure

```
secrets-scanner/
├── assets/
│   └── gitleaks.toml          # Bundled ruleset (committed, updated via scripts/update_rules.sh)
├── scripts/
│   ├── update_rules.sh        # Shell script: download latest gitleaks rules
│   └── generate_fixtures.py   # Python script: generate positive test cases matching custom rules
├── src/
│   ├── lib.rs                 # Public scanner library API
│   ├── main.rs                # Thin binary entrypoint; delegates to `cli::run()`
│   ├── cli/                   # Clap args, dispatch, scan/rules/completions handlers
│   ├── scanner.rs             # Scanner facade; submodules handle walk/matching/redaction/types
│   ├── format.rs              # CLI text/JSON/JSONL/SARIF writers
│   └── rules/
│       ├── mod.rs             # load_rules() — three-tier rule loading
│       ├── updater.rs         # Runtime HTTP updater (feature-gated: `updater`)
│       └── validation.rs      # Rule TOML and Regex validator
├── build.rs                   # Validates and merges manifest-selected rule sources at compile time
└── Makefile                   # Developer convenience targets
```

---

## Gitleaks Rules

### Rule Sources

| Priority | Source | When active |
|---|---|---|
| 1 (highest) | `$SECRETS_SCANNER_RULES` env var | Any time the var is set |
| 2 | Cached file in OS data dir | After a successful `update-rules` run |
| 3 (default) | Bundled manifest-merged ruleset embedded in binary | Always (compile-time fallback) |

**Gotchas:**
- Runtime loading is three-tier: `scan`/`list-rules` read the OS data-dir cache *before* the embedded rules, so they don't reflect the bundled set. To test embedded rules, set `SECRETS_SCANNER_RULES=<file>` or run `make clean-rules`.
- Many local rules use look-around (`(?<!…)`/`(?!…)`) which Rust's `regex` rejects, so those rules are disabled — raw rule count ≫ compiled/active count (e.g. lean 1136 merged → 987 active). `tests/scan_integration.rs` snapshots the compiled rule + keyword counts.

### Upstream URL

```
https://raw.githubusercontent.com/gitleaks/gitleaks/refs/heads/master/config/gitleaks.toml
```

### Updating Rules — Two Paths

#### 1. Shell script (build-time / CI)

Downloads the latest ruleset into `assets/gitleaks.toml` and updates the committed file so
the next binary build embeds a fresh copy.

```bash
# Download and replace assets/gitleaks.toml
./scripts/update_rules.sh

# Check whether an update is available (exit 1 if yes, 0 if current)
./scripts/update_rules.sh --check

# Makefile shortcut
make update-rules
```

The script uses SHA-256 comparison to skip unnecessary writes and is idempotent.

#### 2. Runtime CLI (end-user / deployed binary)

Requires the binary to be built with `--features updater` (adds the `ureq` HTTP dep).
Downloads to the OS user-data directory and takes effect on the **next scan** without
rebuilding the binary.

```bash
# Download latest rules to OS data dir
secrets-scanner update-rules

# Check-only mode (exit 1 if update available)
secrets-scanner update-rules --check

# Makefile shortcut (builds with updater feature first)
make update-rules-runtime
```

OS data-dir locations:

| OS | Path |
|---|---|
| macOS | `~/Library/Application Support/secrets-scanner/secrets-scanner.toml` |
| Linux | `~/.local/share/secrets-scanner/secrets-scanner.toml` |
| Windows | `%APPDATA%\secrets-scanner\secrets-scanner.toml` |

### Build-time Embedding (manifest-driven)

Rule sources are declared in `assets/sources.toml` (the manifest): each `[[source]]` has a `name`, `file`, `priority` (higher wins collisions), and `embed` flag. `build.rs` reads the manifest, selects the sources to embed (all `embed = true`; `embed = false` ones are added only with `--features full-ruleset`), validates each, merges them via the shared `merge_sources` core (`src/rules/merge.rs`), and writes the combined ruleset to `$OUT_DIR/secrets-scanner.toml`. It is embedded via:

```rust
pub const BUNDLED_RULES: &str = include_str!(concat!(env!("OUT_DIR"), "/secrets-scanner.toml"));
```

The default lean build embeds gitleaks + local + kingfisher (`local` priority 100 > `gitleaks` 10 > `kingfisher` 7, preserving "local overrides upstream"). `secrets-patterns-db` (`embed = false`) is opt-in via `--features full-ruleset`. Changing the manifest or any listed source file triggers a recompile. If `assets/sources.toml` is absent, build.rs falls back to the legacy gitleaks+local 2-way merge.

The committed `assets/secrets-scanner.toml` is a lockfile-style artifact (the lean merge output) regenerated by `make merge-rules` — used for inspection and the CI drift check, NOT written by `build.rs`. The `merge-rules` CLI subcommand calls the same `merge_sources` core, so it stays byte-identical to a lean build.

#### Dedup levels (in `merge_sources`)
1. **id collision** — higher-priority rule wins; lower dropped (recorded).
2. **exact-regex + detection-equivalent** — same regex AND same keywords/path/`secretGroup`/`entropy` → lower dropped (recorded). When the regex matches but those differ, BOTH are kept (a difference in keywords/path/entropy means the rules fire in different situations; dropping one could miss secrets) and the conflict is recorded.
3. **normalized-regex near-dup** — recorded only, never dropped (advisory).

#### Generate / inspect the merged ruleset
```bash
make merge-rules        # regenerate committed assets/secrets-scanner.toml (lean) + target/merge-report.json
make merge-rules-full   # merge incl. embed=false sources → target/secrets-scanner.full.toml
make merge-rules-check  # CI drift: compare without rewriting committed assets/secrets-scanner.toml
make build-full         # cargo build --features full-ruleset
secrets-scanner merge-rules --manifest assets/sources.toml --out <path> [--all] [--report <path>] [--check]
```

#### Finding duplicate rules (advisory, never auto-drops)
`scripts/find_duplicate_rules.py` surfaces likely duplicates across sources for human review using two signals: cross-source **vendor clusters** (rules for the same service in multiple sources, e.g. `openai` in gitleaks + spdb) and **behavioral co-fire** (rules whose regexes bidirectionally match each other's generated example secrets). Needs `pip install -r scripts/requirements-dev.txt` (rapidfuzz) for fuzzy stem merging; falls back to exact stems otherwise.
```bash
make find-dups          # → target/dup-report.md + target/dup-report.json
```

#### Kingfisher source (YAML → TOML converter)
`assets/kingfisher-rules.yml` (MongoDB Kingfisher, ~954 rules, downloaded by `scripts/update_kingfisher_rules.py`) is converted to gitleaks-compatible TOML by `scripts/convert_kingfisher_rules.py`, mirroring the secrets-patterns-db importer. The manifest references the generated `assets/kingfisher-rules.toml` with `embed = true`. The converter:
- maps `id` (kept namespaced), `name`+`confidence` → `description`, `pattern` → `regex` (verbose `(?xi)`, preserved verbatim), `min_entropy` → `entropy`, and sets `secretGroup = 1` (Kingfisher's group 1 is the secret); the keyword is the vendor stem of the id (Aho-Corasick prefilter);
- **skips `visible: false`** helper rules (broad/low-entropy, exist only for composite HTTP validation);
- **drops** features with no TOML home: `pattern_requirements`, `validation`, `depends_on_rule`, `references`, `examples`;
- **behaviorally dedups** against gitleaks+local using the same bidirectional co-fire signal as `find_duplicate_rules.py` (drop a Kingfisher rule when an existing rule already detects its example secret AND vice versa; `--aggressive` makes it one-directional). RNG is seeded for reproducible output;
- runs a **validate-and-drop** pass (`validate-rules` subcommand) so only Rust-`regex`-compilable patterns are emitted — required because the merge engine's exact-regex dedup is byte-level, not behavioral, so the converter must catch what the engine can't. The drop report is `assets/kingfisher-rules-dups.json`.

```bash
make convert-kingfisher        # regenerate assets/kingfisher-rules.toml from the committed .yml
make convert-kingfisher-check  # dry-run: count breakdown, writes nothing
make update-kingfisher         # download latest Kingfisher YAML, then re-convert
```
Regenerate the merged ruleset (`make merge-rules`) and bump the `tests/scan_integration.rs` snapshot after re-converting.

### CI Recommendation

Add a step to your pipeline to check for upstream rule drift:

```yaml
- name: Check gitleaks rules are up to date
  run: ./scripts/update_rules.sh --check
```

Fail the build (or open a PR) when the check exits non-zero.

---

## Custom Rules

Custom rules live alongside the gitleaks rules in the same TOML format for compatibility.
The cached `secrets-scanner.toml` in the OS data directory is a combined ruleset containing both the downloaded upstream gitleaks rules and the local custom rules. Anyone can add new rules by editing the local custom rules file (`assets/local.toml` in the repository, or a `local.toml` file in the working directory or OS data directory).

During startup or rule updates, the scanner automatically merges the two sets of rules. Custom rules take precedence over upstream rules with the same `id`.

### Testing Custom Rules

To prevent regressions and verify that custom rules accurately match target secrets, we use an automated test fixture generation and validation harness.

1. **Fixture Generation (`scripts/generate_fixtures.py`)**: 
   Parses `assets/local.toml` and compiles each regex to generate positive test matches (fake secrets). It ensures that the generated secrets satisfy Aho-Corasick filters by including matching keywords in a `test_content` block. The output is saved to `tests/local_rules_fixtures.json`.
   
   ```bash
   # Generate or update local rule fixtures
   make generate-fixtures
   ```

2. **Integration Test Suite (`tests/local_rules_validation.rs`)**:
   Runs automatically as part of `cargo test` (or `make test`). It reads the generated fixtures JSON, feeds each test string into the compiled scanner, and asserts that the corresponding `rule_id` is successfully detected. Only active rules (i.e. those successfully compiled by Rust's `regex` engine) are tested.

---

## Scanning & Hardening

The `scan` subcommand is hardened for hostile/attacker-controlled repository
content (e.g. running as a GitHub Action). Key behaviors:

- **Bounded reads** (`src/scanner/walk.rs`): owned read (not mmap) capped with
  `Take`, closing the TOCTOU window if a file grows after the metadata check.
- **Symlinks rejected**: `symlink_metadata` + `is_file()` skips symlinks (incl.
  git-tracked), preventing reads outside the tree.
- **Content-based binary detection** (`src/filters.rs::is_probably_binary`):
  NUL-byte / control-byte ratio, independent of extension. `--binary-policy
  auto|skip|scan` (default `auto`). `auto` skips binaries unless the path is
  source/secret-bearing (`is_source_allowlisted`: `.env*`, `.pem`, `.key`,
  `.json`, `.yaml`/`.yml`, `.toml`, `.properties`, `.npmrc`, `.pypirc`,
  `Dockerfile`, `Makefile`); `skip` ignores the allowlist; `scan` never skips.
- **Git path safety** (`src/scanner/walk.rs`): NUL-delimited output
  (`-z`, `core.quotePath=false`), absolute paths from git are dropped (containment),
  `--diff-base <ref>` scans `<base>...HEAD`, `--include-untracked` adds
  `ls-files --others --exclude-standard`. On any git failure the scan falls back
  to a directory walk and the fallback is recorded (`ScanStats.git_fallback`) so
  the scope change (may include untracked/ignored files) is surfaced, not silent.
  Directory-walk traversal errors (e.g. an unreadable subdir) count toward
  `ScanStats.errored`, not silently dropped.
- **Staged mode** (`src/scanner/walk_staged.rs`): `--staged` scans the **index
  blob content** that is about to be committed (`git diff --cached
  --name-only --diff-filter=ACMR` then `git cat-file -s`/`blob :path`), NOT the
  working-tree files — so a secret staged then scrubbed from the working copy (or
  staged via `git add -p`) is still caught. Blob size is checked before the read
  (bounded-memory). Staged deletions are excluded. It is mutually exclusive with
  `--git-diff`/`--diff-base`/`--include-untracked` (enforced by clap).
- **Inline suppression**: a line containing `secrets-scanner:allow` or
  `gitleaks:allow` (ecosystem compat) skips that finding (`matching.rs`). For
  multi-line matches (e.g. PEM keys) the marker is honored on the match's first
  line only.
- **Result caps**: `--max-files`, `--max-findings`, `--max-findings-per-file`.
  Every cap that fires logs a truncation notice (never silent).
- **Honest coverage**: `ScanStats.errored` counts files that could not be
  stat'd/read (distinct from intentional binary/oversized skips) and the CLI
  summary reports `N unreadable`, so an errored file never looks like a
  scanned-and-clean one.
- **Entropy floor**: `--min-entropy` (`min_entropy_override`) only *raises* a
  rule's threshold (`max(override, rule_threshold)`); a low value can never
  weaken a stricter rule.
- **Safe CI logging**: `--no-context` suppresses context lines; text output
  escapes control chars in paths/matched (`safe_display::sanitize_display`) to
  prevent terminal/CI-log injection. A file-level summary (counts only, no
  secrets) is logged to stderr via `ScanStats` (`Scanner::scan_path_with_stats`).
- **Baseline** (`--baseline`/`--generate-baseline`): suppression matches on a
  line-tolerant SHA-256 v2 fingerprint (`fingerprint::finding_fingerprint` over
  rule id + file + raw secret, computed pre-redaction so it is redact-agnostic),
  with a fallback to the legacy `(file, line, rule)` tuple for baselines written
  before fingerprints existed. `--generate-baseline <file>` writes the current
  findings as JSON (includes fingerprints) and exits 0. The `matched` field is
  force-redacted even under `--no-redact` (suppression keys on the fingerprint,
  not the text), so a committed/uploaded baseline never carries raw secrets.
  Baselines from older FNV-fingerprint builds should be regenerated once.
- **SARIF** (`src/format.rs::write_sarif`, serde_json): `--output <file>`,
  generic `message.text` (rule + entropy, never the matched value),
  `partialFingerprints` (the finding's pre-redaction fingerprint, falling back to
  `fingerprint::location_fingerprint` over `rule_id|uri|start|end` — never the
  matched value), `startLine`/`startColumn`/`endColumn` clamped `>= 1` (a
  `line == 0` finding cannot emit an invalid region), columns in **UTF-16 code
  units** (SARIF's default `columnKind`, which GitHub assumes; byte columns are
  kept for text/JSON), repo-relative `uri` + `uriBaseId: "SRCROOT"` (multi-path
  scans relativize against the current directory), driver metadata,
  `automationDetails`.

### Proxy / untrusted content

The file-walk path is hardened for hostile repos; the **in-memory content APIs**
(`scan_content`, `scan_and_redact_bytes`) are not, on their own. For a redaction
proxy filtering attacker-controlled LLM traffic, use the dedicated entry point:

- **`Scanner::scan_proxy(content) -> Result<ScanOutput<Vec<u8>>, ProxyError>`**
  (`src/scanner.rs`): **fails closed** — input over `max_file_size` returns
  `ProxyError::InputTooLarge` and produces no output, so oversized content is
  never forwarded unscanned. The hardened posture is **enforced, not advisory**:
  if the scanner's config is not hardened (redact off, allow markers honored,
  context captured, or finding/`matched` caps unset) `scan_proxy` returns
  `ProxyError::NotHardened` without scanning, so the untrusted path cannot be used
  un-hardened by accident (e.g. `Scanner::from_bundled()?.scan_proxy(...)`). Pair
  with **`ScanConfig::proxy()`** (`src/scanner/types.rs`), which: redacts; sets
  `honor_allow_markers = false`
  (an attacker can't append `secrets-scanner:allow` to forward a secret in the
  clear); sets `capture_context = false` (no whole-payload context blowup on
  newline-free input); caps `max_findings_per_file` (enforced inside
  `scan_bytes`, not just the walk) and `max_matched_len` (a match longer than the
  cap is reported as `[MATCH OMITTED: N bytes]` instead of a payload-length
  redaction string). Forwarded content always uses the fixed `[REDACTED_SECRET]`
  marker.

Deployment caveats (not enforced in code):

- **Encoded/obfuscated/split secrets evade detection** (base64/hex/zero-width/
  line-fragmented) — same limitation as below; this redactor catches literal,
  recognizable secrets only.
- **Redaction is not injection sanitization.** Non-secret bytes (shell/SQL/XSS/
  prompt-injection payloads) pass through untouched; do not treat post-redaction
  output as safe to hand to a shell/renderer.
- **Findings carry raw attacker bytes** (`matched`, `context_lines` may contain
  control/ANSI chars). Library callers must sanitize at the logging boundary
  (the CLI does this via `safe_display::sanitize_display`).
- Audit the active ruleset for `regexTarget = line|match` allowlists: in proxy
  mode the attacker controls the haystack those allowlists run against.

### Known limitations

Detection runs on raw file bytes, so it does not see secrets that are
base64/URL-encoded, JSON-escaped, or inside skipped archives (`.zip`, `.tar`,
Docker layers). This matches gitleaks. A decode-then-rescan pass is a possible
future enhancement.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed; no findings (or `--no-fail`) |
| 1 | Completed; findings present (unless `--no-fail`) |
| 2 | Runtime error (I/O, baseline read/parse, output write) |
| 3 | Invalid configuration/rules (rules file unreadable or uncompilable) |

The table above is the `scan` mapping. `--no-fail` writes output but always
exits 0 on findings, so a workflow can upload SARIF and gate separately.

`validate-rules` has its own mapping (validity is its result, not a config error
blocking a scan): **0** = all files valid; **1** = ≥1 file parsed but invalid
(a rule/regex failed); **2** = ≥1 file unreadable (I/O). A read error takes
precedence over invalid content. Exit 3 stays reserved for `scan`'s runtime
rule-load failures.

### GitHub Action

`action.yml` is a composite action: it downloads the pinned prebuilt release
binary (target triple per `install.sh`; version from `inputs.version`, else the
action ref, else latest) and runs `scan` with a safe-by-default posture
(`--git --redact --no-context --format sarif --output <file>`). Inputs:
`path`, `config`, `fail-on-findings`, `sarif`, `sarif-file`, `git`,
`diff-base`, `max-file-size`, `binary-policy`, `version`, `extra-args`. Output:
`sarif-file`. A runnable example that dogfoods `uses: ./` lives at
`.github/workflows/secrets-scan.yml` (non-blocking; flip `fail-on-findings`).

Upload SARIF with `github/codeql-action/upload-sarif` (needs
`security-events: write`; private repos also `actions: read` + `contents: read`).
Use `if: always()` on the upload step (or `fail-on-findings: false` + a separate
gate) so SARIF uploads even when findings are present.

### Docker

`Dockerfile` is a multi-stage build: `rust:1-alpine` (musl, lean default build,
no `updater` feature) → `alpine:3` runtime with `git` + `ca-certificates`.
`ENTRYPOINT secrets-scanner`, `WORKDIR /repo`. `git` is bundled because the
safe-default `--git` mode shells out to it. Rules are embedded at compile time
(no runtime `update-rules`), so rebuild the image to refresh them.
`.dockerignore` excludes `target/`/`.git/` but **not** `assets/` (build.rs reads
it). Auto-published to Docker Hub on release tags.
`docker run --rm -v "$PWD:/repo" <image> scan /repo --git`.

---

## Rule Validation

To ensure rules have valid TOML syntax and that their regular expressions are fully compilable (without syntax or size limit issues), the project includes a validation layer (`src/rules/validation.rs`).

### Validation Checks
- **TOML Structure**: Verifies the file parses into the expected `RulesetConfig` format.
- **Rule IDs**: Ensures every rule has a non-empty, unique ID.
- **Regex Compilation**: Escapes literal braces and increases compilation size limits (to 100MB) to strictly verify that all rule detection regexes, path filters, local allowlists, and global allowlists compile under Rust's `regex` engine.

### Validation Environments

#### 1. Compile-Time (`build.rs`)
Runs automatically during `cargo build` or `cargo test`. It validates each selected manifest source before merging, and validates the combined ruleset (written to `$OUT_DIR`) after merging. If any error is found, the build fails with a detailed panic message.

#### 2. Update-Time (`src/rules/updater.rs`)
Runs automatically during rule updates. It validates downloaded rules and the merged result before writing them to the cache, preventing corrupted rules from disabling the scanner on subsequent runs.

#### 3. CLI Subcommand (`validate-rules`)
Allows manual validation of any TOML rules file.
```bash
# Validate default assets
secrets-scanner validate-rules

# Validate specific rules files
secrets-scanner validate-rules path/to/my-rules.toml
```
Exit: 0 valid, 1 invalid rules, 2 unreadable file (see Exit codes above).

#### 4. Makefile Shortcut
```bash
make validate-rules
```
This is also run automatically after downloading rules with `make update-rules` and is part of the `make ci` suite.

---

## Release

Release is CI-only. Do not publish from a local machine except for dry-run validation.

Pre-release:
- Make the GitHub repo public before pushing the release tag if Homebrew install should work. A private repo can still publish crates.io and GitHub Release artifacts, but normal Homebrew installs cannot fetch private release asset URLs.
- Update `Cargo.toml` `[package].version`, `Dockerfile` `LABEL version`, and `CHANGELOG.md` for the same `vX.Y.Z`.
- Run `make ci`. For packaging changes, also run `cargo publish --dry-run --locked` from the clean release commit.
- Commit and push the release prep to `main`.

Publish:
```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

The tag must match `Cargo.toml` and the `Dockerfile` version; `.github/workflows/release.yml` fails otherwise. The release workflow builds updater-enabled binaries, creates the GitHub Release, publishes the `secrets_scanner` crate with `CARGO_REGISTRY_TOKEN`, publishes the Docker image to Docker Hub, and updates `whit3rabbit/homebrew-tap/Casks/secrets-scanner.rb` with `HOMEBREW_TAP_TOKEN` when the repo is public.

Post-release:
- Watch the GitHub Actions `Release` run to completion.
- Verify `gh release view vX.Y.Z`, `cargo search secrets_scanner --limit 3`, and `gh api 'repos/whit3rabbit/homebrew-tap/contents/Casks/secrets-scanner.rb?ref=main'`.
- Run `git fetch origin main --tags` before trusting local release state.


<!-- syntext-agent:claude:start -->
## Code Search

Use `st` instead of `rg` or `grep` when `.syntext/` exists.
Before the first search in a repo, run `test -d .syntext || st index`.
After file edits, run `st update` before relying on search results.
<!-- syntext-agent:claude:end -->
