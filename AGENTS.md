# Secrets Scanner

- A Rust library/binary that pulls rules from gitleaks and custom secret lookups to scan code
repos, or act as a proxy to intercept secrets (e.g. in LLM pipelines).

- First is to build as a library scanner. Then as a CLI. Users should be able to integrate scanner into their own codebase.

---

## Coding Guidelines

- Safety first, speed second
- `CLAUDE.md` is a symlink to `AGENTS.md` — edit `AGENTS.md` (the `Write` tool refuses symlinks).
- `.claude/skills/secrets-scanner` is a committed symlink to `plugins/secrets-scanner/skills/secrets-scanner` (canonical skill home, also distributed via the plugin marketplace in `.claude-plugin/marketplace.json`). `.gitignore` deliberately re-includes only that path under the otherwise-ignored `.claude/` — don't drop the exception or the project skill stops being tracked. The skill is pinned to `model: haiku`. Only `.claude/` is a symlink to the canonical plugin; the `.codex/`, `.hermes/`, and `.openclaw/` skill dirs are **independent copies** (SKILL.md, REFERENCE.md, scripts), so any shared-content edit must be applied to all four runtimes (they diverge only by intended per-runtime frontmatter, the `$SKILL_DIR` vs `{baseDir}` token, and the MCP section, which Hermes/OpenClaw omit).
- The `install-skill`/`uninstall-skill` CLI subcommands (`src/cli/skill.rs`) install the skill into agent runtimes for **end users** via the `agent-config` crate. They embed the **canonical** skill (`include_str!` of `plugins/.../secrets-scanner/{SKILL.md,REFERENCE.md,scripts/*}`, like `BUNDLED_RULES`) and hand `agent-config` one `SkillSpec`, which **re-renders** `SKILL.md` per runtime. So that path produces a single shared body and does **not** reproduce the per-runtime nuances of the committed copies (the `$SKILL_DIR`/`{baseDir}` token, the MCP-section omission, hermes/openclaw frontmatter). The committed copies and the installer are independent; update the canonical `plugins/...` skill to change both. `agent-config` installs `codex`+`openclaw` under `.agents/skills/`, `claude` under `.claude/skills/`, etc. Owner tag is `secrets-scanner`; uninstall only removes skills carrying it.
- Two plugin marketplaces ship side by side and must be kept in sync: **Claude** (`.claude-plugin/marketplace.json` + `plugins/secrets-scanner/.claude-plugin/plugin.json`; `source` is a string) and **Codex** (`.agents/plugins/marketplace.json` + `plugins/secrets-scanner/.codex-plugin/plugin.json`; `source` is an object `{"source":"local","path":...}`, plugin entry also needs `policy`+`category`, top-level `interface.displayName`). Codex `source.path` resolves from the repo root. Schemas verified against developers.openai.com/codex/plugins/build.
- Files included by `build.rs` via `#[path]` (`merge.rs`, `validation.rs`, `manifest.rs`) must stay crate-independent: no `crate::`/`super::`, only std + `[build-dependencies]` (serde/toml/regex/log).
- A `#[cfg(test)] mod tests;` in any file that `build.rs` `#[path]`-includes needs an explicit `#[path = "..."]`, or `cargo fmt` fails to resolve the submodule.
- Keep source files ≤ 400 lines; split tests into a dedicated `tests/` module when a file exceeds this. When *non-test* code exceeds 400 lines, extract a cohesive concern into a sibling file declared `#[path = "x.rs"] mod x;` — a child module reuses the parent's private items (structs, fns, fields) via `super::` (e.g. `walk_staged.rs` inside `walk.rs`).
- Document every public function, struct, and trait with a `///` doc comment.
- Prefer `--features updater` builds for development; the default (no feature) build is the lean release artifact.
- The `bench` feature gates per-scan timing instrumentation; run `cargo test --features bench` to exercise bench-gated tests (default builds show expected rust-analyzer "inactive-code" hints on those lines — not errors).
- No `unwrap()` in library code — use `?` or explicit error handling.
- Benchmark throughput is dominated by keyword-hit *density*, not rule count. The README table uses a low-density benign corpus (`scripts/gen_corpus.sh`); a keyword-dense corpus is orders of magnitude slower (~6 GiB/s vs ~0.03 GiB/s). Default `max_file_size` is 2 MiB, so corpora must be many files (rayon parallelizes across files, not within one). The `scan` time prints to stderr at `info` by default (no `RUST_LOG` needed).
- On macOS, `docker` is the Docker Desktop Linux VM (musl artifact), so its benchmark numbers are slower and NOT comparable to a native macOS build — keep the two in separate, labeled tables.
- CLI `--rules`/`Scanner::from_file`/`from_toml` use the STRICT loader (errors on any uncompilable regex), but merged rule files and raw `assets/gitleaks.toml` still load because the merge already drops uncompilable look-around rules (so merged count == active count).
- `bindings/node` is a **separate crate** (root `Cargo.toml` has no `[workspace]`), so `make ci` and root `cargo fmt`/`clippy`/`test` do NOT cover it. After touching it, run inside `bindings/node/`: `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, plus `npm run build && npm run typecheck && npm test`.
- The clippy gate is `-D warnings` (`make ci` → `cargo clippy -- -D warnings`); a warning fails CI. That target omits `--all-targets`, so lint test code with `cargo clippy --all-targets -- -D warnings` to catch what `make ci` misses.
- rust-analyzer/IDE inline diagnostics are often stale here: after editing
  `ScanConfig`/`Finding` or test files you may see phantom "missing field" or
  `Option` vs `Vec` errors that `cargo build`/`cargo test` do not. Trust a direct
  `cargo` run, not the IDE diagnostics.
- `Scanner` does not implement `Debug`, so `expect_err()`/`unwrap_err()` on a
  `Result<Scanner, _>` (e.g. testing `Scanner::from_toml` rejection) will not
  compile — assert the error path with `match { Ok(_) => panic!(...), Err(e) => e }`.
- `make ci` builds/tests only the **default** feature set. Code behind a feature
  (e.g. `updater`, including `updater_tests.rs` and any `#[cfg(not(feature =
  "updater"))]` stub) is verified only by `cargo clippy --features updater
  --all-targets` + `cargo test --features updater`. Changing a feature-gated fn
  signature also requires updating its cfg-disabled stub to match.

---

## Commands

| Command | Purpose |
|---|---|
| `make ci` | Full local gate: fmt, clippy, tests, rule drift/validation, merge drift, full build |
| `make test-updater` | Run tests with the runtime updater feature enabled |
| `make merge-rules-check` | Verify committed `assets/secrets-scanner.toml` matches the lean manifest merge |
| `make build-full` | Build with `--features full-ruleset` |
| `cargo test --bin secrets-scanner --features updater` | Fast focused check for binary/CLI refactors |
| `cargo run -- scan <path> --git-tracked` | Run a scan locally (git-tracked files) |
| `cargo run -- completions <shell>` | Generate shell completions (bash/zsh/fish/...) |
| `cargo run -- install-skill --agent <id> [--local [PATH]] [--dry-run]` | Install the bundled agent skill into a runtime via `agent-config` (default scope: user home; `--local` targets a repo) |
| `cargo run -- uninstall-skill --agent <id> [--local [PATH]]` | Remove the agent skill (only skills owned by `secrets-scanner`) |
| `CORPUS=<dir> scripts/benchmark.sh "label\|rules.toml" ...` | Reproduce the README runtime-ruleset table (CLI harness, NOT `cargo bench`); self-bootstraps a benign corpus via `scripts/gen_corpus.sh`, portable across BSD/GNU `time` |

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
├── bindings/
│   └── node/                  # NAPI-RS Node bindings (@whit3rabbit/rsecrets-scanner); see bindings/node/CLAUDE.md
├── plugins/
│   └── secrets-scanner/       # Claude Code plugin: skill + install/uninstall/pre-commit scripts
├── .claude-plugin/            # Plugin marketplace manifest (marketplace.json lists plugins/secrets-scanner)
├── .claude/                   # Claude Code local config and symlinked skill
├── .openclaw/                 # OpenClaw agent local config, skills, and SOUL.md
├── .hermes/                   # Hermes Agent local config, skills, and SOUL.md
├── .codex/                    # Codex Agent local config, skills, and SOUL.md
├── build.rs                   # Validates and merges manifest-selected rule sources at compile time
└── Makefile                   # Developer convenience targets
```

---

## Agent Skills and Plugins

To prevent secrets from being leaked during agent-assisted development, this repository bundles compatible agent skills and `SOUL.md` personality core rules for multiple AI agent runtimes:

- **Claude Code:** Configured under `.claude/` and `plugins/secrets-scanner/`. Auto-triggers for Claude Code prompts requesting installation or execution.
- **OpenClaw:** Configured under `.openclaw/` and loaded from `.openclaw/skills/secrets-scanner/` and `.openclaw/SOUL.md`.
- **Hermes Agent:** Configured under `.hermes/` and loaded from `.hermes/skills/secrets-scanner/` and `.hermes/SOUL.md`.
- **Codex Agent:** Configured under `.codex/` and loaded from `.codex/skills/secrets-scanner/` and `.codex/SOUL.md`.

Each skill contains instructions guiding the respective agent on how to:
1. Install `secrets-scanner` locally.
2. Configure git pre-commit hooks to block commits containing secrets.
3. Perform on-demand scans of staged files or full history.

The corresponding `SOUL.md` files inject a cognitive identity policy into the agent's system prompt, instructing it to always check for credentials and strictly redact raw keys from output/files.

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

# Force a re-fetch + re-merge + cache rewrite (bypasses the "already current" fast-path)
secrets-scanner update-rules --force

# Makefile shortcut (builds with updater feature first)
make update-rules-runtime
```

The "already current" fast-path is keyed on **three** sidecars, not just the
upstream SHA: the cached upstream SHA (`*.sha256`), the merged-content integrity
SHA (`*.cache.sha256`), and the local-input SHA (`*.local.sha256`). So editing
local rules (e.g. `assets/local.toml`) while upstream is unchanged correctly
invalidates the cache and triggers a re-merge — the upstream-SHA-only check used
to miss this and report "already current". `--force` bypasses the fast-path
entirely (and conflicts with `--check`).

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

### Testing Git Modes

Git/history/staged-mode tests live in `tests/hardening.rs`. Use the inline
`SECRET_RULE` via the `scanner(ScanConfig)` helper plus `init_repo()` / `git()`;
the canonical test secret is `SECRET123456` (rule `SECRET[0-9]{6}`, keyword
`secret`, matched case-insensitively).

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
- **Git modes & path safety** (`src/scanner/walk.rs`): NUL-delimited output
  (`-z`, `core.quotePath=false`), absolute paths from git are dropped (containment).
  The current-content modes scan the working-tree bytes of selected files:
  `--git-tracked` (`git ls-files`), `--changed-files` (`git diff --name-only`,
  whole files not hunks), `--base <ref>` (implies `--changed-files`; scans
  `<base>...HEAD`), `--include-untracked` adds `ls-files --others
  --exclude-standard`. **Fail-closed:** on git failure an explicit git mode exits
  2 (`ScanStats.git_failed`) and scans nothing, rather than silently widening
  scope to the whole tree. `--git-fallback=walk` opts back into the legacy
  directory-walk fallback (recorded as `ScanStats.git_fallback`, scope may include
  untracked/ignored files); it does not apply to `--git-history`.
  Directory-walk traversal errors (e.g. an unreadable subdir) count toward
  `ScanStats.errored`, not silently dropped.
- **History mode** (`src/scanner/walk_history.rs`): `--git-history` scans
  `git log -p -U0 --no-color --no-ext-diff --full-history [--all] [<log-opts>...]
  --`, attributing each finding to the commit that ADDED the matched line
  (`Finding.commit`). This catches secrets committed then later removed — the gap
  versus current-content modes. The **scan unit is one file diff** (all hunks of a
  file within a commit): their added (`+`) lines are reconstructed into one buffer
  handed to `scan_bytes` exactly like a working-tree file, so binary detection,
  `max_findings_per_file`, `max_files` (counted as file diffs), `max_findings`
  (with a truncation notice), and redaction all apply uniformly — history is NOT a
  parallel path that re-derives caps per hunk. A `line_map` records each buffered
  line's real new-file line so findings (and context lines) report file-accurate
  numbers across non-contiguous hunks; byte offsets stay buffer-relative (a patch
  has no single real-file byte offset). The `+++ b/path` header is recognized only
  BEFORE a file's first hunk, so an added content line beginning with `++ `
  (patch form `+++ `) is not mistaken for a header. Merge/combined diffs (`@@@`)
  and deletions are not attributed (merge content is caught on a non-merge
  ancestor; deleted content was an addition in an earlier commit). `--full-history`
  is always on in history mode (decoupled from `--log-opts` so narrowing traversal
  never silently reduces coverage). `--log-opts <OPT>` is **operator-trusted**
  (repeatable; each occurrence is one verbatim argv entry — `allow_hyphen_values`,
  so a value may begin with `-` or contain spaces — never split or run through a
  shell; the `--base` dash-rejection does not apply); terminated with `--`. Always
  fails closed on git error (no walk fallback). `--history-timeout <SECS>` (`0`
  = unlimited, the default; `ScanConfig::history_timeout_secs`) is an opt-in
  wall-clock budget checked while streaming `git log`: on expiry the stream is
  stopped, the child killed, partial findings kept, and `findings_truncated` +
  `ScanStats.history_timed_out` set (surfaced in the summary and Node
  `findingsTruncated`) so a huge history cannot run unbounded. The clock is
  sampled every ~1024 patch lines, not per line. The CLI aggregates
  `history_timed_out` across paths and **exits 2 unconditionally** on a trip
  (after writing output): a timed-out history scan left commits unscanned, so it
  must not look like a clean or merely-truncated scan. This is not gated behind a
  flag (the caller opted into the budget by setting the timeout); exit 2 takes
  precedence over the findings exit 1 and ignores `--no-fail`.
- **Staged mode** (`src/scanner/walk_staged.rs`): `--staged` scans the **index
  blob content** that is about to be committed (`git diff --cached
  --name-only --diff-filter=ACMRT` then `git cat-file -t`/`-s`/`blob :path`), NOT
  the working-tree files — so a secret staged then scrubbed from the working copy
  (or staged via `git add -p`) is still caught. Type-changes (`T`) are included
  but each object is verified to be a blob (a `T` change can stage a gitlink/tree).
  Non-UTF-8 paths are passed to git byte-exact (`OsString` pathspec), not lossily
  mangled. Blob size is checked before the read (bounded-memory). Staged deletions
  are excluded. It is mutually exclusive with the other git modes (enforced by clap).
- **Inline suppression**: a line containing `secrets-scanner:allow` or
  `gitleaks:allow` (ecosystem compat) skips that finding (`matching.rs`). The
  check is **line-level** (the marker may appear anywhere on the match's first
  line, not just as a trailing comment — gitleaks parity), so a marker inside a
  same-line string value also suppresses. For multi-line matches (e.g. PEM keys)
  the marker is honored on the match's first line only. `--no-allow-markers`
  (`honor_allow_markers = false`) turns this off for the CLI scan — use it on
  untrusted content where an author could append a marker to smuggle a secret
  past the scan. (The library `ScanConfig::proxy()` preset already disables it.)
- **Result caps**: `--max-files`, `--max-findings`, `--max-findings-per-file`.
  All three reject `0` at parse time (clap `value_parser`, exit 2): a zero cap
  would silently scan nothing and read as a clean result. The library `scan_capped`
  path still tolerates `0` defensively for programmatic callers.
  Every cap that fires logs a truncation notice (never silent), and per-path
  truncation is folded into the aggregate `ScanStats.findings_truncated` and the
  CLI summary suffix (so a `--max-findings-per-file` truncation shows even when
  `--max-findings` never fires). **All three** caps conflict with
  `--generate-baseline` (enforced by clap): a capped baseline would silently
  under-suppress later scans by omitting findings/files, so the combinations are
  rejected rather than dropping a cap quietly. The caps still work with
  `--baseline` (they apply after suppression).
- **Redaction style**: `--redaction partial|full` controls the `matched` field
  when redaction is on (default `partial` keeps the first/last 4 chars via
  `filters::redact`; `full` replaces it with the fixed `[REDACTED]` marker via
  `filters::redact_full`, hiding even the length). Orthogonal to `--no-redact`
  (raw text), which it conflicts with. Carried on `ScanConfig::redaction_mode`
  (`RedactionMode`); the proxy preset uses `Full`.
- **Honest coverage**: `ScanStats.errored` counts files that could not be
  stat'd/read (distinct from intentional binary/oversized skips) and the CLI
  summary reports `N unreadable`, so an errored file never looks like a
  scanned-and-clean one. `--error-on-unreadable` (off by default) turns a
  non-zero `errored` count into **exit 2** (incomplete coverage) after output is
  written; it takes precedence over the findings exit 1, is independent of
  `--no-fail`, and does not apply to `--generate-baseline`. `--error-on-skipped`
  (off by default) does the same for files skipped **by policy** (binary +
  oversized): a skipped file is "not scanned", not "scanned clean", so a strict
  caller can fail on that gap. The Node binding exposes the same signal as the
  additive `PathScanResult.skippedByPolicy` boolean (distinct from `incomplete`,
  which already counts oversized/errored/cap/git but treats binary skips as
  policy, not a coverage failure).
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
  findings as JSON (includes fingerprints) and exits 0 — **unless coverage was
  incomplete**: it refuses to write (exit 2, no file) when `ScanStats.errored > 0`
  or `history_timed_out`, since a baseline missing findings would silently
  under-suppress later scans (the same rationale that makes the caps conflict with
  `--generate-baseline`). Binary/oversized *policy* skips are deliberately not a
  blocker — those files skip identically on the next scan, so they never
  contribute findings to suppress. The `matched` field is
  replaced by the fixed `[REDACTED_SECRET]` marker for **every** finding,
  regardless of redaction mode (including `--no-redact` and default partial
  redaction) — suppression keys on the fingerprint, not the text, so a
  committed/uploaded baseline never carries raw secrets *or* the length/first-last
  structure that partial redaction would otherwise preserve.
  Baselines from older FNV-fingerprint builds should be regenerated once.
  Setting `SECRETS_SCANNER_FINGERPRINT_KEY` switches every fingerprint to a keyed
  HMAC-SHA256 (`hmac-sha256:` prefix instead of `sha256:`), which removes the
  offline-guessing target for low-entropy secrets and makes baselines unlinkable
  across keys. The key is read once per process. A keyed baseline only suppresses
  when scanned with the same key; changing or unsetting the key requires
  regenerating the baseline. `suppress_baseline` accepts both prefixes.
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
- **Hardened output writes** (`cli/scan.rs::create_private_file`): every
  scanner-written file (`--output` in any format, and `--generate-baseline`) is
  created `0600` on Unix and opened with `O_NOFOLLOW | O_CLOEXEC`, then the opened
  descriptor is verified to be a regular file. So an attacker-planted symlink at
  the output path is not followed (open fails `ELOOP`) and a pre-existing
  fifo/device/dir is rejected instead of being truncated/chmod'd — matching the
  read-side symlink hardening.

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
(`--git-tracked --redact --no-context --format sarif --output <file>`). Inputs:
`path`, `config`, `fail-on-findings`, `sarif`, `sarif-file`, `git-tracked`,
`base`, `max-file-size`, `binary-policy`, `version`, `extra-args`. Output:
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
safe-default `--git-tracked` mode shells out to it. Rules are embedded at compile
time (no runtime `update-rules`), so rebuild the image to refresh them.
`.dockerignore` excludes `target/`/`.git/` but **not** `assets/` (build.rs reads
it). Auto-published to Docker Hub on release tags.
`docker run --rm -v "$PWD:/repo" <image> scan /repo --git-tracked`.

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
- A tag also triggers `.github/workflows/publish.yml` (npm), so bump the node binding in lockstep: `bindings/node/package.json` (incl. its `optionalDependencies` pins), `bindings/node/Cargo.toml`, and both `Cargo.lock` files. A stale node version makes the npm publish reject an already-published version.
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
