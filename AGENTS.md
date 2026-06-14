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
- Keep source files ≤ 400 lines; split tests into a dedicated `tests/` module when a file exceeds this.
- Document every public function, struct, and trait with a `///` doc comment.
- Prefer `--features updater` builds for development; the default (no feature) build is the lean release artifact.
- No `unwrap()` in library code — use `?` or explicit error handling.

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
│   ├── main.rs                # CLI entry point; dispatches `update-rules` and `validate-rules` subcommands
│   └── rules/
│       ├── mod.rs             # load_rules() — three-tier rule loading
│       ├── updater.rs         # Runtime HTTP updater (feature-gated: `updater`)
│       └── validation.rs      # Rule TOML and Regex validator
├── build.rs                   # Validates rules and merges assets/gitleaks.toml + local.toml at compile time
└── Makefile                   # Developer convenience targets
```

---

## Gitleaks Rules

### Rule Sources

| Priority | Source | When active |
|---|---|---|
| 1 (highest) | `$SECRETS_SCANNER_RULES` env var | Any time the var is set |
| 2 | Cached file in OS data dir | After a successful `update-rules` run |
| 3 (default) | `assets/gitleaks.toml` embedded in binary | Always (compile-time fallback) |

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
make merge-rules-check  # CI drift: regenerate then fail if the committed file is stale
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

#### 4. Makefile Shortcut
```bash
make validate-rules
```
This is also run automatically after downloading rules with `make update-rules` and is part of the `make ci` suite.


<!-- syntext-agent:claude:start -->
## Code Search

Use `st` instead of `rg` or `grep` when `.syntext/` exists.
Before the first search in a repo, run `test -d .syntext || st index`.
After file edits, run `st update` before relying on search results.
<!-- syntext-agent:claude:end -->
