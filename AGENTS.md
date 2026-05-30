# Secrets Scanner

- A Rust library/binary that pulls rules from gitleaks and custom secret lookups to scan code
repos, or act as a proxy to intercept secrets (e.g. in LLM pipelines).

- First is to build as a library scanner. Then as a CLI. Users should be able to integrate scanner into their own codebase.

---

## Coding Guidelines

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
│   └── update_rules.sh        # Shell script: download latest gitleaks rules
├── src/
│   ├── main.rs                # CLI entry point; dispatches `update-rules` subcommand
│   └── rules/
│       ├── mod.rs             # load_rules() — three-tier rule loading
│       └── updater.rs         # Runtime HTTP updater (feature-gated: `updater`)
├── build.rs                   # Embeds assets/gitleaks.toml at compile time
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

### Build-time Embedding

`build.rs` validates that `assets/gitleaks.toml` and `assets/local.toml` exist before compilation, merges them (with local custom rules taking precedence), and writes the combined ruleset to `assets/secrets-scanner.toml`. The combined ruleset is embedded via:

```rust
pub const BUNDLED_RULES: &str = include_str!("../../assets/secrets-scanner.toml");
```

Any change to either `assets/gitleaks.toml` or `assets/local.toml` triggers an automatic recompile.

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


<!-- syntext-agent:claude:start -->
## Code Search

Use `st` instead of `rg` or `grep` when `.syntext/` exists.
Before the first search in a repo, run `test -d .syntext || st index`.
After file edits, run `st update` before relying on search results.
<!-- syntext-agent:claude:end -->
