# secrets-scanner reference

## Scan modes (mutually exclusive unless noted)

| Mode | Flag | Scans |
|---|---|---|
| Git-tracked | `--git-tracked` | working-tree bytes of `git ls-files` (safe default) |
| Changed files | `--changed-files` | whole files changed vs HEAD (not hunks) |
| Diff base | `--base <ref>` | `<ref>...HEAD` changed files (implies `--changed-files`) |
| Untracked | `--include-untracked` | adds untracked, non-ignored files (with the above) |
| Staged | `--staged` | **index blob content** about to be committed (best for pre-commit) |
| History | `--git-history [--all] [--log-opts <opt>]` | every commit's added lines; attributes findings to the adding commit |
| Walk | (default / `--git-fallback=walk`) | plain directory walk |

Git modes fail closed: on a git error the scan exits 2 and scans nothing rather than
widening scope. `--git-history` never falls back to a walk.

## Why `--staged` for pre-commit

It reads the staged index blobs, not the working tree. A secret staged then deleted from
the working copy (or staged via `git add -p`) is still caught. Findings exit 1 → commit blocked.

## Output / safety flags

- `--redact` — mask matched secret values in output.
- `--no-context` — omit surrounding lines (CI-log-injection safe; text output also escapes control chars).
- `--format text|json|jsonl|sarif`, `--output <file>` — SARIF for GitHub code-scanning upload.
- `--baseline <file>` — suppress findings recorded in a baseline (line-tolerant fingerprint).
- `--generate-baseline <file>` — write current findings as a baseline and exit 0. `matched` is
  always redacted in baselines, so committing one never leaks secrets.
- `--min-entropy <f>` — only *raises* a rule's entropy floor (never weakens a stricter rule).
- `--max-file-size`, `--max-files`, `--max-findings`, `--max-findings-per-file` — bounds; each cap logs a notice when it fires.
- `--binary-policy auto|skip|scan` — content-based binary detection; `auto` still scans secret-bearing source types.
- `--no-fail` — write output but exit 0 even with findings (upload SARIF, gate separately).

## Exit codes (scan)

`0` clean · `1` findings present · `2` runtime error (I/O, baseline, output) · `3` invalid config/rules.

## Rule updates (binary built with `--features updater`)

- `secrets-scanner update-rules` — download latest rules to the OS data dir; takes effect next scan.
- `secrets-scanner update-rules --check` — exit 1 if an update is available.
- `secrets-scanner list-rules` / `validate-rules [file...]` — inspect/validate rules.
- Custom rules: drop a `local.toml` (gitleaks TOML format) in the working dir or OS data dir; same-id rules override upstream.

## Install locations

- Prebuilt download (install.sh fallback): `~/.secrets-scanner/bin/secrets-scanner` (add to PATH).
- Homebrew / cargo: managed on PATH by those tools.
- OS data-dir rule cache: macOS `~/Library/Application Support/secrets-scanner/`,
  Linux `~/.local/share/secrets-scanner/`, Windows `%APPDATA%\secrets-scanner\`.

## CI / GitHub Action

Composite action `whit3rabbit/secrets-scanner` (downloads pinned release binary):
runs `scan --git-tracked --redact --no-context --format sarif`. Upload with
`github/codeql-action/upload-sarif` (needs `security-events: write`), `if: always()`.
