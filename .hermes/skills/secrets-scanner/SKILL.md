---
name: secrets-scanner
description: Install, uninstall, set up a pre-commit hook for, or run the secrets-scanner CLI (whit3rabbit/secrets-scanner) that detects leaked secrets, API keys, and credentials. Use when the user wants to install or remove secrets-scanner, add a git pre-commit secret-scan hook, block secrets before committing, or scan a repo/path for secrets on demand.
version: 1.0.0
author: whit3rabbit
license: MIT
platforms: [macos, linux]
metadata:
  hermes:
    tags: [Security, Git, Secrets, CLI]
    category: security
    related_skills: []
    requires_tools: [run_command]
---

# secrets-scanner (Hermes Agent Skill)

CLI that scans code for leaked secrets using gitleaks-derived + custom rules.
Binary name: `secrets-scanner`. Crate: `secrets_scanner`. Repo: `whit3rabbit/secrets-scanner`.

Pick the workflow that matches the request. Prefer the bundled scripts over hand-writing
hooks because they handle existing hooks, backups, and PATH detection.

Before running a bundled script, resolve `SKILL_DIR` to the directory containing
this `SKILL.md`, then run scripts from `"$SKILL_DIR/scripts/"`. Do not assume the
current working directory is the skill directory.

## Install

Run the helper (tries Homebrew cask → cargo → prebuilt binary download):

```sh
bash "$SKILL_DIR/scripts/install.sh"
```

Or pick one directly:
- macOS/Linux (Homebrew): `brew install --cask whit3rabbit/tap/secrets-scanner`
- Any platform with Rust: `cargo install secrets_scanner` (or `cargo binstall secrets_scanner`)
- Official one-liner: `curl -fsSL https://raw.githubusercontent.com/whit3rabbit/secrets-scanner/main/install.sh | bash`
- Windows: run `install.ps1` from the repo.

Verify: `secrets-scanner --version`. The prebuilt-download path installs to
`~/.secrets-scanner/bin`; if that's not on `PATH`, add it (the installer prints the line).

## Uninstall

```sh
bash "$SKILL_DIR/scripts/uninstall.sh"
```

It detects the install method (brew / cargo / prebuilt dir) and removes the binary.
Remove managed pre-commit hooks first so repos do not fail closed after the binary is gone.

## Pre-commit hook (block secrets before committing)

Two paths — choose based on what the repo already uses:

1. **Native git hook** (no framework). Run inside the target repo:
   ```sh
   bash "$SKILL_DIR/scripts/install-git-hook.sh"
   ```
   Writes `.git/hooks/pre-commit` calling `secrets-scanner scan . --staged --redact --no-context`.
   `--staged` scans the **index blob content** about to be committed (catches secrets
   staged then scrubbed from the working tree). Findings, scan errors, or a missing scanner
   binary block the commit.
   Backs up any existing non-managed hook to `pre-commit.bak`. Remove with
   `bash "$SKILL_DIR/scripts/uninstall-git-hook.sh"`.

2. **pre-commit framework** (repo has `.pre-commit-config.yaml`). Add:
   ```yaml
   repos:
     - repo: https://github.com/whit3rabbit/secrets-scanner
       rev: v0.1.0   # pin a released tag
       hooks:
         - id: secrets-scanner
   ```
   Then `pre-commit install`. The shipped hook runs `scan . --staged --redact --no-context`
   with `pass_filenames: false`, so it scans index blobs rather than pre-commit's filename list.

## On-demand scan

```sh
secrets-scanner scan <path> --git-tracked      # scan git-tracked files (safe default)
secrets-scanner scan <path> --staged           # only staged index content
secrets-scanner scan <path> --git-history --all # secrets ever committed, even if later removed
secrets-scanner scan <path> --changed-files --base origin/main  # only diff vs a base ref
```

Useful flags: `--redact` (mask matched values), `--no-context` (CI-safe, no surrounding lines),
`--format text|json|jsonl|sarif`, `--output <file>` (SARIF for GitHub code-scanning),
`--baseline <file>` / `--generate-baseline <file>` (suppress known findings),
`--max-file-size`, `--binary-policy auto|skip|scan`, `--no-fail` (always exit 0).

Exit codes: `0` clean, `1` findings, `2` runtime error, `3` invalid config/rules.

## Proxy integration

For untrusted in-memory content such as LLM prompts or tool payloads, use the
hardened library entry points documented in `REFERENCE.md`: Rust
`Scanner::scan_proxy` or Node `scanProxyAsync`. A skill can guide agents to call
those APIs, but it cannot transparently intercept every agent or gateway message
without a separate runtime integration.

## References

- Detailed flag/mode reference and gotchas: [REFERENCE.md](REFERENCE.md)
- Scripts: `scripts/install.sh`, `scripts/uninstall.sh`, `scripts/install-git-hook.sh`, `scripts/uninstall-git-hook.sh`
