# secrets-scanner (Claude Code plugin)

A Claude Code plugin that helps you install, uninstall, set up a git pre-commit hook for,
or run the [secrets-scanner](https://github.com/whit3rabbit/secrets-scanner) CLI.

## Install

```
/plugin marketplace add whit3rabbit/secrets-scanner
/plugin install secrets-scanner@whit3rabbit
```

`marketplace add` clones the repo; the plugin is resolved from the marketplace's
relative `source` path. After install, the bundled skill auto-triggers when you ask
Claude to install/remove the scanner, add a pre-commit secret-scan hook, or scan for secrets.

## What's bundled

- `skills/secrets-scanner/` — the skill (SKILL.md + REFERENCE.md) plus helper scripts:
  - `scripts/install.sh`, `scripts/uninstall.sh` — install/remove the CLI
  - `scripts/install-git-hook.sh`, `scripts/uninstall-git-hook.sh` — manage a native pre-commit hook (`scan --staged`)

The same skill is symlinked into this repo's `.claude/skills/` so it is also available
as a project skill when developing the scanner itself; the plugin copy is canonical.
