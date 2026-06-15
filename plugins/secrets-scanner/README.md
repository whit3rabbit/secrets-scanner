# secrets-scanner agent plugin

An agent plugin/skill package that helps Claude Code, Codex, Hermes, and OpenClaw
install, uninstall, set up a fail-closed git pre-commit hook for, or run the
[secrets-scanner](https://github.com/whit3rabbit/secrets-scanner) CLI.

## Claude Code install

```
/plugin marketplace add whit3rabbit/secrets-scanner
/plugin install secrets-scanner@whit3rabbit
```

`marketplace add` clones the repo; the plugin is resolved from the marketplace's
relative `source` path. After install, the bundled skill auto-triggers when you ask
Claude to install/remove the scanner, add a pre-commit secret-scan hook, or scan for secrets.

## Codex install

From a checkout:

```bash
codex plugin marketplace add .agents/plugins
codex plugin add secrets-scanner@whit3rabbit
```

The Codex manifest lives at `.codex-plugin/plugin.json` in this plugin directory.

## Hermes and OpenClaw install

Hermes can install a single skill from the GitHub repo/path:

```bash
hermes skills install whit3rabbit/secrets-scanner/plugins/secrets-scanner/skills/secrets-scanner
```

OpenClaw can install the skill directory from a local checkout:

```bash
openclaw skills install ./plugins/secrets-scanner/skills/secrets-scanner
```

## What's bundled

- `skills/secrets-scanner/` — the skill (SKILL.md + REFERENCE.md) plus helper scripts:
  - `scripts/install.sh`, `scripts/uninstall.sh` — install/remove the CLI
  - `scripts/install-git-hook.sh`, `scripts/uninstall-git-hook.sh` — manage a native fail-closed pre-commit hook (`scan . --staged --redact --no-context`)

The same skill is symlinked into this repo's `.claude/skills/` so it is also available
as a project skill when developing the scanner itself; the plugin copy is canonical.
