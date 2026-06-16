# @whit3rabbit/rsecrets-scanner-mcp

MCP stdio server for `secrets-scanner`, built on the native Node binding.

## Install / Run

```bash
npx -y @whit3rabbit/rsecrets-scanner-mcp --root /path/to/project
```

Example MCP client config:

```json
{
  "mcpServers": {
    "rsecrets": {
      "command": "npx",
      "args": [
        "-y",
        "@whit3rabbit/rsecrets-scanner-mcp",
        "--root",
        "/path/to/project"
      ]
    }
  }
}
```

## Tools

- `redact_text` — scan untrusted text with the hardened proxy path and return
  redacted text plus safe finding metadata.
- `scan_text` — scan untrusted text and return safe finding metadata only.
- `scan_file` — scan one file under `--root`.
- `scan_workspace` — scan a root-bound path using `walk`, `git-tracked`,
  `changed-files`, or `staged` mode.
- `scan_git_history` — scan git history only when the server starts with
  `--enable-history`.

## Safety

The server never returns raw `matched` values or context lines. File tools
resolve paths inside `--root`, use strict async path scans, and return tool
errors for incomplete coverage. Tool-supplied caps are clamped to startup caps.
Raw `git log` options are startup-only through repeatable `--history-log-opt`;
MCP tool calls cannot set arbitrary history options.

Useful startup options:

```bash
rsecrets-scanner-mcp \
  --root . \
  --max-file-size 2097152 \
  --max-files 5000 \
  --max-findings 1000 \
  --max-findings-per-file 100
```

History scanning is intentionally opt-in:

```bash
rsecrets-scanner-mcp \
  --root . \
  --enable-history \
  --history-timeout-secs 30 \
  --history-log-opt "--since=30 days ago"
```

Use `--rules-file <path>` only as an operator-controlled startup option. Rules
files are not accepted from tool input.
