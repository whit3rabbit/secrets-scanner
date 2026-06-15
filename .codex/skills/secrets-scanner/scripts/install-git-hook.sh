#!/usr/bin/env bash
# Install a native git pre-commit hook that scans STAGED content for secrets.
# Run from inside the target git repository. Backs up any existing,
# non-managed pre-commit hook to pre-commit.bak.
set -euo pipefail

info() { printf '\033[0;32m[git-hook]\033[0m %s\n' "$1"; }
warn() { printf '\033[0;33m[git-hook]\033[0m %s\n' "$1" >&2; }
die()  { printf '\033[0;31m[git-hook]\033[0m %s\n' "$1" >&2; exit 1; }

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "not inside a git repository"

HOOK_DIR="$(git rev-parse --git-path hooks)"
HOOK="$HOOK_DIR/pre-commit"
MARKER="# managed-by: secrets-scanner-skill"

mkdir -p "$HOOK_DIR"

if [ -e "$HOOK" ] && ! grep -q "$MARKER" "$HOOK" 2>/dev/null; then
  warn "existing pre-commit hook found; backing up to ${HOOK}.bak"
  mv "$HOOK" "${HOOK}.bak"
fi

cat > "$HOOK" <<EOF
#!/usr/bin/env sh
$MARKER
# Blocks commits containing secrets. Scans the staged index blobs (--staged),
# so a secret staged then removed from the working tree is still caught.
# Set SECRETS_SCANNER_REQUIRED=1 to fail the commit when the binary is missing
# (default: warn and allow, so teammates without it can still commit).
if ! command -v secrets-scanner >/dev/null 2>&1; then
  if [ "\${SECRETS_SCANNER_REQUIRED:-0}" = "1" ]; then
    echo "secrets-scanner not installed; blocking commit (SECRETS_SCANNER_REQUIRED=1)" >&2
    exit 1
  fi
  echo "secrets-scanner not installed; skipping secret scan" >&2
  echo "install: https://github.com/whit3rabbit/secrets-scanner" >&2
  exit 0
fi
exec secrets-scanner scan --staged --redact --no-context
EOF

chmod +x "$HOOK"
info "installed pre-commit hook at $HOOK"
info "it runs: secrets-scanner scan --staged --redact --no-context"
info "bypass a single commit with: git commit --no-verify"
