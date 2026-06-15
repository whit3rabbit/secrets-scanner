#!/usr/bin/env bash
# Remove the secrets-scanner pre-commit hook from the current repo.
# Restores a backed-up pre-commit.bak if one exists.
set -euo pipefail

info() { printf '\033[0;32m[git-hook]\033[0m %s\n' "$1"; }
warn() { printf '\033[0;33m[git-hook]\033[0m %s\n' "$1" >&2; }
die()  { printf '\033[0;31m[git-hook]\033[0m %s\n' "$1" >&2; exit 1; }

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "not inside a git repository"

HOOK_DIR="$(git rev-parse --git-path hooks)"
HOOK="$HOOK_DIR/pre-commit"
MARKER="# managed-by: secrets-scanner-skill"

[ -e "$HOOK" ] || { warn "no pre-commit hook present; nothing to do"; exit 0; }

if ! grep -q "$MARKER" "$HOOK" 2>/dev/null; then
  warn "pre-commit hook is not managed by this skill; leaving it untouched"
  exit 0
fi

rm -f "$HOOK"
info "removed managed pre-commit hook"

if [ -e "${HOOK}.bak" ]; then
  mv "${HOOK}.bak" "$HOOK"
  info "restored previous hook from pre-commit.bak"
fi
