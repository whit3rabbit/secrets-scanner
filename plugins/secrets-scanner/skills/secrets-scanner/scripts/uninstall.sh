#!/usr/bin/env bash
# Uninstall secrets-scanner. Detects the install method and removes the binary.
# Does NOT remove git pre-commit hooks — run uninstall-git-hook.sh per repo first.
set -euo pipefail

has() { command -v "$1" >/dev/null 2>&1; }
info() { printf '\033[0;32m[uninstall]\033[0m %s\n' "$1"; }
warn() { printf '\033[0;33m[uninstall]\033[0m %s\n' "$1" >&2; }

removed=0

# Homebrew
if has brew && brew list --formula 2>/dev/null | grep -qx secrets-scanner \
   || (has brew && brew list --cask 2>/dev/null | grep -qx secrets-scanner); then
  info "removing via Homebrew..."
  brew uninstall secrets-scanner && removed=1 || warn "brew uninstall failed"
fi

# cargo
if has cargo && cargo install --list 2>/dev/null | grep -q '^secrets_scanner '; then
  info "removing via cargo..."
  cargo uninstall secrets_scanner && removed=1 || warn "cargo uninstall failed"
fi

# prebuilt-binary install dir (~/.secrets-scanner/bin)
PREBUILT="$HOME/.secrets-scanner/bin/secrets-scanner"
if [ -e "$PREBUILT" ]; then
  info "removing prebuilt binary at $PREBUILT..."
  rm -f "$PREBUILT" && removed=1
  info "you may also remove $HOME/.secrets-scanner from PATH in your shell rc"
fi

if has secrets-scanner; then
  warn "secrets-scanner still on PATH at: $(command -v secrets-scanner)"
  warn "remove it manually if it was installed another way."
elif [ "$removed" -eq 1 ]; then
  info "uninstalled."
else
  warn "secrets-scanner not found; nothing to remove."
fi
