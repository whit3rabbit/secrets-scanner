#!/usr/bin/env bash
# Install secrets-scanner. Tries, in order: Homebrew cask, cargo-binstall,
# cargo install, then the official upstream install.sh (prebuilt download).
# Idempotent: exits early if already installed (use --force to reinstall).
set -euo pipefail

REPO="whit3rabbit/secrets-scanner"
FORCE="${1:-}"

has() { command -v "$1" >/dev/null 2>&1; }
info() { printf '\033[0;32m[install]\033[0m %s\n' "$1"; }
warn() { printf '\033[0;33m[install]\033[0m %s\n' "$1" >&2; }

if has secrets-scanner && [ "$FORCE" != "--force" ]; then
  info "already installed: $(secrets-scanner --version 2>/dev/null || echo present)"
  info "re-run with --force to reinstall"
  exit 0
fi

if has brew; then
  info "trying Homebrew..."
  if brew install "whit3rabbit/tap/secrets-scanner"; then
    info "installed via Homebrew"; secrets-scanner --version || true; exit 0
  fi
  warn "Homebrew install failed, trying next method"
fi

if has cargo-binstall; then
  info "trying cargo-binstall..."
  if cargo binstall -y secrets_scanner; then
    info "installed via cargo-binstall"; secrets-scanner --version || true; exit 0
  fi
  warn "cargo-binstall failed, trying next method"
fi

if has cargo; then
  info "trying cargo install (compiles from source, may take minutes)..."
  if cargo install secrets_scanner; then
    info "installed via cargo"; secrets-scanner --version || true; exit 0
  fi
  warn "cargo install failed, trying next method"
fi

if has curl; then
  info "falling back to upstream prebuilt-binary installer..."
  curl -fsSL "https://raw.githubusercontent.com/${REPO}/main/install.sh" | bash
  exit 0
fi

warn "no supported install method found (need brew, cargo, or curl)."
warn "See https://github.com/${REPO} for manual install."
exit 1
