#!/usr/bin/env bash
# update_rules.sh — Download the latest gitleaks ruleset into assets/
# Usage:
#   ./scripts/update_rules.sh            # download to assets/gitleaks.toml
#   ./scripts/update_rules.sh --check    # compare remote SHA with local, no write
#   RULES_URL=<url> ./scripts/update_rules.sh  # override source URL

set -euo pipefail

RULES_URL="${RULES_URL:-https://raw.githubusercontent.com/gitleaks/gitleaks/refs/heads/master/config/gitleaks.toml}"
DEST_DIR="$(cd "$(dirname "$0")/.." && pwd)/assets"
DEST_FILE="$DEST_DIR/gitleaks.toml"
TMP_FILE="$(mktemp /tmp/gitleaks_XXXXXX.toml)"
CHECK_ONLY=false

# ── helpers ──────────────────────────────────────────────────────────────────
info()    { echo "[INFO]  $*"; }
success() { echo "[OK]    $*"; }
warn()    { echo "[WARN]  $*" >&2; }
die()     { echo "[ERROR] $*" >&2; exit 1; }

cleanup() { rm -f "$TMP_FILE"; }
trap cleanup EXIT

# ── parse args ────────────────────────────────────────────────────────────────
for arg in "$@"; do
    case "$arg" in
        --check) CHECK_ONLY=true ;;
        --help|-h)
            echo "Usage: $0 [--check]"
            echo "  --check  Print whether an update is available; do not write."
            exit 0
            ;;
        *) die "Unknown argument: $arg" ;;
    esac
done

# ── dependency check ─────────────────────────────────────────────────────────
if command -v curl &>/dev/null; then
    FETCHER="curl"
elif command -v wget &>/dev/null; then
    FETCHER="wget"
else
    die "Neither curl nor wget found. Install one and retry."
fi

fetch() {
    local url="$1" dest="$2"
    if [[ "$FETCHER" == "curl" ]]; then
        curl --silent --show-error --fail --location \
             --retry 3 --retry-delay 2 \
             --max-time 30 \
             -o "$dest" "$url"
    else
        wget --quiet --tries=3 --timeout=30 -O "$dest" "$url"
    fi
}

sha256_of() {
    if command -v sha256sum &>/dev/null; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# ── fetch remote ─────────────────────────────────────────────────────────────
info "Fetching rules from: $RULES_URL"
fetch "$RULES_URL" "$TMP_FILE"

remote_sha=$(sha256_of "$TMP_FILE")
info "Remote SHA-256: $remote_sha"

# ── compare with local ────────────────────────────────────────────────────────
if [[ -f "$DEST_FILE" ]]; then
    local_sha=$(sha256_of "$DEST_FILE")
    info "Local  SHA-256: $local_sha"

    if [[ "$remote_sha" == "$local_sha" ]]; then
        success "assets/gitleaks.toml is already up to date."
        exit 0
    else
        if $CHECK_ONLY; then
            warn "Update available! Run without --check to apply."
            exit 1   # non-zero signals "update needed" to callers / CI
        fi
        info "Update detected — replacing assets/gitleaks.toml"
    fi
else
    info "No existing file found — creating assets/gitleaks.toml"
    if $CHECK_ONLY; then
        warn "No local file exists yet. Run without --check to download."
        exit 1
    fi
fi

# ── install ───────────────────────────────────────────────────────────────────
mkdir -p "$DEST_DIR"
cp "$TMP_FILE" "$DEST_FILE"
success "assets/gitleaks.toml updated (SHA-256: $remote_sha)"
