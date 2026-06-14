#!/usr/bin/env bash

# secrets-scanner installation script
#
# This script will attempt to install secrets-scanner by:
# 1. Using Homebrew Cask (on macOS, if brew is available)
# 2. Using Cargo / cargo-binstall (if cargo is available)
# 3. Downloading the pre-compiled binary from GitHub Releases (fallback)

set -euo pipefail

REPO="whit3rabbit/secrets-scanner"
BINARY_NAME="secrets-scanner"
INSTALL_DIR="$HOME/.secrets-scanner/bin"

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

log_info() {
    printf "\033[0;32m[info]\033[0m %s\n" "$1"
}

log_warn() {
    printf "\033[0;33m[warn]\033[0m %s\n" "$1"
}

log_error() {
    printf "\033[0;31m[error]\033[0m %s\n" "$1" >&2
}

# Check if a command exists
has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# -----------------------------------------------------------------------------
# Method 1: Homebrew (macOS Cask)
# -----------------------------------------------------------------------------
try_homebrew() {
    if [ "$(uname -s)" = "Darwin" ] && has_cmd brew; then
        log_info "Homebrew detected on macOS. Attempting installation via Homebrew Cask..."
        # If the tap is already added or public, install should work.
        if brew install --cask "whit3rabbit/tap/secrets-scanner"; then
            log_info "secrets-scanner successfully installed via Homebrew!"
            exit 0
        else
            log_warn "Homebrew cask installation failed (tap/cask may not be public yet)."
            log_info "Proceeding to fallback installation methods..."
        fi
    fi
}

# -----------------------------------------------------------------------------
# Method 2: Cargo / cargo-binstall
# -----------------------------------------------------------------------------
try_cargo() {
    if has_cmd cargo; then
        log_info "Rust Cargo detected. Attempting Cargo installation..."
        
        if has_cmd cargo-binstall; then
            log_info "cargo-binstall detected. Installing pre-built binary..."
            if cargo binstall -y secrets_scanner; then
                log_info "secrets-scanner successfully installed via cargo-binstall!"
                exit 0
            else
                log_warn "cargo-binstall failed. Trying cargo install..."
            fi
        fi

        log_info "Installing secrets-scanner from source (this may take a few minutes)..."
        if cargo install secrets_scanner; then
            log_info "secrets-scanner successfully installed via cargo!"
            exit 0
        else
            log_warn "Cargo installation failed."
            log_info "Proceeding to download pre-built binary..."
        fi
    fi
}

# -----------------------------------------------------------------------------
# Method 3: Pre-built Binary Download
# -----------------------------------------------------------------------------
download_binary() {
    local os
    local arch
    local target
    
    os="$(uname -s)"
    arch="$(uname -m)"

    # Determine target triple
    case "$os" in
        Darwin)
            if [ "$arch" = "arm64" ] || [ "$arch" = "aarch64" ]; then
                target="aarch64-apple-darwin"
            else
                target="x86_64-apple-darwin"
            fi
            ;;
        Linux)
            if [ "$arch" = "x86_64" ]; then
                target="x86_64-unknown-linux-musl"
            else
                log_error "Unsupported Linux architecture: $arch. Pre-built binaries are only available for x86_64 on Linux."
                # If cargo is installed, we would have tried it, but since we are here, cargo either failed or is not installed.
                exit 1
            fi
            ;;
        *)
            log_error "Unsupported operating system: $os. Only macOS and Linux are supported by this shell script."
            log_error "Please compile from source using Rust/Cargo or use Windows (install.ps1)."
            exit 1
            ;;
    esac

    # Determine version to download
    local version="${VERSION:-}"
    if [ -z "$version" ]; then
        log_info "Fetching latest release version from GitHub..."
        # Query Github API
        local api_url="https://api.github.com/repos/${REPO}/releases/latest"
        local api_response
        api_response=$(curl -sSL -H "Accept: application/vnd.github.v3+json" "$api_url" || true)
        
        local tag
        tag=$(echo "$api_response" | grep '"tag_name":' | sed -E 's/.*"tag_name": "([^"]+)".*/\1/' || true)
        
        if [ -z "$tag" ]; then
            log_error "Could not retrieve the latest release version from GitHub."
            log_error "This might happen if the repository is private or no releases exist yet."
            log_error "To force installation of a specific version, run:"
            log_error "  VERSION=v0.1.0 $0"
            exit 1
        fi
        version="$tag"
    fi

    # Normalize tag and raw version string
    local tag
    local ver_raw
    if [[ "$version" == v* ]]; then
        tag="$version"
        ver_raw="${version#v}"
    else
        tag="v$version"
        ver_raw="$version"
    fi

    # Construct download URL
    local asset_name="secrets-scanner-${ver_raw}-${target}"
    local download_url="https://github.com/ToReplaceForPublicUrl/${REPO}/releases/download/${tag}/${asset_name}"
    # Wait, the repo is whit3rabbit/secrets-scanner
    download_url="https://github.com/${REPO}/releases/download/${tag}/${asset_name}"

    log_info "Downloading secrets-scanner version $tag ($target)..."
    
    # Ensure install directory exists
    mkdir -p "$INSTALL_DIR"
    local dest_path="$INSTALL_DIR/${BINARY_NAME}"
    local temp_dest_path="${dest_path}.tmp"

    if ! curl -fsSL "$download_url" -o "$temp_dest_path"; then
        log_error "Failed to download binary from $download_url"
        log_error "Please check the version and target combination."
        exit 1
    fi

    chmod +x "$temp_dest_path"
    mv "$temp_dest_path" "$dest_path"

    log_info "Successfully installed secrets-scanner to $dest_path"

    # Print PATH addition helper instructions if necessary
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        echo ""
        log_info "To use secrets-scanner, you need to add it to your PATH."
        log_info "Please add the following line to your shell configuration (e.g. ~/.bashrc, ~/.zshrc, or ~/.profile):"
        echo ""
        printf "  \033[1mexport PATH=\"\$PATH:%s\"\033[0m\n" "$INSTALL_DIR"
        echo ""
        log_info "After adding it, restart your terminal or run 'source <config_file>' to apply."
    else
        log_info "secrets-scanner is ready to use!"
    fi
}

# -----------------------------------------------------------------------------
# Main Execution Flow
# -----------------------------------------------------------------------------

main() {
    # 1. Prefer Homebrew (if macOS & brew installed)
    try_homebrew
    
    # 2. Prefer Cargo/cargo-binstall (if cargo installed)
    try_cargo
    
    # 3. Fallback to direct release binary download
    download_binary
}

main
