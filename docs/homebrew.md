# Homebrew and cargo-binstall Installation

## Quick Install with cargo-binstall

If you have `cargo-binstall` installed, you can install secrets-scanner directly:

```bash
cargo binstall secrets-scanner
```

This downloads a pre-built binary from GitHub Releases (no local Rust compilation needed).

## Homebrew Tap

A third-party Homebrew tap is available:

```bash
# Add the tap
brew tap whit3rabbit/tap

# Install
brew install secrets-scanner
```

## Sample Homebrew Formula

If you maintain your own tap, the formula looks like this:

```ruby
class SecretsScanner < Formula
  desc "High-performance secrets scanner using Aho-Corasick and regex"
  homepage "https://github.com/whit3rabbit/secrets-scanner"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/whit3rabbit/secrets-scanner/releases/latest/download/secrets-scanner-aarch64-apple-darwin"
      sha256 "<SHA256 of the release binary>"
    else
      url "https://github.com/whit3rabbit/secrets-scanner/releases/latest/download/secrets-scanner-x86_64-apple-darwin"
      sha256 "<SHA256 of the release binary>"
    end
  end

  on_linux do
    url "https://github.com/whit3rabbit/secrets-scanner/releases/latest/download/secrets-scanner-x86_64-unknown-linux-musl"
    sha256 "<SHA256 of the release binary>"
  end

  def install
    bin.install "secrets-scanner"
  end

  test do
    assert_match "secrets-scanner", shell_output("#{bin}/secrets-scanner --help")
  end
end
```

## Manual Install

1. Download the binary for your platform from [GitHub Releases](https://github.com/whit3rabbit/secrets-scanner/releases)
2. Make it executable: `chmod +x secrets-scanner-*`
3. Move it to your PATH: `mv secrets-scanner-* /usr/local/bin/secrets-scanner`
