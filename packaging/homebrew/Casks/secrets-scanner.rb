cask "secrets-scanner" do
  arch arm: "arm64", intel: "x86_64"

  version "__VERSION__"
  sha256 arm:   "__ARM_SHA256__",
         intel: "__X86_SHA256__"

  url "https://github.com/whit3rabbit/secrets-scanner/releases/download/v#{version}/secrets-scanner-#{version}-macos-#{arch}.zip"
  name "secrets-scanner"
  desc "High-performance secrets scanner using gitleaks-compatible rules"
  homepage "https://github.com/whit3rabbit/secrets-scanner"

  binary "secrets-scanner"
end
