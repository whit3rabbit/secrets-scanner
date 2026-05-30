/// CLI entry point for secrets-scanner.
///
/// This is a thin shell over the `secrets_scanner` library. It handles:
/// - CLI argument parsing (clap)
/// - Dispatching to the `update-rules` subcommand
/// - Running the scan pipeline and printing results
///
/// All scanning logic lives in the library crate (`src/lib.rs`).

use clap::{Parser, Subcommand};
use secrets_scanner::{Scanner, ScanConfig};

mod rules_cli {
    // Re-export the rules module for the update-rules subcommand.
    // The library crate's `rules` module handles loading; this just
    // needs the updater.
    pub use secrets_scanner::rules::updater;
}

// ─────────────────────────────────────────────
// CLI ARGUMENT DEFINITION
// ─────────────────────────────────────────────

/// A high-performance secrets scanner powered by Aho-Corasick and regex.
#[derive(Parser)]
#[command(name = "secrets-scanner", version, about = "A Rust secrets scanner")]
struct Cli {
    /// Optional subcommand to execute.
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to the directory to scan.
    #[arg(default_value = ".")]
    path: String,

    /// Update the rules from upstream.
    #[arg(long)]
    update: bool,

    /// Only check for updates without downloading (used with --update).
    #[arg(long, requires = "update")]
    check: bool,

    /// Disable secret redaction in output (show raw matches).
    #[arg(long)]
    no_redact: bool,
}

/// Available subcommands.
#[derive(Subcommand)]
enum Commands {
    /// Update the scanning rules from upstream.
    #[command(name = "update-rules", alias = "update")]
    UpdateRules {
        /// Only check for updates without downloading.
        #[arg(long)]
        check: bool,
    },

    /// Validate one or more rules TOML files for structural and regex correctness.
    #[command(name = "validate-rules", alias = "validate")]
    ValidateRules {
        /// Paths to the TOML rules files to validate. If empty, defaults to validating active local assets.
        #[arg(default_values = &["assets/gitleaks.toml", "assets/local.toml", "assets/secrets-scanner.toml"])]
        files: Vec<String>,
    },
}

// ─────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    // Handle validate-rules subcommand
    if let Some(Commands::ValidateRules { files }) = &cli.command {
        handle_validate(files);
        return;
    }

    // Handle update-rules subcommand
    let check_only = match &cli.command {
        Some(Commands::UpdateRules { check }) => Some(*check),
        None if cli.update => Some(cli.check),
        _ => None,
    };

    if let Some(check_only) = check_only {
        handle_update(check_only);
        return;
    }

    // Scan mode
    let config = ScanConfig {
        redact: !cli.no_redact,
        ..Default::default()
    };

    let scanner = match Scanner::new() {
        Ok(s) => s.with_config(config),
        Err(e) => {
            eprintln!("❌ Failed to load rules: {e}");
            std::process::exit(2);
        }
    };

    eprintln!(
        "[scanner] Loaded {} rules ({} keywords)",
        scanner.engine().rule_count(),
        scanner.engine().keyword_count(),
    );

    println!("🔍 Scanning: {}\n", cli.path);
    let start = std::time::Instant::now();

    let findings = scanner.scan_path(&cli.path);

    let elapsed = start.elapsed();

    if findings.is_empty() {
        println!("✅ No secrets found.");
    } else {
        println!("🚨 Found {} potential secret(s):\n", findings.len());
        for f in &findings {
            println!(
                "  {}:{} | rule={} entropy={:.2} | {}",
                f.file, f.line, f.rule_id, f.entropy, f.matched
            );
            if !f.rule_description.is_empty() {
                println!("    └─ {}", f.rule_description);
            }
        }
    }

    println!("\n⏱  Scanned in {:.2?}", elapsed);
}

/// Handle the update-rules subcommand.
fn handle_update(check_only: bool) {
    match rules_cli::updater::update_rules(check_only) {
        Ok(rules_cli::updater::UpdateResult::AlreadyCurrent { sha256 }) => {
            println!("✅ Rules already up to date (SHA-256: {sha256})");
        }
        Ok(rules_cli::updater::UpdateResult::Updated { sha256 }) => {
            println!("✅ Rules updated (SHA-256: {sha256})");
        }
        Ok(rules_cli::updater::UpdateResult::UpdateAvailable {
            local_sha,
            remote_sha,
        }) => {
            println!("⚠️  Update available!");
            println!("   Local:  {local_sha}");
            println!("   Remote: {remote_sha}");
            println!("   Run without --check to apply.");
            std::process::exit(1);
        }
        Ok(rules_cli::updater::UpdateResult::CheckedCurrent { sha256 }) => {
            println!("✅ Rules are current (SHA-256: {sha256})");
        }
        Err(e) => {
            eprintln!("❌ Update failed: {e}");
            std::process::exit(2);
        }
    }
}

/// Handle the validate-rules subcommand.
fn handle_validate(files: &[String]) {
    let mut all_valid = true;
    for file in files {
        match std::fs::read_to_string(file) {
            Ok(content) => {
                match secrets_scanner::rules::validation::validate_rules_toml(&content) {
                    Ok(()) => {
                        println!("✅ {file} is valid");
                    }
                    Err(errors) => {
                        all_valid = false;
                        eprintln!("❌ {file} validation failed:");
                        for err in errors {
                            eprintln!("  - {err}");
                        }
                    }
                }
            }
            Err(e) => {
                all_valid = false;
                eprintln!("❌ Failed to read {file}: {e}");
            }
        }
    }
    if !all_valid {
        std::process::exit(1);
    }
}

// ─────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use secrets_scanner::{Scanner, ScanConfig};

    #[test]
    fn scanner_loads_from_bundled() {
        let scanner = Scanner::from_bundled().expect("should load bundled rules");
        assert!(scanner.engine().rule_count() > 100);
    }

    #[test]
    fn scanner_detects_planted_secret() {
        let scanner = Scanner::from_bundled()
            .expect("should load")
            .with_config(ScanConfig {
                redact: false,
                ..Default::default()
            });

        let content = "export GITHUB_TOKEN=ghp_n0tArEaLsEcReTgHuBpAt1234567890AbCde";
        let findings = scanner.scan_content("deploy.sh", content);
        assert!(!findings.is_empty(), "should detect GitHub PAT");
        assert_eq!(findings[0].rule_id, "github-pat");
    }
}