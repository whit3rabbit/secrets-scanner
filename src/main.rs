//! CLI entry point for secrets-scanner.
//!
//! All command parsing, dispatch, and handlers live under `src/cli/` so this
//! file only initializes the binary crate modules and starts the CLI.

mod cli;
mod format;
#[path = "safe_display.rs"]
mod safe_display;

fn main() {
    cli::run();
}
