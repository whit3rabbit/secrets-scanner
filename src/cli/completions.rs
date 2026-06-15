use clap::CommandFactory;
use clap_complete::Shell;

use super::args::Cli;

/// Handle the `completions` subcommand.
pub(super) fn handle(shell: Shell) {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
}
