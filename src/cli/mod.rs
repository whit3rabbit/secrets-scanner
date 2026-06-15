mod args;
mod completions;
mod rules;
mod scan;

use clap::Parser;

use args::{Cli, Commands};

pub(crate) fn run() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_target(false)
        .format_module_path(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan(args) => scan::handle(args),
        Commands::UpdateRules { check, url } => rules::handle_update(check, url),
        Commands::ValidateRules { files } => rules::handle_validate(&files),
        Commands::MergeRules {
            manifest,
            all,
            out,
            report,
            check,
        } => rules::handle_merge_rules(&manifest, all, &out, report.as_deref(), check),
        Commands::ListRules { rules: rules_path } => {
            rules::handle_list_rules(rules_path.as_deref());
        }
        Commands::Completions { shell } => completions::handle(shell),
    }
}
