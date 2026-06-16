use super::{Cli, Commands, ScanArgs};
use clap::Parser;

/// Parse argv and return the `scan` args, panicking on any other command.
fn scan_args(argv: &[&str]) -> ScanArgs {
    match Cli::try_parse_from(argv)
        .expect("args should parse")
        .command
    {
        Commands::Scan(args) => args,
        _ => panic!("expected scan subcommand"),
    }
}

#[test]
fn base_alone_implies_changed_files() {
    // Regression: clap does not auto-imply, so `--base` passed without
    // `--changed-files` must still derive changed-files mode rather than
    // silently falling back to a full directory walk that discards the base.
    let args = scan_args(&["secrets-scanner", "scan", ".", "--base", "origin/main"]);
    assert!(!args.changed_files, "only --base was passed");
    assert_eq!(args.base.as_deref(), Some("origin/main"));
    assert!(
        super::super::scan::resolve_changed_files(&args),
        "--base must imply changed-files mode"
    );
}

#[test]
fn staged_conflicts_with_git_tracked() {
    // `--staged` is its own git mode; combined with `--git-tracked` (which
    // would otherwise silently win at runtime) it must be a parse error.
    assert!(
        Cli::try_parse_from(["secrets-scanner", "scan", ".", "--staged", "--git-tracked"]).is_err(),
        "--staged --git-tracked must conflict"
    );
}

#[test]
fn git_tracked_conflicts_with_changed_files() {
    assert!(
        Cli::try_parse_from([
            "secrets-scanner",
            "scan",
            ".",
            "--git-tracked",
            "--changed-files",
        ])
        .is_err(),
        "--git-tracked --changed-files must conflict"
    );
}

#[test]
fn git_history_conflicts_with_other_git_modes() {
    for other in ["--git-tracked", "--changed-files", "--staged"] {
        assert!(
            Cli::try_parse_from(["secrets-scanner", "scan", ".", "--git-history", other]).is_err(),
            "--git-history {other} must conflict"
        );
    }
}

#[test]
fn max_file_size_rejects_zero() {
    assert!(
        Cli::try_parse_from(["secrets-scanner", "scan", ".", "--max-file-size", "0"]).is_err(),
        "--max-file-size 0 must be rejected"
    );
}

#[test]
fn history_options_require_git_history() {
    // `--all`/`--log-opts` are meaningless without history mode and must be
    // rejected so they cannot silently no-op.
    assert!(
        Cli::try_parse_from(["secrets-scanner", "scan", ".", "--all"]).is_err(),
        "--all requires --git-history"
    );
    assert!(
        Cli::try_parse_from(["secrets-scanner", "scan", ".", "--log-opts", "-c"]).is_err(),
        "--log-opts requires --git-history"
    );
}

#[test]
fn old_git_flag_names_are_rejected() {
    // Clean break: the pre-rename flags must no longer parse.
    for old in ["--git", "--git-diff", "--diff-base"] {
        assert!(
            Cli::try_parse_from(["secrets-scanner", "scan", ".", old]).is_err(),
            "old flag {old} must be rejected after the rename"
        );
    }
}

#[test]
fn staged_alone_parses() {
    assert!(scan_args(&["secrets-scanner", "scan", ".", "--staged"]).staged);
}

#[test]
fn max_findings_conflicts_with_generate_baseline() {
    // A capped baseline silently under-suppresses later; reject the combo
    // instead of dropping the cap on the quiet.
    assert!(
        Cli::try_parse_from([
            "secrets-scanner",
            "scan",
            ".",
            "--generate-baseline",
            "b.json",
            "--max-findings",
            "5",
        ])
        .is_err(),
        "--max-findings with --generate-baseline must conflict"
    );
}

#[test]
fn redaction_full_conflicts_with_no_redact() {
    // `--no-redact` shows raw text; pairing it with a redaction style is
    // contradictory.
    assert!(
        Cli::try_parse_from([
            "secrets-scanner",
            "scan",
            ".",
            "--no-redact",
            "--redaction",
            "full",
        ])
        .is_err(),
        "--no-redact --redaction full must conflict"
    );
    let args = scan_args(&["secrets-scanner", "scan", ".", "--redaction", "full"]);
    assert!(matches!(args.redaction, super::RedactionModeArg::Full));
}

#[test]
fn error_on_unreadable_defaults_off_and_parses() {
    assert!(!scan_args(&["secrets-scanner", "scan", "."]).error_on_unreadable);
    assert!(
        scan_args(&["secrets-scanner", "scan", ".", "--error-on-unreadable"]).error_on_unreadable
    );
}

#[test]
fn max_files_conflicts_with_generate_baseline() {
    // Dropping whole files writes a baseline missing their findings, which then
    // silently fail to suppress on a later uncapped scan.
    assert!(
        Cli::try_parse_from([
            "secrets-scanner",
            "scan",
            ".",
            "--generate-baseline",
            "b.json",
            "--max-files",
            "5",
        ])
        .is_err(),
        "--max-files with --generate-baseline must conflict"
    );
}

#[test]
fn max_findings_per_file_conflicts_with_generate_baseline() {
    assert!(
        Cli::try_parse_from([
            "secrets-scanner",
            "scan",
            ".",
            "--generate-baseline",
            "b.json",
            "--max-findings-per-file",
            "5",
        ])
        .is_err(),
        "--max-findings-per-file with --generate-baseline must conflict"
    );
}

#[test]
fn error_on_skipped_defaults_off_and_parses() {
    assert!(!scan_args(&["secrets-scanner", "scan", "."]).error_on_skipped);
    assert!(scan_args(&["secrets-scanner", "scan", ".", "--error-on-skipped"]).error_on_skipped);
}

#[test]
fn history_timeout_defaults_zero_and_requires_history() {
    // Default is unlimited (0) and the flag is meaningless without history mode.
    assert_eq!(
        scan_args(&["secrets-scanner", "scan", "."]).history_timeout,
        0
    );
    assert_eq!(
        scan_args(&[
            "secrets-scanner",
            "scan",
            ".",
            "--git-history",
            "--history-timeout",
            "30",
        ])
        .history_timeout,
        30
    );
    assert!(
        Cli::try_parse_from(["secrets-scanner", "scan", ".", "--history-timeout", "30"]).is_err(),
        "--history-timeout requires --git-history"
    );
}
