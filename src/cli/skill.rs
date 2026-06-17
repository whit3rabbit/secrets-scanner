//! `install-skill` / `uninstall-skill` subcommands.
//!
//! Installs the bundled secrets-scanner agent skill (`SKILL.md`, `REFERENCE.md`,
//! and the helper scripts) into one or more agent runtimes via the `agent-config`
//! library, which owns per-runtime skill paths, atomic writes, first-touch `.bak`
//! backups, an ownership ledger, idempotency, and reversible uninstall.

use std::path::PathBuf;

use agent_config::{
    skill_by_id, skill_capable, AgentConfigError, InstallPlan, PlanStatus, Scope, SkillAsset,
    SkillSpec, SkillSurface,
};

/// Owner tag recorded in agent-config's ownership ledger. Uninstall only removes
/// skills carrying this tag, so it must stay stable across releases.
const OWNER_TAG: &str = "secrets-scanner";

/// Skill directory name created under each runtime's `skills/` root.
const SKILL_NAME: &str = "secrets-scanner";

// The binary is distributed standalone (Homebrew/cargo/prebuilt release), so the
// skill content is compiled in rather than read from the repo at runtime —
// mirroring the `include_str!` embedding of `BUNDLED_RULES` in `rules/mod.rs`.
// The canonical skill home is `plugins/.../secrets-scanner/`; `.claude/` is a
// symlink to it.
const SKILL_MD: &str =
    include_str!("../../plugins/secrets-scanner/skills/secrets-scanner/SKILL.md");
const REFERENCE_MD: &str =
    include_str!("../../plugins/secrets-scanner/skills/secrets-scanner/REFERENCE.md");
const INSTALL_SH: &str =
    include_str!("../../plugins/secrets-scanner/skills/secrets-scanner/scripts/install.sh");
const UNINSTALL_SH: &str =
    include_str!("../../plugins/secrets-scanner/skills/secrets-scanner/scripts/uninstall.sh");
const INSTALL_HOOK_SH: &str = include_str!(
    "../../plugins/secrets-scanner/skills/secrets-scanner/scripts/install-git-hook.sh"
);
const UNINSTALL_HOOK_SH: &str = include_str!(
    "../../plugins/secrets-scanner/skills/secrets-scanner/scripts/uninstall-git-hook.sh"
);

/// The helper scripts, each shipped as an executable asset under `scripts/`.
const SCRIPTS: &[(&str, &str)] = &[
    ("scripts/install.sh", INSTALL_SH),
    ("scripts/uninstall.sh", UNINSTALL_SH),
    ("scripts/install-git-hook.sh", INSTALL_HOOK_SH),
    ("scripts/uninstall-git-hook.sh", UNINSTALL_HOOK_SH),
];

/// Handle the `install-skill` subcommand. Exit codes: 0 = all targets handled
/// successfully (including idempotent no-ops); 2 = an unknown agent id or any
/// install/plan error.
pub(super) fn handle_install(agents: &[String], local: Option<&str>, dry_run: bool) {
    let spec = match build_spec() {
        Ok(spec) => spec,
        Err(e) => {
            eprintln!("error: could not build skill spec: {e}");
            std::process::exit(2);
        }
    };
    let scope = resolve_scope(local);
    let surfaces = resolve_agents(agents);

    let mut failed = false;
    for surface in &surfaces {
        let id = surface.id();
        if dry_run {
            match surface.plan_install_skill(&scope, &spec) {
                Ok(plan) => print_plan(id, &plan),
                Err(e) => {
                    eprintln!("[{id}] error: {e}");
                    failed = true;
                }
            }
            continue;
        }
        match surface.install_skill(&scope, &spec) {
            Ok(report) if report.already_installed => {
                println!("[{id}] already installed (no changes)");
            }
            Ok(report) => {
                println!(
                    "[{id}] installed: {} created, {} patched, {} backed up",
                    report.created.len(),
                    report.patched.len(),
                    report.backed_up.len()
                );
                for path in &report.created {
                    println!("       + {}", path.display());
                }
            }
            Err(e) => {
                eprintln!("[{id}] install failed: {e}");
                failed = true;
            }
        }
    }
    if failed {
        std::process::exit(2);
    }
}

/// Handle the `uninstall-skill` subcommand. Removes only the skill owned by this
/// tool. Exit codes: 0 = all targets handled (including not-installed no-ops);
/// 2 = an unknown agent id, an ownership conflict, or any removal error.
pub(super) fn handle_uninstall(agents: &[String], local: Option<&str>) {
    let scope = resolve_scope(local);
    let surfaces = resolve_agents(agents);

    let mut failed = false;
    for surface in &surfaces {
        let id = surface.id();
        match surface.uninstall_skill(&scope, SKILL_NAME, OWNER_TAG) {
            Ok(report) if report.not_installed => {
                println!("[{id}] not installed (nothing to remove)");
            }
            Ok(report) => {
                println!(
                    "[{id}] uninstalled: {} removed, {} restored",
                    report.removed.len(),
                    report.restored.len()
                );
            }
            Err(AgentConfigError::NotOwnedByCaller { actual, .. }) => {
                let owner = actual.as_deref().unwrap_or("another tool");
                eprintln!("[{id}] skipped: skill is owned by {owner}, not {OWNER_TAG}");
                failed = true;
            }
            Err(e) => {
                eprintln!("[{id}] uninstall failed: {e}");
                failed = true;
            }
        }
    }
    if failed {
        std::process::exit(2);
    }
}

/// Resolve `--local [PATH]` (defaulting to the current dir) versus the default
/// user-home install.
fn resolve_scope(local: Option<&str>) -> Scope {
    match local {
        Some(path) => Scope::Local(PathBuf::from(path)),
        None => Scope::Global,
    }
}

/// Look up each requested agent id against the agent-config registry. Exits 2
/// with the list of skill-capable ids if any id is unknown or skill-incapable.
fn resolve_agents(agents: &[String]) -> Vec<Box<dyn SkillSurface>> {
    let mut resolved = Vec::with_capacity(agents.len());
    for id in agents {
        match skill_by_id(id) {
            Some(surface) => resolved.push(surface),
            None => {
                let mut valid: Vec<&str> = skill_capable().iter().map(|s| s.id()).collect();
                valid.sort_unstable();
                eprintln!(
                    "error: unknown or skill-incapable agent '{id}'\n  supported: {}",
                    valid.join(", ")
                );
                std::process::exit(2);
            }
        }
    }
    resolved
}

/// Build the shared [`SkillSpec`] from the embedded skill content: the
/// `SKILL.md` frontmatter supplies the description and optional model, its body
/// becomes the skill body, and `REFERENCE.md` plus the scripts become assets.
fn build_spec() -> Result<SkillSpec, String> {
    let (description, model, body) = parse_skill_md(SKILL_MD)
        .ok_or_else(|| "embedded SKILL.md is missing its `---` frontmatter fences".to_string())?;

    let mut builder = SkillSpec::builder(SKILL_NAME)
        .owner(OWNER_TAG)
        .description(description)
        .body(body)
        .asset(SkillAsset {
            relative_path: PathBuf::from("REFERENCE.md"),
            bytes: REFERENCE_MD.as_bytes().to_vec(),
            executable: false,
        });
    if let Some(model) = model {
        builder = builder.model(model);
    }
    for (path, contents) in SCRIPTS {
        builder = builder.asset(SkillAsset {
            relative_path: PathBuf::from(path),
            bytes: contents.as_bytes().to_vec(),
            executable: true,
        });
    }
    builder.try_build().map_err(|e| e.to_string())
}

/// Split a `SKILL.md` string into its frontmatter `description`, optional
/// `model`, and markdown body. Returns `None` if the leading `---` fences are
/// absent or no `description:` is present.
fn parse_skill_md(md: &str) -> Option<(String, Option<String>, String)> {
    // Tolerate CRLF line endings (e.g. a Windows `git` checkout of the embedded
    // SKILL.md under autocrlf) so the `---\n` fence matching below isn't defeated
    // by a stray `\r`. Only allocate when CR is actually present.
    let normalized;
    let md = if md.contains('\r') {
        normalized = md.replace("\r\n", "\n");
        normalized.as_str()
    } else {
        md
    };

    let after_open = md.strip_prefix("---\n")?;
    // The first "\n---" after the opening fence is the closing fence; any body
    // "---" comes later, so this never mistakes content for the boundary.
    let close = after_open.find("\n---")?;
    let front = &after_open[..close];

    // Body begins on the line after the closing fence.
    let rest = &after_open[close + 1..]; // starts with "---"
    let body_offset = rest.find('\n').map(|n| n + 1).unwrap_or(rest.len());
    let body = rest[body_offset..].trim_start_matches('\n').to_string();

    let mut description = None;
    let mut model = None;
    for line in front.lines() {
        if let Some(value) = line.strip_prefix("description:") {
            description = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("model:") {
            model = Some(value.trim().to_string());
        }
    }
    description.map(|d| (d, model, body))
}

/// Print a dry-run install plan for one agent.
fn print_plan(id: &str, plan: &InstallPlan) {
    let status = match plan.status {
        PlanStatus::WillChange => "would change",
        PlanStatus::NoOp => "already installed (no changes)",
        PlanStatus::Refused => "refused",
        // PlanStatus is #[non_exhaustive]; treat any future variant as a
        // conservative "unknown" rather than failing to compile on upgrade.
        _ => "unknown status",
    };
    println!("[{id}] dry run: {status}");
    for change in &plan.changes {
        println!("       {change:?}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_embedded_skill_md() {
        let (description, model, body) =
            parse_skill_md(SKILL_MD).expect("embedded SKILL.md parses");
        assert!(!description.trim().is_empty());
        assert!(description.contains("secrets-scanner"));
        // The canonical (Claude) skill pins the model.
        assert_eq!(model.as_deref(), Some("haiku"));
        assert!(body.starts_with("# secrets-scanner"));
        assert!(!body.contains("\n---\n# secrets-scanner")); // frontmatter stripped
    }

    #[test]
    fn parses_skill_md_with_crlf_line_endings() {
        // A Windows checkout (autocrlf) embeds the LF source as CRLF; the parser
        // must still find the `---` fences and strip the frontmatter.
        let crlf = "---\r\ndescription: a secrets-scanner skill\r\nmodel: haiku\r\n---\r\n# secrets-scanner\r\nbody\r\n";
        let (description, model, body) = parse_skill_md(crlf).expect("CRLF SKILL.md parses");
        assert_eq!(description, "a secrets-scanner skill");
        assert_eq!(model.as_deref(), Some("haiku"));
        assert!(body.starts_with("# secrets-scanner"));
        assert!(!body.contains("---")); // no leftover fence
    }

    #[test]
    fn build_spec_succeeds_with_all_assets() {
        let spec = build_spec().expect("spec builds");
        assert_eq!(spec.name, SKILL_NAME);
        assert_eq!(spec.owner_tag, OWNER_TAG);
        // REFERENCE.md + 4 scripts.
        assert_eq!(spec.assets.len(), 1 + SCRIPTS.len());
        let script_assets = spec.assets.iter().filter(|a| a.executable).count();
        assert_eq!(script_assets, SCRIPTS.len());
    }

    #[test]
    fn parse_returns_none_without_frontmatter() {
        assert!(parse_skill_md("# no frontmatter here\n").is_none());
    }
}
