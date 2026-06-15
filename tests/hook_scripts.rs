//! Integration tests for the bundled agent skill hook scripts.

#[cfg(unix)]
mod unix {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    fn script(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("plugins/secrets-scanner/skills/secrets-scanner/scripts")
            .join(name)
    }

    fn run_ok(repo: &Path, script_name: &str) {
        let output = Command::new("bash")
            .arg(script(script_name))
            .current_dir(repo)
            .output()
            .expect("run hook script");
        assert!(
            output.status.success(),
            "{script_name} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn git(repo: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .status()
            .expect("run git");
        assert!(status.success(), "git {args:?} failed");
    }

    fn init_repo(repo: &Path) {
        git(repo, &["init", "-q"]);
        git(repo, &["config", "user.email", "test@example.com"]);
        git(repo, &["config", "user.name", "Test User"]);
    }

    fn write_executable(path: &Path, contents: &str) {
        fs::write(path, contents).expect("write hook");
        let mut perms = fs::metadata(path).expect("stat hook").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("chmod hook");
    }

    #[test]
    fn install_hook_fails_closed_when_scanner_missing_and_restores_backup() {
        let repo = tempfile::tempdir().expect("repo");
        init_repo(repo.path());
        let hook = repo.path().join(".git/hooks/pre-commit");
        let backup = repo.path().join(".git/hooks/pre-commit.bak");
        let original = "#!/bin/sh\necho previous hook\n";
        write_executable(&hook, original);

        run_ok(repo.path(), "install-git-hook.sh");

        let installed = fs::read_to_string(&hook).expect("read installed hook");
        assert!(installed.contains("# managed-by: secrets-scanner-skill"));
        assert!(installed.contains("secrets-scanner scan . --staged --redact --no-context"));
        assert!(installed.contains("secrets-scanner not installed; blocking commit"));
        assert!(!installed.contains("SECRETS_SCANNER_REQUIRED"));
        assert!(!installed.contains("--no-verify"));
        assert_eq!(
            fs::read_to_string(&backup).expect("read backup"),
            original,
            "existing unmanaged hook should be backed up"
        );

        let empty_path = tempfile::tempdir().expect("empty path");
        let output = Command::new("/bin/sh")
            .arg(&hook)
            .current_dir(repo.path())
            .env("PATH", empty_path.path())
            .output()
            .expect("run installed hook");
        assert!(!output.status.success(), "missing scanner must block");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("secrets-scanner not installed; blocking commit"),
            "stderr should explain fail-closed behavior"
        );

        run_ok(repo.path(), "uninstall-git-hook.sh");
        assert_eq!(
            fs::read_to_string(&hook).expect("read restored hook"),
            original,
            "uninstall should restore the backed-up hook"
        );
        assert!(!backup.exists(), "backup should be moved back into place");
    }

    #[test]
    fn uninstall_leaves_unmanaged_hook_untouched() {
        let repo = tempfile::tempdir().expect("repo");
        init_repo(repo.path());
        let hook = repo.path().join(".git/hooks/pre-commit");
        let backup = repo.path().join(".git/hooks/pre-commit.bak");
        let unmanaged = "#!/bin/sh\necho unmanaged\n";
        let backup_contents = "#!/bin/sh\necho backup\n";
        write_executable(&hook, unmanaged);
        write_executable(&backup, backup_contents);

        run_ok(repo.path(), "uninstall-git-hook.sh");

        assert_eq!(
            fs::read_to_string(&hook).expect("read unmanaged hook"),
            unmanaged,
            "unmanaged hook must not be removed"
        );
        assert_eq!(
            fs::read_to_string(&backup).expect("read backup"),
            backup_contents,
            "unmanaged uninstall must not restore or delete backups"
        );
    }
}
