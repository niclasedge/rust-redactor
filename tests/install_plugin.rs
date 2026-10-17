//! End-to-end tests for `redactor install-plugin` and related subcommands.

use assert_cmd::Command;
use tempfile::tempdir;

fn redactor() -> Command {
    let mut cmd = Command::cargo_bin("redactor").unwrap();
    cmd.env("REDACTOR_LOG_DIR", "/tmp/redactor-install-plugin-test-logs");
    cmd
}

// ── install-plugin local ────────────────────────────────────────────────────

#[test]
fn install_plugin_local_creates_artifacts() {
    let dir = tempdir().unwrap();
    redactor()
        .args(["install-plugin", "local", dir.path().to_str().unwrap()])
        .assert()
        .success();
    let claude = dir.path().join(".claude");
    assert!(
        claude.join("settings.json").exists(),
        "settings.json missing"
    );
    assert!(claude.join("CLAUDE.md").exists(), "CLAUDE.md missing");
    let content = std::fs::read_to_string(claude.join("settings.json")).unwrap();
    assert!(
        content.contains("redactor hook"),
        "settings must wire redactor hooks"
    );
}

#[test]
fn install_plugin_local_default_target_is_cwd() {
    let dir = tempdir().unwrap();
    redactor()
        .current_dir(dir.path())
        .args(["install-plugin", "local"])
        .assert()
        .success();
    assert!(dir.path().join(".claude").join("settings.json").exists());
}

#[test]
fn install_plugin_local_backs_up_existing_dir() {
    let dir = tempdir().unwrap();
    let claude_dir = dir.path().join(".claude");
    std::fs::create_dir(&claude_dir).unwrap();
    std::fs::write(claude_dir.join("marker.txt"), "old").unwrap();

    redactor()
        .args(["install-plugin", "local", dir.path().to_str().unwrap()])
        .assert()
        .success();

    assert!(dir.path().join(".claude").join("settings.json").exists());
    let backups: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".claude.bak."))
        .collect();
    assert_eq!(backups.len(), 1, "exactly one backup expected");
    assert!(backups[0].path().join("marker.txt").exists());
}

#[test]
fn install_plugin_local_force_no_backup() {
    let dir = tempdir().unwrap();
    let claude_dir = dir.path().join(".claude");
    std::fs::create_dir(&claude_dir).unwrap();
    std::fs::write(claude_dir.join("marker.txt"), "old").unwrap();

    redactor()
        .args([
            "install-plugin",
            "local",
            "--force",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(dir.path().join(".claude").join("settings.json").exists());
    assert!(!dir.path().join(".claude").join("marker.txt").exists());
    let backups: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".claude.bak."))
        .collect();
    assert_eq!(backups.len(), 0, "force must not create backup");
}

#[test]
fn install_plugin_local_dry_run_writes_nothing() {
    let dir = tempdir().unwrap();
    redactor()
        .args([
            "install-plugin",
            "local",
            "--dry-run",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();
    // dry-run must not create the .claude dir
    assert!(
        !dir.path().join(".claude").exists(),
        ".claude must not be created in dry-run"
    );
}

#[test]
fn install_plugin_local_merge_is_idempotent() {
    let dir = tempdir().unwrap();
    // First install
    redactor()
        .args(["install-plugin", "local", dir.path().to_str().unwrap()])
        .assert()
        .success();
    let settings_before =
        std::fs::read_to_string(dir.path().join(".claude").join("settings.json")).unwrap();

    // Second run with --merge — should add zero hooks
    let out = redactor()
        .args([
            "install-plugin",
            "local",
            "--merge",
            dir.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("already up-to-date") || stdout.contains("0 hooks"),
        "second --merge run should report idempotent: got {stdout}"
    );
    let settings_after =
        std::fs::read_to_string(dir.path().join(".claude").join("settings.json")).unwrap();
    assert_eq!(
        settings_before, settings_after,
        "settings.json must not change on second --merge run"
    );
}

#[test]
fn install_plugin_local_fails_for_missing_target() {
    let dir = tempdir().unwrap();
    let nonexistent = dir.path().join("nope");
    let out = redactor()
        .args(["install-plugin", "local", nonexistent.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("does not exist") || stderr.contains("install-plugin"));
}

// ── install-plugin global (isolated via REDACTOR_CLAUDE_DIR) ────────────────
//
// We use REDACTOR_CLAUDE_DIR (cross-platform) instead of HOME/USERPROFILE so
// the global install code stays isolated on both Linux and Windows CI runners.

#[test]
fn install_plugin_global_dry_run_writes_nothing() {
    let fake_claude = tempdir().unwrap();
    let out = redactor()
        .args(["install-plugin", "global", "--dry-run"])
        .env("REDACTOR_CLAUDE_DIR", fake_claude.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "dry-run must exit 0");
    assert!(
        !fake_claude.path().join("settings.json").exists(),
        "dry-run must not write settings.json"
    );
}

#[test]
fn install_plugin_global_creates_settings_and_claudemd() {
    let fake_claude = tempdir().unwrap();
    redactor()
        .args(["install-plugin", "global"])
        .env("REDACTOR_CLAUDE_DIR", fake_claude.path())
        .assert()
        .success();

    let settings = fake_claude.path().join("settings.json");
    let claudemd = fake_claude.path().join("CLAUDE.md");
    assert!(settings.exists(), "settings.json must be created");
    assert!(claudemd.exists(), "CLAUDE.md must be created");
    let s = std::fs::read_to_string(&settings).unwrap();
    assert!(
        s.contains("redactor hook pre-bash"),
        "pre-bash hook must be present"
    );
    assert!(
        s.contains("redactor hook prompt"),
        "prompt hook must be present"
    );
    let md = std::fs::read_to_string(&claudemd).unwrap();
    assert!(
        md.contains("BEGIN: redactor strict mode"),
        "managed block must be present"
    );
}

#[test]
fn install_plugin_global_creates_backup() {
    let fake_claude = tempdir().unwrap();
    std::fs::write(
        fake_claude.path().join("settings.json"),
        r#"{"existing":true}"#,
    )
    .unwrap();

    redactor()
        .args(["install-plugin", "global"])
        .env("REDACTOR_CLAUDE_DIR", fake_claude.path())
        .assert()
        .success();

    let backups: Vec<_> = std::fs::read_dir(fake_claude.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("settings.json.bak.")
        })
        .collect();
    assert_eq!(backups.len(), 1, "exactly one backup expected");
}

#[test]
fn install_plugin_global_is_idempotent() {
    let fake_claude = tempdir().unwrap();
    // First install
    redactor()
        .args(["install-plugin", "global", "--force"])
        .env("REDACTOR_CLAUDE_DIR", fake_claude.path())
        .assert()
        .success();

    let settings_after_first =
        std::fs::read_to_string(fake_claude.path().join("settings.json")).unwrap();

    // Second install (force to skip backup)
    let out = redactor()
        .args(["install-plugin", "global", "--force"])
        .env("REDACTOR_CLAUDE_DIR", fake_claude.path())
        .output()
        .unwrap();
    assert!(out.status.success());

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("0 new hook") || stdout.contains("0 hook(s) added"),
        "second run must report 0 new hooks added: got {stdout}"
    );

    let settings_after_second =
        std::fs::read_to_string(fake_claude.path().join("settings.json")).unwrap();
    let hooks_count_first = settings_after_first.matches("redactor hook").count();
    let hooks_count_second = settings_after_second.matches("redactor hook").count();
    assert_eq!(
        hooks_count_first, hooks_count_second,
        "hook count must not grow on second run"
    );
}

// ── uninstall-plugin ─────────────────────────────────────────────────────────

#[test]
fn uninstall_plugin_removes_claude_dir() {
    let dir = tempdir().unwrap();
    redactor()
        .args(["install-plugin", "local", dir.path().to_str().unwrap()])
        .assert()
        .success();
    assert!(dir.path().join(".claude").exists());

    redactor()
        .args(["uninstall-plugin", dir.path().to_str().unwrap()])
        .assert()
        .success();
    assert!(
        !dir.path().join(".claude").exists(),
        ".claude must be removed"
    );
}

#[test]
fn uninstall_plugin_dry_run_removes_nothing() {
    let dir = tempdir().unwrap();
    redactor()
        .args(["install-plugin", "local", dir.path().to_str().unwrap()])
        .assert()
        .success();

    redactor()
        .args([
            "uninstall-plugin",
            "--dry-run",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();
    assert!(
        dir.path().join(".claude").exists(),
        ".claude must remain after dry-run"
    );
}

#[test]
fn uninstall_plugin_noop_when_not_installed() {
    let dir = tempdir().unwrap();
    redactor()
        .args(["uninstall-plugin", dir.path().to_str().unwrap()])
        .assert()
        .success(); // must not fail
}

// ── plugin-status ────────────────────────────────────────────────────────────

#[test]
fn plugin_status_shows_local_state() {
    let dir = tempdir().unwrap();
    let out = redactor()
        .args(["plugin-status", "--target", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("local plugin status"),
        "must show local section"
    );
    assert!(
        stdout.contains("missing"),
        "must report missing settings.json"
    );
}

#[test]
fn plugin_status_shows_installed_state() {
    let dir = tempdir().unwrap();
    redactor()
        .args(["install-plugin", "local", dir.path().to_str().unwrap()])
        .assert()
        .success();

    let out = redactor()
        .args(["plugin-status", "--target", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("redactor hooks present"),
        "must show hook count"
    );
}

// ── install-hooks backward-compat alias ─────────────────────────────────────

#[test]
fn install_hooks_compat_dry_run() {
    let dir = tempdir().unwrap();
    redactor()
        .args(["install-hooks", "--dry-run", dir.path().to_str().unwrap()])
        .assert()
        .success();
    assert!(
        !dir.path().join(".claude").exists(),
        "dry-run must not write"
    );
}

#[test]
fn install_hooks_compat_global_dry_run() {
    let fake_claude = tempdir().unwrap();
    redactor()
        .args(["install-hooks", "--global", "--dry-run"])
        .env("REDACTOR_CLAUDE_DIR", fake_claude.path())
        .assert()
        .success();
    assert!(
        !fake_claude.path().join("settings.json").exists(),
        "dry-run must not write"
    );
}
