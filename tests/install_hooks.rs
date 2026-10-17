//! End-to-end tests for `redactor install-hooks`.
//!
//! Each test runs the actual `redactor` binary against a tempdir and asserts
//! on the deployed `.claude/settings.json` + `.claude/CLAUDE.md`.

use assert_cmd::Command;
use tempfile::tempdir;

fn redactor() -> Command {
    let mut cmd = Command::cargo_bin("redactor").unwrap();
    cmd.env("REDACTOR_LOG_DIR", "/tmp/redactor-install-test-logs");
    cmd
}

// ---------- 1. positive: writes settings.json + CLAUDE.md ----------

#[test]
fn install_hooks_creates_claude_dir() {
    let dir = tempdir().unwrap();
    redactor()
        .arg("install-hooks")
        .arg(dir.path())
        .assert()
        .success();
    let claude = dir.path().join(".claude");
    let settings = claude.join("settings.json");
    let claudemd = claude.join("CLAUDE.md");
    assert!(settings.exists(), "settings.json must be written");
    assert!(claudemd.exists(), "CLAUDE.md must be written");

    let content = std::fs::read_to_string(&settings).unwrap();
    assert!(
        content.contains("redactor hook"),
        "settings must wire `redactor hook` commands"
    );
}

// ---------- 2. positive: default target = current directory ----------

#[test]
fn install_hooks_default_target_is_cwd() {
    let dir = tempdir().unwrap();
    redactor()
        .current_dir(dir.path())
        .arg("install-hooks")
        .assert()
        .success();
    assert!(dir.path().join(".claude").join("settings.json").exists());
    assert!(dir.path().join(".claude").join("CLAUDE.md").exists());
}

// ---------- 3. existing .claude/ is preserved as backup (default) ----------

#[test]
fn install_hooks_backs_up_existing_dir() {
    let dir = tempdir().unwrap();
    let claude_dir = dir.path().join(".claude");
    std::fs::create_dir(&claude_dir).unwrap();
    std::fs::write(claude_dir.join("marker.txt"), "old-content").unwrap();

    redactor()
        .arg("install-hooks")
        .arg(dir.path())
        .assert()
        .success();

    // new files exist
    assert!(dir.path().join(".claude").join("settings.json").exists());

    // old content was moved into a backup dir
    let backups: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".claude.bak."))
        .collect();
    assert_eq!(backups.len(), 1, "exactly one backup dir expected");
    let marker = backups[0].path().join("marker.txt");
    assert!(marker.exists(), "backup must keep old content");
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "old-content");
}

// ---------- 4. --force overwrites without backup ----------

#[test]
fn install_hooks_force_overwrites_without_backup() {
    let dir = tempdir().unwrap();
    let claude_dir = dir.path().join(".claude");
    std::fs::create_dir(&claude_dir).unwrap();
    std::fs::write(claude_dir.join("marker.txt"), "old").unwrap();

    redactor()
        .arg("install-hooks")
        .arg("--force")
        .arg(dir.path())
        .assert()
        .success();

    // settings.json present
    assert!(dir.path().join(".claude").join("settings.json").exists());
    // marker.txt was wiped (force = no backup)
    assert!(!dir.path().join(".claude").join("marker.txt").exists());

    // no .claude.bak.* dir created
    let backups: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".claude.bak."))
        .collect();
    assert_eq!(backups.len(), 0, "force mode must not create a backup dir");
}

// ---------- 5. negative: target dir does not exist ----------

#[test]
fn install_hooks_fails_when_target_missing() {
    let dir = tempdir().unwrap();
    let nonexistent = dir.path().join("does-not-exist");
    let out = redactor()
        .arg("install-hooks")
        .arg(&nonexistent)
        .output()
        .unwrap();
    assert!(!out.status.success(), "must fail when target is missing");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("does not exist") || stderr.contains("install-hooks"),
        "stderr should explain the failure, got: {stderr}"
    );
}

// ---------- 6. negative: target is a file, not a directory ----------

#[test]
fn install_hooks_fails_when_target_is_file() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("not-a-dir");
    std::fs::write(&file, "x").unwrap();
    let out = redactor().arg("install-hooks").arg(&file).output().unwrap();
    assert!(!out.status.success(), "must fail when target is a file");
}

// ---------- 7. settings.json wires all four hook events ----------

#[test]
fn install_hooks_settings_references_all_events() {
    let dir = tempdir().unwrap();
    redactor()
        .arg("install-hooks")
        .arg(dir.path())
        .assert()
        .success();
    let settings = dir.path().join(".claude").join("settings.json");
    let content = std::fs::read_to_string(&settings).unwrap();
    assert!(content.contains("prompt"), "must wire prompt hook");
    assert!(content.contains("pre-bash"), "must wire pre-bash hook");
    assert!(content.contains("pre-read"), "must wire pre-read hook");
    assert!(content.contains("post-tool"), "must wire post-tool hook");
}
