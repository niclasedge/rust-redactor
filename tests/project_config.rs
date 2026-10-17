//! Integration tests for `.redactor.toml` (rred-12).
//!
//! Spawn the actual `redactor` binary with a tempdir as `current_dir`,
//! place a `.redactor.toml` inside, pipe input, and assert on output.

use std::io::Write;
use std::process::{Command as StdCommand, Stdio};
use tempfile::tempdir;

fn redact_in_dir(cwd: &std::path::Path, input: &str) -> std::process::Output {
    let bin = assert_cmd::cargo::cargo_bin("redactor");
    let log_dir = tempdir().unwrap();
    let mut child = StdCommand::new(&bin)
        .current_dir(cwd)
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .env(
            "REDACTOR_CONFIG_DIR",
            "/tmp/project-config-tests-no-such-dir",
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn write_cfg(dir: &std::path::Path, body: &str) {
    std::fs::write(dir.join(".redactor.toml"), body).unwrap();
}

#[test]
fn project_pattern_redacts_via_binary() {
    let td = tempdir().unwrap();
    write_cfg(
        td.path(),
        r#"
[[patterns.custom]]
name = "internal_id"
re = 'INT-\d{6}'
"#,
    );
    let out = redact_in_dir(td.path(), "see INT-123456 ende");
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("<redacted:internal_id>"));
    assert!(!s.contains("INT-123456"));
}

#[test]
fn project_pattern_explicit_sub_wins_via_binary() {
    let td = tempdir().unwrap();
    write_cfg(
        td.path(),
        r#"
[[patterns.custom]]
name = "ticket"
re = 'TICKET-\d+'
sub = "[T]"
"#,
    );
    let out = redact_in_dir(td.path(), "see TICKET-77 in log");
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("[T]"));
    assert!(!s.contains("TICKET-77"));
}

#[test]
fn project_pattern_combined_with_defaults() {
    // Default OPENAI_API_KEY plus project-specific INT-id in same input.
    let td = tempdir().unwrap();
    write_cfg(
        td.path(),
        r#"
[[patterns.custom]]
name = "internal_id"
re = 'INT-\d{6}'
"#,
    );
    let out = redact_in_dir(
        td.path(),
        "auth=sk-proj-abcdefghij1234567890 ticket=INT-654321 done",
    );
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("<redacted:openai_key>"));
    assert!(s.contains("<redacted:internal_id>"));
}

#[test]
fn project_no_config_no_change() {
    // No .redactor.toml at all -> built-ins still apply but no project rules.
    let td = tempdir().unwrap();
    let out = redact_in_dir(td.path(), "see INT-123456 ende");
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    // INT-123456 has no built-in rule, so it must remain.
    assert!(s.contains("INT-123456"));
    assert!(!s.contains("<redacted:internal_id>"));
}

#[test]
fn project_walks_up_tree() {
    // Place .redactor.toml two dirs up; binary runs in the nested dir.
    let td = tempdir().unwrap();
    let nested = td.path().join("a/b");
    std::fs::create_dir_all(&nested).unwrap();
    write_cfg(
        td.path(),
        r#"
[[patterns.custom]]
name = "ticket"
re = 'TICKET-\d+'
"#,
    );
    let out = redact_in_dir(&nested, "see TICKET-1234 ende");
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("<redacted:ticket>"));
}

#[test]
fn project_invalid_toml_yields_error() {
    let td = tempdir().unwrap();
    write_cfg(td.path(), "[patterns\n garbage");
    let out = redact_in_dir(td.path(), "any input");
    // Invalid TOML must not silently pass — the binary should error out.
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("redactor.toml") || stderr.contains("redactor:"),
        "stderr should mention the config file, got: {stderr}"
    );
}
