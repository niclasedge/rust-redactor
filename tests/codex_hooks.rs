use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::tempdir;

fn run_hook(event: &str, payload: &str) -> std::process::Output {
    let bin = assert_cmd::cargo::cargo_bin("redactor");
    let log_dir = tempdir().unwrap();
    let mut child = Command::new(&bin)
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .env("REDACTOR_CONFIG_DIR", "/tmp/codex-hooks-no-such-config-dir")
        .arg("hook")
        .arg(event)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn pre_patch_blocks_sensitive_patch_target() {
    let payload = r#"{"hook_event_name":"PreToolUse","tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Update File: .env\n@@\n-OLD=1\n+OLD=2\n*** End Patch\n"}}"#;
    let out = run_hook("pre-patch", payload);
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("\"decision\":\"block\""), "must block, got: {s}");
    assert!(s.contains("sensitive patch target"), "got: {s}");
}

#[test]
fn pre_patch_allows_regular_patch_target() {
    let payload = r#"{"hook_event_name":"PreToolUse","tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Update File: src/main.rs\n@@\n-fn old() {}\n+fn new() {}\n*** End Patch\n"}}"#;
    let out = run_hook("pre-patch", payload);
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert_eq!(s.trim(), "{}", "expected allow, got: {s}");
}

#[test]
fn post_write_validates_json_from_apply_patch_payload() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("broken.json");
    std::fs::write(&path, "{ nope").unwrap();
    let payload = format!(
        r#"{{"hook_event_name":"PostToolUse","tool_name":"apply_patch","tool_input":{{"command":"*** Begin Patch\n*** Update File: {}\n@@\n-a\n+b\n*** End Patch\n"}}}}"#,
        path.display().to_string().replace("\\", "/")
    );
    let out = run_hook("post-write", &payload);
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("\"decision\":\"block\""), "must block, got: {s}");
    assert!(s.contains("invalid JSON"), "got: {s}");
}
