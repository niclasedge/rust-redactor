//! Integration tests for the new Phase-5 hooks (rred-18..20):
//! `session-start`, `post-write`, and the network-guard inside `pre-bash`.

use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::tempdir;

fn run_hook(event: &str, payload: &str) -> std::process::Output {
    let bin = assert_cmd::cargo::cargo_bin("redactor");
    let log_dir = tempdir().unwrap();
    let mut child = Command::new(&bin)
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .env("REDACTOR_CONFIG_DIR", "/tmp/hook-phase5-no-such-config-dir")
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

fn run_hook_in_dir(event: &str, payload: &str, cwd: &std::path::Path) -> std::process::Output {
    let bin = assert_cmd::cargo::cargo_bin("redactor");
    let log_dir = tempdir().unwrap();
    let mut child = Command::new(&bin)
        .current_dir(cwd)
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .env("REDACTOR_CONFIG_DIR", "/tmp/hook-phase5-no-such-config-dir")
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
fn session_start_allows_and_emits_empty_object() {
    let out = run_hook("session-start", r#"{"hook_event_name":"SessionStart"}"#);
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.trim().starts_with('{'));
}

#[test]
fn post_write_blocks_on_invalid_json() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("broken.json");
    std::fs::write(&path, "{ not json").unwrap();
    let payload = format!(
        r#"{{"hook_event_name":"PostToolUse","tool_input":{{"file_path":"{}"}}}}"#,
        path.display().to_string().replace("\\", "/")
    );
    let out = run_hook("post-write", &payload);
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("decision"));
    assert!(s.contains("block"));
    assert!(s.contains("invalid JSON"));
}

#[test]
fn post_write_allows_valid_json() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("ok.json");
    std::fs::write(&path, r#"{"a":1,"b":[1,2]}"#).unwrap();
    let payload = format!(
        r#"{{"hook_event_name":"PostToolUse","tool_input":{{"file_path":"{}"}}}}"#,
        path.display().to_string().replace("\\", "/")
    );
    let out = run_hook("post-write", &payload);
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(!s.contains("decision"));
}

#[test]
fn post_write_skips_unsupported_extension() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("notes.txt");
    std::fs::write(&path, "anything goes").unwrap();
    let payload = format!(
        r#"{{"hook_event_name":"PostToolUse","tool_input":{{"file_path":"{}"}}}}"#,
        path.display().to_string().replace("\\", "/")
    );
    let out = run_hook("post-write", &payload);
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(!s.contains("decision"));
}

#[test]
fn network_guard_disabled_when_no_config() {
    let dir = tempdir().unwrap();
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"curl https://api.github.com/"}}"#;
    let out = run_hook_in_dir("pre-bash", payload, dir.path());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(
        !s.contains("network-guard"),
        "expected no network-guard message, got: {s}"
    );
}

#[test]
fn network_guard_blocks_unlisted_when_config_present() {
    let dir = tempdir().unwrap();
    let cfg = dir.path().join(".redactor-urls.json");
    std::fs::write(
        &cfg,
        r#"{"erlaubte_domains":["github.com"],"erlaubte_urls":[],"blockierte_domains":[],"fail_closed":true}"#,
    )
    .unwrap();
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"redactor wrap -- curl https://evil.example.com/"}}"#;
    let out = run_hook_in_dir("pre-bash", payload, dir.path());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("decision"));
    assert!(s.contains("block"));
    assert!(s.contains("network-guard"));
}

#[test]
fn network_guard_allows_listed_domain() {
    let dir = tempdir().unwrap();
    let cfg = dir.path().join(".redactor-urls.json");
    std::fs::write(
        &cfg,
        r#"{"erlaubte_domains":["github.com"],"erlaubte_urls":[],"blockierte_domains":[],"fail_closed":true}"#,
    )
    .unwrap();
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"redactor wrap -- git push git@github.com:u/r main"}}"#;
    let out = run_hook_in_dir("pre-bash", payload, dir.path());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(
        !s.contains("network-guard"),
        "github.com should be allowed, got: {s}"
    );
}

// ============================================================================
// rred-36 — fixed-deny hooks for tools without a safe canonical form
// (mcp__*, Grep, NotebookEdit). Each must always block with a helpful reason.
// ============================================================================

#[test]
fn deny_mcp_blocks_with_helpful_reason() {
    let payload = r#"{"hook_event_name":"PreToolUse","tool_name":"mcp__claude_ai_Gmail__search_threads","tool_input":{"query":"invoice"}}"#;
    let out = run_hook("deny-mcp", payload);
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("\"decision\":\"block\""), "must block, got: {s}");
    assert!(s.contains("MCP tools"), "reason must mention MCP, got: {s}");
    assert!(
        s.contains("Gmail") || s.contains("Drive"),
        "reason should name example servers, got: {s}"
    );
}

#[test]
fn deny_mcp_blocks_even_with_empty_payload() {
    // We must not depend on payload shape — block unconditionally.
    let out = run_hook("deny-mcp", "{}");
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("\"decision\":\"block\""), "must block, got: {s}");
}

#[test]
fn deny_grep_blocks_and_suggests_redactor_wrap() {
    let payload = r#"{"hook_event_name":"PreToolUse","tool_name":"Grep","tool_input":{"pattern":"sk-","path":"."}}"#;
    let out = run_hook("deny-grep", payload);
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("\"decision\":\"block\""), "must block, got: {s}");
    assert!(s.contains("Grep tool is disabled"), "got: {s}");
    assert!(
        s.contains("redactor wrap -- rg") && s.contains("redactor wrap -- grep -r"),
        "must suggest both rg and grep replacements, got: {s}"
    );
}

#[test]
fn deny_notebook_blocks() {
    let payload = r#"{"hook_event_name":"PreToolUse","tool_name":"NotebookEdit","tool_input":{"notebook_path":"x.ipynb"}}"#;
    let out = run_hook("deny-notebook", payload);
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("\"decision\":\"block\""), "must block, got: {s}");
    assert!(s.contains("NotebookEdit tool is disabled"), "got: {s}");
}

// ============================================================================
// rred-36 — PowerShell goes through the existing pre-bash hook (same
// strict-prefix + path-guard + struct-file rules). Verify that the hook
// behaves identically regardless of the tool_name in the payload.
// ============================================================================

#[test]
fn pre_bash_accepts_redactor_wrap_powershell() {
    let payload = r#"{"hook_event_name":"PreToolUse","tool_name":"PowerShell","tool_input":{"command":"redactor wrap -- pwsh -Command Get-Process"}}"#;
    let out = run_hook("pre-bash", payload);
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        s.trim(),
        "{}",
        "redactor wrap -- pwsh ... should be allowed, got: {s}"
    );
}

#[test]
fn pre_bash_blocks_bare_powershell_command() {
    let payload = r#"{"hook_event_name":"PreToolUse","tool_name":"PowerShell","tool_input":{"command":"pwsh -Command Get-Process"}}"#;
    let out = run_hook("pre-bash", payload);
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(
        s.contains("\"decision\":\"block\""),
        "bare pwsh must be blocked, got: {s}"
    );
    assert!(
        s.contains("must go through redactor"),
        "should suggest redactor wrap, got: {s}"
    );
}

#[test]
fn pre_bash_blocks_powershell_touching_sensitive_path() {
    let payload = r#"{"hook_event_name":"PreToolUse","tool_name":"PowerShell","tool_input":{"command":"redactor wrap -- pwsh -Command Get-Content .env"}}"#;
    let out = run_hook("pre-bash", payload);
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(
        s.contains("\"decision\":\"block\""),
        "path-guard must apply to PowerShell, got: {s}"
    );
    assert!(s.contains("path-guard"), "got: {s}");
}
