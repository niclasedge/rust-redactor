//! Integration tests for `redactor scan` (rred-13).

use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::tempdir;

fn run_scan(input: &str) -> std::process::Output {
    let bin = assert_cmd::cargo::cargo_bin("redactor");
    let log_dir = tempdir().unwrap();
    let mut child = Command::new(&bin)
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .env("REDACTOR_CONFIG_DIR", "/tmp/scan-test-no-such-config-dir")
        .arg("scan")
        .arg("-")
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

#[test]
fn scan_emits_jsonl_for_secret() {
    let out = run_scan("KEY=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n");
    assert!(out.status.success(), "scan should always exit 0");
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(!s.is_empty(), "expected at least one finding line");
    let line = s.lines().next().unwrap();
    let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON line");
    assert_eq!(v["rule"], "github_token");
    assert_eq!(v["mode"], "pattern");
    assert!(v["line"].as_u64().is_some());
    assert!(v["col"].as_u64().is_some());
}

#[test]
fn scan_clean_input_no_output() {
    let out = run_scan("nothing sensitive here\n");
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(
        s.is_empty(),
        "clean input should produce no findings, got: {s}"
    );
}

#[test]
fn scan_emits_one_line_per_match() {
    let out = run_scan(
        "k1=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa k2=ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
    );
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    let count = s.lines().filter(|l| l.contains("github_token")).count();
    assert_eq!(count, 2, "expected 2 github_token findings, got: {s}");
}

#[test]
fn scan_does_not_print_sanitized_text() {
    let out = run_scan("key=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n");
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(
        !s.contains("<redacted:"),
        "scan must not emit redacted tokens"
    );
}
