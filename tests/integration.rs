//! End-to-end CLI tests covering all four modes + every realistic Bash invocation
//! pattern documented in the README. Each test runs the actual `redactor` binary.
//!
//! Logging is written to a per-test tempdir so tests don't pollute the repo.

use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::tempdir;

fn redactor() -> Command {
    let mut cmd = Command::cargo_bin("redactor").unwrap();
    cmd.env(
        "REDACTOR_LOG_DIR",
        "/tmp/redactor-test-logs-must-be-overridden",
    );
    cmd
}

fn pipe_input(cmd: &mut Command, input: &str) -> std::process::Output {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

// ---------- 1. CSV via file ----------

#[test]
fn csv_via_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("data.csv");
    std::fs::write(&path, "id,email\n1,a@x.de\n2,b@x.de\n3,c@x.de\n").unwrap();
    let log_dir = tempdir().unwrap();
    let assert = redactor()
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .arg(&path)
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(out.contains("id,email"));
    assert!(out.contains("<redacted>,<redacted>"));
    assert!(out.contains("# ... 2 more rows redacted"));
    // logging happened
    let entries: Vec<_> = std::fs::read_dir(log_dir.path()).unwrap().collect();
    assert_eq!(entries.len(), 1, "exactly one log file written");
}

// ---------- 2. JSON via stdin ----------

#[test]
fn json_via_stdin() {
    let log_dir = tempdir().unwrap();
    let mut cmd = redactor();
    cmd.env("REDACTOR_LOG_DIR", log_dir.path())
        .arg("-")
        .arg("--type")
        .arg("json");
    let out = pipe_input(&mut cmd, r#"{"k":"sek","arr":[1,2,3]}"#);
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("<redacted>"));
    assert!(s.contains("more items redacted"));
}

// ---------- 3. ENV via .env auto-detect ----------

#[test]
fn env_via_dotfile() {
    let dir = tempdir().unwrap();
    let path = dir.path().join(".env");
    std::fs::write(&path, "OPENAI_API_KEY=sk-real\n# c\nexport FOO=bar\n").unwrap();
    let log_dir = tempdir().unwrap();
    let assert = redactor()
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .arg(&path)
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(out.contains("OPENAI_API_KEY=<redacted>"));
    assert!(out.contains("export FOO=<redacted>"));
    assert!(out.contains("# c"));
}

// ---------- 4. Pattern via plain pipe (THE main use case) ----------

#[test]
fn pattern_pipe_simple() {
    let log_dir = tempdir().unwrap();
    let mut cmd = redactor();
    cmd.env("REDACTOR_LOG_DIR", log_dir.path());
    let out = pipe_input(&mut cmd, "key=sk-proj-abcdefghij1234567890XYZ end");
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("<redacted:openai_key>"));
    assert!(!s.contains("sk-proj-abc"));
}

// ---------- 5. Pattern with custom keyword ----------

#[test]
fn pattern_with_keywords() {
    let log_dir = tempdir().unwrap();
    let mut cmd = redactor();
    cmd.env("REDACTOR_LOG_DIR", log_dir.path())
        .arg("-")
        .arg("--keywords")
        .arg("PROJECT-NIGHTHAWK,internal-host");
    let out = pipe_input(&mut cmd, "shipped PROJECT-NIGHTHAWK to internal-host now");
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("<redacted:keyword>"));
    assert!(!s.contains("PROJECT-NIGHTHAWK"));
    assert!(!s.contains("internal-host"));
}

// ---------- 6. Pattern with --patterns FILE ----------

#[test]
fn pattern_with_custom_rules_file() {
    let dir = tempdir().unwrap();
    let rules = dir.path().join("rules.json");
    std::fs::write(
        &rules,
        r#"[{"name":"email","re":"[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}"}]"#,
    )
    .unwrap();
    let log_dir = tempdir().unwrap();
    let mut cmd = redactor();
    cmd.env("REDACTOR_LOG_DIR", log_dir.path())
        .arg("-")
        .arg("--patterns")
        .arg(&rules);
    // Use a non-whitelisted domain — `example.com` is exempted by the
    // built-in email FP-filter, which would mask this test's intent.
    let out = pipe_input(&mut cmd, "user alice@acme-corp.io signed in");
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("<redacted:email>"));
}

// ---------- 7. Logging produces TSV with rule + count + sample + command ----------

#[test]
fn logging_writes_what_when_where() {
    let log_dir = tempdir().unwrap();
    let mut cmd = redactor();
    cmd.env("REDACTOR_LOG_DIR", log_dir.path());
    let out = pipe_input(&mut cmd, "AKIAIOSFODNN7EXAMPLE and AKIAEXAMPLE2EXAMPLE2");
    assert!(out.status.success());

    let entries: Vec<_> = std::fs::read_dir(log_dir.path()).unwrap().collect();
    assert_eq!(entries.len(), 1);
    let log_path = entries[0].as_ref().unwrap().path();
    let content = std::fs::read_to_string(&log_path).unwrap();
    assert!(content.contains(r#""source":"stdin""#));
    assert!(content.contains(r#""mode":"pattern""#));
    assert!(content.contains(r#""rule":"aws_access_key""#));
    assert!(content.contains(r#""count":2"#));
    // command field defaults to "-" when no --source-label given
    assert!(content.contains(r#""command":"-""#));
    // file name is YYYY-MM-DD-redacted.jsonl
    let name = log_path.file_name().unwrap().to_string_lossy().to_string();
    assert!(name.ends_with("-redacted.jsonl"));
}

// ---------- 7b. --source-label is logged as command=... ----------

#[test]
fn source_label_appears_in_log() {
    let log_dir = tempdir().unwrap();
    let mut cmd = redactor();
    cmd.env("REDACTOR_LOG_DIR", log_dir.path())
        .env("REDACTOR_CONFIG_DIR", "/tmp/no-such-redactor-cfg")
        .arg("-")
        .arg("--source-label")
        .arg("Read test.csv");
    let out = pipe_input(&mut cmd, "AKIAIOSFODNN7EXAMPLE");
    assert!(out.status.success());
    let entries: Vec<_> = std::fs::read_dir(log_dir.path()).unwrap().collect();
    let content = std::fs::read_to_string(entries[0].as_ref().unwrap().path()).unwrap();
    assert!(content.contains(r#""command":"Read test.csv""#));
}

// ---------- 8. --no-log disables logging ----------

#[test]
fn no_log_writes_nothing() {
    let log_dir = tempdir().unwrap();
    let mut cmd = redactor();
    cmd.env("REDACTOR_LOG_DIR", log_dir.path()).arg("--no-log");
    let _ = pipe_input(&mut cmd, "AKIAIOSFODNN7EXAMPLE");
    let entries: Vec<_> = std::fs::read_dir(log_dir.path()).unwrap().collect();
    assert_eq!(entries.len(), 0);
}

// ---------- 9. Realistic bash patterns: combined stdout+stderr ----------

#[test]
fn realistic_bash_combined_output() {
    // simulates: ( ./run.sh ) 2>&1 | redactor
    // (we just feed mixed text on stdin with secrets across lines)
    let mixed = "INFO starting\n\
        ERROR creds: AKIAIOSFODNN7EXAMPLE\n\
        DEBUG curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sigfake'\n\
        INFO done\n";
    let log_dir = tempdir().unwrap();
    let mut cmd = redactor();
    cmd.env("REDACTOR_LOG_DIR", log_dir.path());
    let out = pipe_input(&mut cmd, mixed);
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("<redacted:aws_access_key>"));
    // The JWT is inside an `Authorization: Bearer …` header, so the broader
    // `auth_header` rule covers the whole header value (including the JWT)
    // before the `jwt` rule can mark it specifically. Either label proves the
    // secret is gone — accept whichever fired.
    assert!(
        s.contains("<redacted:auth_header>") || s.contains("<redacted:jwt>"),
        "neither auth_header nor jwt label present: {s}"
    );
    assert!(!s.contains("eyJhbGciOiJIUzI1NiJ9"));
    assert!(s.contains("INFO starting"));
    assert!(s.contains("INFO done"));
}

// ---------- 10. Empty input is OK ----------

#[test]
fn empty_input_succeeds() {
    let log_dir = tempdir().unwrap();
    let mut cmd = redactor();
    cmd.env("REDACTOR_LOG_DIR", log_dir.path());
    let out = pipe_input(&mut cmd, "");
    assert!(out.status.success());
}

// ---------- 11. Auto mode for log file extension routes to pattern ----------

#[test]
fn auto_routes_log_to_pattern() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("app.log");
    std::fs::write(&path, "key=ghp_abcdefghij1234567890ABCDEFGHabcdefgh\n").unwrap();
    let log_dir = tempdir().unwrap();
    let assert = redactor()
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .arg(&path)
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(out.contains("<redacted:github_token>"));
}

// ---------- 12. Help text mentions all modes ----------

#[test]
fn help_lists_modes() {
    redactor()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("csv"))
        .stdout(predicate::str::contains("json"))
        .stdout(predicate::str::contains("env"))
        .stdout(predicate::str::contains("pattern"))
        .stdout(predicate::str::contains("auto"));
}

// ---------- 13. wrap: simple subprocess, secret on stdout ----------

#[test]
fn wrap_redacts_stdout() {
    let log_dir = tempdir().unwrap();
    let assert = redactor()
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .arg("wrap")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("echo key=sk-proj-FAKE12345678901234567890")
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(out.contains("<redacted:openai_key>"));
    assert!(!out.contains("sk-proj-FAKE"));
}

// ---------- 14. wrap: secrets on stderr too ----------

#[test]
fn wrap_redacts_stderr() {
    let log_dir = tempdir().unwrap();
    let assert = redactor()
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .arg("wrap")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("echo OK; echo ERR=AKIAIOSFODNN7EXAMPLE >&2")
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let err = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(out.contains("OK"));
    assert!(err.contains("<redacted:aws_access_key>"));
    assert!(!err.contains("AKIAIOSFODNN7EXAMPLE"));
}

// ---------- 15. wrap: forwards exit code ----------

#[test]
fn wrap_forwards_exit_code() {
    let log_dir = tempdir().unwrap();
    let out = redactor()
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .arg("wrap")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("echo done; exit 7")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(7));
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("done"));
}

// ---------- 16. wrap: nonexistent command fails cleanly ----------

#[test]
fn wrap_missing_command_fails() {
    let log_dir = tempdir().unwrap();
    let out = redactor()
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .arg("wrap")
        .arg("--")
        .arg("/nonexistent-binary-xyz")
        .output()
        .unwrap();
    assert!(!out.status.success());
}

// ---------- 17a. --keywords-file (txt format) ----------

#[test]
fn keywords_file_txt() {
    let dir = tempdir().unwrap();
    let kw = dir.path().join("words.txt");
    std::fs::write(&kw, "# header\nalice\nbob\n\n# tail\n").unwrap();
    let log_dir = tempdir().unwrap();
    let mut cmd = redactor();
    cmd.env("REDACTOR_LOG_DIR", log_dir.path())
        .env("REDACTOR_CONFIG_DIR", "/tmp/nonexistent-config-dir")
        .arg("-")
        .arg("--keywords-file")
        .arg(&kw);
    let out = pipe_input(&mut cmd, "found Alice and BOB in here");
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("<redacted:keyword>"));
    assert!(!s.contains("Alice"));
    assert!(!s.contains("BOB"));
}

// ---------- 17b. --keywords-file (json array) ----------

#[test]
fn keywords_file_json_array() {
    let dir = tempdir().unwrap();
    let kw = dir.path().join("words.json");
    std::fs::write(&kw, r#"["alpha","beta-gamma"]"#).unwrap();
    let log_dir = tempdir().unwrap();
    let mut cmd = redactor();
    cmd.env("REDACTOR_LOG_DIR", log_dir.path())
        .env("REDACTOR_CONFIG_DIR", "/tmp/nonexistent-config-dir")
        .arg("-")
        .arg("--keywords-file")
        .arg(&kw);
    let out = pipe_input(&mut cmd, "alpha plus beta-gamma equals gold");
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(!s.contains("alpha"));
    assert!(!s.contains("beta-gamma"));
}

// ---------- 17c. autoload from $REDACTOR_CONFIG_DIR/keywords.txt ----------

#[test]
fn autoload_keywords_from_config_dir() {
    let cfg = tempdir().unwrap();
    std::fs::write(cfg.path().join("keywords.txt"), "alice\nbob\n").unwrap();
    let log_dir = tempdir().unwrap();
    let mut cmd = redactor();
    cmd.env("REDACTOR_LOG_DIR", log_dir.path())
        .env("REDACTOR_CONFIG_DIR", cfg.path())
        // Isolate from a real `~/.redactorignore`, which otherwise takes
        // precedence over the legacy keywords.txt and shadows this fixture.
        .env(
            "REDACTOR_IGNOREFILE_PATH",
            cfg.path().join("nonexistent.redactorignore"),
        );
    let out = pipe_input(&mut cmd, "alice met bob today");
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(!s.contains("alice"));
    assert!(!s.contains("bob"));
}

// ---------- 17d. --no-config bypasses autoload ----------

#[test]
fn no_config_skips_autoload() {
    let cfg = tempdir().unwrap();
    std::fs::write(cfg.path().join("keywords.txt"), "alice\n").unwrap();
    let log_dir = tempdir().unwrap();
    let mut cmd = redactor();
    cmd.env("REDACTOR_LOG_DIR", log_dir.path())
        .env("REDACTOR_CONFIG_DIR", cfg.path())
        .arg("-")
        .arg("--no-config");
    let out = pipe_input(&mut cmd, "alice was here");
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("alice")); // not redacted because --no-config
}

// ---------- 17e. init-config writes starter files ----------

#[test]
fn init_config_writes_files() {
    let cfg = tempdir().unwrap();
    redactor()
        .env("REDACTOR_CONFIG_DIR", cfg.path())
        .arg("init-config")
        .assert()
        .success();
    assert!(cfg.path().join("keywords.txt").exists());
    assert!(cfg.path().join("patterns.json").exists());
}

// ---------- 17f. config-path prints resolved location ----------

#[test]
fn config_path_prints_dir() {
    let cfg = tempdir().unwrap();
    let assert = redactor()
        .env("REDACTOR_CONFIG_DIR", cfg.path())
        .arg("config-path")
        .assert()
        .success();
    let s = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(s.contains("config_dir="));
    assert!(s.contains("keywords_file="));
}

// ---------- 18. wrap: writes log entries with mode=wrap ----------

#[test]
fn wrap_logs_with_correct_mode_and_source() {
    let log_dir = tempdir().unwrap();
    let _ = redactor()
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .arg("wrap")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("echo k=sk-proj-FAKE12345678901234567890")
        .output()
        .unwrap();
    let entries: Vec<_> = std::fs::read_dir(log_dir.path()).unwrap().collect();
    assert_eq!(entries.len(), 1);
    let content = std::fs::read_to_string(entries[0].as_ref().unwrap().path()).unwrap();
    assert!(content.contains(r#""mode":"wrap""#));
    assert!(content.contains(r#""source":"wrap:sh""#));
    assert!(content.contains(r#""rule":"openai_key""#));
    // wrap auto-fills command with the joined argv
    assert!(content.contains(r#""command":"sh -c echo k="#));
}

// ---------- 19. wrap: explicit --source-label overrides argv-derived command ----------

#[test]
fn wrap_source_label_overrides_argv() {
    let log_dir = tempdir().unwrap();
    let _ = redactor()
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .arg("wrap")
        .arg("--source-label")
        .arg("Bash:deploy")
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg("echo k=AKIAIOSFODNN7EXAMPLE")
        .output()
        .unwrap();
    let entries: Vec<_> = std::fs::read_dir(log_dir.path()).unwrap().collect();
    let content = std::fs::read_to_string(entries[0].as_ref().unwrap().path()).unwrap();
    assert!(content.contains(r#""command":"Bash:deploy""#));
    // and NOT the auto argv label
    assert!(!content.contains(r#""command":"sh -c"#));
}
