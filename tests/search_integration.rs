#[allow(unused_imports)]
use assert_cmd::Command;
#[allow(unused_imports)]
use std::fs;
#[allow(unused_imports)]
use std::path::PathBuf;
#[allow(unused_imports)]
use tempfile::TempDir;

fn redactor_bin() -> Command {
    Command::cargo_bin("redactor").expect("redactor binary built")
}

#[test]
fn search_errors_on_missing_query() {
    redactor_bin().args(["search"]).assert().failure();
}

#[test]
fn search_help_lists_required_flags() {
    let output = redactor_bin()
        .args(["search", "--help"])
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // --all and -a are hidden but still present in the parser
    assert!(stdout.contains("--limit"));
    assert!(stdout.contains("--format"));
    assert!(stdout.contains("--no-wiki"));
    assert!(stdout.contains("--code-only"));
    assert!(stdout.contains("--tasks-only"));
    assert!(stdout.contains("--knowledge-only"));
    assert!(stdout.contains("--wiki-only"));
}

// Adapted: was checking flat hits[], now checks sections.wiki.hits[] via REDACTOR_SEARCH_GLOBAL_ROOTS
#[test]
fn search_global_with_fixture_root_via_env() {
    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/search");
    let log_dir = TempDir::new().unwrap();

    // Use --wiki-only so only one section appears; fixture dir acts as wiki via env var
    let output = redactor_bin()
        .env(
            "REDACTOR_SEARCH_GLOBAL_ROOTS",
            fixture_dir.to_str().unwrap(),
        )
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .args(["search", "rust", "--wiki-only", "--format", "json"])
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"query\": \"rust\""),
        "expected query field, got: {stdout}"
    );
    assert!(
        stdout.contains("\"wiki\""),
        "expected wiki section in JSON, got: {stdout}"
    );
    assert!(
        stdout.contains("Custom Title From Frontmatter"),
        "expected fixture hit, got: {stdout}"
    );
}

// Adapted: --code is still valid alias for --code-only; checks sections.code.hits[]
#[test]
fn search_code_finds_terms_in_source() {
    let log_dir = TempDir::new().unwrap();
    let output = redactor_bin()
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .args([
            "search",
            "redact_pattern",
            "--code",
            "--limit",
            "5",
            "--format",
            "json",
        ])
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("redactor.rs") || stdout.contains("redactor"),
        "expected redactor.rs in code section, got: {stdout}"
    );
}

// Adapted: checks sections.tasks.hits[] for task:// paths.
// Ignored by default — requires the TaskMD `task` CLI in PATH (not available on
// stock CI runners). Run locally with: cargo test -- --ignored
#[test]
#[ignore]
fn search_includes_tasks_in_default_corpus() {
    let log_dir = TempDir::new().unwrap();
    let output = redactor_bin()
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .args([
            "search",
            "search_decay",
            "--tasks-only",
            "--format",
            "json",
            "--limit",
            "20",
        ])
        .output()
        .expect("redactor search runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Expect tasks section with task:// hits
    assert!(
        stdout.contains("\"path\": \"task://"),
        "expected at least one task:// hit in tasks section, stdout was:\n{stdout}"
    );
}

// NEW: default run emits all four section keys
#[test]
fn search_default_emits_four_sections() {
    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/search");
    let log_dir = TempDir::new().unwrap();
    let output = redactor_bin()
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        // Use fixture dir as wiki so all four sections have something to query
        .env(
            "REDACTOR_SEARCH_GLOBAL_ROOTS",
            fixture_dir.to_str().unwrap(),
        )
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .args(["search", "redactor", "--format", "json", "--limit", "5"])
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"knowledge\""),
        "expected knowledge section: {stdout}"
    );
    assert!(
        stdout.contains("\"tasks\""),
        "expected tasks section: {stdout}"
    );
    assert!(
        stdout.contains("\"code\""),
        "expected code section: {stdout}"
    );
    assert!(
        stdout.contains("\"wiki\""),
        "expected wiki section: {stdout}"
    );
}

// NEW: --no-wiki omits wiki section key
#[test]
fn search_no_wiki_omits_wiki_section() {
    let log_dir = TempDir::new().unwrap();
    let output = redactor_bin()
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .args([
            "search",
            "redactor",
            "--no-wiki",
            "--format",
            "json",
            "--limit",
            "5",
        ])
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("\"wiki\""),
        "expected no wiki key with --no-wiki, got: {stdout}"
    );
    assert!(
        stdout.contains("\"knowledge\"")
            || stdout.contains("\"tasks\"")
            || stdout.contains("\"code\""),
        "expected at least one project section: {stdout}"
    );
}

// NEW: --code-only returns only the code section
#[test]
fn search_modal_only_returns_single_section() {
    let log_dir = TempDir::new().unwrap();
    let output = redactor_bin()
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .args([
            "search",
            "redactor",
            "--code-only",
            "--format",
            "json",
            "--limit",
            "5",
        ])
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"code\""),
        "expected code section with --code-only: {stdout}"
    );
    assert!(
        !stdout.contains("\"wiki\""),
        "unexpected wiki section with --code-only: {stdout}"
    );
    assert!(
        !stdout.contains("\"knowledge\""),
        "unexpected knowledge section with --code-only: {stdout}"
    );
    assert!(
        !stdout.contains("\"tasks\""),
        "unexpected tasks section with --code-only: {stdout}"
    );
}

// NEW: running outside any project sets outside_project: true on project sections
#[test]
fn search_outside_project_shows_marker() {
    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/search");
    let log_dir = TempDir::new().unwrap();
    // tempdir is OS-agnostic and outside the repo, so detect_project_root's
    // .git-walk finds nothing → outside_project must be true.
    let cwd_dir = TempDir::new().unwrap();
    let output = redactor_bin()
        .current_dir(cwd_dir.path())
        .env(
            "REDACTOR_SEARCH_GLOBAL_ROOTS",
            fixture_dir.to_str().unwrap(),
        )
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .args([
            "search",
            "rust",
            "--no-wiki",
            "--format",
            "json",
            "--limit",
            "5",
        ])
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"outside_project\": true"),
        "expected outside_project: true for /tmp cwd, got: {stdout}"
    );
}

// NEW: -a emits deprecation warning on stderr but still succeeds
#[test]
fn search_minus_a_warns_and_continues() {
    let fixture_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/search");
    let log_dir = TempDir::new().unwrap();
    let output = redactor_bin()
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env(
            "REDACTOR_SEARCH_GLOBAL_ROOTS",
            fixture_dir.to_str().unwrap(),
        )
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .args(["search", "rust", "-a", "--format", "json", "--limit", "3"])
        .output()
        .expect("run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "expected success with -a, got exit code: {}",
        output.status
    );
    assert!(
        stderr.contains("no-op since v0.6.0"),
        "expected deprecation warning on stderr, got: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should still produce sectioned output
    assert!(
        stdout.contains("\"sections\""),
        "expected sections in output with -a: {stdout}"
    );
}
