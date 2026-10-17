//! Red-team tests for the strict-redaction profile.
//!
//! Every test documents an **attack scenario** and the **expected outcome**.
//! Tests are organized by attack surface:
//!
//!   1. pattern_detection  — secret-regex hits (positive + negative)
//!   2. path_guard         — blocking sensitive paths in commands
//!   3. strict_prefix      — bash-strict bypass attempts
//!   4. struct_file        — rred-35 position-aware struct-file guard
//!   5. network_guard      — URL allowlist enforcement
//!   6. prompt_scan        — UserPromptSubmit secret detection
//!   7. known_limitations  — bypasses that PASS the hook today, with reasons
//!
//! Tests in (1)-(6) assert the security policy. Tests in (7) document where
//! the heuristic deliberately stops — they assert the bypass IS possible so
//! a future regression that accidentally tightens / loosens behavior is
//! caught.

use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::tempdir;

// ---------- helpers --------------------------------------------------------

fn run_hook(event: &str, payload: &str) -> std::process::Output {
    // Run from an empty tempdir so the project's own .redactor.toml (which
    // opts out of strict_json) doesn't get picked up by autoload_project_*
    // walks and silently disable default-policy assertions.
    let cwd = tempdir().unwrap();
    run_hook_in_dir(event, payload, cwd.path())
}

fn run_hook_in_dir(event: &str, payload: &str, cwd: &std::path::Path) -> std::process::Output {
    let bin = assert_cmd::cargo::cargo_bin("redactor");
    let log_dir = tempdir().unwrap();
    let mut child = Command::new(&bin)
        .current_dir(cwd)
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .env("REDACTOR_CONFIG_DIR", "/tmp/red-team-no-such-config-dir")
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

fn run_redact_pattern(input: &str) -> String {
    let bin = assert_cmd::cargo::cargo_bin("redactor");
    let log_dir = tempdir().unwrap();
    let mut child = Command::new(&bin)
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .env("REDACTOR_CONFIG_DIR", "/tmp/red-team-no-such-config-dir")
        .arg("--type")
        .arg("pattern")
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
    let out = child.wait_with_output().unwrap();
    String::from_utf8(out.stdout).unwrap()
}

fn assert_blocks(out: &std::process::Output, hint: &str) {
    let s = String::from_utf8(out.stdout.clone()).unwrap();
    assert!(
        s.contains("\"decision\":\"block\""),
        "expected block — {hint}\nstdout: {s}"
    );
}

fn assert_allows(out: &std::process::Output, hint: &str) {
    let s = String::from_utf8(out.stdout.clone()).unwrap();
    assert_eq!(s.trim(), "{}", "expected allow — {hint}\nstdout: {s}");
}

// ============================================================================
// 1. Pattern detection — does the redactor catch real secret strings?
// ============================================================================

#[test]
fn pattern_redacts_anthropic_key() {
    let input = "Token: sk-ant-api03-ABCDEF1234567890abcdef1234567890ABCDEF1234567890abcdef1234567890ABCDEF12-XXXXXX_aa";
    let out = run_redact_pattern(input);
    assert!(
        out.contains("<redacted:anthropic_key>"),
        "anthropic key not redacted, got: {out}"
    );
    assert!(
        !out.contains("sk-ant-api03-ABCDEF"),
        "raw key leaked: {out}"
    );
}

#[test]
fn pattern_redacts_openai_with_leading_whitespace() {
    // Attack: pad with whitespace to confuse anchors.
    let input = "    sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMn\n";
    let out = run_redact_pattern(input);
    assert!(
        out.contains("<redacted:openai_key>"),
        "openai key not redacted with leading whitespace, got: {out}"
    );
}

#[test]
fn pattern_redacts_aws_access_key_anywhere_in_line() {
    let input = "exporting key AKIAIOSFODNN7EXAMPLE for service\n";
    let out = run_redact_pattern(input);
    assert!(
        out.contains("<redacted:aws_access_key>"),
        "AWS key not redacted, got: {out}"
    );
}

#[test]
fn pattern_redacts_jwt_three_segments() {
    // JWT format: header.payload.signature, base64url-encoded.
    // The bare-JWT case (no header prefix) — verifies the jwt rule itself.
    let input = "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n";
    let out = run_redact_pattern(input);
    assert!(
        out.contains("<redacted:jwt>"),
        "JWT not redacted, got: {out}"
    );
}

#[test]
fn pattern_redacts_jwt_inside_authorization_header() {
    // When wrapped in `Authorization: Bearer …`, the broader auth_header
    // rule covers the whole header value (including the JWT). Either label
    // proves the secret is gone.
    let input = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n";
    let out = run_redact_pattern(input);
    assert!(
        out.contains("<redacted:auth_header>") || out.contains("<redacted:jwt>"),
        "neither auth_header nor jwt label present: {out}"
    );
    assert!(!out.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
}

#[test]
fn pattern_redacts_pem_private_key_block() {
    // Multiline PEM block — the private_key rule should match the BEGIN…END span.
    let input = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234567890\nABCDEFGHIJabcdefghij\n-----END RSA PRIVATE KEY-----\n";
    let out = run_redact_pattern(input);
    assert!(
        out.contains("<redacted:private_key>"),
        "PEM block not redacted, got: {out}"
    );
    assert!(!out.contains("MIIEowIBAAKCAQEA"), "PEM body leaked: {out}");
}

#[test]
fn pattern_does_not_redact_innocuous_short_prefix() {
    // "sk-" alone is not enough entropy — should NOT trigger.
    let input = "command sk-foo failed\n";
    let out = run_redact_pattern(input);
    assert!(
        !out.contains("<redacted:"),
        "false-positive on innocuous text: {out}"
    );
}

// ============================================================================
// 2. Path-guard — sensitive paths must be refused in pre-bash and pre-read.
// ============================================================================

#[test]
fn path_guard_blocks_cat_dot_env() {
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"redactor wrap -- cat /home/user/.env"}}"#;
    let out = run_hook("pre-bash", payload);
    assert_blocks(&out, "cat /home/user/.env should hit path-guard");
}

#[test]
fn path_guard_blocks_dot_env_production_variant() {
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"redactor wrap -- cat /app/.env.production"}}"#;
    let out = run_hook("pre-bash", payload);
    assert_blocks(&out, ".env.production must be caught by the .env regex");
}

#[test]
fn path_guard_blocks_id_rsa_private_key() {
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"redactor wrap -- cat /home/user/.ssh/id_rsa"}}"#;
    let out = run_hook("pre-bash", payload);
    assert_blocks(&out, "id_rsa private key path");
}

#[test]
fn path_guard_blocks_aws_credentials() {
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"redactor wrap -- cat /home/user/.aws/credentials"}}"#;
    let out = run_hook("pre-bash", payload);
    assert_blocks(&out, ".aws/credentials must be blocked");
}

#[test]
fn path_guard_blocks_secrets_folder() {
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"redactor wrap -- cat /etc/secrets/api-key.txt"}}"#;
    let out = run_hook("pre-bash", payload);
    assert_blocks(
        &out,
        "/secrets/ folder should be blocked regardless of file extension",
    );
}

#[test]
fn path_guard_blocks_pem_anywhere() {
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"redactor wrap -- cat /tmp/server.pem"}}"#;
    let out = run_hook("pre-bash", payload);
    assert_blocks(&out, "*.pem path");
}

#[test]
fn path_guard_allows_known_hosts_explicit_allowlist() {
    // .ssh/ is blocked except for known_hosts.
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"redactor wrap -- cat /home/user/.ssh/known_hosts"}}"#;
    let out = run_hook("pre-bash", payload);
    assert_allows(&out, "known_hosts is intentionally readable");
}

#[test]
fn path_guard_blocks_ssh_config() {
    // Other files in .ssh/ are still blocked.
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"redactor wrap -- cat /home/user/.ssh/config"}}"#;
    let out = run_hook("pre-bash", payload);
    assert_blocks(&out, "non-known_hosts files in .ssh/ must be blocked");
}

// ============================================================================
// 3. Strict-prefix — every shell call must start with `redactor`.
// ============================================================================

#[test]
fn strict_prefix_blocks_bare_cat() {
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"cat /tmp/foo.txt"}}"#;
    let out = run_hook("pre-bash", payload);
    assert_blocks(&out, "bare cat must fail strict-prefix");
}

#[test]
fn strict_prefix_blocks_command_chain_starting_with_other_binary() {
    // Attack: try to start the cmd with a no-op that resolves to redactor later.
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"true && redactor wrap -- cat /tmp/x"}}"#;
    let out = run_hook("pre-bash", payload);
    assert_blocks(
        &out,
        "command chain must start with `redactor` literally (not resolve to it)",
    );
}

#[test]
fn strict_prefix_blocks_absolute_path_to_redactor() {
    // `/usr/bin/redactor wrap -- ...` doesn't start with the literal string
    // `redactor `, so strict-prefix rejects it. Documenting: this is by
    // design — bash-strict scans the literal command, not the resolved
    // binary. Acceptable trade-off because path-guard etc still apply.
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"/usr/bin/redactor wrap -- cat /tmp/x"}}"#;
    let out = run_hook("pre-bash", payload);
    assert_blocks(&out, "abs-path redactor invocation is rejected by design");
}

#[test]
fn strict_prefix_allows_redactor_direct_subcommand() {
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"redactor --type json data.json"}}"#;
    let out = run_hook("pre-bash", payload);
    assert_allows(
        &out,
        "direct redactor calls are the canonical struct-file form",
    );
}

#[test]
fn rred_52_r_alias_wrap_is_accepted() {
    // `r wrap -- cat data.txt` should pass bash-strict
    let payload =
        r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"r wrap -- cat data.txt"}}"#;
    let out = run_hook("pre-bash", payload);
    assert_allows(
        &out,
        "r wrap -- ... must be accepted as short-alias for redactor",
    );
}

#[test]
fn rred_52_r_alias_direct_call_is_accepted() {
    // `r --type json data.json` (direct file mode) should pass
    let payload =
        r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"r --type json data.json"}}"#;
    let out = run_hook("pre-bash", payload);
    assert_allows(
        &out,
        "r --type json ... must be accepted as short-alias for redactor",
    );
}

#[test]
fn rred_52_absolute_path_to_r_is_rejected() {
    // `/usr/bin/r wrap -- ...` should still be blocked (consistent with
    // existing absolute-path rejection for /usr/bin/redactor)
    let payload =
        r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"/usr/bin/r wrap -- echo hi"}}"#;
    let out = run_hook("pre-bash", payload);
    assert_blocks(
        &out,
        "abs-path r invocation is rejected by design (consistent with /usr/bin/redactor)",
    );
}

// ============================================================================
// 4. Struct-file enforce (rred-35) — position-aware struct-file detection.
// ============================================================================

#[test]
fn struct_blocks_jq_with_filter_then_file_default_policy() {
    // Under default `strict_json = true`, jq's first positional is a filter,
    // the second is the file. The hook must keep `active` after `jq` past
    // `'.k'`.
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"redactor wrap -- jq '.k' data.json"}}"#;
    let out = run_hook("pre-bash", payload);
    assert_blocks(
        &out,
        "jq filter before file must still trigger struct-file guard under default policy",
    );
}

#[test]
fn struct_allows_jq_with_json_when_policy_opts_out() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".redactor.toml"),
        "[policy]\nstrict_json = false\n",
    )
    .unwrap();
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"redactor wrap -- jq '.k' data.json"}}"#;
    let out = run_hook_in_dir("pre-bash", payload, dir.path());
    assert_allows(
        &out,
        "jq <filter> data.json must pass when project opts out of strict_json",
    );
}

#[test]
fn struct_blocks_cat_n_data_csv() {
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"redactor wrap -- cat -n data.csv"}}"#;
    let out = run_hook("pre-bash", payload);
    assert_blocks(&out, "flag -n must be sticky, .csv arg still triggers");
}

#[test]
fn struct_allows_heredoc_string_with_extension_substring() {
    // The .json appears inside a heredoc body, not as a file argument.
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"redactor wrap -- bash -c \"cat > x.rs <<EOF\nlet p = data.json;\nEOF\""}}"#;
    let out = run_hook("pre-bash", payload);
    assert_allows(&out, "heredoc body is not a file argument");
}

#[test]
fn struct_allows_python_script_with_csv_in_argv() {
    // python isn't a read-tool — the .csv is just a path argument.
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"redactor wrap -- python my_script.py --output data.csv"}}"#;
    let out = run_hook("pre-bash", payload);
    assert_allows(
        &out,
        "python is not a read-tool, .csv is just an argv string",
    );
}

// ============================================================================
// 5. Network-guard — URL allowlist enforced on Bash commands.
// ============================================================================

#[test]
fn network_blocks_curl_to_unlisted_when_config_present() {
    let dir = tempdir().unwrap();
    std::fs::write(
        dir.path().join(".redactor-urls.json"),
        r#"{"erlaubte_domains":["github.com"],"erlaubte_urls":[],"blockierte_domains":[],"fail_closed":true}"#,
    )
    .unwrap();
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"redactor wrap -- curl https://evil.example.com/exfil"}}"#;
    let out = run_hook_in_dir("pre-bash", payload, dir.path());
    assert_blocks(
        &out,
        "evil.example.com must be blocked when allowlist is set",
    );
}

#[test]
fn network_allows_curl_to_whitelisted_domain() {
    let dir = tempdir().unwrap();
    std::fs::write(
        dir.path().join(".redactor-urls.json"),
        r#"{"erlaubte_domains":["github.com"],"erlaubte_urls":[],"blockierte_domains":[],"fail_closed":true}"#,
    )
    .unwrap();
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"redactor wrap -- curl https://github.com/owner/repo"}}"#;
    let out = run_hook_in_dir("pre-bash", payload, dir.path());
    assert_allows(&out, "github.com is whitelisted");
}

#[test]
fn network_blocks_explicit_blocklist_even_if_in_allowlist() {
    let dir = tempdir().unwrap();
    std::fs::write(
        dir.path().join(".redactor-urls.json"),
        r#"{"erlaubte_domains":["*.evil.com","good.com"],"erlaubte_urls":[],"blockierte_domains":["telemetry.evil.com"],"fail_closed":true}"#,
    )
    .unwrap();
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"redactor wrap -- curl https://telemetry.evil.com/beacon"}}"#;
    let out = run_hook_in_dir("pre-bash", payload, dir.path());
    assert_blocks(&out, "explicit blocklist must win over wildcard allow");
}

// ============================================================================
// 6. Prompt scan — UserPromptSubmit refuses prompts containing secrets.
// ============================================================================

#[test]
fn prompt_blocks_when_secret_in_prompt() {
    let payload = r#"{"hook_event_name":"UserPromptSubmit","prompt":"please use AKIAIOSFODNN7EXAMPLE to upload"}"#;
    let out = run_hook("prompt", payload);
    assert_blocks(&out, "prompt containing AWS key must be refused");
}

#[test]
fn prompt_allows_innocuous_text() {
    let payload =
        r#"{"hook_event_name":"UserPromptSubmit","prompt":"please review the unit tests"}"#;
    let out = run_hook("prompt", payload);
    assert_allows(&out, "innocuous prompt must pass");
}

// ============================================================================
// 7. Known limitations — by-design bypasses. These tests assert the bypass
//    IS possible today so a future change that closes them (intentionally
//    or not) shows up as a test diff requiring a decision.
// ============================================================================

#[test]
fn limitation_xargs_pipe_bypasses_struct_file_guard() {
    // Attack: `echo data.json | xargs cat` — xargs reads filenames from
    // stdin and invokes cat. Our heuristic sees `cat` at the END of the
    // tokens with no following positional → no struct-file match.
    //
    // Mitigation in place: path-guard would still fire if data.json is in a
    // sensitive-path location (e.g. `echo .env | xargs cat` → blocked by
    // path-guard's `.env` regex on the literal command string).
    //
    // For non-sensitive struct files: this passes today. Out-of-scope per
    // rred-35 spec ("Heuristik, kein Bash-Parser").
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"redactor wrap -- bash -c \"echo data.json | xargs cat\""}}"#;
    let out = run_hook("pre-bash", payload);
    assert_allows(
        &out,
        "DOCUMENTED LIMITATION: xargs pipeline bypasses struct-file heuristic",
    );
}

#[test]
fn limitation_process_substitution_bypasses_struct_file_guard() {
    // Attack: `cat <(cat data.json)` — process substitution. Our tokenizer
    // sees `cat` then `<(cat` (with the `<(` glued to the inner cat). The
    // inner cat IS detected, but there's no extension in the next token
    // because `data.json)` has trailing parenthesis. ext_to_mode trims
    // quotes/backticks but NOT parens.
    //
    // We don't claim to handle this; documenting.
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"command":"redactor wrap -- bash -c \"cat <(cat data.json)\""}}"#;
    let out = run_hook("pre-bash", payload);
    let s = String::from_utf8(out.stdout.clone()).unwrap();
    // Outcome here may be allow OR block depending on tokenization details
    // — the assertion is just that we don't panic and produce a valid JSON.
    assert!(
        s.contains("\"decision\":\"block\"") || s.trim() == "{}",
        "process-substitution attack: result must be either valid block or allow JSON, got: {s}"
    );
}

#[test]
fn limitation_url_encoded_secret_in_prompt() {
    // URL-encoded AWS key — our regex doesn't decode percent-encoding.
    // Documented limitation: redactor scans literal bytes. If you pass
    // %41%4B%49%41%49%4F (= AKIAIO) in a prompt, we won't catch it.
    // Defense: the consumer must decode before scanning, or add an
    // additional pre-scan in the hook chain.
    let payload = r#"{"hook_event_name":"UserPromptSubmit","prompt":"key %41%4B%49%41%49%4F%53%46%4F%44%4E%4E%37%45%58%41%4D%50%4C%45 here"}"#;
    let out = run_hook("prompt", payload);
    assert_allows(&out, "DOCUMENTED LIMITATION: redactor doesn't url-decode");
}

#[test]
fn limitation_secret_split_across_lines_in_wrap() {
    // wrap is line-buffered. A secret split across two lines would NOT be
    // caught by single-line regex matching. Multi-line patterns (PEM) handle
    // this via `(?s)` in the regex; single-line patterns (sk-…, AKIA…) do
    // not.
    //
    // Real exploitability is low (you'd have to send the secret as two
    // halves with a literal newline), but worth pinning behavior.
    let input = "AKIA\nIOSFODNN7EXAMPLE\n";
    let out = run_redact_pattern(input);
    // The secret is split — current behavior: NOT caught.
    assert!(
        !out.contains("<redacted:aws_access_key>"),
        "DOCUMENTED LIMITATION: pattern-mode is line-buffered, split secrets pass through"
    );
}

// ============================================================================
// 8. MCP / Grep / NotebookEdit fixed-deny (rred-36) — already covered in
//    hook_phase5.rs but spot-check the decision JSON shape from the
//    red-team angle: even unusual payloads get rejected.
// ============================================================================

#[test]
fn deny_mcp_rejects_non_standard_payload() {
    // Even when payload has a wrong tool_name field shape, deny-mcp blocks.
    let payload = r#"{"weird":"shape","tool_name":"mcp__memory__create_entities","tool_input":{"entities":[{"name":"sensitive"}]}}"#;
    let out = run_hook("deny-mcp", payload);
    assert_blocks(
        &out,
        "deny-mcp must block any MCP call regardless of payload",
    );
}

#[test]
fn deny_grep_rejects_with_path_argument() {
    let payload = r#"{"hook_event_name":"PreToolUse","tool_name":"Grep","tool_input":{"pattern":"sk-","path":"/etc/secrets"}}"#;
    let out = run_hook("deny-grep", payload);
    assert_blocks(
        &out,
        "Grep must always block — even when targeting a non-sensitive path",
    );
}

// ============================================================================
// 9. False-positive surface — what legitimate data passes the prompt-scan
//    cleanly vs. what gets flagged. The user is allowed to paste these
//    formats in prompts; tests pin the current behavior so future tightening
//    of patterns is caught and the docs in CLAUDE.md stay in sync.
//
// Recommendation in CLAUDE.md: when a legitimate value is flagged, prefer
// reformulating to an unambiguous shape (ISO 8601 dates, hyphenated phone
// numbers without leading 0, version strings prefixed with `v`).
// ============================================================================

// ---------- pattern-mode (CLI direct) coverage ----------------------------

#[test]
fn fp_iso_date_passes_clean() {
    // YYYY-MM-DD — preferred form, never matches birthdate_de.
    assert_eq!(
        run_redact_pattern("Heute ist 2026-04-28").trim(),
        "Heute ist 2026-04-28"
    );
}

#[test]
fn fp_iso_datetime_with_timezone_passes_clean() {
    // ISO 8601 datetime with offset — passes cleanly through all rules.
    let input = "Stand: 2026-04-28T20:50:00+02:00\n";
    let out = run_redact_pattern(input);
    assert!(
        !out.contains("<redacted:"),
        "ISO datetime must pass clean, got: {out}"
    );
}

#[test]
fn fp_german_date_dd_mm_yyyy_is_redacted_documented_fp() {
    // KNOWN FALSE POSITIVE: birthdate_de matches DD.MM.YYYY, DD-MM-YYYY, DD/MM/YYYY.
    // If the user pastes a German date in a prompt or output, it WILL be redacted.
    // Workaround: rewrite as ISO `2026-04-28`, or add a project-specific
    // override (see CLAUDE.md "Filter tuning" section).
    let out = run_redact_pattern("Termin am 28.04.2026 um 10 Uhr");
    assert!(
        out.contains("<redacted:birthdate>"),
        "DOCUMENTED FP: 28.04.2026 hits birthdate_de pattern, got: {out}"
    );
}

#[test]
fn fp_private_ipv4_passes_clean_smart_filter() {
    // is_private_ipv4() in src/redactor.rs exempts RFC1918 + loopback ranges.
    let inputs = [
        "Server-IP 192.168.1.1 ist down",
        "Loopback 127.0.0.1 ok",
        "Internal 10.0.0.5 reachable",
        "RFC1918-mid 172.16.0.1 ok",
        "RFC1918-edge 172.31.255.254 ok",
    ];
    for input in inputs {
        let out = run_redact_pattern(input);
        assert!(
            !out.contains("<redacted:ipv4>"),
            "private/loopback IP must NOT be redacted: input={input:?} got={out:?}"
        );
    }
}

#[test]
fn fp_public_ipv4_is_redacted() {
    // Public IPs WILL be redacted (correct behavior).
    let out = run_redact_pattern("DNS 8.8.8.8 fragen");
    assert!(
        out.contains("<redacted:ipv4>"),
        "public IP must be redacted, got: {out}"
    );
}

#[test]
fn fp_version_string_passes_when_quoted_or_versioned() {
    // The contextual ipv4 FP-filter exempts matches that are either enclosed
    // in matching ASCII quotes, or preceded by a known version vocabulary
    // word (version, ver, v, build, rev, release, semver, tag).
    let inputs = [
        "Version 1.2.3.4 released",
        "version: 5.1.0.0 ok",
        "build 1.2.3.4 done",
        "release 9.0.0.0 sealed",
        "v 4.0.0.1 ready",
        "tag: 2.0.0.0",
        "PackageManagement '5.3.4.X' line",
        "PackageManagement \"5.3.4.1\" line",
    ];
    for input in inputs {
        let out = run_redact_pattern(input);
        assert!(
            !out.contains("<redacted:ipv4>"),
            "version-context input must NOT trigger ipv4: {input:?} -> {out:?}"
        );
    }
}

#[test]
fn fp_version_filter_does_not_mask_real_ips() {
    // Real IPs with no version-vocab and no quotes around them still get
    // redacted as before.
    let out = run_redact_pattern("DNS 8.8.8.8 fragen");
    assert!(out.contains("<redacted:ipv4>"));
    let out = run_redact_pattern("client=8.8.4.4 down");
    assert!(out.contains("<redacted:ipv4>"));
}

#[test]
fn phone_numbers_pass_through_unredacted() {
    // phone_de was dropped — too many false positives in tenant IDs, GUIDs,
    // ISO timestamps, build numbers. Users who need phone redaction must
    // add a custom rule.
    for s in ["Tel: 0123 456789", "+49 30 12345678", "0049 30 12345678"] {
        let out = run_redact_pattern(s);
        assert!(
            !out.contains("<redacted:phone_de>"),
            "phone_de must be gone for {s:?}, got: {out}"
        );
    }
}

#[test]
fn fp_uuid_and_hex_pass_clean() {
    // UUIDs and hex hashes are common in logs — must NOT be redacted.
    let inputs = [
        "trace-id: 550e8400-e29b-41d4-a716-446655440000",
        "commit a1b2c3d4e5f67890abcdef1234567890abcdef12",
        "hash: 0xDEADBEEF",
    ];
    for input in inputs {
        let out = run_redact_pattern(input);
        assert!(
            !out.contains("<redacted:"),
            "UUID/hex must pass: input={input:?} got={out:?}"
        );
    }
}

#[test]
fn fp_example_domains_pass_clean_via_whitelist() {
    // WHITELIST_SUBSTRINGS exempts example.com / .test / .org / localhost.
    let inputs = [
        "API at example.com/v1",
        "test against example.test:8080",
        "noreply@example.org sent",
    ];
    for input in inputs {
        let out = run_redact_pattern(input);
        assert!(
            !out.contains("<redacted:"),
            "example domains must pass: input={input:?} got={out:?}"
        );
    }
}

#[test]
fn fp_test_iban_de00_passes_clean() {
    // Canonical "DE00…" test IBAN is exempted by is_false_positive's
    // rule-specific filter — useful for documentation and code samples.
    let out = run_redact_pattern("Test-IBAN: DE00 0000 0000 0000 0000 00");
    assert!(
        !out.contains("<redacted:iban>"),
        "DE00-prefix test IBAN must pass: {out}"
    );
}

// ---------- prompt-scan (UserPromptSubmit hook) coverage -------------------

#[test]
fn prompt_allows_iso_date_and_datetime() {
    // The user's main concern: pasting timestamps into prompts must work.
    let payload = r#"{"hook_event_name":"UserPromptSubmit","prompt":"Termin 2026-04-28 um 10:00, deadline 2026-05-15T18:00:00+02:00"}"#;
    let out = run_hook("prompt", payload);
    assert_allows(&out, "ISO date + datetime in prompt must pass cleanly");
}

#[test]
fn prompt_allows_private_ip_and_version_with_v_prefix() {
    let payload = r#"{"hook_event_name":"UserPromptSubmit","prompt":"Server 192.168.1.1 läuft v1.2.3 — prüfen"}"#;
    let out = run_hook("prompt", payload);
    assert_allows(
        &out,
        "private IP + v-prefixed version must pass — preferred shape per CLAUDE.md",
    );
}

#[test]
fn prompt_allows_uuid_and_commit_hash() {
    let payload = r#"{"hook_event_name":"UserPromptSubmit","prompt":"Bug in trace 550e8400-e29b-41d4-a716-446655440000, commit a1b2c3d4"}"#;
    let out = run_hook("prompt", payload);
    assert_allows(&out, "UUIDs and short commit hashes must pass cleanly");
}

#[test]
fn prompt_blocks_german_date_documented_fp() {
    // KNOWN FP repeated at the prompt layer — same workaround documented in
    // CLAUDE.md ("rewrite to ISO 8601").
    let payload = r#"{"hook_event_name":"UserPromptSubmit","prompt":"Geburtstag am 28.04.1990"}"#;
    let out = run_hook("prompt", payload);
    assert_blocks(&out, "DOCUMENTED FP: German DD.MM.YYYY blocks the prompt");
}

#[test]
fn prompt_blocks_real_secret_from_user_paste() {
    // Sanity: if the user genuinely pastes a real secret in a prompt, the
    // scan blocks it. This is correct behavior — the user must remove the
    // secret before resubmitting (or use --no-config on a direct redactor
    // call to bypass this single time, see CLAUDE.md "Escape hatches").
    let payload = r#"{"hook_event_name":"UserPromptSubmit","prompt":"please use AKIAIOSFODNN7EXAMPLE for upload"}"#;
    let out = run_hook("prompt", payload);
    assert_blocks(&out, "real AWS key in prompt must be refused");
}

#[test]
fn prompt_allows_multiline_with_code_block_and_dates() {
    // Realistic copy-paste: a code block plus surrounding ISO timestamps.
    let payload = r#"{"hook_event_name":"UserPromptSubmit","prompt":"Stand 2026-04-28T20:50:00+02:00:\n\n```rust\nfn foo() -> i32 { 42 }\n```\n\nTests: 192.168.1.1 ok, v1.2.3 deployed."}"#;
    let out = run_hook("prompt", payload);
    assert_allows(&out, "realistic mixed prompt must pass cleanly");
}

#[test]
fn prompt_allows_already_redacted_paste() {
    // Workflow: user pastes prompt → blocked → pastes redacted preview → must
    // pass. Some rules (`client_secret`, `auth_header`, …) re-match their own
    // `<redacted:LABEL>` placeholders with an idempotent replacement. That
    // produces a non-empty events list while `sanitized == input`, so the
    // hook used to block the second paste even though nothing actually
    // changed. The contract: if sanitization leaves the text byte-identical,
    // allow.
    let payload = r#"{"hook_event_name":"UserPromptSubmit","prompt":"APP_CLIENT_SECRET=<redacted:client_secret>\nAuthorization: <redacted:auth_header>"}"#;
    let out = run_hook("prompt", payload);
    assert_allows(
        &out,
        "already-redacted prompt must pass — idempotent matches are not real redactions",
    );
}

// ============================================================================
// 8. read-strict — structured files refused, source/markdown allowed.
// ============================================================================

#[test]
fn pre_read_blocks_json_file_by_default() {
    // Default policy is strict_json = true → JSON reads must be forced
    // through `redactor --type json <file>`.
    let payload =
        r#"{"hook_event_name":"PreToolUse","tool_input":{"file_path":"/proj/config.json"}}"#;
    let out = run_hook("pre-read", payload);
    assert_blocks(&out, ".json must force --type json under default policy");
}

#[test]
fn pre_read_allows_json_when_policy_strict_json_false() {
    // Opt-out via `.redactor.toml` makes JSON pass through.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".redactor.toml"),
        "[policy]\nstrict_json = false\n",
    )
    .unwrap();
    let payload =
        r#"{"hook_event_name":"PreToolUse","tool_input":{"file_path":"/proj/config.json"}}"#;
    let out = run_hook_in_dir("pre-read", payload, dir.path());
    assert_allows(
        &out,
        ".json must pass through when project has [policy] strict_json = false",
    );
}

#[test]
fn pre_read_blocks_csv_file() {
    let payload =
        r#"{"hook_event_name":"PreToolUse","tool_input":{"file_path":"/data/customers.csv"}}"#;
    let out = run_hook("pre-read", payload);
    assert_blocks(&out, ".csv must force --type csv");
}

#[test]
fn pre_read_blocks_tsv_file() {
    let payload =
        r#"{"hook_event_name":"PreToolUse","tool_input":{"file_path":"/data/users.tsv"}}"#;
    let out = run_hook("pre-read", payload);
    assert_blocks(&out, ".tsv shares the csv code path");
}

#[test]
fn pre_read_blocks_env_file_via_path_guard() {
    // .env hits the path-guard step BEFORE the structured-extension test —
    // either way the result is a block. We assert on block, not on the
    // specific reason, to keep the test stable across reorderings.
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"file_path":"/proj/.env"}}"#;
    let out = run_hook("pre-read", payload);
    assert_blocks(&out, ".env must be refused");
}

#[test]
fn pre_read_allows_rust_source() {
    let payload =
        r#"{"hook_event_name":"PreToolUse","tool_input":{"file_path":"/proj/src/main.rs"}}"#;
    let out = run_hook("pre-read", payload);
    assert_allows(
        &out,
        ".rs source must pass — post-tool sanitises pattern matches",
    );
}

#[test]
fn pre_read_allows_python_source() {
    let payload =
        r#"{"hook_event_name":"PreToolUse","tool_input":{"file_path":"/proj/script.py"}}"#;
    let out = run_hook("pre-read", payload);
    assert_allows(&out, ".py source must pass");
}

#[test]
fn pre_read_allows_markdown() {
    let payload =
        r#"{"hook_event_name":"PreToolUse","tool_input":{"file_path":"/proj/README.md"}}"#;
    let out = run_hook("pre-read", payload);
    assert_allows(&out, ".md must pass — typically docs/notes");
}

#[test]
fn pre_read_allows_no_extension() {
    let payload = r#"{"hook_event_name":"PreToolUse","tool_input":{"file_path":"/proj/Justfile"}}"#;
    let out = run_hook("pre-read", payload);
    assert_allows(
        &out,
        "extension-less files (Justfile, Makefile, Dockerfile) must pass",
    );
}

#[test]
fn pre_read_blocks_sensitive_path_even_if_allowed_extension() {
    // .pem would be 'extension-less' wrt detect_struct_extension, but the
    // path-guard step (1) catches it first. Belt-and-braces — ensure the
    // extension-relaxation in step (2) didn't accidentally short-circuit
    // the path-guard.
    let payload =
        r#"{"hook_event_name":"PreToolUse","tool_input":{"file_path":"/etc/ssl/server.pem"}}"#;
    let out = run_hook("pre-read", payload);
    assert_blocks(&out, ".pem must still be path-guard-blocked");
}

#[test]
fn pre_read_blocks_aws_creds_via_path_guard() {
    let payload =
        r#"{"hook_event_name":"PreToolUse","tool_input":{"file_path":"/home/u/.aws/credentials"}}"#;
    let out = run_hook("pre-read", payload);
    assert_blocks(&out, "AWS creds must be path-guard-blocked");
}
