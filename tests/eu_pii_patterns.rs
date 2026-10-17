//! Integration tests for rred-1..6: EU PII, IPv4 with FP filter, connection
//! strings, Azure credentials, cert thumbprints + client secrets, plus the
//! generic false-positive filter.

use std::io::Write;
use std::process::{Command as StdCommand, Stdio};
use tempfile::tempdir;

fn redact(input: &str) -> String {
    let log_dir = tempdir().unwrap();
    let bin = assert_cmd::cargo::cargo_bin("redactor");
    let mut child = StdCommand::new(bin)
        .env("REDACTOR_LOG_DIR", log_dir.path())
        .env(
            "REDACTOR_CONFIG_DIR",
            "/tmp/eu-pii-tests-no-such-config-dir",
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
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "redactor failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

// ---------- rred-1 IBAN ----------

#[test]
fn iban_de_redacted_with_spaces() {
    let out = redact("IBAN: DE89 3704 0044 0532 0130 00 ende");
    assert!(out.contains("<redacted:iban>"));
}

#[test]
fn iban_de_redacted_compact() {
    let out = redact("acct=DE89370400440532013000");
    assert!(out.contains("<redacted:iban>"));
}

#[test]
fn iban_de_test_iban_passes_through() {
    let out = redact("Test DE00 0000 0000 0000 0000 00 ende");
    assert!(out.contains("DE00 0000"));
    assert!(!out.contains("<redacted:iban>"));
}

// ---------- rred-1 phone (removed: phone_de pattern dropped — too many FPs) ----------

#[test]
fn phone_de_pattern_no_longer_exists() {
    // Phone numbers (+49 …) now pass through verbatim; users who need this
    // must add a custom rule via `--patterns` or per-project .redactor.toml.
    let out = redact("call +49 30 12345678 now");
    assert!(
        !out.contains("<redacted:phone_de>") && out.contains("+49 30 12345678"),
        "phone_de must be gone, got: {out}"
    );
}

// ---------- rred-1 birthdate ----------

#[test]
fn birthdate_de_dot_format_redacted() {
    let out = redact("born 15.03.1985 in DE");
    assert!(out.contains("<redacted:birthdate>"));
}

#[test]
fn birthdate_de_invalid_passes() {
    let out = redact("date 32.13.1985 bogus");
    assert!(out.contains("32.13.1985"));
    assert!(!out.contains("<redacted:birthdate>"));
}

// ---------- rred-1 SVN ----------

#[test]
fn svn_de_redacted() {
    let out = redact("svn 12A123456B789 yep");
    assert!(out.contains("<redacted:svn>"));
}

#[test]
fn svn_de_too_short_passes() {
    let out = redact("svn 12X123456 short");
    assert!(out.contains("12X123456"));
    assert!(!out.contains("<redacted:svn>"));
}

// ---------- rred-2 IPv4 with FP filter ----------

#[test]
fn ipv4_public_redacted() {
    let out = redact("client=8.8.8.8 ext");
    assert!(out.contains("<redacted:ipv4>"));
    assert!(!out.contains("8.8.8.8"));
}

#[test]
fn ipv4_private_passes() {
    let out = redact("internal 192.168.1.1, lo 127.0.0.1, ten 10.0.0.5");
    assert!(out.contains("192.168.1.1"));
    assert!(out.contains("127.0.0.1"));
    assert!(out.contains("10.0.0.5"));
}

// ---------- rred-3 connection strings ----------

#[test]
fn conn_string_postgres_redacted() {
    let out = redact("DATABASE_URL=postgres://admin:s3cret@db:5432/app extra");
    assert!(out.contains("<redacted:conn_string>"));
    assert!(!out.contains("s3cret"));
}

#[test]
fn conn_string_mongodb_srv_redacted() {
    let out = redact("uri=mongodb+srv://u:p@cluster/test others");
    assert!(out.contains("<redacted:conn_string>"));
}

#[test]
fn conn_string_https_passes() {
    let out = redact("see https://api.acme.com/postgres-guide");
    assert!(out.contains("acme.com"));
    assert!(!out.contains("<redacted:conn_string>"));
}

#[test]
fn conn_string_word_postgres_passes() {
    let out = redact("Use postgres for storage.");
    assert!(out.contains("postgres"));
    assert!(!out.contains("<redacted:conn_string>"));
}

// ---------- rred-4 Azure GUIDs ----------

#[test]
fn azure_tenant_id_redacted() {
    let out = redact("TenantId: 11111111-2222-3333-4444-555555555555 ende");
    assert!(out.contains("<redacted:azure_guid>"));
    assert!(out.contains("TenantId="));
}

#[test]
fn azure_orderid_passes_through() {
    let out = redact("OrderId: 11111111-2222-3333-4444-555555555555");
    assert!(out.contains("11111111-2222-3333-4444-555555555555"));
    assert!(!out.contains("<redacted:azure_guid>"));
}

// ---------- rred-5 cert thumbprint + client secret ----------

#[test]
fn cert_thumbprint_redacted() {
    let out = redact("Thumbprint: 0123456789ABCDEF0123456789ABCDEF01234567 done");
    assert!(out.contains("<redacted:cert_thumbprint>"));
    assert!(!out.contains("0123456789ABCDEF"));
}

#[test]
fn cert_thumbprint_short_passes() {
    let out = redact("Thumbprint: 0123 short");
    assert!(out.contains("0123 short"));
    assert!(!out.contains("<redacted:cert_thumbprint>"));
}

#[test]
fn client_secret_redacted() {
    let out = redact("ClientSecret=abcdef1234567890");
    assert!(out.contains("<redacted:client_secret>"));
    assert!(!out.contains("abcdef1234"));
}

#[test]
fn client_secret_too_short_passes() {
    let out = redact("ClientSecret=short");
    assert!(out.contains("ClientSecret=short"));
    assert!(!out.contains("<redacted:client_secret>"));
}

// ---------- rred-6 FP filter holistic ----------

#[test]
fn fp_filter_combined_log_line() {
    let s = "user 8.8.8.8 wrote conn=postgres://u:p@db/x with TenantId: 11111111-2222-3333-4444-555555555555 home 192.168.1.1";
    let out = redact(s);
    assert!(out.contains("<redacted:ipv4>"));
    assert!(out.contains("<redacted:conn_string>"));
    assert!(out.contains("<redacted:azure_guid>"));
    assert!(out.contains("192.168.1.1"));
    assert!(!out.contains("8.8.8.8"));
}

#[test]
fn fp_filter_does_not_break_existing_patterns() {
    let out = redact("OPENAI_API_KEY=sk-proj-abcdefghij1234567890");
    assert!(out.contains("<redacted:openai_key>"));
}

#[test]
fn matrix_iban_birthdate_svn() {
    let s = "DE89 3704 0044 0532 0130 00 then 15.03.1985 then 12A123456B789";
    let out = redact(s);
    assert!(out.contains("<redacted:iban>"));
    assert!(out.contains("<redacted:birthdate>"));
    assert!(out.contains("<redacted:svn>"));
}
