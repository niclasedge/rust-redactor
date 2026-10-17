//! Core redaction logic. Each mode returns the redacted text plus a set of
//! `LogEntry` values describing what was redacted (so main.rs can emit one
//! line per rule-hit to the daily log).

use crate::patterns::Rule;
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

const REDACTED: &str = "<redacted>";

/// One bookkeeping entry per rule that fired (or per per-mode-bucket for
/// structural modes).
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub rule: String,
    pub count: usize,
    pub sample: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Csv,
    Json,
    Env,
    Pattern,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Mode::Csv => "csv",
            Mode::Json => "json",
            Mode::Env => "env",
            Mode::Pattern => "pattern",
        }
    }
}

impl std::str::FromStr for Mode {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "pattern" => Ok(Mode::Pattern),
            "csv" => Ok(Mode::Csv),
            "json" => Ok(Mode::Json),
            "env" => Ok(Mode::Env),
            other => anyhow::bail!("unknown mode '{other}'"),
        }
    }
}

/// Detect mode from a path's basename + extension. Project-level overrides
/// (from .redactor.toml [modes]) win over the hardcoded fallback.
pub fn detect_mode(
    path: &Path,
    overrides: &std::collections::HashMap<String, Mode>,
) -> Option<Mode> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    // Override map (keyed by normalized extension) wins first.
    if !ext.is_empty() {
        if let Some(m) = overrides.get(&ext) {
            return Some(*m);
        }
    }

    if name == ".env" || name == ".envrc" || name.starts_with(".env.") {
        return Some(Mode::Env);
    }
    match ext.as_str() {
        "csv" => Some(Mode::Csv),
        "json" => Some(Mode::Json),
        "env" => Some(Mode::Env),
        "log" | "txt" => Some(Mode::Pattern),
        _ => None,
    }
}

// ---------- CSV ----------

pub fn redact_csv(text: &str) -> Result<(String, Vec<LogEntry>)> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(text.as_bytes());

    let mut records = reader.records();
    let header = match records.next() {
        Some(r) => r.context("read header")?,
        None => return Ok((String::new(), vec![])),
    };
    let header_len = header.len();
    let rest: Vec<csv::StringRecord> = records.collect::<Result<_, _>>()?;
    let total_rows = rest.len();

    let mut out = Vec::<u8>::new();
    {
        let mut writer = csv::WriterBuilder::new().from_writer(&mut out);
        writer.write_record(header.iter())?;
        if total_rows > 0 {
            let redacted: Vec<&str> = (0..header_len).map(|_| REDACTED).collect();
            writer.write_record(redacted)?;
        }
        writer.flush()?;
    } // writer drops here, &mut out released

    let mut s = String::from_utf8(out).context("csv output utf-8")?;
    while s.ends_with('\n') {
        s.pop();
    }
    let extra = total_rows.saturating_sub(1);
    if extra > 0 {
        s.push('\n');
        s.push_str(&format!("# ... {extra} more rows redacted"));
    }
    let logs = vec![LogEntry {
        rule: "csv_rows".into(),
        count: total_rows,
        sample: format!("header_cols={header_len}"),
    }];
    Ok((s, logs))
}

// ---------- JSON ----------

pub fn redact_json(text: &str) -> Result<(String, Vec<LogEntry>)> {
    let v: Value = serde_json::from_str(text).context("parse json")?;
    let mut counter = JsonCounter::default();
    let red = redact_json_value(&v, &mut counter);
    let pretty = serde_json::to_string_pretty(&red)?;
    let logs = vec![LogEntry {
        rule: "json_leaves".into(),
        count: counter.leaves,
        sample: format!(
            "leaves={} list_truncated={}",
            counter.leaves, counter.lists_truncated
        ),
    }];
    Ok((pretty, logs))
}

#[derive(Default)]
struct JsonCounter {
    leaves: usize,
    lists_truncated: usize,
}

fn redact_json_value(v: &Value, c: &mut JsonCounter) -> Value {
    match v {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, val) in map {
                out.insert(k.clone(), redact_json_value(val, c));
            }
            Value::Object(out)
        }
        Value::Array(arr) => {
            if arr.is_empty() {
                return Value::Array(vec![]);
            }
            let head = redact_json_value(&arr[0], c);
            if arr.len() == 1 {
                Value::Array(vec![head])
            } else {
                c.lists_truncated += 1;
                Value::Array(vec![
                    head,
                    Value::String(format!("... {} more items redacted", arr.len() - 1)),
                ])
            }
        }
        // leaf
        _ => {
            c.leaves += 1;
            Value::String(REDACTED.to_string())
        }
    }
}

// ---------- ENV ----------

pub fn redact_env(text: &str) -> Result<(String, Vec<LogEntry>)> {
    let mut out = String::new();
    let mut count = 0usize;
    let mut first_key: Option<String> = None;
    for line in text.split('\n') {
        let stripped = line.trim_start();
        if stripped.is_empty() || stripped.starts_with('#') {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let leading_ws_len = line.len() - stripped.len();
        let leading_ws = &line[..leading_ws_len];
        let (prefix, body) = if let Some(rest) = stripped.strip_prefix("export ") {
            (format!("{leading_ws}export "), rest.to_string())
        } else {
            (leading_ws.to_string(), stripped.to_string())
        };
        if let Some(eq_idx) = body.find('=') {
            let key = &body[..eq_idx];
            if first_key.is_none() {
                first_key = Some(key.to_string());
            }
            count += 1;
            out.push_str(&prefix);
            out.push_str(key);
            out.push('=');
            out.push_str(REDACTED);
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    // strip trailing newline if input had none
    if !text.ends_with('\n') {
        out.pop();
    }
    let logs = vec![LogEntry {
        rule: "env_var".into(),
        count,
        sample: first_key.unwrap_or_else(|| "(none)".to_string()),
    }];
    Ok((out, logs))
}

// ---------- PATTERN ----------

pub fn redact_pattern(text: &str, rules: &[Rule]) -> (String, Vec<LogEntry>) {
    let mut buf = text.to_string();
    let mut logs = Vec::new();
    for rule in rules {
        let mut count: usize = 0;
        let mut sample: Option<String> = None;
        let snapshot = buf.clone();
        let after = rule
            .regex
            .replace_all(&snapshot, |caps: &regex::Captures<'_>| -> String {
                let mat = caps.get(0).unwrap();
                let m = mat.as_str();
                let start = mat.start();
                let end = mat.end();
                let bstart = snapshot[..start]
                    .char_indices()
                    .rev()
                    .nth(15)
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                let aend = snapshot[end..]
                    .char_indices()
                    .nth(16)
                    .map(|(i, _)| end + i)
                    .unwrap_or(snapshot.len());
                let before = &snapshot[bstart..start];
                let after_ctx = &snapshot[end..aend];
                if is_false_positive(m, &rule.name, before, after_ctx) {
                    return m.to_string();
                }
                count += 1;
                if sample.is_none() {
                    sample = Some(m.to_string());
                }
                // Expand backrefs ($1, $2, ...) the way replace_all normally does.
                let mut dst = String::new();
                caps.expand(&rule.replacement, &mut dst);
                dst
            })
            .into_owned();
        buf = after;
        if count > 0 {
            logs.push(LogEntry {
                rule: rule.name.clone(),
                count,
                sample: sample.unwrap_or_default(),
            });
        }
    }
    (buf, logs)
}

/// Substrings that, if present in a match, mark it as a false positive
/// (typical doc/example values that should never be redacted).
const WHITELIST_SUBSTRINGS: &[&str] = &[
    "example.com",
    "example.test",
    "example.org",
    "localhost",
    "noreply@",
    "no-reply@",
];

/// True for IPv6 strings that should NOT be redacted: loopback (`::1`),
/// unspecified (`::`), link-local (`fe80::/10`) and unique-local
/// (`fc00::/7`). Anything malformed also returns `true` (safer to skip).
pub fn is_private_ipv6(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    if lower == "::" || lower == "::1" {
        return true;
    }
    // Link-local: fe80::/10 → fe80..febf in the first 16 bits.
    if let Some(prefix) = lower.split(':').next() {
        if let Ok(first) = u16::from_str_radix(prefix, 16) {
            // fe80::/10 — top 10 bits == 1111 1110 10 → 0xfe80..0xfebf
            if (0xfe80..=0xfebf).contains(&first) {
                return true;
            }
            // fc00::/7 — top 7 bits == 1111 110 → 0xfc00..0xfdff
            if (0xfc00..=0xfdff).contains(&first) {
                return true;
            }
        }
    }
    // Reject obviously non-IPv6 shapes (no `::` and < 7 colons).
    let colon_count = s.bytes().filter(|b| *b == b':').count();
    if !s.contains("::") && colon_count < 7 {
        return true;
    }
    false
}

/// True for private/loopback/zero IPv4 ranges that should NOT be redacted.
/// Malformed inputs return true (safer to leave them alone).
pub fn is_private_ipv4(s: &str) -> bool {
    let parts: Vec<u8> = s.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 4 {
        return true;
    }
    match parts.as_slice() {
        [10, ..] => true,
        [127, ..] => true,
        [0, 0, 0, 0] => true,
        [192, 168, ..] => true,
        [172, b, ..] if (16..=31).contains(b) => true,
        _ => false,
    }
}

/// True if a regex match should be treated as a false positive and passed
/// through unredacted. Combines a generic substring whitelist with rule-
/// specific filters (e.g. private IPv4 ranges, canonical test IBAN, or
/// version-string-shaped IPv4 matches). The `before`/`after` slices are
/// up to ~16 chars of surrounding context — empty strings mean "no context
/// available" and disable contextual filters.
pub fn is_false_positive(matched: &str, rule_name: &str, before: &str, after: &str) -> bool {
    let lower = matched.to_ascii_lowercase();
    if WHITELIST_SUBSTRINGS.iter().any(|s| lower == *s) {
        return true;
    }
    match rule_name {
        "ipv4" => is_private_ipv4(matched) || looks_like_version_string(before, after),
        "ipv6" => is_private_ipv6(matched),
        "iban_de" => matched.replace(' ', "").starts_with("DE000000"),
        // For emails, treat WHITELIST as substring-match (noreply@example.org,
        // anything @example.com/.test/.org/localhost). Exact-equality whitelist
        // never fires for emails — the matched span is the full address.
        "email" => WHITELIST_SUBSTRINGS.iter().any(|w| lower.contains(w)),
        // Phase 7h: internal_hostname — don't redact bare TLDs in prose
        // ("a .local file", "fix the .corp domain"). Require at least one
        // dot inside the matched span (i.e. the regex already enforces this,
        // but we sanity-check).
        "internal_hostname" => !matched.contains('.'),
        _ => false,
    }
}

/// True when the surrounding context strongly suggests a software version
/// (e.g. `'1.2.3.4'`, `Version 5.1.0.0`, `build 1.2.3.4 released`) rather
/// than a real IP address. Heuristic — false negatives are tolerated; we'd
/// rather under-exempt and redact a build number than leak an actual IP.
///
/// Two orthogonal signals, either is enough:
/// 1. The match is enclosed in matching ASCII quotes (`'…'` or `"…"`).
/// 2. The last whitespace-separated token before the match is a known
///    version vocabulary word.
fn looks_like_version_string(before: &str, after: &str) -> bool {
    let last = before.chars().last();
    let first = after.chars().next();
    if matches!(
        (last, first),
        (Some('\''), Some('\'')) | (Some('"'), Some('"'))
    ) {
        return true;
    }
    const VOCAB: &[&str] = &[
        "version", "ver", "v", "build", "rev", "release", "semver", "tag",
    ];
    let prev = before
        .rsplit(|c: char| c.is_whitespace() || c == '=' || c == ':' || c == '(')
        .find(|t| !t.is_empty())
        .unwrap_or("")
        .trim_end_matches(['.', ',', ';']);
    if prev.is_empty() {
        return false;
    }
    let prev_lc = prev.to_ascii_lowercase();
    VOCAB.iter().any(|w| prev_lc == *w)
}

// ---------- SCAN (rred-13) ----------

/// One pattern match emitted by `redactor scan`. Serializes to JSONL with a
/// stable schema: `{"rule":..,"line":N,"col":N,"sample":"..","mode":"pattern"}`.
#[derive(Debug, serde::Serialize)]
pub struct Finding<'a> {
    pub rule: &'a str,
    pub line: usize,
    pub col: usize,
    pub sample: String,
    pub mode: &'a str,
}

fn offset_to_line_col(text: &str, off: usize) -> (usize, usize) {
    let bytes = text.as_bytes();
    let upto = off.min(bytes.len());
    let mut line = 1usize;
    let mut last_nl = 0usize;
    for (i, b) in bytes[..upto].iter().enumerate() {
        if *b == b'\n' {
            line += 1;
            last_nl = i + 1;
        }
    }
    (line, off - last_nl + 1)
}

/// Scan `text` against every `Rule` and emit one `Finding` per match. Does
/// NOT mutate `text` and does NOT consult the FP filter — `scan` is meant
/// for audit pipelines, not for production redaction.
pub fn scan_pattern<'a>(text: &str, rules: &'a [Rule]) -> Vec<Finding<'a>> {
    let mut out = Vec::new();
    for rule in rules {
        for m in rule.regex.find_iter(text) {
            let (line, col) = offset_to_line_col(text, m.start());
            let mut sample = m.as_str().replace(['\n', '\r', '\t'], " ");
            if sample.chars().count() > 60 {
                sample = sample.chars().take(60).collect::<String>() + "...";
            }
            out.push(Finding {
                rule: &rule.name,
                line,
                col,
                sample,
                mode: "pattern",
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns;

    #[test]
    fn csv_keeps_header_redacts_rest() {
        let input = "id,name,email\n1,Alice,a@x.de\n2,Bob,b@x.de\n3,Carol,c@x.de\n";
        let (out, logs) = redact_csv(input).unwrap();
        assert!(out.starts_with("id,name,email"));
        assert!(out.contains("<redacted>,<redacted>,<redacted>"));
        assert!(out.contains("# ... 2 more rows redacted"));
        assert_eq!(logs[0].count, 3);
    }

    #[test]
    fn csv_header_only() {
        let input = "a,b,c\n";
        let (out, _) = redact_csv(input).unwrap();
        assert_eq!(out, "a,b,c");
    }

    #[test]
    fn json_recursive() {
        let input = r#"{"k":"secret","arr":[1,2,3],"nested":{"x":42}}"#;
        let (out, logs) = redact_json(input).unwrap();
        assert!(out.contains("<redacted>"));
        assert!(out.contains("more items redacted"));
        // 3 actual leaves: "secret", arr[0]=1, nested.x=42
        assert_eq!(logs[0].count, 3);
    }

    #[test]
    fn env_keeps_keys() {
        let input = "# comment\nFOO=bar\nexport BAZ=qux\n\nNOEQ\n";
        let (out, logs) = redact_env(input).unwrap();
        assert!(out.contains("# comment"));
        assert!(out.contains("FOO=<redacted>"));
        assert!(out.contains("export BAZ=<redacted>"));
        assert!(out.contains("NOEQ")); // pass-through
        assert_eq!(logs[0].count, 2);
    }

    #[test]
    fn pattern_redacts_known_secrets() {
        let rules = patterns::defaults();
        let input = "OPENAI_API_KEY=sk-proj-abcdefghij1234567890XYZ\nAWS=AKIAIOSFODNN7EXAMPLE\n";
        let (out, logs) = redact_pattern(input, &rules);
        assert!(out.contains("<redacted:openai_key>"));
        assert!(out.contains("<redacted:aws_access_key>"));
        assert!(logs.iter().any(|l| l.rule == "openai_key" && l.count == 1));
    }

    #[test]
    fn detect_mode_basics() {
        let none = std::collections::HashMap::new();
        assert_eq!(detect_mode(Path::new(".env"), &none), Some(Mode::Env));
        assert_eq!(detect_mode(Path::new("data.csv"), &none), Some(Mode::Csv));
        assert_eq!(detect_mode(Path::new("blob.json"), &none), Some(Mode::Json));
        assert_eq!(
            detect_mode(Path::new("app.log"), &none),
            Some(Mode::Pattern)
        );
        assert_eq!(detect_mode(Path::new("unknown.zzz"), &none), None);
    }

    // ---------- rred-2 / rred-6 FP filter ----------

    #[test]
    fn ipv4_redacts_public_only() {
        let rules = patterns::defaults();
        let input = "client=8.8.8.8 internal=192.168.1.1 lo=127.0.0.1 ten=10.0.0.5";
        let (out, _) = redact_pattern(input, &rules);
        assert!(out.contains("<redacted:ipv4>"));
        assert!(out.contains("192.168.1.1"));
        assert!(out.contains("127.0.0.1"));
        assert!(out.contains("10.0.0.5"));
        assert!(!out.contains("8.8.8.8"));
    }

    #[test]
    fn ipv4_redacts_172_16_31_only() {
        let rules = patterns::defaults();
        // 172.15.x is public, 172.16-31.x is private.
        let input = "pub=172.15.0.1 priv=172.16.0.1 priv=172.31.255.254 pub=172.32.0.1";
        let (out, _) = redact_pattern(input, &rules);
        assert!(out.contains("172.16.0.1"));
        assert!(out.contains("172.31.255.254"));
        assert!(!out.contains("172.15.0.1"));
        assert!(!out.contains("172.32.0.1"));
    }

    #[test]
    fn fp_filter_test_iban_passes_through() {
        let rules = patterns::defaults();
        let input = "Test-IBAN DE00 0000 0000 0000 0000 00 ende";
        let (out, _) = redact_pattern(input, &rules);
        assert!(out.contains("DE00 0000"));
        assert!(!out.contains("<redacted:iban>"));
    }

    #[test]
    fn fp_filter_real_iban_redacted() {
        let rules = patterns::defaults();
        let input = "IBAN DE89 3704 0044 0532 0130 00 ende";
        let (out, _) = redact_pattern(input, &rules);
        assert!(out.contains("<redacted:iban>"));
        assert!(!out.contains("DE89 3704"));
    }

    // ---------- Phase 7g: IPv6 FP filter ----------
    #[test]
    fn ipv6_public_address_redacted() {
        let rules = patterns::defaults();
        let input = "client 2606:4700:4700::1111 via Cloudflare DNS";
        let (out, _) = redact_pattern(input, &rules);
        assert!(out.contains("<redacted:ipv6>"));
        assert!(!out.contains("2606:4700"));
    }
    #[test]
    fn ipv6_link_local_passes_through() {
        let rules = patterns::defaults();
        let input = "interface fe80::1234:abcd:5678:9ef0 up";
        let (out, _) = redact_pattern(input, &rules);
        assert!(out.contains("fe80::1234"));
        assert!(!out.contains("<redacted:ipv6>"));
    }
    #[test]
    fn ipv6_unique_local_passes_through() {
        let rules = patterns::defaults();
        let input = "host fd00::1 in private mesh";
        let (out, _) = redact_pattern(input, &rules);
        assert!(out.contains("fd00::1"));
        assert!(!out.contains("<redacted:ipv6>"));
    }
    #[test]
    fn is_private_ipv6_basic_classes() {
        assert!(is_private_ipv6("::"));
        assert!(is_private_ipv6("::1"));
        assert!(is_private_ipv6("fe80::1")); // link-local
        assert!(is_private_ipv6("febf::ffff")); // top of fe80::/10
        assert!(is_private_ipv6("fc00::1")); // unique-local
        assert!(is_private_ipv6("fdff::ffff")); // top of fc00::/7
                                                // Public ranges should NOT be private.
        assert!(!is_private_ipv6("2606:4700:4700::1111"));
        assert!(!is_private_ipv6("2001:db8::1"));
        // fec0::/10 (site-local) is deprecated since RFC 3879; we don't
        // treat it as private. Tool calls that surface site-local addresses
        // are misconfigurations worth seeing.
        assert!(!is_private_ipv6("fec0::1"));
    }

    #[test]
    fn is_private_ipv4_basic_classes() {
        assert!(is_private_ipv4("10.0.0.1"));
        assert!(is_private_ipv4("127.0.0.1"));
        assert!(is_private_ipv4("0.0.0.0"));
        assert!(is_private_ipv4("192.168.1.1"));
        assert!(is_private_ipv4("172.16.0.1"));
        assert!(is_private_ipv4("172.31.255.254"));
        assert!(!is_private_ipv4("8.8.8.8"));
        assert!(!is_private_ipv4("1.1.1.1"));
        assert!(!is_private_ipv4("172.15.0.1"));
        assert!(!is_private_ipv4("172.32.0.1"));
        // malformed -> safer to skip
        assert!(is_private_ipv4("not.an.ip.x"));
    }

    #[test]
    fn is_false_positive_localhost_exact() {
        // Exact "localhost" string is filtered; embedded localhost is not.
        assert!(is_false_positive("localhost", "anything", "", ""));
        assert!(!is_false_positive(
            "postgres://localhost/db",
            "conn_string",
            "",
            ""
        ));
    }

    #[test]
    fn redact_pattern_preserves_backref_for_generic_assign() {
        let rules = patterns::defaults();
        // Regression: closure-based replace must still expand $1$2 backrefs.
        let input = "password=topsecret123 done";
        let (out, _) = redact_pattern(input, &rules);
        assert!(out.contains("password=<redacted>"));
    }

    #[test]
    fn redact_pattern_preserves_backref_for_azure_guid() {
        let rules = patterns::defaults();
        let input = "TenantId: 11111111-2222-3333-4444-555555555555";
        let (out, _) = redact_pattern(input, &rules);
        assert!(out.contains("TenantId="));
        assert!(out.contains("<redacted:azure_guid>"));
    }

    // ---------- rred-13 scan_pattern ----------

    #[test]
    fn scan_emits_finding_per_match() {
        let rules = patterns::defaults();
        let txt = "line 1\nline 2\nKEY=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n";
        let findings = scan_pattern(txt, &rules);
        let f = findings.iter().find(|f| f.rule == "github_token").unwrap();
        assert_eq!(f.line, 3);
        assert_eq!(f.col, 5);
    }

    #[test]
    fn scan_finds_two_matches_same_line() {
        let rules = patterns::defaults();
        let txt = "key1=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa key2=ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n";
        let findings: Vec<_> = scan_pattern(txt, &rules)
            .into_iter()
            .filter(|f| f.rule == "github_token")
            .collect();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].line, 1);
        assert_eq!(findings[1].line, 1);
        assert!(findings[0].col < findings[1].col);
    }

    #[test]
    fn scan_empty_input_no_findings() {
        let rules = patterns::defaults();
        assert!(scan_pattern("", &rules).is_empty());
    }
}
