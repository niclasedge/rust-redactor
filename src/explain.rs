//! Phase 6d — `redactor explain <target>` subcommand.
//!
//! Surfaces *why* a path or string would be blocked / redacted:
//! - which path-guard rule (hardcoded sensitive, crypto, office-doc, …)
//! - which `~/.redactorignore` line (path glob or keyword)
//! - which built-in pattern rule (matched against the literal text)
//!
//! Output is a small table on stdout. Returns 0 on success regardless of
//! whether any rules matched — explain is informational.

use crate::ignorefile;
use crate::patterns;
use crate::redactor;
use anyhow::Result;
use std::path::Path;

#[derive(Debug, Clone)]
struct Hit {
    source: String,
    rule_or_line: String,
    category: String,
}

const CRYPTO_EXTS: &[(&str, &str)] = &[
    (".kdbx", "KeePass database"),
    (".kdb", "KeePass database (legacy)"),
    (".gpg", "GPG-encrypted file"),
    (".pgp", "PGP-encrypted file"),
    (".asc", "ASCII-armored PGP file"),
    (".age", "age-encrypted file"),
    (".p12", "PKCS#12 cert bundle"),
    (".pfx", "PKCS#12 cert bundle"),
    (".keychain-db", "macOS Keychain"),
];

const OFFICE_EXTS: &[(&str, &str)] = &[
    (".xlsx", "Excel workbook"),
    (".xls", "Excel workbook (legacy)"),
    (".xlsm", "Excel workbook (macro)"),
    (".docx", "Word document"),
    (".doc", "Word document (legacy)"),
    (".pptx", "PowerPoint presentation"),
    (".ppt", "PowerPoint presentation (legacy)"),
    (".pdf", "PDF document"),
];

const SENSITIVE_PATTERNS: &[(&str, &str)] = &[
    (r"(^|[\s/=:])\.env(\.|$|[\s])", ".env"),
    (r"(^|[\s/=:])\.envrc($|\.|[\s])", ".envrc"),
    (r"/id_rsa($|\.|/)", "id_rsa"),
    (r"/\.aws/(credentials|config)", "AWS creds"),
    (r"/secrets/", "/secrets/ folder"),
    (r"[/~]\S*\.pem($|[^A-Za-z0-9_])", ".pem"),
    (r"[/~]\S*\.key($|[^A-Za-z0-9_])", ".key"),
    (r"/\.netrc($|\.)", ".netrc"),
    (r"/\.ssh/[^\s]+", ".ssh/"),
];

fn collect_path_hits(target: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    let lower = target.to_ascii_lowercase();

    // 1. self-protect
    if let Some(home_ign) = ignorefile::ignorefile_path() {
        let home_str = home_ign.display().to_string();
        if target == home_str || target.contains(&home_str) || target.contains("~/.redactorignore")
        {
            hits.push(Hit {
                source: "self-protect".into(),
                rule_or_line: home_str.clone(),
                category: "unblockable".into(),
            });
        }
    }

    // 2. crypto containers
    for (ext, label) in CRYPTO_EXTS {
        if lower.contains(ext) {
            hits.push(Hit {
                source: "crypto-container".into(),
                rule_or_line: format!("{ext} ({label})"),
                category: "unblockable".into(),
            });
            break;
        }
    }

    // 3. sensitive path patterns
    for (pat, label) in SENSITIVE_PATTERNS {
        if let Ok(re) = regex::Regex::new(pat) {
            if re.is_match(target) {
                // .ssh/known_hosts allowlist
                if *label == ".ssh/" && target.contains(".ssh/known_hosts") {
                    continue;
                }
                hits.push(Hit {
                    source: "sensitive-path".into(),
                    rule_or_line: format!("{label} ({pat})"),
                    category: "hardcoded".into(),
                });
                break;
            }
        }
    }

    // 4. office docs (read-block)
    for (ext, label) in OFFICE_EXTS {
        if lower.ends_with(ext) {
            hits.push(Hit {
                source: "office-doc".into(),
                rule_or_line: format!("{ext} ({label})"),
                category: "default-block".into(),
            });
            break;
        }
    }

    // 5. ~/.redactorignore path entries
    if let Ok(f) = ignorefile::autoload() {
        let p = Path::new(target);
        if f.path_matches(p) {
            // Find which include pattern matched (last include wins).
            let mut last_include: Option<(usize, &str)> = None;
            for (idx, entry) in f.paths.iter().enumerate() {
                if entry.matcher.is_match(p) && !entry.negate {
                    last_include = Some((idx + 1, &entry.raw));
                }
            }
            if let Some((line_no, raw)) = last_include {
                hits.push(Hit {
                    source: "user-path".into(),
                    rule_or_line: format!("~/.redactorignore:{line_no} `{raw}`"),
                    category: "user_path".into(),
                });
            }
        }
    }

    hits
}

fn collect_keyword_hits(text: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    if let Ok(f) = ignorefile::autoload() {
        for (idx, kw) in f.keywords.iter().enumerate() {
            if text.to_lowercase().contains(&kw.to_lowercase()) {
                hits.push(Hit {
                    source: "user-keyword".into(),
                    rule_or_line: format!("~/.redactorignore keyword #{} `{kw}`", idx + 1),
                    category: "user_keyword".into(),
                });
            }
        }
    }
    hits
}

fn collect_pattern_hits(text: &str) -> Vec<Hit> {
    let mut hits = Vec::new();
    for rule in patterns::defaults() {
        if rule.regex.find(text).is_some() {
            // Phase 6d FP-filter alignment with redactor.rs::is_false_positive
            // (only filter the obvious doc-substring case; this is informational).
            let matched = rule.regex.find(text).unwrap().as_str();
            if redactor::is_false_positive(matched, &rule.name, "", "") {
                continue;
            }
            hits.push(Hit {
                source: "pattern-match".into(),
                rule_or_line: format!("patterns.rs::{}", rule.name),
                category: "builtin".into(),
            });
        }
    }
    hits
}

/// Entry point: `redactor explain <target>`.
pub fn run_explain(target: &str) -> Result<i32> {
    if target.is_empty() {
        eprintln!("explain: nothing to explain (empty target)");
        return Ok(0);
    }

    let mut all_hits = Vec::new();
    all_hits.extend(collect_path_hits(target));
    all_hits.extend(collect_keyword_hits(target));
    all_hits.extend(collect_pattern_hits(target));

    if all_hits.is_empty() {
        println!("explain: '{target}' would not be blocked or redacted by any active rule.");
        return Ok(0);
    }

    println!();
    println!("redactor explain: '{target}'");
    println!();
    println!("{:20}  {:50}  category", "block source", "rule/line");
    println!("{}", "─".repeat(96));
    for h in &all_hits {
        println!(
            "{:20}  {:50}  {}",
            h.source,
            truncate(&h.rule_or_line, 50),
            h.category
        );
    }
    println!();
    Ok(0)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max - 1).collect();
        format!("{truncated}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_target_returns_zero() {
        assert_eq!(run_explain("").unwrap(), 0);
    }

    #[test]
    fn crypto_container_path_is_detected() {
        let hits = collect_path_hits("/Users/x/vault.kdbx");
        assert!(hits
            .iter()
            .any(|h| h.source == "crypto-container" && h.rule_or_line.contains(".kdbx")));
    }

    #[test]
    fn office_doc_is_detected() {
        let hits = collect_path_hits("/Users/x/report.pdf");
        assert!(hits.iter().any(|h| h.source == "office-doc"));
    }

    #[test]
    fn sensitive_env_path_is_detected() {
        let hits = collect_path_hits("/home/x/.env.local");
        assert!(hits.iter().any(|h| h.source == "sensitive-path"));
    }

    #[test]
    fn ssh_known_hosts_is_allowlisted() {
        let hits = collect_path_hits("/home/x/.ssh/known_hosts");
        assert!(!hits.iter().any(|h| h.source == "sensitive-path"));
    }

    #[test]
    fn pattern_match_on_aws_key_is_detected() {
        let hits = collect_pattern_hits("AKIAIOSFODNN7EXAMPLE");
        assert!(hits
            .iter()
            .any(|h| h.rule_or_line.contains("aws_access_key")));
    }

    #[test]
    fn no_match_means_empty_hits() {
        let hits = collect_path_hits("/tmp/just-a-readme.md");
        assert!(hits.is_empty());
    }
}
