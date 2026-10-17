//! `.redactorignore` parser and matcher.
//!
//! Single file `~/.redactorignore` mixes two entry kinds with one heuristic:
//!
//! - **Keyword**  — plain literal term, matched case-insensitive everywhere in
//!   tool output (becomes `<redacted:keyword>`).
//! - **Path pattern** — gitignore-style glob matched against file paths in the
//!   path-guard.
//!
//! ## Heuristic per line
//!
//! 1. Trim. Empty or starts with `#` → skipped (comment).
//! 2. Leading `!` → negation, strip and recurse for type detection.
//! 3. Surrounded by double quotes → unquote, forced to be a **keyword**
//!    (escape hatch for keywords that contain path-like characters).
//! 4. Contains any of `/`, `\`, `~`, or a glob char (`*`, `?`, `[`) → **path**.
//! 5. Otherwise → **keyword**.
//!
//! ## Path expansion
//!
//! Patterns starting with `~/` are expanded against `dirs::home_dir()` at
//! parse time. Other patterns are matched verbatim by `globset` (which
//! understands `**`, `*`, `?`, `[abc]`).
//!
//! ## Self-protection
//!
//! The file `~/.redactorignore` itself is not represented in the parsed
//! struct — the path-guard in `hook.rs` has a hardcoded check that runs
//! independently of this module.

use anyhow::{Context, Result};
use globset::{Glob, GlobMatcher};
use std::path::{Path, PathBuf};

use crate::patterns::Rule;

/// Default filename: `~/.redactorignore`.
pub const IGNOREFILE_NAME: &str = ".redactorignore";

/// Returns the default location: `$HOME/.redactorignore`. None on rare
/// systems where `dirs::home_dir()` fails.
pub fn default_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(IGNOREFILE_NAME))
}

/// Resolved path with `REDACTOR_IGNOREFILE_PATH` env override (test/CI use).
/// Falls back to `default_path()`.
pub fn ignorefile_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("REDACTOR_IGNOREFILE_PATH") {
        return Some(PathBuf::from(p));
    }
    default_path()
}

/// Convenience: load the resolved file (or empty struct if missing / no
/// home dir available).
pub fn autoload() -> Result<Ignorefile> {
    match ignorefile_path() {
        Some(p) => Ignorefile::parse_file(&p),
        None => Ok(Ignorefile::default()),
    }
}

/// One path entry — the parsed pattern plus a flag for negation.
#[derive(Debug, Clone)]
pub struct PathEntry {
    /// Original line (after trimming + unquoting + negation strip).
    pub raw: String,
    /// True iff the line started with `!` (re-allow).
    pub negate: bool,
    /// Compiled glob matcher.
    pub matcher: GlobMatcher,
}

/// Parsed contents of a `.redactorignore` file.
#[derive(Debug, Default, Clone)]
pub struct Ignorefile {
    /// Literal terms (case-insensitive). Final list, deduplicated.
    pub keywords: Vec<String>,
    /// Path patterns in document order. Negations interleaved.
    pub paths: Vec<PathEntry>,
}

impl Ignorefile {
    /// Parse the textual contents of a `.redactorignore`. Invalid glob
    /// patterns produce a single error with the offending line number.
    pub fn parse(text: &str) -> Result<Self> {
        let mut out = Ignorefile::default();
        let mut seen_kw: Vec<String> = Vec::new();

        for (idx, raw_line) in text.lines().enumerate() {
            let lineno = idx + 1;
            let line = raw_line.trim_start_matches('\u{feff}').trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Detect negation.
            let (negate, body) = match line.strip_prefix('!') {
                Some(rest) => (true, rest.trim_start()),
                None => (false, line),
            };

            // Detect explicit-quoted keyword (escape hatch).
            let (forced_keyword, body) = match unquote(body) {
                Some(inner) => (true, inner),
                None => (false, body.to_string()),
            };

            if body.is_empty() {
                continue;
            }

            // Classification.
            let is_path = !forced_keyword && looks_like_path(&body);

            if is_path {
                let expanded = expand_tilde(&body);
                let glob = Glob::new(&expanded)
                    .with_context(|| format!("invalid glob pattern at line {lineno}: '{body}'"))?;
                out.paths.push(PathEntry {
                    raw: body,
                    negate,
                    matcher: glob.compile_matcher(),
                });
            } else {
                // Keyword — case-insensitive dedup.
                let lower = body.to_ascii_lowercase();
                if !seen_kw.contains(&lower) {
                    seen_kw.push(lower);
                    out.keywords.push(body);
                }
                // (Negation has no meaning for keywords — silently ignored.)
            }
        }

        Ok(out)
    }

    /// Parse a file from disk. Missing file → empty `Ignorefile` (not an
    /// error — `.redactorignore` is opt-in).
    pub fn parse_file(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(t) => Self::parse(&t),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(anyhow::Error::new(e).context(format!("read {}", path.display()))),
        }
    }

    /// Returns true iff `path` matches an include pattern AND is not later
    /// negated by a `!pattern`. Document order of negations matters
    /// (gitignore semantics).
    pub fn path_matches(&self, path: &Path) -> bool {
        let mut matched = false;
        for entry in &self.paths {
            if entry.matcher.is_match(path) {
                matched = !entry.negate;
            }
        }
        matched
    }

    /// Build keyword Rules for the redaction pipeline (same shape as
    /// `config::load_keywords_file` output).
    pub fn keyword_rules(&self) -> Vec<Rule> {
        self.keywords
            .iter()
            .filter(|w| !w.is_empty())
            .filter_map(|kw| {
                let pat = format!("(?i){}", regex::escape(kw));
                Rule::new("keyword", &pat, "<redacted:keyword>").ok()
            })
            .collect()
    }
}

/// Returns the inner string if `s` is wrapped in matching `"..."`.
fn unquote(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"' {
        Some(s[1..s.len() - 1].to_string())
    } else {
        None
    }
}

/// Heuristic: does this look like a path pattern rather than a literal keyword?
fn looks_like_path(s: &str) -> bool {
    s.contains('/')
        || s.contains('\\')
        || s.starts_with('~')
        || s.contains('*')
        || s.contains('?')
        || s.contains('[')
}

/// Expand `~/foo` → `<home>/foo`. Leaves other strings untouched.
fn expand_tilde(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return format!("{}/{}", home.display(), rest);
        }
    }
    s.to_string()
}

// ============================================================================
// Shared test plumbing
// ============================================================================
//
// Several tests mutate process-wide env vars (`REDACTOR_IGNOREFILE_PATH`,
// `REDACTOR_CONFIG_DIR`). They must NOT run in parallel — but they live in
// different modules. Expose a single shared mutex so every test module can
// serialize via the same lock. Includes poison-recovery: a panic in one
// test does NOT cascade to the next.

#[cfg(test)]
pub(crate) fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    let m = L.get_or_init(|| Mutex::new(()));
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_yields_empty_struct() {
        let f = Ignorefile::parse("").unwrap();
        assert!(f.keywords.is_empty());
        assert!(f.paths.is_empty());
    }

    #[test]
    fn comments_and_blank_lines_skipped() {
        let f = Ignorefile::parse("# hi\n\n# bye\n").unwrap();
        assert!(f.keywords.is_empty());
        assert!(f.paths.is_empty());
    }

    #[test]
    fn keyword_plain_term() {
        let f = Ignorefile::parse("Alice Mustermann\nBob\n").unwrap();
        assert_eq!(f.keywords, vec!["Alice Mustermann", "Bob"]);
        assert!(f.paths.is_empty());
    }

    #[test]
    fn path_detected_by_slash() {
        let f = Ignorefile::parse("foo/bar\n").unwrap();
        assert!(f.keywords.is_empty());
        assert_eq!(f.paths.len(), 1);
        assert_eq!(f.paths[0].raw, "foo/bar");
        assert!(!f.paths[0].negate);
    }

    #[test]
    fn path_detected_by_tilde_prefix() {
        let f = Ignorefile::parse("~/Documents/Steuer/\n").unwrap();
        assert_eq!(f.paths.len(), 1);
        assert_eq!(f.keywords.len(), 0);
    }

    #[test]
    fn path_detected_by_glob_star() {
        let f = Ignorefile::parse("*.kdbx\n").unwrap();
        assert_eq!(f.paths.len(), 1);
        assert!(f.keywords.is_empty());
    }

    #[test]
    fn path_detected_by_question_mark() {
        let f = Ignorefile::parse("file?.bak\n").unwrap();
        assert_eq!(f.paths.len(), 1);
    }

    #[test]
    fn path_detected_by_charclass() {
        let f = Ignorefile::parse("file[0-9].txt\n").unwrap();
        assert_eq!(f.paths.len(), 1);
    }

    #[test]
    fn path_detected_by_backslash() {
        let f = Ignorefile::parse("C:\\Users\\Foo\\secrets.txt\n").unwrap();
        assert_eq!(f.paths.len(), 1);
    }

    #[test]
    fn quoted_string_forces_keyword_even_with_slash() {
        let f = Ignorefile::parse("\"example.com/internal-path\"\n").unwrap();
        assert_eq!(f.keywords, vec!["example.com/internal-path"]);
        assert!(f.paths.is_empty());
    }

    #[test]
    fn negation_recognized() {
        let f = Ignorefile::parse("~/Documents/Steuer/\n!~/Documents/Steuer/musterbeleg.pdf\n")
            .unwrap();
        assert_eq!(f.paths.len(), 2);
        assert!(!f.paths[0].negate);
        assert!(f.paths[1].negate);
    }

    #[test]
    fn negation_with_space_after_bang() {
        let f = Ignorefile::parse("!  /etc/foo\n").unwrap();
        assert_eq!(f.paths.len(), 1);
        assert!(f.paths[0].negate);
        assert_eq!(f.paths[0].raw, "/etc/foo");
    }

    #[test]
    fn keyword_dedup_case_insensitive() {
        let f = Ignorefile::parse("Alice\nALICE\nalice\n").unwrap();
        // First-occurrence wins, others dropped.
        assert_eq!(f.keywords, vec!["Alice"]);
    }

    #[test]
    fn bom_at_file_start_is_stripped() {
        let f = Ignorefile::parse("\u{feff}Alice\n").unwrap();
        assert_eq!(f.keywords, vec!["Alice"]);
    }

    #[test]
    fn crlf_line_endings_handled() {
        let f = Ignorefile::parse("Alice\r\nBob\r\n").unwrap();
        assert_eq!(f.keywords, vec!["Alice", "Bob"]);
    }

    #[test]
    fn whitespace_trimmed_around_lines() {
        let f = Ignorefile::parse("   Alice  \n\t Bob \t\n").unwrap();
        assert_eq!(f.keywords, vec!["Alice", "Bob"]);
    }

    #[test]
    fn invalid_glob_pattern_errors_with_line_number() {
        // `[` is the start of a char class — unclosed → invalid glob.
        let res = Ignorefile::parse("foo[bar\n");
        assert!(res.is_err());
        let msg = format!("{:#}", res.unwrap_err());
        assert!(msg.contains("line 1"), "expected 'line 1' in: {msg}");
    }

    #[test]
    fn parse_file_missing_returns_empty() {
        let f = Ignorefile::parse_file(Path::new("/nonexistent/__never__.redactorignore")).unwrap();
        assert!(f.keywords.is_empty());
        assert!(f.paths.is_empty());
    }

    #[test]
    fn parse_file_reads_from_disk() {
        let td = tempfile::tempdir().unwrap();
        let p = td.path().join(".redactorignore");
        std::fs::write(&p, "Alice\n~/foo/\n").unwrap();
        let f = Ignorefile::parse_file(&p).unwrap();
        assert_eq!(f.keywords, vec!["Alice"]);
        assert_eq!(f.paths.len(), 1);
    }

    // ---------- path matching ----------

    #[test]
    fn path_matches_simple_pattern() {
        let f = Ignorefile::parse("/etc/shadow\n").unwrap();
        assert!(f.path_matches(Path::new("/etc/shadow")));
        assert!(!f.path_matches(Path::new("/etc/passwd")));
    }

    #[test]
    fn path_matches_glob_star() {
        let f = Ignorefile::parse("*.kdbx\n").unwrap();
        // globset's *.kdbx matches basename-style; full-path matching needs **/
        assert!(f.path_matches(Path::new("vault.kdbx")));
    }

    #[test]
    fn path_matches_doublestar_recursive() {
        let f = Ignorefile::parse("~/Documents/**/*.pdf\n").unwrap();
        let home = dirs::home_dir().unwrap();
        let target = home.join("Documents/Steuer/2024/x.pdf");
        assert!(f.path_matches(&target));
    }

    #[test]
    fn path_matches_negation_overrides_include() {
        let f = Ignorefile::parse("~/Documents/Steuer/**\n!~/Documents/Steuer/musterbeleg.pdf\n")
            .unwrap();
        let home = dirs::home_dir().unwrap();
        let inside = home.join("Documents/Steuer/2024.pdf");
        let exempt = home.join("Documents/Steuer/musterbeleg.pdf");
        assert!(f.path_matches(&inside));
        assert!(!f.path_matches(&exempt));
    }

    #[test]
    fn path_matches_negation_order_matters() {
        // Negation appearing BEFORE the broader pattern does NOT exempt —
        // the later include wins (gitignore semantics).
        let f = Ignorefile::parse("!~/Documents/Steuer/musterbeleg.pdf\n~/Documents/Steuer/**\n")
            .unwrap();
        let home = dirs::home_dir().unwrap();
        let exempt = home.join("Documents/Steuer/musterbeleg.pdf");
        assert!(f.path_matches(&exempt)); // include came after, wins
    }

    // ---------- keyword rules ----------

    #[test]
    fn keyword_rules_redact_case_insensitive() {
        let f = Ignorefile::parse("Alice\nProject-Nighthawk\n").unwrap();
        let rules = f.keyword_rules();
        assert_eq!(rules.len(), 2);

        let out = rules[0]
            .regex
            .replace_all("hello ALICE today", &rules[0].replacement[..]);
        assert!(out.contains("<redacted:keyword>"));
    }

    #[test]
    fn keyword_rules_special_chars_escaped() {
        // Period and dash in the keyword must NOT be regex-active.
        let f = Ignorefile::parse("\"a.b\"\n").unwrap();
        let rules = f.keyword_rules();
        let out = rules[0]
            .regex
            .replace_all("x axb y", &rules[0].replacement[..]);
        assert_eq!(out, "x axb y", "period must be literal");
    }

    // ---------- mixed-content integration ----------

    #[test]
    fn mixed_keywords_and_paths_parse_correctly() {
        let text = "\
# customers
Alice Mustermann
PROJECT-NIGHTHAWK

# paths
~/Documents/Steuer/**
*.kdbx
!~/Documents/Steuer/musterbeleg.pdf

# escaped keyword that LOOKS like a path
\"https://example.com\"
";
        let f = Ignorefile::parse(text).unwrap();
        assert_eq!(
            f.keywords,
            vec![
                "Alice Mustermann",
                "PROJECT-NIGHTHAWK",
                "https://example.com"
            ]
        );
        assert_eq!(f.paths.len(), 3);
        assert!(!f.paths[0].negate);
        assert!(!f.paths[1].negate);
        assert!(f.paths[2].negate);
    }
}
