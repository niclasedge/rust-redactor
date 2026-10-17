//! Config-file conventions and keyword-file loading.
//!
//! Default config directory:
//!   - `$REDACTOR_CONFIG_DIR` if set
//!   - else platform-native config home + "redactor":
//!     - macOS:   `~/Library/Application Support/redactor/`
//!     - Linux:   `~/.config/redactor/`
//!     - Windows: `%APPDATA%\redactor\`
//!
//! Auto-loaded files (additive to CLI flags):
//!   - `keywords.txt`  — line-per-keyword, `#` comments, blank lines ignored
//!   - `patterns.json` — same schema as `--patterns FILE`

use crate::patterns::{self, Rule};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub const KEYWORDS_FILE: &str = "keywords.txt";
pub const PATTERNS_FILE: &str = "patterns.json";

pub fn config_dir() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("REDACTOR_CONFIG_DIR") {
        return Some(PathBuf::from(p));
    }
    dirs::config_dir().map(|d| d.join("redactor"))
}

/// Load keywords from a file. Returns regex Rules ready to push into the rule list.
///
/// Format detection by extension:
///   - `.json`             → array of strings: `["alice", "bob"]`
///   - `.txt` / `.list` / no ext → one keyword per line, `#` comments
pub fn load_keywords_file(path: &Path) -> Result<Vec<Rule>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read keywords file {}", path.display()))?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();

    let words: Vec<String> = match ext.as_str() {
        "json" => parse_json_keywords(&text)?,
        _ => parse_text_keywords(&text),
    };

    Ok(words
        .into_iter()
        .filter(|w| !w.is_empty())
        .filter_map(|kw| {
            let pat = format!("(?i){}", regex::escape(&kw));
            Rule::new("keyword", &pat, "<redacted:keyword>").ok()
        })
        .collect())
}

fn parse_text_keywords(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

fn parse_json_keywords(text: &str) -> Result<Vec<String>> {
    let arr: Vec<String> = serde_json::from_str(text)
        .context("expected JSON array of strings, e.g. [\"alice\",\"bob\"]")?;
    Ok(arr)
}

/// Auto-load keyword + pattern rules.
///
/// Source-of-truth precedence:
///   1. `~/.redactorignore` (v0.7+) — preferred. Keywords are extracted via
///      `ignorefile::Ignorefile::keyword_rules`.
///   2. Legacy `<config>/keywords.txt` — loaded only if `.redactorignore`
///      does NOT exist. A deprecation warning is emitted to stderr.
///   3. `<config>/patterns.json` is independent and always loaded.
///
/// When BOTH `.redactorignore` and `keywords.txt` exist, only
/// `.redactorignore` is used and a warning is emitted (legacy file is
/// stale).
pub fn autoload_rules() -> Result<Vec<Rule>> {
    let mut out = Vec::new();

    let ignorefile_path = crate::ignorefile::ignorefile_path();
    let ignorefile_exists = ignorefile_path
        .as_ref()
        .map(|p| p.exists())
        .unwrap_or(false);

    let legacy_kw = config_dir().map(|d| d.join(KEYWORDS_FILE));
    let legacy_exists = legacy_kw.as_ref().map(|p| p.exists()).unwrap_or(false);

    if ignorefile_exists {
        let f = crate::ignorefile::autoload()?;
        out.extend(f.keyword_rules());
        if legacy_exists {
            eprintln!(
                "[redactor] warning: legacy {KEYWORDS_FILE} found alongside ~/.redactorignore."
            );
            eprintln!(
                "          Only ~/.redactorignore is used. Run `redactor migrate-keywords` to retire the legacy file."
            );
        }
    } else if legacy_exists {
        let legacy = legacy_kw.unwrap();
        eprintln!(
            "[redactor] warning: {} is deprecated as of v0.7.0.",
            legacy.display()
        );
        eprintln!("          Run `redactor migrate-keywords` to convert to ~/.redactorignore.");
        out.extend(load_keywords_file(&legacy)?);
    }

    if let Some(dir) = config_dir() {
        let pat = dir.join(PATTERNS_FILE);
        if pat.exists() {
            out.extend(patterns::load_custom(&pat)?);
        }
    }

    Ok(out)
}

/// `redactor init-config` — write starter files into the config dir.
pub fn init_config(force: bool) -> Result<PathBuf> {
    let dir = config_dir().context("could not determine config directory")?;
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;

    let kw_path = dir.join(KEYWORDS_FILE);
    if !kw_path.exists() || force {
        std::fs::write(
            &kw_path,
            "# redactor keywords - one literal term per line.\n\
             # Lines starting with `#` and blank lines are ignored.\n\
             # Matching is case-insensitive (LENOVO matches lenovo, Lenovo, LeNoVo).\n\
             # Every match becomes <redacted:keyword> in any redactor invocation.\n\
             #\n\
             # Active examples (delete or comment lines you don't want):\n\
             LENOVO\n\
             ACMECORP\n\
             #\n\
             # Add more, one per line. Common choices:\n\
             #   - customer / company names you don't want in chat context\n\
             #   - internal project codenames\n\
             #   - sensitive hostnames (e.g. internal-host.corp)\n\
             #   - personal email addresses\n",
        )?;
    }

    let pat_path = dir.join(PATTERNS_FILE);
    if !pat_path.exists() || force {
        std::fs::write(
            &pat_path,
            "[\n  \
                {\"name\": \"email\", \"re\": \"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\\\.[A-Za-z]{2,}\"}\n]\n",
        )?;
    }

    Ok(dir)
}

// ============================================================================
// rred-8..11 — per-project .redactor.toml support
// ============================================================================

use crate::redactor::Mode;
use serde::Deserialize;
use std::collections::HashMap;

pub const PROJECT_CONFIG_FILE: &str = ".redactor.toml";

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ProjectConfig {
    pub patterns: PatternsSection,
    pub whitelist: WhitelistSection,
    pub modes: ModesSection,
    pub policy: PolicySection,
    pub allow: AllowSection,
}

/// v0.7 — project-level overrides for the path-guard. Distinguished from
/// `[whitelist]` (pattern-skip semantics) by name: `[allow]` says
/// "let these tool calls through" while `[whitelist]` says "skip secret
/// detection in these files".
///
/// `paths` accepts gitignore-style globs (compiled via `globset`).
/// `filetypes` is a list of bare extensions (no leading dot) that re-enables
/// the corresponding default office-doc block project-wide — useful for
/// projects with legitimate `.xlsx` / `.docx` test fixtures.
///
/// `[allow]` is **incapable** of overriding unblockable categories:
/// `~/.redactorignore` self-protect, crypto containers (`.kdbx` etc.), or
/// the hardcoded `.env`/`.ssh`/`.aws/credentials` family. See spec §3.3.
#[derive(Debug, Default, Deserialize, Clone)]
#[serde(default)]
pub struct AllowSection {
    pub paths: Vec<String>,
    pub filetypes: Vec<String>,
    /// Phase 6b — case-insensitive substrings that should never appear as
    /// keyword suggestions in `.redactorignore.keywords.suggested`. Useful
    /// for GLiNER false-positives that the entity-type filter doesn't catch
    /// (e.g. long Markdown titles labelled as ORGANIZATION). Lookup is a
    /// substring-contains, so `"obsidian"` blocks `"obsidian vault"`,
    /// `"Obsidian Plugin Dev"`, etc.
    pub keywords: Vec<String>,
}

/// Per-project policy switches that toggle hook strictness. All fields default
/// to the secure-by-default behaviour; a project's `.redactor.toml` can opt
/// out of individual checks where the trade-off makes sense locally.
#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct PolicySection {
    /// When `true` (default), `.json` / `.jsonl` / `.ndjson` reads are forced
    /// through `redactor --type json <file>` (direct mode). Setting `false`
    /// lets pattern-mode handle the content — useful when the agent legitimately
    /// needs the raw structure (Power Automate exports, package manifests,
    /// hook-payload fixtures, …).
    pub strict_json: bool,

    /// When `true`, the current user's `$USERNAME` / `$USER` and
    /// every `C:\Users\<x>` / `/home/<x>` / `/Users/<x>` path segment is
    /// redacted as `<redacted:username>` in tool output. Default is `false`
    /// (since v0.7.1) — home-dir paths flow through verbatim, which matches
    /// the common path-heavy workflow. Set `true` in `.redactor.toml` for
    /// projects that share screenshots / pastes with non-trusted parties.
    pub mask_username: bool,
}

impl Default for PolicySection {
    fn default() -> Self {
        Self {
            strict_json: true,
            mask_username: false,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct PatternsSection {
    pub custom: Vec<PatternEntry>,
}

#[derive(Debug, Deserialize)]
pub struct PatternEntry {
    pub name: String,
    pub re: String,
    #[serde(default)]
    pub sub: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct WhitelistSection {
    pub paths: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, transparent)]
pub struct ModesSection {
    pub by_ext: HashMap<String, String>,
}

/// Walk from `start` up the directory tree, returning the first
/// `.redactor.toml` found. `None` if none exists between `start` and `/`.
pub fn discover_project_config(start: &Path) -> Option<PathBuf> {
    let mut cur: Option<&Path> = Some(start);
    while let Some(d) = cur {
        let candidate = d.join(PROJECT_CONFIG_FILE);
        if candidate.is_file() {
            return Some(candidate);
        }
        cur = d.parent();
    }
    None
}

/// Parse a `.redactor.toml`. Errors include the file path in their message.
pub fn load_project_config(path: &Path) -> Result<ProjectConfig> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let cfg: ProjectConfig =
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    Ok(cfg)
}

/// Convert `[[patterns.custom]]` entries to runtime `Rule`s. The default
/// replacement is `<redacted:<name>>` if `sub` is omitted.
pub fn project_rules(cfg: &ProjectConfig) -> Result<Vec<Rule>> {
    let mut out = Vec::with_capacity(cfg.patterns.custom.len());
    for entry in &cfg.patterns.custom {
        let sub = entry
            .sub
            .clone()
            .unwrap_or_else(|| format!("<redacted:{}>", entry.name));
        let rule = Rule::new(&entry.name, &entry.re, &sub)
            .with_context(|| format!("invalid pattern '{}' in .redactor.toml", entry.name))?;
        out.push(rule);
    }
    Ok(out)
}

/// Convert `[modes]` entries to a `HashMap<ext, Mode>`. Unknown mode-strings
/// log a warning to stderr and are silently skipped (fail-open). Extension
/// keys are normalized: lowercase + leading `.` stripped.
pub fn project_modes(cfg: &ProjectConfig) -> HashMap<String, Mode> {
    let mut out = HashMap::new();
    for (ext, name) in &cfg.modes.by_ext {
        match name.parse::<Mode>() {
            Ok(m) => {
                let key = ext.trim_start_matches('.').to_ascii_lowercase();
                out.insert(key, m);
            }
            Err(_) => eprintln!(
                "[redactor] .redactor.toml: unknown mode '{name}' for ext '{ext}' (skipped)"
            ),
        }
    }
    out
}

/// Discover and load `.redactor.toml`, returning the runtime rules. No file
/// found → `Ok(vec![])`. Errors only when a file IS found but malformed or
/// contains an invalid regex.
pub fn autoload_project_rules(start: &Path) -> Result<Vec<Rule>> {
    let Some(path) = discover_project_config(start) else {
        return Ok(vec![]);
    };
    let cfg = load_project_config(&path)?;
    project_rules(&cfg)
}

/// Discover and load whitelist paths. Empty if no file or no `[whitelist]`.
pub fn autoload_project_whitelist(start: &Path) -> Result<Vec<String>> {
    let Some(path) = discover_project_config(start) else {
        return Ok(vec![]);
    };
    let cfg = load_project_config(&path)?;
    Ok(cfg.whitelist.paths.clone())
}

/// Discover and load mode overrides. Empty map if no file or no `[modes]`.
pub fn autoload_project_modes(start: &Path) -> Result<HashMap<String, Mode>> {
    let Some(path) = discover_project_config(start) else {
        return Ok(HashMap::new());
    };
    let cfg = load_project_config(&path)?;
    Ok(project_modes(&cfg))
}

/// Discover and load the `[policy]` section. Falls back to `PolicySection::default()`
/// (strict-by-default) when no `.redactor.toml` is found, when the file omits
/// `[policy]`, or when the file fails to parse — strictness wins on uncertainty.
pub fn autoload_project_policy(start: &Path) -> Result<PolicySection> {
    let Some(path) = discover_project_config(start) else {
        return Ok(PolicySection::default());
    };
    let cfg = load_project_config(&path)?;
    Ok(cfg.policy)
}

/// Discover and load the `[allow]` section. Returns the project-local
/// `[allow]` (walked up from `start`) MERGED with any `[allow]` from
/// `~/.redactor.toml` (global defaults). Lists (`paths`, `filetypes`,
/// `keywords`) are concatenated. When the project-config IS `~/.redactor.toml`
/// (i.e. cwd is at/above `$HOME`), it's loaded only once.
///
/// Empty `AllowSection::default()` when neither file exists.
pub fn autoload_project_allow(start: &Path) -> Result<AllowSection> {
    let project_path = discover_project_config(start);
    let mut allow = match project_path.as_ref() {
        Some(p) => load_project_config(p)?.allow,
        None => AllowSection::default(),
    };

    // Always also pull in `~/.redactor.toml` (global defaults) when it's
    // distinct from the project file. Walks-up "first wins" means a
    // project-local `.redactor.toml` would otherwise hide the global one.
    if let Some(home) = dirs::home_dir() {
        let global = home.join(PROJECT_CONFIG_FILE);
        let same_file = project_path.as_ref().map(|p| p == &global).unwrap_or(false);
        if !same_file && global.is_file() {
            match load_project_config(&global) {
                Ok(g) => {
                    allow.paths.extend(g.allow.paths);
                    allow.filetypes.extend(g.allow.filetypes);
                    allow.keywords.extend(g.allow.keywords);
                }
                Err(e) => {
                    eprintln!("[redactor] warning: failed to load global ~/.redactor.toml: {e}");
                }
            }
        }
    }
    Ok(allow)
}

/// True iff `target` matches an `[allow].paths` glob (relative or absolute,
/// compiled via `globset`) OR if its extension is in `[allow].filetypes`.
///
/// Extension matching is case-insensitive and accepts both `"xlsx"` and
/// `".xlsx"` in the config list (we normalize).
pub fn allow_matches(allow: &AllowSection, target: &str) -> bool {
    use globset::Glob;
    use std::path::Path;

    // 1. paths — gitignore-style glob match
    let p = Path::new(target);
    for pat in &allow.paths {
        if let Ok(glob) = Glob::new(pat) {
            let m = glob.compile_matcher();
            if m.is_match(p) || m.is_match(target) {
                return true;
            }
        }
    }

    // 2. filetypes — normalize and compare extensions
    if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
        let ext_lower = ext.to_ascii_lowercase();
        for raw in &allow.filetypes {
            let cleaned = raw.trim_start_matches('.').to_ascii_lowercase();
            if cleaned == ext_lower {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parse_txt_keywords_with_comments() {
        let s = "# header\nalice\n\nbob \n# tail\n  carol  \n";
        let words = parse_text_keywords(s);
        assert_eq!(words, vec!["alice", "bob", "carol"]);
    }

    #[test]
    fn parse_json_array_of_strings() {
        let words = parse_json_keywords(r#"["alice","bob","carol"]"#).unwrap();
        assert_eq!(words, vec!["alice", "bob", "carol"]);
    }

    #[test]
    fn load_keywords_file_txt() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("k.txt");
        std::fs::write(&p, "# c\nalice\nBob\n").unwrap();
        let rules = load_keywords_file(&p).unwrap();
        assert_eq!(rules.len(), 2);
        let red = rules[0]
            .regex
            .replace_all("found ALICE today", &rules[0].replacement[..]);
        assert!(red.contains("<redacted:keyword>"));
    }

    #[test]
    fn load_keywords_file_json() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("k.json");
        std::fs::write(&p, r#"["alpha","beta"]"#).unwrap();
        let rules = load_keywords_file(&p).unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn init_creates_files() {
        let _g = crate::ignorefile::test_env_lock();
        let dir = tempdir().unwrap();
        std::env::set_var("REDACTOR_CONFIG_DIR", dir.path());
        let written = init_config(false).unwrap();
        assert!(written.join("keywords.txt").exists());
        assert!(written.join("patterns.json").exists());
        std::env::remove_var("REDACTOR_CONFIG_DIR");
    }

    // ---------- v0.7 .redactorignore loader ----------
    //
    // These tests mutate two process-wide env vars together — they must NOT
    // run in parallel. We serialize via the shared mutex in `ignorefile`
    // so config tests + hook tests serialize together.

    struct EnvScope {
        prev_cfg: Option<String>,
        prev_ign: Option<String>,
    }
    impl EnvScope {
        fn new(cfg: &Path, ignorefile: Option<&Path>) -> Self {
            let prev_cfg = std::env::var("REDACTOR_CONFIG_DIR").ok();
            let prev_ign = std::env::var("REDACTOR_IGNOREFILE_PATH").ok();
            std::env::set_var("REDACTOR_CONFIG_DIR", cfg);
            match ignorefile {
                Some(p) => std::env::set_var("REDACTOR_IGNOREFILE_PATH", p),
                None => std::env::remove_var("REDACTOR_IGNOREFILE_PATH"),
            }
            Self { prev_cfg, prev_ign }
        }
    }
    impl Drop for EnvScope {
        fn drop(&mut self) {
            match self.prev_cfg.take() {
                Some(v) => std::env::set_var("REDACTOR_CONFIG_DIR", v),
                None => std::env::remove_var("REDACTOR_CONFIG_DIR"),
            }
            match self.prev_ign.take() {
                Some(v) => std::env::set_var("REDACTOR_IGNOREFILE_PATH", v),
                None => std::env::remove_var("REDACTOR_IGNOREFILE_PATH"),
            }
        }
    }

    #[test]
    fn autoload_uses_redactorignore_when_present() {
        let _g = crate::ignorefile::test_env_lock();
        let cfg = tempdir().unwrap();
        let ign = cfg.path().join(".redactorignore");
        std::fs::write(&ign, "Alpha\nBeta\n").unwrap();
        let _scope = EnvScope::new(cfg.path(), Some(&ign));

        let rules = autoload_rules().unwrap();
        // Two keywords from .redactorignore, no other sources.
        assert_eq!(rules.len(), 2);
        let out = rules[0]
            .regex
            .replace_all("see ALPHA today", &rules[0].replacement[..]);
        assert!(out.contains("<redacted:keyword>"));
    }

    #[test]
    fn autoload_falls_back_to_legacy_keywords_txt() {
        let _g = crate::ignorefile::test_env_lock();
        let cfg = tempdir().unwrap();
        std::fs::write(cfg.path().join("keywords.txt"), "Legacy1\nLegacy2\n").unwrap();
        // .redactorignore points at a nonexistent path → triggers legacy path
        let _scope = EnvScope::new(
            cfg.path(),
            Some(&cfg.path().join("__nonexistent__.redactorignore")),
        );

        let rules = autoload_rules().unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn autoload_prefers_redactorignore_when_both_exist() {
        let _g = crate::ignorefile::test_env_lock();
        let cfg = tempdir().unwrap();
        let ign = cfg.path().join(".redactorignore");
        std::fs::write(&ign, "NewWord\n").unwrap();
        std::fs::write(cfg.path().join("keywords.txt"), "LegacyA\nLegacyB\n").unwrap();
        let _scope = EnvScope::new(cfg.path(), Some(&ign));

        let rules = autoload_rules().unwrap();
        // Only the one keyword from .redactorignore — legacy is ignored.
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn autoload_empty_when_no_sources() {
        let _g = crate::ignorefile::test_env_lock();
        let cfg = tempdir().unwrap();
        let _scope = EnvScope::new(
            cfg.path(),
            Some(&cfg.path().join("__nonexistent__.redactorignore")),
        );
        let rules = autoload_rules().unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn autoload_combines_redactorignore_with_patterns_json() {
        let _g = crate::ignorefile::test_env_lock();
        let cfg = tempdir().unwrap();
        let ign = cfg.path().join(".redactorignore");
        std::fs::write(&ign, "Alpha\n").unwrap();
        std::fs::write(
            cfg.path().join("patterns.json"),
            r#"[{"name":"int","re":"INT-\\d+"}]"#,
        )
        .unwrap();
        let _scope = EnvScope::new(cfg.path(), Some(&ign));

        let rules = autoload_rules().unwrap();
        // 1 keyword + 1 custom pattern
        assert_eq!(rules.len(), 2);
    }

    // ---------- v0.7 [allow] section ----------

    #[test]
    fn allow_section_parses_paths_and_filetypes() {
        let td = tempfile::tempdir().unwrap();
        let body = r#"
[allow]
paths = ["fixtures/sample.xlsx", "data/**/*.docx"]
filetypes = ["xlsx", "docx"]
"#;
        write_cfg(td.path(), body);
        let cfg = load_project_config(&td.path().join(PROJECT_CONFIG_FILE)).unwrap();
        assert_eq!(cfg.allow.paths.len(), 2);
        assert_eq!(cfg.allow.filetypes.len(), 2);
    }

    #[test]
    fn allow_section_default_empty_when_omitted() {
        let td = tempfile::tempdir().unwrap();
        write_cfg(td.path(), "");
        let cfg = load_project_config(&td.path().join(PROJECT_CONFIG_FILE)).unwrap();
        assert!(cfg.allow.paths.is_empty());
        assert!(cfg.allow.filetypes.is_empty());
    }

    #[test]
    fn autoload_allow_returns_empty_when_no_config() {
        let td = tempfile::tempdir().unwrap();
        let allow = autoload_project_allow(td.path()).unwrap();
        assert!(allow.paths.is_empty());
        assert!(allow.filetypes.is_empty());
    }

    #[test]
    fn autoload_allow_walks_up_tree() {
        let td = tempfile::tempdir().unwrap();
        let nested = td.path().join("sub/deep");
        std::fs::create_dir_all(&nested).unwrap();
        write_cfg(td.path(), "[allow]\npaths = [\"foo/*\"]\n");
        let allow = autoload_project_allow(&nested).unwrap();
        assert_eq!(allow.paths, vec!["foo/*"]);
    }

    #[test]
    fn allow_matches_path_glob() {
        let a = AllowSection {
            paths: vec!["fixtures/**/*.docx".into()],
            filetypes: vec![],
            keywords: vec![],
        };
        assert!(allow_matches(&a, "fixtures/legal/contract.docx"));
        assert!(!allow_matches(&a, "src/legal/contract.docx"));
    }

    #[test]
    fn allow_matches_filetypes_with_and_without_leading_dot() {
        let a = AllowSection {
            paths: vec![],
            filetypes: vec!["xlsx".into(), ".docx".into()],
            keywords: vec![],
        };
        assert!(allow_matches(&a, "anywhere/report.xlsx"));
        assert!(allow_matches(&a, "letter.docx"));
        assert!(!allow_matches(&a, "deck.pptx"));
    }

    #[test]
    fn allow_matches_filetypes_case_insensitive() {
        let a = AllowSection {
            paths: vec![],
            filetypes: vec!["XLSX".into()],
            keywords: vec![],
        };
        assert!(allow_matches(&a, "report.xlsx"));
        assert!(allow_matches(&a, "REPORT.XLSX"));
    }

    #[test]
    fn allow_matches_returns_false_for_empty_section() {
        let a = AllowSection::default();
        assert!(!allow_matches(&a, "anything.xlsx"));
        assert!(!allow_matches(&a, "/any/path"));
    }

    // ---------- rred-8..11 .redactor.toml tests ----------

    use std::fs;

    fn write_cfg(dir: &std::path::Path, body: &str) {
        fs::write(dir.join(PROJECT_CONFIG_FILE), body).unwrap();
    }

    #[test]
    fn discover_finds_in_start_dir() {
        let td = tempfile::tempdir().unwrap();
        write_cfg(td.path(), "");
        assert_eq!(
            discover_project_config(td.path()).unwrap(),
            td.path().join(PROJECT_CONFIG_FILE)
        );
    }

    #[test]
    fn discover_walks_up_tree() {
        let td = tempfile::tempdir().unwrap();
        let nested = td.path().join("a/b/c");
        std::fs::create_dir_all(&nested).unwrap();
        write_cfg(td.path(), "");
        assert_eq!(
            discover_project_config(&nested).unwrap(),
            td.path().join(PROJECT_CONFIG_FILE)
        );
    }

    #[test]
    fn discover_returns_none_when_missing() {
        let td = tempfile::tempdir().unwrap();
        assert!(discover_project_config(td.path()).is_none());
    }

    #[test]
    fn load_empty_yields_default() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join(PROJECT_CONFIG_FILE);
        write_cfg(td.path(), "");
        let cfg = load_project_config(&path).unwrap();
        assert!(cfg.patterns.custom.is_empty());
        assert!(cfg.whitelist.paths.is_empty());
        assert!(cfg.modes.by_ext.is_empty());
    }

    #[test]
    fn load_full_config_parses() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join(PROJECT_CONFIG_FILE);
        let body = r#"
[[patterns.custom]]
name = "internal_id"
re = 'INT-\d{6}'

[[patterns.custom]]
name = "ticket"
re = 'TICKET-\d+'
sub = "[T]"

[whitelist]
paths = ["docs/example.cfg", "fixtures/*.crt"]

[modes]
"tf" = "pattern"
"yaml" = "json"
"#;
        write_cfg(td.path(), body);
        let cfg = load_project_config(&path).unwrap();
        assert_eq!(cfg.patterns.custom.len(), 2);
        assert_eq!(cfg.whitelist.paths.len(), 2);
        assert_eq!(cfg.modes.by_ext.len(), 2);
    }

    #[test]
    fn load_malformed_returns_err_with_path() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join(PROJECT_CONFIG_FILE);
        write_cfg(td.path(), "[patterns\n garbage");
        let err = load_project_config(&path).unwrap_err();
        assert!(err.to_string().contains(&path.display().to_string()));
    }

    // ---------- rred-9 pattern override ----------

    #[test]
    fn project_rules_default_replacement_uses_name() {
        let td = tempfile::tempdir().unwrap();
        let body = r#"
[[patterns.custom]]
name = "internal_id"
re = 'INT-\d{6}'
"#;
        write_cfg(td.path(), body);
        let rules = autoload_project_rules(td.path()).unwrap();
        assert_eq!(rules.len(), 1);
        let out = rules[0]
            .regex
            .replace_all("see INT-123456 ende", &rules[0].replacement[..]);
        assert!(out.contains("<redacted:internal_id>"));
    }

    #[test]
    fn project_rules_explicit_sub_wins() {
        let td = tempfile::tempdir().unwrap();
        let body = r#"
[[patterns.custom]]
name = "ticket"
re = 'TICKET-\d+'
sub = "[T]"
"#;
        write_cfg(td.path(), body);
        let rules = autoload_project_rules(td.path()).unwrap();
        assert_eq!(rules.len(), 1);
        let out = rules[0]
            .regex
            .replace_all("see TICKET-77 ende", &rules[0].replacement[..]);
        assert!(out.contains("[T]"));
        assert!(!out.contains("TICKET-77"));
    }

    #[test]
    fn project_rules_invalid_regex_errors_with_name() {
        let td = tempfile::tempdir().unwrap();
        let body = r#"
[[patterns.custom]]
name = "broken"
re = "[unclosed"
"#;
        write_cfg(td.path(), body);
        let err = autoload_project_rules(td.path()).unwrap_err();
        assert!(err.to_string().contains("broken"));
    }

    #[test]
    fn autoload_no_file_returns_empty() {
        let td = tempfile::tempdir().unwrap();
        assert!(autoload_project_rules(td.path()).unwrap().is_empty());
        assert!(autoload_project_whitelist(td.path()).unwrap().is_empty());
        assert!(autoload_project_modes(td.path()).unwrap().is_empty());
    }

    // ---------- rred-11 modes ----------

    #[test]
    fn project_modes_string_to_enum() {
        let td = tempfile::tempdir().unwrap();
        let body = r#"
[modes]
"tf" = "pattern"
".yaml" = "json"
"YML" = "JSON"
"#;
        write_cfg(td.path(), body);
        let modes = autoload_project_modes(td.path()).unwrap();
        assert_eq!(modes.get("tf"), Some(&crate::redactor::Mode::Pattern));
        assert_eq!(modes.get("yaml"), Some(&crate::redactor::Mode::Json));
        assert_eq!(modes.get("yml"), Some(&crate::redactor::Mode::Json));
    }

    #[test]
    fn project_modes_unknown_string_skipped() {
        let td = tempfile::tempdir().unwrap();
        let body = r#"
[modes]
"py" = "banana"
"tf" = "pattern"
"#;
        write_cfg(td.path(), body);
        let modes = autoload_project_modes(td.path()).unwrap();
        assert_eq!(modes.len(), 1);
        assert!(modes.contains_key("tf"));
        assert!(!modes.contains_key("py"));
    }
}
