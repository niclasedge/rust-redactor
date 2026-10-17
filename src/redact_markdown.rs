//! Interactive batch redaction for Markdown files (Obsidian vaults).
//!
//! Walks `*.md`, previews keyword/pattern hits side-by-side (original →
//! placeholder), and applies changes only after manual batch confirmation.

use anyhow::{bail, Context, Result};
use clap::Args;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::patterns::Rule;
use crate::redactor;

const STATE_FILE: &str = "redact-markdown-state.json";

/// Built-in rules disabled for vault markdown — dates and `@`-mentions in
/// notes are usually metadata, not secrets to scrub in-place.
const MARKDOWN_SKIP_RULES: &[&str] = &["email", "birthdate_de"];

/// Directories skipped during the vault walk (same spirit as classify_walk).
const SKIP_DIR_NAMES: &[&str] = &[
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "target",
    "dist",
    "build",
    ".cache",
    ".trash",
];

/// One match that would be rewritten in-place.
#[derive(Debug, Clone)]
pub struct HitPreview {
    pub rule: String,
    pub original: String,
    pub replacement: String,
    pub line: usize,
}

/// Per-file preview bundle shown in a batch.
#[derive(Debug, Clone)]
pub struct FilePreview {
    pub path: PathBuf,
    pub rel: String,
    pub redacted: String,
    pub hits: Vec<HitPreview>,
}

/// User decision for an entire batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BatchDecision {
    ApplyAll,
    Skip,
    ReviewEach,
    Quit,
}

/// User decision for a single file inside a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileDecision {
    Apply,
    Skip,
    Quit,
}

#[derive(Debug, Clone, Args)]
pub struct RedactMarkdownArgs {
    /// Vault / directory root. Default: `$OBSIDIAN_VAULT_PATH` or
    /// `~/GITHUB/ObsidianPKM`.
    pub directory: Option<PathBuf>,

    /// Files per interactive batch (default 10).
    #[arg(long, default_value_t = 10)]
    pub batch_size: usize,

    /// Cap walk depth (default: unlimited).
    #[arg(long)]
    pub max_depth: Option<usize>,

    /// Preview only — never write files.
    #[arg(long)]
    pub dry_run: bool,

    /// Skip the interactive prompt and apply every batch automatically.
    #[arg(long, conflicts_with = "dry_run")]
    pub yes: bool,

    /// Resume a previous run: skip paths recorded as applied or skipped in
    /// `<config>/redact-markdown-state.json`.
    #[arg(long)]
    pub resume: bool,

    /// Re-scan everything, ignoring the resume state file.
    #[arg(long, conflicts_with = "resume")]
    pub force: bool,

    /// Skip a directory (repeatable). Matched relative to the scan root, e.g.
    /// `--exclude notes/Sources --exclude tasks`. A bare name like `tasks`
    /// also skips that folder anywhere in the tree.
    #[arg(long = "exclude", value_name = "PATH")]
    pub exclude: Vec<String>,

    /// Only redact literal keywords from `~/.redactorignore` / `--keywords`.
    /// Built-in patterns (ipv4, crypto paths, API keys, …) and custom regex
    /// from `patterns.json` are ignored.
    #[arg(long)]
    pub keyword_only: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ResumeState {
    root: String,
    applied: HashSet<String>,
    skipped: HashSet<String>,
}

impl ResumeState {
    fn load(path: &Path) -> Result<Self> {
        if path.exists() {
            let body = std::fs::read_to_string(path)
                .with_context(|| format!("read {}", path.display()))?;
            Ok(serde_json::from_str(&body)?)
        } else {
            Ok(Self::default())
        }
    }

    fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let body = serde_json::to_string_pretty(self)?;
        std::fs::write(path, body).with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }
}

fn state_path() -> Option<PathBuf> {
    crate::config::config_dir().map(|d| d.join(STATE_FILE))
}

/// Resolve the Obsidian vault root.
pub fn default_vault_dir() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("OBSIDIAN_VAULT_PATH") {
        let pb = PathBuf::from(p);
        if pb.is_dir() {
            return Some(pb);
        }
    }
    dirs::home_dir().map(|h| h.join("GITHUB/ObsidianPKM"))
}

fn resolve_root(args: &RedactMarkdownArgs) -> Result<PathBuf> {
    let raw = args
        .directory
        .clone()
        .or_else(default_vault_dir)
        .context("no directory given and default vault path not found")?;
    raw.canonicalize()
        .with_context(|| format!("cannot read directory {}", raw.display()))
}

fn should_skip_dir(name: &str) -> bool {
    SKIP_DIR_NAMES.contains(&name) || name.starts_with('.') && name != "."
}

/// Normalize a user-supplied `--exclude` value for matching.
fn normalize_exclude(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("./")
        .trim_matches('/')
        .replace('\\', "/")
        .to_ascii_lowercase()
}

/// Compile `--exclude` strings into normalized patterns (deduped).
pub fn compile_excludes(raw: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for r in raw {
        let n = normalize_exclude(r);
        if !n.is_empty() && !out.contains(&n) {
            out.push(n);
        }
    }
    out
}

/// True when `path` (absolute, under `root`) falls under an exclude rule.
pub fn is_excluded_path(path: &Path, root: &Path, excludes: &[String]) -> bool {
    if excludes.is_empty() {
        return false;
    }
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let rel = rel.trim_start_matches('/');
    if rel.is_empty() {
        return false;
    }
    for ex in excludes {
        if rel == *ex || rel.starts_with(&format!("{ex}/")) {
            return true;
        }
        if rel.split('/').any(|seg| seg == ex.as_str()) {
            return true;
        }
    }
    false
}

/// Collect every `*.md` file under `root`, sorted for stable batches.
pub fn walk_markdown(
    root: &Path,
    max_depth: Option<usize>,
    excludes: &[String],
) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut walker = WalkDir::new(root).follow_links(false).sort_by_file_name();
    if let Some(d) = max_depth {
        walker = walker.max_depth(d);
    }
    let walker = walker.into_iter().filter_entry(|entry| {
        if entry.depth() == 0 {
            return true;
        }
        let path = entry.path();
        if is_excluded_path(path, root, excludes) {
            return false;
        }
        if entry.file_type().is_dir() {
            entry
                .file_name()
                .to_str()
                .map(|n| !should_skip_dir(n))
                .unwrap_or(true)
        } else {
            true
        }
    });
    for entry in walker {
        let entry = entry.with_context(|| format!("walk {}", root.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.into_path();
        if is_excluded_path(&path, root, excludes) {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) == Some("md") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// Keep only literal-keyword rules (`<redacted:keyword>`).
pub fn keyword_only_rules(rules: &[Rule]) -> Vec<Rule> {
    rules
        .iter()
        .filter(|r| r.name == "keyword")
        .cloned()
        .collect()
}

/// Build a preview for one file. Returns `None` when redaction would not change
/// the content (no hits after the false-positive filter).
pub fn preview_file(path: &Path, root: &Path, rules: &[Rule]) -> Result<Option<FilePreview>> {
    let original =
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let hits = collect_hits(&original, rules);
    if hits.is_empty() {
        return Ok(None);
    }
    let (redacted, _) = redactor::redact_pattern(&original, rules);
    if redacted == original {
        return Ok(None);
    }
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string();
    Ok(Some(FilePreview {
        path: path.to_path_buf(),
        rel,
        redacted,
        hits,
    }))
}

/// Collect would-be redactions using the same false-positive filter as
/// [`redactor::redact_pattern`].
fn collect_hits(text: &str, rules: &[Rule]) -> Vec<HitPreview> {
    let mut out = Vec::new();
    for rule in rules {
        for mat in rule.regex.find_iter(text) {
            let m = mat.as_str();
            let start = mat.start();
            let end = mat.end();
            let bstart = text[..start]
                .char_indices()
                .rev()
                .nth(15)
                .map(|(i, _)| i)
                .unwrap_or(0);
            let aend = text[end..]
                .char_indices()
                .nth(16)
                .map(|(i, _)| end + i)
                .unwrap_or(text.len());
            let before = &text[bstart..start];
            let after_ctx = &text[end..aend];
            if redactor::is_false_positive(m, &rule.name, before, after_ctx) {
                continue;
            }
            let mut replacement = String::new();
            if let Some(caps) = rule.regex.captures_at(text, start) {
                caps.expand(&rule.replacement, &mut replacement);
            } else {
                replacement = rule.replacement.clone();
            }
            let line = text[..start].lines().count();
            out.push(HitPreview {
                rule: rule.name.clone(),
                original: m.to_string(),
                replacement,
                line,
            });
        }
    }
    out.sort_by_key(|h| (h.line, h.rule.clone()));
    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max).collect::<String>() + "…"
}

fn print_file_preview(
    out: &mut impl Write,
    idx: usize,
    batch_len: usize,
    fp: &FilePreview,
) -> Result<()> {
    writeln!(out)?;
    writeln!(out, "[{}/{}] {}", idx + 1, batch_len, fp.rel)?;
    writeln!(out, "  {} hit(s):", fp.hits.len())?;
    for hit in &fp.hits {
        writeln!(
            out,
            "    L{:>4}  {:<18}  \"{}\"  →  {}",
            hit.line,
            hit.rule,
            truncate(&hit.original, 48),
            hit.replacement
        )?;
    }
    Ok(())
}

fn prompt_batch(
    batch_idx: usize,
    total_batches: usize,
    batch: &[FilePreview],
    reader: &mut impl BufRead,
    out: &mut impl Write,
) -> Result<BatchDecision> {
    writeln!(out)?;
    writeln!(
        out,
        "══ Batch {}/{} — {} file(s) with redactions ══",
        batch_idx + 1,
        total_batches,
        batch.len()
    )?;
    for (i, fp) in batch.iter().enumerate() {
        print_file_preview(out, i, batch.len(), fp)?;
    }
    if batch.is_empty() {
        return Ok(BatchDecision::Skip);
    }
    write!(
        out,
        "\nApply this batch? [y]es all / [r]eview each / [n]o skip / [q]uit: "
    )?;
    out.flush()?;
    read_decision(reader, |ch| match ch {
        'y' => BatchDecision::ApplyAll,
        'r' => BatchDecision::ReviewEach,
        'n' => BatchDecision::Skip,
        'q' => BatchDecision::Quit,
        _ => BatchDecision::Skip,
    })
}

fn prompt_file(
    fp: &FilePreview,
    reader: &mut impl BufRead,
    out: &mut impl Write,
) -> Result<FileDecision> {
    writeln!(out)?;
    writeln!(out, "  → {}", fp.rel)?;
    for hit in &fp.hits {
        writeln!(
            out,
            "      \"{}\"  →  {}",
            truncate(&hit.original, 40),
            hit.replacement
        )?;
    }
    write!(out, "  Redact this file? [y]es / [n]o / [q]uit: ")?;
    out.flush()?;
    read_decision(reader, |ch| match ch {
        'y' => FileDecision::Apply,
        'n' => FileDecision::Skip,
        'q' => FileDecision::Quit,
        _ => FileDecision::Skip,
    })
}

fn read_decision<T, F>(reader: &mut impl BufRead, map: F) -> Result<T>
where
    F: FnOnce(char) -> T,
{
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(map('q'));
    }
    let ch = line
        .trim()
        .chars()
        .next()
        .unwrap_or('n')
        .to_ascii_lowercase();
    Ok(map(ch))
}

fn apply_file(fp: &FilePreview, dry_run: bool) -> Result<()> {
    if dry_run {
        eprintln!("  (dry-run) would write {}", fp.path.display());
        return Ok(());
    }
    std::fs::write(&fp.path, &fp.redacted)
        .with_context(|| format!("write {}", fp.path.display()))?;
    eprintln!("  redacted {}", fp.rel);
    Ok(())
}

/// Entry point from `main.rs`.
pub fn run(args: RedactMarkdownArgs, rules: &[Rule]) -> Result<i32> {
    let rules: Vec<Rule> = if args.keyword_only {
        keyword_only_rules(rules)
    } else {
        rules
            .iter()
            .filter(|r| !MARKDOWN_SKIP_RULES.contains(&r.name.as_str()))
            .cloned()
            .collect()
    };
    if rules.is_empty() {
        if args.keyword_only {
            bail!(
                "redact-markdown: --keyword-only but no keywords loaded \
                 (add terms to ~/.redactorignore or pass --keywords)"
            );
        }
        bail!("redact-markdown: no rules loaded (check ~/.redactorignore and patterns)");
    }
    if args.batch_size == 0 {
        bail!("redact-markdown: --batch-size must be >= 1");
    }

    let root = resolve_root(&args)?;
    let excludes = compile_excludes(&args.exclude);
    eprintln!("redactor: scanning markdown under {}", root.display());
    if !excludes.is_empty() {
        eprintln!("redactor: excluding: {}", excludes.join(", "));
    }
    if args.keyword_only {
        eprintln!(
            "redactor: keyword-only mode ({} keyword rule(s))",
            rules.len()
        );
    }

    let all_md = walk_markdown(&root, args.max_depth, &excludes)?;
    eprintln!("redactor: {} markdown files found", all_md.len());

    let mut resume = ResumeState {
        root: root.display().to_string(),
        ..Default::default()
    };
    let state_file = state_path();
    if args.resume && !args.force {
        if let Some(ref sp) = state_file {
            resume = ResumeState::load(sp)?;
            if !resume.root.is_empty() && resume.root != root.display().to_string() {
                eprintln!(
                    "redactor: warning: resume state is for {} (current: {})",
                    resume.root,
                    root.display()
                );
            }
        }
    } else if args.force {
        resume = ResumeState {
            root: root.display().to_string(),
            ..Default::default()
        };
    }

    let mut previews: Vec<FilePreview> = Vec::new();
    let mut clean = 0usize;
    let mut resumed = 0usize;
    for path in &all_md {
        let key = path.display().to_string();
        if args.resume
            && !args.force
            && (resume.applied.contains(&key) || resume.skipped.contains(&key))
        {
            resumed += 1;
            continue;
        }
        match preview_file(path, &root, &rules)? {
            Some(fp) => previews.push(fp),
            None => clean += 1,
        }
    }

    eprintln!(
        "redactor: {} file(s) with redactions, {} clean, {} skipped (resume)",
        previews.len(),
        clean,
        resumed
    );

    if previews.is_empty() {
        eprintln!("redactor: nothing to do.");
        return Ok(0);
    }

    let batch_size = args.batch_size;
    let total_batches = previews.len().div_ceil(batch_size);
    let mut applied = 0usize;
    let mut skipped = 0usize;

    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut stderr = std::io::stderr().lock();

    for (batch_idx, chunk) in previews.chunks(batch_size).enumerate() {
        if args.dry_run {
            writeln!(stderr)?;
            writeln!(
                stderr,
                "══ Batch {}/{} — {} file(s) (dry-run) ══",
                batch_idx + 1,
                total_batches,
                chunk.len()
            )?;
            for (i, fp) in chunk.iter().enumerate() {
                print_file_preview(&mut stderr, i, chunk.len(), fp)?;
            }
            skipped += chunk.len();
            continue;
        }

        let decision = if args.yes {
            BatchDecision::ApplyAll
        } else {
            prompt_batch(batch_idx, total_batches, chunk, &mut reader, &mut stderr)?
        };

        match decision {
            BatchDecision::Quit => {
                eprintln!("redactor: stopped by user.");
                break;
            }
            BatchDecision::Skip => {
                for fp in chunk {
                    resume.skipped.insert(fp.path.display().to_string());
                    skipped += 1;
                }
                continue;
            }
            BatchDecision::ApplyAll => {
                for fp in chunk {
                    apply_file(fp, args.dry_run)?;
                    resume.applied.insert(fp.path.display().to_string());
                    applied += 1;
                }
            }
            BatchDecision::ReviewEach => {
                for fp in chunk {
                    let fd = if args.yes {
                        FileDecision::Apply
                    } else {
                        prompt_file(fp, &mut reader, &mut stderr)?
                    };
                    match fd {
                        FileDecision::Quit => {
                            eprintln!("redactor: stopped by user.");
                            if let Some(ref sp) = state_file {
                                let _ = resume.save(sp);
                            }
                            eprintln!("redactor: applied {applied}, skipped {skipped} this run");
                            return Ok(0);
                        }
                        FileDecision::Apply => {
                            apply_file(fp, args.dry_run)?;
                            resume.applied.insert(fp.path.display().to_string());
                            applied += 1;
                        }
                        FileDecision::Skip => {
                            resume.skipped.insert(fp.path.display().to_string());
                            skipped += 1;
                        }
                    }
                }
            }
        }

        if let Some(ref sp) = state_file {
            let _ = resume.save(sp);
        }
    }

    eprintln!(
        "redactor: done — applied {applied}, skipped {skipped} (dry-run={})",
        args.dry_run
    );
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn preview_finds_keyword_hit() {
        let td = tempdir().unwrap();
        let p = td.path().join("note.md");
        fs::write(&p, "Meeting with ACMECORP tomorrow.\n").unwrap();
        let rules = patterns::from_keywords("ACMECORP");
        let prev = preview_file(&p, td.path(), &rules).unwrap().unwrap();
        assert_eq!(prev.hits.len(), 1);
        assert!(prev.redacted.contains("<redacted:keyword>"));
        assert!(!prev.redacted.contains("ACMECORP"));
    }

    #[test]
    fn preview_skips_clean_file() {
        let td = tempdir().unwrap();
        let p = td.path().join("clean.md");
        fs::write(&p, "# Hello\n\nNo secrets here.\n").unwrap();
        let rules = patterns::from_keywords("ACMECORP");
        assert!(preview_file(&p, td.path(), &rules).unwrap().is_none());
    }

    #[test]
    fn walk_finds_md_only() {
        let td = tempdir().unwrap();
        fs::write(td.path().join("a.md"), "x").unwrap();
        fs::write(td.path().join("b.txt"), "y").unwrap();
        fs::create_dir(td.path().join(".git")).unwrap();
        fs::write(td.path().join(".git/ignored.md"), "z").unwrap();
        let found = walk_markdown(td.path(), None, &[]).unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].ends_with("a.md"));
    }

    #[test]
    fn exclude_skips_subtree() {
        let td = tempdir().unwrap();
        fs::create_dir_all(td.path().join("notes/Wiki")).unwrap();
        fs::create_dir_all(td.path().join("notes/Sources")).unwrap();
        fs::write(td.path().join("notes/Wiki/keep.md"), "a").unwrap();
        fs::write(td.path().join("notes/Sources/skip.md"), "b").unwrap();
        fs::write(td.path().join("root.md"), "c").unwrap();
        let ex = compile_excludes(&["notes/Sources".into()]);
        let found = walk_markdown(td.path(), None, &ex).unwrap();
        assert_eq!(found.len(), 2);
        assert!(found.iter().any(|p| p.ends_with("keep.md")));
        assert!(found.iter().any(|p| p.ends_with("root.md")));
        assert!(!found.iter().any(|p| p.ends_with("skip.md")));
    }

    #[test]
    fn exclude_bare_name_matches_anywhere() {
        let td = tempdir().unwrap();
        fs::create_dir_all(td.path().join("foo/tasks")).unwrap();
        fs::write(td.path().join("foo/tasks/x.md"), "a").unwrap();
        fs::write(td.path().join("foo/ok.md"), "b").unwrap();
        let ex = compile_excludes(&["tasks".into()]);
        let found = walk_markdown(td.path(), None, &ex).unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].ends_with("ok.md"));
    }

    #[test]
    fn keyword_only_keeps_keyword_rule() {
        let defaults = patterns::defaults();
        let kw = patterns::from_keywords("ACMECORP");
        let mut all = defaults;
        all.extend(kw);
        let filtered = keyword_only_rules(&all);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "keyword");
    }

    #[test]
    fn markdown_skip_rules_drop_email_and_birthdate() {
        let td = tempdir().unwrap();
        let p = td.path().join("meta.md");
        fs::write(
            &p,
            "Contact: alice@example.com\nBorn: 28-04-2026\nKey: sk-proj-abcdefghij1234567890XYZ\n",
        )
        .unwrap();
        let all_rules = patterns::defaults();
        let filtered: Vec<_> = all_rules
            .iter()
            .filter(|r| !MARKDOWN_SKIP_RULES.contains(&r.name.as_str()))
            .cloned()
            .collect();
        assert!(preview_file(&p, td.path(), &all_rules).unwrap().is_some());
        let prev = preview_file(&p, td.path(), &filtered).unwrap().unwrap();
        assert!(prev.hits.iter().any(|h| h.rule == "openai_key"));
        assert!(!prev.hits.iter().any(|h| h.rule == "email"));
        assert!(!prev.hits.iter().any(|h| h.rule == "birthdate_de"));
    }
}
